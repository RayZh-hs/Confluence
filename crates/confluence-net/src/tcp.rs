use confluence_core::{
    AsyncStream, ChannelCaps, ChannelErr, CoreErr, Node, STREAM_CHUNK, ScopeInstance,
    StreamChannel, StreamListener, StreamRead, StreamWrite,
};
use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
};

use super::{connect_error, io_error, locator, source_tag_for_ip};

/// Pure native TCP Stream carrier (Seam 1A).
#[derive(Clone, Copy)]
pub struct TcpCarrier {
    chunk_limit: u16,
}

impl Default for TcpCarrier {
    fn default() -> Self {
        Self {
            chunk_limit: STREAM_CHUNK as u16,
        }
    }
}

impl TcpCarrier {
    pub fn with_chunk_limit(chunk_limit: u16) -> Self {
        Self {
            chunk_limit: chunk_limit.min(STREAM_CHUNK as u16),
        }
    }
}

impl StreamChannel for TcpCarrier {
    type Stream = TcpIo;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.chunk_limit, true)
    }

    async fn dial_stream(&self, bytes: &[u8]) -> Result<TcpIo, CoreErr> {
        let stream = TcpStream::connect(locator(bytes)?)
            .await
            .map_err(connect_error)?;
        TcpIo::new(stream, self.chunk_limit)
    }
}

/// [`AsyncStream`] wrapper over a `TCP_NODELAY` Tokio [`TcpStream`].
pub struct TcpIo {
    stream: TcpStream,
    chunk_limit: u16,
    source_tag: [u8; 16],
}

impl TcpIo {
    pub fn new(stream: TcpStream, chunk_limit: u16) -> Result<Self, CoreErr> {
        stream.set_nodelay(true).map_err(io_error)?;
        let source_tag = stream
            .peer_addr()
            .map(|addr| source_tag_for_ip(addr.ip()))
            .unwrap_or([0; 16]);
        Ok(Self {
            stream,
            chunk_limit,
            source_tag,
        })
    }
}

/// Poll-based read half of [`TcpIo`].
pub struct TcpReadHalf(OwnedReadHalf);

/// Poll-based write half of [`TcpIo`].
pub struct TcpWriteHalf(OwnedWriteHalf);

impl AsyncStream for TcpIo {
    type Read = TcpReadHalf;
    type Write = TcpWriteHalf;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.chunk_limit, true)
    }

    fn split(self) -> (TcpReadHalf, TcpWriteHalf) {
        let (read, write) = self.stream.into_split();
        (TcpReadHalf(read), TcpWriteHalf(write))
    }

    fn source_tag(&self) -> [u8; 16] {
        self.source_tag
    }
}

impl StreamRead for TcpReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ChannelErr>> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.0).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(io_error(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl StreamWrite for TcpWriteHalf {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ChannelErr>> {
        Pin::new(&mut self.0).poll_write(cx, buf).map_err(io_error)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ChannelErr>> {
        Pin::new(&mut self.0).poll_flush(cx).map_err(io_error)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ChannelErr>> {
        Pin::new(&mut self.0).poll_shutdown(cx).map_err(io_error)
    }
}

/// Composable [`StreamListener`] backed by an explicitly bound [`TcpListener`].
pub struct TcpListenerSource {
    listener: TcpListener,
    chunk_limit: u16,
}

impl TcpListenerSource {
    pub fn new(listener: TcpListener, carrier: TcpCarrier) -> Self {
        Self {
            listener,
            chunk_limit: carrier.chunk_limit,
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, CoreErr> {
        self.listener.local_addr().map_err(io_error)
    }
}

impl StreamListener for TcpListenerSource {
    type Stream = TcpIo;

    async fn accept(&self) -> Result<TcpIo, CoreErr> {
        let (stream, _) = self.listener.accept().await.map_err(io_error)?;
        TcpIo::new(stream, self.chunk_limit)
    }
}

/// Serves an explicitly bound TCP listener into a single [`ScopeInstance`].
pub async fn serve_tcp(
    listener: TcpListener,
    scope: ScopeInstance,
    carrier: TcpCarrier,
) -> Result<(), CoreErr> {
    let source = TcpListenerSource::new(listener, carrier);
    scope.serve_stream_listener(&source).await
}

/// Serves an explicitly bound TCP listener into a multi-scope [`Node`].
pub async fn serve_tcp_node(
    listener: TcpListener,
    node: Node,
    carrier: TcpCarrier,
) -> Result<(), CoreErr> {
    let source = TcpListenerSource::new(listener, carrier);
    node.serve_stream_listener(&source).await
}

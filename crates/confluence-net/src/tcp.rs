use confluence_core::{
    AsyncStream, BoxFut, ChannelCaps, CoreErr, STREAM_CHUNK, ScopeInstance, StreamChannel,
    StreamRead, StreamWrite,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
};

use super::{connect_error, io_error, locator};

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
    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.chunk_limit, true)
    }
    fn dial_stream<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> BoxFut<'a, Result<Box<dyn AsyncStream>, CoreErr>> {
        Box::pin(async move {
            let stream = TcpStream::connect(locator(bytes)?)
                .await
                .map_err(connect_error)?;
            Ok(Box::new(TcpIo::new(stream, self.chunk_limit)?) as Box<dyn AsyncStream>)
        })
    }
}

pub struct TcpIo {
    stream: TcpStream,
    chunk_limit: u16,
}
impl TcpIo {
    pub fn new(stream: TcpStream, chunk_limit: u16) -> Result<Self, CoreErr> {
        stream.set_nodelay(true).map_err(io_error)?;
        Ok(Self {
            stream,
            chunk_limit,
        })
    }
}
struct ReadHalf(OwnedReadHalf);
struct WriteHalf(OwnedWriteHalf);
impl AsyncStream for TcpIo {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.chunk_limit, true)
    }
    fn split(self: Box<Self>) -> (Box<dyn StreamRead>, Box<dyn StreamWrite>) {
        let (read, write) = self.stream.into_split();
        (Box::new(ReadHalf(read)), Box::new(WriteHalf(write)))
    }
}
impl StreamRead for ReadHalf {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFut<'a, Result<usize, CoreErr>> {
        Box::pin(async move { self.0.read(buf).await.map_err(io_error) })
    }
}
impl StreamWrite for WriteHalf {
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFut<'a, Result<(), CoreErr>> {
        Box::pin(async move { self.0.write_all(buf).await.map_err(io_error) })
    }
    fn shutdown(&mut self) -> BoxFut<'_, Result<(), CoreErr>> {
        Box::pin(async move { self.0.shutdown().await.map_err(io_error) })
    }
}

/// Serves a listener the embedding application explicitly bound.
pub async fn serve_tcp(
    listener: TcpListener,
    scope: ScopeInstance,
    carrier: TcpCarrier,
) -> Result<(), CoreErr> {
    loop {
        let (stream, _) = listener.accept().await.map_err(io_error)?;
        if let Ok(stream) = TcpIo::new(stream, carrier.chunk_limit) {
            let _ = scope.accept_stream(Box::new(stream));
        }
    }
}

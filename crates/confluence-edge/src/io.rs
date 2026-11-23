//! Ecosystem `tokio::io::AsyncRead + AsyncWrite` adapter over [`confluence_core::E2eStream`].

use confluence_core::{CoreErr, E2eStream};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    sync::watch,
};

#[derive(Clone, Copy, Default)]
struct WriteProgress {
    forwarded: u64,
    fin_sent: bool,
    error: Option<io::ErrorKind>,
}

type ProgressWait = Pin<Box<dyn Future<Output = Result<(), watch::error::RecvError>> + Send>>;

/// Adapts an [`E2eStream`] into a standard `tokio::io::AsyncRead + AsyncWrite + Unpin + Send`
/// stream for seamless integration with `tokio::io::copy_bidirectional`, Hyper, Tonic, etc.
///
/// Preserves Confluence's truncation protection: clean EOF (`Ok(0)`) occurs only after an
/// authenticated `E2E_FIN`, while unexpected carrier drops surface `io::ErrorKind::UnexpectedEof`
/// and revocations surface `io::ErrorKind::PermissionDenied`.
pub struct E2eStreamIo {
    app: DuplexStream,
    written: u64,
    progress: watch::Receiver<WriteProgress>,
    progress_wait: Option<ProgressWait>,
    pump: tokio::task::JoinHandle<()>,
}

impl E2eStreamIo {
    /// Wraps `stream` in a buffered `AsyncRead + AsyncWrite` bridge on the current Tokio runtime.
    pub fn new(stream: E2eStream) -> Self {
        let (app, bridge) = tokio::io::duplex(64 * 1024);
        let (progress_tx, progress) = watch::channel(WriteProgress::default());

        let pump = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut app_rd, mut app_wr) = tokio::io::split(bridge);
            let max_chunk = stream.max_write_size().max(1);

            let to_remote = async {
                let mut buf = vec![0u8; max_chunk];
                loop {
                    let n = app_rd
                        .read(&mut buf)
                        .await
                        .map_err(|_| CoreErr::UnexpectedEof)?;
                    if n == 0 {
                        stream.shutdown().await?;
                        progress_tx.send_modify(|progress| progress.fin_sent = true);
                        return Ok(());
                    }
                    stream.write_all(&buf[..n]).await?;
                    progress_tx.send_modify(|progress| progress.forwarded += n as u64);
                }
            };
            let to_local = async {
                let mut buf = vec![0u8; max_chunk];
                loop {
                    let n = stream.read(&mut buf).await?;
                    if n == 0 {
                        let _ = app_wr.shutdown().await;
                        return Ok(());
                    }
                    app_wr
                        .write_all(&buf[..n])
                        .await
                        .map_err(|_| CoreErr::Closed)?;
                }
            };

            if let Err(err) = tokio::try_join!(to_remote, to_local) {
                progress_tx.send_modify(|progress| progress.error = Some(map_core_err(&err)));
            }
        });

        Self {
            app,
            written: 0,
            progress,
            progress_wait: None,
            pump,
        }
    }

    fn terminal_error(&self) -> Option<io::Error> {
        self.progress.borrow().error.map(stream_error)
    }

    fn poll_write_progress(&mut self, cx: &mut Context<'_>, fin: bool) -> Poll<io::Result<()>> {
        let mut closed = false;
        loop {
            let progress = *self.progress.borrow_and_update();
            if fin && progress.fin_sent {
                return Poll::Ready(Ok(()));
            }
            if let Some(kind) = progress.error {
                return Poll::Ready(Err(stream_error(kind)));
            }
            if !fin && progress.forwarded == self.written {
                return Poll::Ready(Ok(()));
            }
            if closed {
                return Poll::Ready(Err(stream_error(io::ErrorKind::BrokenPipe)));
            }
            let wait = self.progress_wait.get_or_insert_with(|| {
                let mut progress = self.progress.clone();
                Box::pin(async move { progress.changed().await })
            });
            closed = ready!(wait.as_mut().poll(cx)).is_err();
            self.progress_wait = None;
        }
    }
}

impl Drop for E2eStreamIo {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

fn map_core_err(err: &CoreErr) -> io::ErrorKind {
    match err {
        CoreErr::Revoked | CoreErr::Expired | CoreErr::Denied | CoreErr::Unpublished => {
            io::ErrorKind::PermissionDenied
        }
        CoreErr::UnexpectedEof => io::ErrorKind::UnexpectedEof,
        CoreErr::TargetRefused => io::ErrorKind::ConnectionRefused,
        CoreErr::Timeout => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::BrokenPipe,
    }
}

fn stream_error(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, "confluence stream terminated")
}

impl AsyncRead for E2eStreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.app).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() == before
                    && let Some(err) = self.terminal_error()
                {
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                if let Some(err) = self.terminal_error() {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncWrite for E2eStreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(err) = self.terminal_error() {
            return Poll::Ready(Err(err));
        }
        let written = ready!(Pin::new(&mut self.app).poll_write(cx, buf))?;
        self.written += written as u64;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_progress(cx, false)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut self.app).poll_shutdown(cx))?;
        self.poll_write_progress(cx, true)
    }
}

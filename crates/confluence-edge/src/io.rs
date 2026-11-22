//! Ecosystem `tokio::io::AsyncRead + AsyncWrite` adapter over [`confluence_core::E2eStream`].

use confluence_core::{CoreErr, E2eStream};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

/// Adapts an [`E2eStream`] into a standard `tokio::io::AsyncRead + AsyncWrite + Unpin + Send`
/// stream for seamless integration with `tokio::io::copy_bidirectional`, Hyper, Tonic, etc.
///
/// Preserves Confluence's truncation protection: clean EOF (`Ok(0)`) occurs only after an
/// authenticated `E2E_FIN`, while unexpected carrier drops surface `io::ErrorKind::UnexpectedEof`
/// and revocations surface `io::ErrorKind::PermissionDenied`.
pub struct E2eStreamIo {
    app: DuplexStream,
    terminal_error: std::sync::Arc<parking_lot::Mutex<Option<io::ErrorKind>>>,
    error_wait: Pin<Box<dyn Future<Output = ()> + Send>>,
    pump: tokio::task::JoinHandle<()>,
}

impl E2eStreamIo {
    /// Wraps `stream` in a buffered `AsyncRead + AsyncWrite` bridge on the current Tokio runtime.
    pub fn new(stream: E2eStream) -> Self {
        let (app, bridge) = tokio::io::duplex(64 * 1024);
        let terminal_error = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let (err_tx, mut err_rx) = tokio::sync::watch::channel(false);

        let err_slot = terminal_error.clone();
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
                        return stream.shutdown().await;
                    }
                    stream.write_all(&buf[..n]).await?;
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

            let res = tokio::try_join!(to_remote, to_local);
            if let Err(err) = res
                && err != CoreErr::Closed
            {
                let kind = map_core_err(&err);
                *err_slot.lock() = Some(kind);
                let _ = err_tx.send(true);
            }
        });

        let error_wait = Box::pin(async move {
            let _ = err_rx.wait_for(|&failed| failed).await;
        });

        Self {
            app,
            terminal_error,
            error_wait,
            pump,
        }
    }

    fn poll_terminal_error(&mut self, cx: &mut Context<'_>) -> Option<io::Error> {
        let _ = self.error_wait.as_mut().poll(cx);
        self.terminal_error
            .lock()
            .map(|kind| io::Error::new(kind, "confluence stream terminated"))
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

impl AsyncRead for E2eStreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.app).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() == before
                    && let Some(err) = self.poll_terminal_error(cx)
                {
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                if let Some(err) = self.poll_terminal_error(cx) {
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
        if let Some(err) = self.poll_terminal_error(cx) {
            return Poll::Ready(Err(err));
        }
        Pin::new(&mut self.app).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(err) = self.poll_terminal_error(cx) {
            return Poll::Ready(Err(err));
        }
        Pin::new(&mut self.app).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.app).poll_shutdown(cx)
    }
}

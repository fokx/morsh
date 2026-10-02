use std::io::{Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::thread;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tracing::debug;

/// Asynchronous wrapper for reading from a PTY master file descriptor.
pub struct AsyncPtyReader {
    rx: mpsc::Receiver<Vec<u8>>,
    current_chunk: Option<Vec<u8>>,
    offset: usize,
}

impl AsyncPtyReader {
    /// Creates a new AsyncPtyReader backed by a dedicated blocking reader thread.
    pub fn new(mut reader: Box<dyn Read + Send>) -> Self {
        let (tx, rx) = mpsc::channel(64);

        thread::Builder::new()
            .name("morsh-pty-reader".into())
            .spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => {
                            debug!("PTY master reader reached clean EOF");
                            break;
                        }
                        Ok(n) => {
                            if tx.blocking_send(buf[..n].to_vec()).is_err() {
                                debug!("PTY reader channel closed by receiver");
                                break;
                            }
                        }
                        Err(e) => {
                            // On Linux/Unix, slave closure yields EIO (errno 5) on the master PTY.
                            if e.raw_os_error() == Some(5) {
                                debug!("PTY slave closed (EIO); ending master reader");
                            } else {
                                debug!(error = %e, "PTY read error; ending reader");
                            }
                            break;
                        }
                    }
                }
            })
            .expect("Failed to spawn PTY reader thread");

        Self {
            rx,
            current_chunk: None,
            offset: 0,
        }
    }

    /// Asynchronously receives the next chunk of raw bytes from the PTY.
    pub async fn read_chunk(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

impl AsyncRead for AsyncPtyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            let (to_copy, chunk_len) = if let Some(ref chunk) = self.current_chunk {
                let to_copy = (chunk.len() - self.offset).min(buf.remaining());
                buf.put_slice(&chunk[self.offset..self.offset + to_copy]);
                (to_copy, chunk.len())
            } else {
                (0, 0)
            };

            if chunk_len > 0 {
                self.offset += to_copy;
                if self.offset >= chunk_len {
                    self.current_chunk = None;
                    self.offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    if data.is_empty() {
                        continue;
                    }
                    self.current_chunk = Some(data);
                    self.offset = 0;
                    // Loop again to fill buf
                }
                Poll::Ready(None) => {
                    // Channel closed, EOF reached
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

/// Asynchronous wrapper for writing into a PTY master file descriptor.
pub struct AsyncPtyWriter {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl AsyncPtyWriter {
    /// Creates a new AsyncPtyWriter backed by a dedicated blocking writer thread.
    pub fn new(mut writer: Box<dyn Write + Send>) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

        thread::Builder::new()
            .name("morsh-pty-writer".into())
            .spawn(move || {
                while let Some(chunk) = rx.blocking_recv() {
                    if let Err(e) = writer.write_all(&chunk) {
                        debug!(error = %e, "PTY write_all failed; exiting writer thread");
                        break;
                    }
                    let _ = writer.flush();
                }
                debug!("PTY writer channel closed; flushing master writer");
                let _ = writer.flush();
            })
            .expect("Failed to spawn PTY writer thread");

        Self { tx }
    }

    /// Asynchronously writes raw bytes to the PTY.
    pub async fn write_bytes(&self, data: &[u8]) -> std::io::Result<()> {
        self.tx
            .send(data.to_vec())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "PTY writer channel closed"))
    }
}

impl AsyncWrite for AsyncPtyWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.tx.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "PTY writer closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

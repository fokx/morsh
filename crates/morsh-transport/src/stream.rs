use crate::tcp_mux::{TcpRecvStream, TcpSendStream};
use std::io::Result as IoResult;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Identifies a multiplexed bidirectional stream across QUIC or TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MorshStreamId(pub u64);

impl MorshStreamId {
    pub fn new(index: u64) -> Self {
        Self(index)
    }

    /// The index of the stream (0 for Stream 0 / Control, 1 for Stream 1 / PTY, etc.)
    pub fn index(&self) -> u64 {
        self.0
    }
}

/// Unified send stream abstraction wrapping either a Quinn QUIC stream or a TCP multiplexed stream.
pub enum MorshSendStream {
    Quic(quinn::SendStream),
    Tcp(TcpSendStream),
}

impl MorshSendStream {
    /// Returns the stream ID and logical index.
    pub fn id(&self) -> MorshStreamId {
        match self {
            Self::Quic(s) => MorshStreamId(s.id().index()),
            Self::Tcp(s) => s.id(),
        }
    }

    /// Asynchronously writes all bytes from `buf` to the stream.
    pub async fn write_all(&mut self, buf: &[u8]) -> IoResult<()> {
        tokio::io::AsyncWriteExt::write_all(self, buf).await
    }

    /// Asynchronously flushes any buffered data.
    pub async fn flush(&mut self) -> IoResult<()> {
        tokio::io::AsyncWriteExt::flush(self).await
    }

    /// Signals end of stream (half-close / FIN) to the peer.
    pub fn finish(&mut self) -> IoResult<()> {
        match self {
            Self::Quic(s) => s
                .finish()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)),
            Self::Tcp(s) => s.finish(),
        }
    }
}

impl AsyncWrite for MorshSendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        match self.get_mut() {
            Self::Quic(s) => AsyncWrite::poll_write(Pin::new(s), cx, buf),
            Self::Tcp(s) => AsyncWrite::poll_write(Pin::new(s), cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        match self.get_mut() {
            Self::Quic(s) => AsyncWrite::poll_flush(Pin::new(s), cx),
            Self::Tcp(s) => AsyncWrite::poll_flush(Pin::new(s), cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        match self.get_mut() {
            Self::Quic(s) => AsyncWrite::poll_shutdown(Pin::new(s), cx),
            Self::Tcp(s) => AsyncWrite::poll_shutdown(Pin::new(s), cx),
        }
    }
}

/// Unified receive stream abstraction wrapping either a Quinn QUIC stream or a TCP multiplexed stream.
pub enum MorshRecvStream {
    Quic(quinn::RecvStream),
    Tcp(TcpRecvStream),
}

impl MorshRecvStream {
    /// Reads data into `buf`, returning `Ok(None)` on clean EOF or `Ok(Some(n))` bytes read.
    pub async fn read(&mut self, buf: &mut [u8]) -> IoResult<Option<usize>> {
        match self {
            Self::Quic(r) => r
                .read(buf)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)),
            Self::Tcp(r) => r.read(buf).await,
        }
    }

    /// Asynchronously reads the exact number of bytes required to fill `buf`.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        tokio::io::AsyncReadExt::read_exact(self, buf).await
    }
}

impl AsyncRead for MorshRecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        match self.get_mut() {
            Self::Quic(r) => AsyncRead::poll_read(Pin::new(r), cx, buf),
            Self::Tcp(r) => AsyncRead::poll_read(Pin::new(r), cx, buf),
        }
    }
}

impl From<quinn::SendStream> for MorshSendStream {
    fn from(s: quinn::SendStream) -> Self {
        Self::Quic(s)
    }
}

impl From<quinn::RecvStream> for MorshRecvStream {
    fn from(r: quinn::RecvStream) -> Self {
        Self::Quic(r)
    }
}

impl From<TcpSendStream> for MorshSendStream {
    fn from(s: TcpSendStream) -> Self {
        Self::Tcp(s)
    }
}

impl From<TcpRecvStream> for MorshRecvStream {
    fn from(r: TcpRecvStream) -> Self {
        Self::Tcp(r)
    }
}

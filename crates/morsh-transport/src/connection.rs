use crate::stream::{MorshRecvStream, MorshSendStream};
use crate::tcp_mux::TcpConnection;
use bytes::Bytes;
use morsh_core::error::{CoreError, Result as CoreResult};
use morsh_core::frame::{read_frame, write_frame};
use morsh_core::protocol::ControlMessage;
use quinn::Connection;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

#[derive(Clone)]
enum MorshConnectionInner {
    Quic(Connection),
    Tcp(Arc<TcpConnection>),
}

/// High-level wrapper over a QUIC or TLS/TCP fallback connection for morsh.
#[derive(Clone)]
pub struct MorshConnection {
    inner: MorshConnectionInner,
}

impl MorshConnection {
    /// Constructs a connection from a Quinn QUIC connection.
    pub fn new(inner: Connection) -> Self {
        Self {
            inner: MorshConnectionInner::Quic(inner),
        }
    }

    /// Constructs a connection from a multiplexed TCP connection.
    pub fn from_tcp(inner: Arc<TcpConnection>) -> Self {
        Self {
            inner: MorshConnectionInner::Tcp(inner),
        }
    }

    /// Returns `true` if this connection is using native QUIC transport.
    pub fn is_quic(&self) -> bool {
        matches!(self.inner, MorshConnectionInner::Quic(_))
    }

    /// Returns `true` if this connection is using TLS 1.3 over TCP fallback.
    pub fn is_tcp(&self) -> bool {
        matches!(self.inner, MorshConnectionInner::Tcp(_))
    }

    /// Returns the human-readable transport name (`"QUIC"` or `"TLS/TCP"`).
    pub fn transport_name(&self) -> &'static str {
        match self.inner {
            MorshConnectionInner::Quic(_) => "QUIC",
            MorshConnectionInner::Tcp(_) => "TLS/TCP",
        }
    }

    /// Access the underlying Quinn connection if this is a QUIC transport.
    /// Panics if called on a TCP fallback connection.
    pub fn inner(&self) -> &Connection {
        match &self.inner {
            MorshConnectionInner::Quic(c) => c,
            MorshConnectionInner::Tcp(_) => {
                panic!("MorshConnection::inner() called on TCP connection; use quic_connection() instead");
            }
        }
    }

    /// Safely retrieves the underlying Quinn connection if using QUIC.
    pub fn quic_connection(&self) -> Option<&Connection> {
        match &self.inner {
            MorshConnectionInner::Quic(c) => Some(c),
            MorshConnectionInner::Tcp(_) => None,
        }
    }

    /// Safely retrieves the underlying multiplexed TCP connection if using TCP.
    pub fn tcp_connection(&self) -> Option<&Arc<TcpConnection>> {
        match &self.inner {
            MorshConnectionInner::Quic(_) => None,
            MorshConnectionInner::Tcp(t) => Some(t),
        }
    }

    /// The remote IP address and port of the peer.
    /// Under QUIC connection migration, this dynamically reflects the new IP if roaming.
    pub fn remote_address(&self) -> SocketAddr {
        match &self.inner {
            MorshConnectionInner::Quic(c) => c.remote_address(),
            MorshConnectionInner::Tcp(t) => t.remote_address(),
        }
    }

    /// Current smoothed Round Trip Time (RTT).
    pub fn rtt(&self) -> Duration {
        match &self.inner {
            MorshConnectionInner::Quic(c) => c.rtt(),
            MorshConnectionInner::Tcp(t) => t.rtt(),
        }
    }

    /// Opens a new bidirectional stream with the peer.
    pub async fn open_bi(&self) -> CoreResult<(MorshSendStream, MorshRecvStream)> {
        match &self.inner {
            MorshConnectionInner::Quic(c) => {
                let (s, r) = c.open_bi().await.map_err(|e| {
                    CoreError::Io(std::io::Error::new(std::io::ErrorKind::ConnectionReset, e))
                })?;
                Ok((MorshSendStream::Quic(s), MorshRecvStream::Quic(r)))
            }
            MorshConnectionInner::Tcp(t) => {
                let (s, r) = t.open_bi().await?;
                Ok((MorshSendStream::Tcp(s), MorshRecvStream::Tcp(r)))
            }
        }
    }

    /// Accepts an incoming bidirectional stream initiated by the peer.
    pub async fn accept_bi(&self) -> CoreResult<(MorshSendStream, MorshRecvStream)> {
        match &self.inner {
            MorshConnectionInner::Quic(c) => {
                let (s, r) = c.accept_bi().await.map_err(|e| {
                    CoreError::Io(std::io::Error::new(std::io::ErrorKind::ConnectionReset, e))
                })?;
                Ok((MorshSendStream::Quic(s), MorshRecvStream::Quic(r)))
            }
            MorshConnectionInner::Tcp(t) => {
                let (s, r) = t.accept_bi().await?;
                Ok((MorshSendStream::Tcp(s), MorshRecvStream::Tcp(r)))
            }
        }
    }

    /// Sends an unreliable datagram to the peer (RFC 9221 over QUIC, or encapsulated frame over TCP).
    pub fn send_datagram(&self, data: Bytes) -> CoreResult<()> {
        match &self.inner {
            MorshConnectionInner::Quic(c) => c
                .send_datagram(data)
                .map_err(|e| CoreError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))),
            MorshConnectionInner::Tcp(t) => t.send_datagram(data),
        }
    }

    /// Receives an unreliable datagram from the peer.
    pub async fn read_datagram(&self) -> CoreResult<Bytes> {
        match &self.inner {
            MorshConnectionInner::Quic(c) => c
                .read_datagram()
                .await
                .map_err(|e| CoreError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))),
            MorshConnectionInner::Tcp(t) => t.read_datagram().await,
        }
    }

    /// Helper to write a ControlMessage frame to an AsyncWrite stream.
    pub async fn send_control_message<W>(writer: &mut W, msg: &ControlMessage) -> CoreResult<()>
    where
        W: AsyncWrite + Unpin,
    {
        write_frame(writer, msg).await
    }

    /// Helper to read a ControlMessage frame from an AsyncRead stream.
    pub async fn read_control_message<R>(reader: &mut R) -> CoreResult<ControlMessage>
    where
        R: AsyncRead + Unpin,
    {
        read_frame(reader).await
    }

    /// Gracefully closes the connection with an error code and reason.
    pub fn close(&self, code: u32, reason: &str) {
        info!(
            code,
            reason,
            transport = self.transport_name(),
            remote = %self.remote_address(),
            "Closing morsh connection"
        );
        match &self.inner {
            MorshConnectionInner::Quic(c) => c.close(code.into(), reason.as_bytes()),
            MorshConnectionInner::Tcp(t) => t.close(code, reason),
        }
    }

    /// Awaits connection termination.
    pub async fn closed(&self) {
        match &self.inner {
            MorshConnectionInner::Quic(c) => {
                let _ = c.closed().await;
            }
            MorshConnectionInner::Tcp(t) => {
                t.closed().await;
            }
        }
    }
}

/// Generates a cryptographically random 16-byte session identifier.
pub fn generate_session_id() -> [u8; 16] {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut id = [0u8; 16];
    rng.fill(&mut id)
        .expect("Failed to generate random session ID");
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_session_id_uniqueness() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();
        assert_ne!(id1, [0u8; 16]);
        assert_ne!(id2, [0u8; 16]);
        assert_ne!(id1, id2);
    }
}

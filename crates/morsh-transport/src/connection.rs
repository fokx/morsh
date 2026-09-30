use bytes::Bytes;
use morsh_core::error::{CoreError, Result as CoreResult};
use morsh_core::frame::{read_frame, write_frame};
use morsh_core::protocol::ControlMessage;
use quinn::{Connection, RecvStream, SendStream};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::info;

/// High-level wrapper over a QUIC connection for morsh.
#[derive(Clone)]
pub struct MorshConnection {
    inner: Connection,
}

impl MorshConnection {
    pub fn new(inner: Connection) -> Self {
        Self { inner }
    }

    /// Access the underlying Quinn connection.
    pub fn inner(&self) -> &Connection {
        &self.inner
    }

    /// The remote IP address and port of the peer.
    /// Note: Under QUIC connection migration, this will dynamically reflect the new IP
    /// if the client roams across networks.
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    /// Current smoothed Round Trip Time (RTT).
    pub fn rtt(&self) -> Duration {
        self.inner.rtt()
    }

    /// Opens a new bidirectional stream with the peer.
    pub async fn open_bi(&self) -> CoreResult<(SendStream, RecvStream)> {
        self.inner
            .open_bi()
            .await
            .map_err(|e| CoreError::Io(std::io::Error::new(std::io::ErrorKind::ConnectionReset, e)))
    }

    /// Accepts an incoming bidirectional stream initiated by the peer.
    pub async fn accept_bi(&self) -> CoreResult<(SendStream, RecvStream)> {
        self.inner
            .accept_bi()
            .await
            .map_err(|e| CoreError::Io(std::io::Error::new(std::io::ErrorKind::ConnectionReset, e)))
    }

    /// Sends an unreliable datagram to the peer (RFC 9221).
    pub fn send_datagram(&self, data: Bytes) -> CoreResult<()> {
        self.inner
            .send_datagram(data)
            .map_err(|e| CoreError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)))
    }

    /// Receives an unreliable datagram from the peer.
    pub async fn read_datagram(&self) -> CoreResult<Bytes> {
        self.inner
            .read_datagram()
            .await
            .map_err(|e| CoreError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)))
    }

    /// Helper to write a ControlMessage frame to a SendStream.
    pub async fn send_control_message(
        writer: &mut SendStream,
        msg: &ControlMessage,
    ) -> CoreResult<()> {
        write_frame(writer, msg).await
    }

    /// Helper to read a ControlMessage frame from a RecvStream.
    pub async fn read_control_message(reader: &mut RecvStream) -> CoreResult<ControlMessage> {
        read_frame(reader).await
    }

    /// Gracefully closes the QUIC connection with an error code and reason.
    pub fn close(&self, code: u32, reason: &str) {
        info!(
            code,
            reason,
            remote = %self.remote_address(),
            "Closing morsh QUIC connection"
        );
        self.inner.close(code.into(), reason.as_bytes());
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

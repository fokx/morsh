use crate::connection::MorshConnection;
use anyhow::{Context, Result};
use quinn::{Connecting, Endpoint, ServerConfig};
use std::net::SocketAddr;
use tracing::{debug, info};

pub struct QuicServer {
    endpoint: Endpoint,
}

impl QuicServer {
    /// Binds a QUIC server on the specified socket address with the given TLS / Quinn configuration.
    pub fn bind(addr: SocketAddr, server_config: ServerConfig) -> Result<Self> {
        let endpoint = Endpoint::server(server_config, addr)
            .with_context(|| format!("Failed to bind QUIC server on {}", addr))?;

        info!("QUIC server bound to {}", endpoint.local_addr()?);
        Ok(Self { endpoint })
    }

    /// Returns the local socket address this server is listening on.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("Failed to get local address")
    }

    /// Asynchronously waits for and accepts the next incoming QUIC connection.
    pub async fn accept(&self) -> Option<Result<MorshConnection>> {
        let incoming = self.endpoint.accept().await?;
        let connecting = match incoming.accept() {
            Ok(c) => c,
            Err(e) => return Some(Err(anyhow::anyhow!("Failed to accept incoming connection: {}", e))),
        };
        Some(Self::handshake(connecting).await)
    }

    async fn handshake(connecting: Connecting) -> Result<MorshConnection> {
        let remote_addr = connecting.remote_address();
        debug!(remote = %remote_addr, "Performing QUIC handshake with incoming peer");
        let conn = connecting
            .await
            .with_context(|| format!("QUIC handshake failed with {}", remote_addr))?;
        info!(remote = %conn.remote_address(), "QUIC connection established");
        Ok(MorshConnection::new(conn))
    }

    /// Stops the server and closes all active connections.
    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.endpoint.close(error_code.into(), reason);
    }
}

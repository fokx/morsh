use crate::connection::MorshConnection;
use anyhow::{Context, Result};
use quinn::{ClientConfig, Endpoint};
use std::net::SocketAddr;
use tracing::{debug, info};

pub struct QuicClient {
    endpoint: Endpoint,
}

impl QuicClient {
    /// Initializes a client endpoint bound to an ephemeral local port.
    pub fn new(client_config: ClientConfig) -> Result<Self> {
        let bind_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let mut endpoint = Endpoint::client(bind_addr)
            .context("Failed to create client QUIC endpoint")?;
        endpoint.set_default_client_config(client_config);
        Ok(Self { endpoint })
    }

    /// Connects to a remote server and completes the QUIC / TLS 1.3 handshake.
    pub async fn connect(
        &self,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<MorshConnection> {
        debug!(
            target_addr = %server_addr,
            server_name = %server_name,
            "Connecting to morsh server"
        );

        let connecting = self
            .endpoint
            .connect(server_addr, server_name)
            .with_context(|| format!("Failed to initiate QUIC connection to {}", server_addr))?;

        let conn = connecting
            .await
            .with_context(|| format!("QUIC connection handshake failed with {}", server_addr))?;

        info!(
            remote = %conn.remote_address(),
            rtt_ms = conn.rtt().as_millis(),
            "Connected to morsh server"
        );

        Ok(MorshConnection::new(conn))
    }

    /// Access the underlying Quinn endpoint.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Retrieves the local socket address this client endpoint is currently bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("Failed to get client local address")
    }

    /// Rebinds the client endpoint to a new UDP socket, triggering QUIC connection migration (roaming).
    pub fn rebind(&self, socket: std::net::UdpSocket) -> Result<()> {
        let new_addr = socket
            .local_addr()
            .context("Failed to get local address of new socket")?;
        self.endpoint
            .rebind(socket)
            .context("Failed to rebind Quinn endpoint to new socket")?;
        info!(new_addr = %new_addr, "Rebound client endpoint to new socket (connection migration)");
        Ok(())
    }

    /// Closes the client endpoint.
    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.endpoint.close(error_code.into(), reason);
    }
}

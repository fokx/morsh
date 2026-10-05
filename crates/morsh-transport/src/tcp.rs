use crate::connection::MorshConnection;
use crate::tcp_mux::TcpConnection;
use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info};

/// TCP TLS fallback server listener.
pub struct TcpServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl TcpServer {
    /// Binds a TCP listener on the specified socket address using the provided rustls ServerConfig.
    pub async fn bind(addr: SocketAddr, server_config: Arc<rustls::ServerConfig>) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind TCP server on {}", addr))?;

        let acceptor = TlsAcceptor::from(server_config);
        info!("TCP fallback server bound to {}", listener.local_addr()?);
        Ok(Self { listener, acceptor })
    }

    /// Returns the local socket address this server is listening on.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .context("Failed to get TCP local address")
    }

    /// Asynchronously waits for and accepts the next incoming TLS 1.3 over TCP connection.
    pub async fn accept(&self) -> Option<Result<MorshConnection>> {
        let (stream, peer_addr) = match self.listener.accept().await {
            Ok(res) => res,
            Err(e) => return Some(Err(anyhow::anyhow!("TCP accept error: {}", e))),
        };

        let acceptor = self.acceptor.clone();
        Some(Self::handshake(stream, peer_addr, acceptor).await)
    }

    async fn handshake(
        stream: TcpStream,
        peer_addr: SocketAddr,
        acceptor: TlsAcceptor,
    ) -> Result<MorshConnection> {
        debug!(remote = %peer_addr, "Performing TLS 1.3 handshake over incoming TCP stream");
        let tls_stream = acceptor
            .accept(stream)
            .await
            .with_context(|| format!("TLS handshake failed with {}", peer_addr))?;

        info!(remote = %peer_addr, "TLS 1.3 over TCP connection established");
        let conn = TcpConnection::new(tls_stream, peer_addr, false);
        Ok(MorshConnection::from_tcp(conn))
    }
}

/// TCP TLS fallback client connector.
pub struct TcpClient;

impl TcpClient {
    /// Connects to a remote server over TCP and completes the TLS 1.3 handshake.
    pub async fn connect(
        server_addr: SocketAddr,
        server_name: &str,
        client_config: Arc<rustls::ClientConfig>,
    ) -> Result<MorshConnection> {
        debug!(
            target_addr = %server_addr,
            server_name = %server_name,
            "Connecting to morsh server over TCP (TLS 1.3 fallback)"
        );

        let stream = TcpStream::connect(server_addr)
            .await
            .with_context(|| format!("Failed to establish TCP connection to {}", server_addr))?;

        let _ = stream.set_nodelay(true);

        let connector = TlsConnector::from(client_config);
        let dns_name = ServerName::try_from(server_name.to_string())
            .with_context(|| format!("Invalid TLS server name: '{}'", server_name))?;

        let tls_stream = connector
            .connect(dns_name, stream)
            .await
            .with_context(|| format!("TLS 1.3 handshake over TCP failed with {}", server_addr))?;

        info!(
            remote = %server_addr,
            "Connected to morsh server via TLS 1.3 over TCP fallback"
        );

        let conn = TcpConnection::new(tls_stream, server_addr, true);
        Ok(MorshConnection::from_tcp(conn))
    }
}

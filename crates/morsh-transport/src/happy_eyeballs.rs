use crate::client::QuicClient;
use crate::connection::MorshConnection;
use crate::tcp::TcpClient;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

pub const DEFAULT_FALLBACK_DELAY: Duration = Duration::from_millis(300);

/// Establishes a connection to the server using Happy Eyeballs auto-detection (RFC 8305 style).
///
/// 1. If `force_tcp` is true, immediately connects using TLS 1.3 over TCP fallback.
/// 2. Otherwise, initiates a QUIC (UDP) connection with a fallback timer (e.g. 300 ms).
/// 3. If QUIC does not establish within the fallback delay or fails, concurrently starts
///    a TLS 1.3 over TCP connection.
/// 4. The first connection to complete its cryptographic handshake wins; the other is cleanly canceled.
pub async fn connect_happy_eyeballs(
    remote_addr: SocketAddr,
    server_name: &str,
    quic_client: &QuicClient,
    tls_client_config: Arc<rustls::ClientConfig>,
    fallback_delay: Duration,
    force_tcp: bool,
) -> Result<MorshConnection> {
    if force_tcp {
        info!(
            remote = %remote_addr,
            "Forced TCP mode active; bypassing QUIC and connecting directly via TLS 1.3 over TCP"
        );
        return TcpClient::connect(remote_addr, server_name, tls_client_config).await;
    }

    debug!(
        remote = %remote_addr,
        fallback_delay_ms = fallback_delay.as_millis(),
        "Attempting QUIC with Happy Eyeballs fallback to TCP"
    );

    let quic_fut = quic_client.connect(remote_addr, server_name);
    tokio::pin!(quic_fut);

    // Phase 1: Wait for QUIC until fallback timeout
    let timer = tokio::time::sleep(fallback_delay);
    tokio::pin!(timer);

    tokio::select! {
        res = &mut quic_fut => {
            match res {
                Ok(conn) => {
                    debug!(remote = %remote_addr, "QUIC connected before fallback timeout");
                    return Ok(conn);
                }
                Err(quic_err) => {
                    warn!(
                        remote = %remote_addr,
                        error = %quic_err,
                        "QUIC failed before fallback timeout; falling back to TCP immediately"
                    );
                    return TcpClient::connect(remote_addr, server_name, tls_client_config)
                        .await
                        .with_context(|| format!("QUIC failed ({}) and TCP fallback also failed", quic_err));
                }
            }
        }
        _ = &mut timer => {
            debug!(
                remote = %remote_addr,
                delay_ms = fallback_delay.as_millis(),
                "QUIC handshake pending past fallback delay; racing TCP fallback concurrently"
            );
        }
    }

    // Phase 2: Race pending QUIC against concurrent TCP fallback
    let tcp_fut = TcpClient::connect(remote_addr, server_name, tls_client_config);
    tokio::pin!(tcp_fut);

    tokio::select! {
        res = &mut quic_fut => {
            match res {
                Ok(conn) => {
                    info!(remote = %remote_addr, "QUIC won Happy Eyeballs race");
                    Ok(conn)
                }
                Err(quic_err) => {
                    debug!(
                        remote = %remote_addr,
                        error = %quic_err,
                        "QUIC failed after fallback initiated; awaiting TCP result"
                    );
                    tcp_fut.await.with_context(|| {
                        format!("QUIC failed ({}) and TCP fallback also failed", quic_err)
                    })
                }
            }
        }
        res = &mut tcp_fut => {
            match res {
                Ok(conn) => {
                    info!(remote = %remote_addr, "TCP fallback won Happy Eyeballs race");
                    Ok(conn)
                }
                Err(tcp_err) => {
                    debug!(
                        remote = %remote_addr,
                        error = %tcp_err,
                        "TCP fallback failed; awaiting QUIC result"
                    );
                    quic_fut.await.with_context(|| {
                        format!("TCP fallback failed ({}) and QUIC also failed", tcp_err)
                    })
                }
            }
        }
    }
}

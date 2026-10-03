use crate::bridge::bridge_tcp_and_quic;
use crate::config::{DynamicRule, ForwardRule};
use crate::error::{Result, TunnelError};
use crate::manager::TunnelManager;
use crate::socks5::{
    handle_socks5_handshake, send_socks5_reply, SOCKS5_REP_CONNECTION_REFUSED, SOCKS5_REP_SUCCESS,
};
use morsh_core::protocol::{
    ControlMessage, TunnelStreamPreamble, TunnelType,
};
use morsh_transport::MorshConnection;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

/// Runs a local TCP forward listener (-L) in a background task.
pub async fn run_local_forward(
    rule: ForwardRule,
    conn: MorshConnection,
    manager: TunnelManager,
) -> Result<()> {
    let bind_addr = rule.bind_socket_addr_str();
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| TunnelError::Io(e))?;

    let local_addr = listener.local_addr()?;
    info!(
        local = %local_addr,
        target = %rule.target_socket_addr_str(),
        "Local TCP forwarding active (-L)"
    );

    loop {
        let (tcp_stream, client_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(e) => {
                warn!(error = %e, "Local forward accept failed; terminating listener");
                break;
            }
        };

        debug!(client = %client_addr, target = %rule.target_socket_addr_str(), "Accepted local forward connection");

        let conn_clone = conn.clone();
        let manager_clone = manager.clone();
        let target_host = rule.target_host.clone();
        let target_port = rule.target_port;

        tokio::spawn(async move {
            let tunnel_id = manager_clone.next_tunnel_id();
            let rx = manager_clone.register_tunnel_open(tunnel_id).await;

            let open_req = ControlMessage::TunnelOpenRequest {
                tunnel_id,
                tunnel_type: TunnelType::LocalTcp,
                host: target_host.clone(),
                port: target_port,
            };

            if let Err(e) = manager_clone.send_control(open_req).await {
                warn!(tunnel_id, error = %e, "Failed to send TunnelOpenRequest");
                return;
            }

            let result = match rx.await {
                Ok(res) => res,
                Err(_) => {
                    warn!(tunnel_id, "Tunnel open response channel closed");
                    return;
                }
            };

            if !result.success {
                warn!(tunnel_id, reason = %result.message, "Server rejected tunnel open");
                return;
            }

            debug!(tunnel_id, "Server accepted tunnel; opening QUIC stream");
            let (mut send, recv) = match conn_clone.open_bi().await {
                Ok(s) => s,
                Err(e) => {
                    error!(tunnel_id, error = %e, "Failed to open QUIC stream for tunnel");
                    return;
                }
            };

            let preamble = TunnelStreamPreamble::new(tunnel_id);
            if let Err(e) = send.write_all(&preamble.to_bytes()).await {
                warn!(tunnel_id, error = %e, "Failed to write tunnel preamble");
                return;
            }
            let _ = send.flush().await;

            let (sent, recv_bytes) = bridge_tcp_and_quic(tcp_stream, send, recv).await;
            debug!(tunnel_id, sent, recv_bytes, "Tunnel closed");

            let _ = manager_clone.send_control(ControlMessage::TunnelClose { tunnel_id }).await;
            manager_clone.remove_tunnel(tunnel_id).await;
        });
    }

    Ok(())
}

/// Runs a local dynamic SOCKS5 proxy listener (-D) in a background task.
pub async fn run_dynamic_socks5(
    rule: DynamicRule,
    conn: MorshConnection,
    manager: TunnelManager,
) -> Result<()> {
    let bind_addr = rule.bind_socket_addr_str();
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| TunnelError::Io(e))?;

    let local_addr = listener.local_addr()?;
    info!(
        local = %local_addr,
        "Dynamic SOCKS5 proxy active (-D)"
    );

    loop {
        let (mut tcp_stream, client_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(e) => {
                warn!(error = %e, "SOCKS5 accept failed; terminating listener");
                break;
            }
        };

        debug!(client = %client_addr, "Accepted SOCKS5 client connection");

        let conn_clone = conn.clone();
        let manager_clone = manager.clone();

        tokio::spawn(async move {
            let req = match handle_socks5_handshake(&mut tcp_stream).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "SOCKS5 handshake failed");
                    return;
                }
            };

            let target_host = req.host_string();
            let target_port = req.dest_port;
            let tunnel_id = manager_clone.next_tunnel_id();

            debug!(tunnel_id, target = %target_host, port = target_port, "SOCKS5 CONNECT request");

            let rx = manager_clone.register_tunnel_open(tunnel_id).await;

            let open_req = ControlMessage::TunnelOpenRequest {
                tunnel_id,
                tunnel_type: TunnelType::Socks5,
                host: target_host.clone(),
                port: target_port,
            };

            if let Err(e) = manager_clone.send_control(open_req).await {
                warn!(tunnel_id, error = %e, "Failed to send SOCKS5 TunnelOpenRequest");
                let _ = send_socks5_reply(&mut tcp_stream, SOCKS5_REP_CONNECTION_REFUSED).await;
                return;
            }

            let result = match rx.await {
                Ok(res) => res,
                Err(_) => {
                    warn!(tunnel_id, "SOCKS5 Tunnel open response channel closed");
                    let _ = send_socks5_reply(&mut tcp_stream, SOCKS5_REP_CONNECTION_REFUSED).await;
                    return;
                }
            };

            if !result.success {
                warn!(tunnel_id, reason = %result.message, "Server failed to connect to SOCKS5 destination");
                let _ = send_socks5_reply(&mut tcp_stream, SOCKS5_REP_CONNECTION_REFUSED).await;
                return;
            }

            if let Err(e) = send_socks5_reply(&mut tcp_stream, SOCKS5_REP_SUCCESS).await {
                warn!(tunnel_id, error = %e, "Failed to send SOCKS5 success reply");
                return;
            }

            let (mut send, recv) = match conn_clone.open_bi().await {
                Ok(s) => s,
                Err(e) => {
                    error!(tunnel_id, error = %e, "Failed to open QUIC stream for SOCKS5 tunnel");
                    return;
                }
            };

            let preamble = TunnelStreamPreamble::new(tunnel_id);
            if let Err(e) = send.write_all(&preamble.to_bytes()).await {
                warn!(tunnel_id, error = %e, "Failed to write tunnel preamble");
                return;
            }
            let _ = send.flush().await;

            let (sent, recv_bytes) = bridge_tcp_and_quic(tcp_stream, send, recv).await;
            debug!(tunnel_id, sent, recv_bytes, "SOCKS5 tunnel finished");

            let _ = manager_clone.send_control(ControlMessage::TunnelClose { tunnel_id }).await;
            manager_clone.remove_tunnel(tunnel_id).await;
        });
    }

    Ok(())
}

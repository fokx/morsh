use crate::bridge::bridge_tcp_and_quic;
use crate::config::ForwardRule;
use crate::error::{Result, TunnelError};
use crate::manager::TunnelManager;
use morsh_core::protocol::{
    ControlMessage, TunnelStreamPreamble, TunnelType,
};
use morsh_transport::MorshConnection;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

/// Requests remote TCP port forwarding (-R) from the server and awaits confirmation.
pub async fn request_remote_forward(
    rule: &ForwardRule,
    manager: &TunnelManager,
) -> Result<()> {
    let rx = manager.register_remote_forward(rule.bind_port).await;

    let req = ControlMessage::RemoteForwardRequest {
        bind_addr: rule.bind_addr.clone(),
        bind_port: rule.bind_port,
        target_host: rule.target_host.clone(),
        target_port: rule.target_port,
    };

    manager.send_control(req).await?;

    let res = rx
        .await
        .map_err(|_| TunnelError::ChannelClosed)?;

    if !res.success {
        return Err(TunnelError::RemoteBindFailed {
            port: rule.bind_port,
            reason: res.message,
        });
    }

    info!(
        remote_bind = %rule.bind_socket_addr_str(),
        target = %rule.target_socket_addr_str(),
        "Remote TCP forwarding established (-R)"
    );

    Ok(())
}

/// Server-side handler: binds a remote port on the server and forwards incoming connections to the client.
pub async fn bind_remote_forward_server(
    bind_addr: String,
    bind_port: u16,
    target_host: String,
    target_port: u16,
    conn: MorshConnection,
    manager: TunnelManager,
) -> Result<u16> {
    let listen_spec = format!("{}:{}", bind_addr, bind_port);
    let listener = TcpListener::bind(&listen_spec)
        .await
        .map_err(|e| TunnelError::Io(e))?;

    let bound_port = listener.local_addr()?.port();
    info!(
        bind = %listen_spec,
        actual_port = bound_port,
        target_host = %target_host,
        target_port,
        "Server bound remote forward port (-R)"
    );

    let conn_clone = conn.clone();
    let manager_clone = manager.clone();

    tokio::spawn(async move {
        loop {
            let (tcp_stream, client_addr) = match listener.accept().await {
                Ok(res) => res,
                Err(e) => {
                    warn!(error = %e, "Remote forward listener accept error; closing listener");
                    break;
                }
            };

            debug!(client = %client_addr, target_host = %target_host, target_port, "Remote forward connection received");

            let conn_child = conn_clone.clone();
            let manager_child = manager_clone.clone();
            let th = target_host.clone();

            tokio::spawn(async move {
                let tunnel_id = manager_child.next_tunnel_id();
                let rx = manager_child.register_tunnel_open(tunnel_id).await;

                // Inform client to connect to local target
                let open_req = ControlMessage::TunnelOpenRequest {
                    tunnel_id,
                    tunnel_type: TunnelType::RemoteTcp,
                    host: th,
                    port: target_port,
                };

                if let Err(e) = manager_child.send_control(open_req).await {
                    warn!(tunnel_id, error = %e, "Failed to send RemoteTcp TunnelOpenRequest to client");
                    return;
                }

                // Wait for client to connect to local target
                let result = match rx.await {
                    Ok(res) => res,
                    Err(_) => {
                        warn!(tunnel_id, "Client response channel closed");
                        return;
                    }
                };

                if !result.success {
                    warn!(tunnel_id, reason = %result.message, "Client failed to connect to remote-forward target");
                    return;
                }

                // Open QUIC stream to client
                let (mut send, recv) = match conn_child.open_bi().await {
                    Ok(s) => s,
                    Err(e) => {
                        error!(tunnel_id, error = %e, "Failed to open QUIC stream for remote forward");
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
                debug!(tunnel_id, sent, recv_bytes, "Remote forward tunnel closed");

                let _ = manager_child.send_control(ControlMessage::TunnelClose { tunnel_id }).await;
                manager_child.remove_tunnel(tunnel_id).await;
            });
        }
    });

    Ok(bound_port)
}

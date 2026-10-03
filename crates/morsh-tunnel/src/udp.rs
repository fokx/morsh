use crate::config::UdpRule;
use crate::error::{Result, TunnelError};
use crate::manager::TunnelManager;
use bytes::Bytes;
use morsh_core::protocol::{ControlMessage, TunnelType};
use morsh_transport::MorshConnection;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

pub const UDP_DATAGRAM_MAGIC: [u8; 4] = *b"MUDP";

/// Encodes a UDP payload into a QUIC datagram frame with tunnel_id.
pub fn encode_udp_datagram(tunnel_id: u32, payload: &[u8]) -> Bytes {
    let mut buf = Vec::with_capacity(8 + payload.len());
    buf.extend_from_slice(&UDP_DATAGRAM_MAGIC);
    buf.extend_from_slice(&tunnel_id.to_be_bytes());
    buf.extend_from_slice(payload);
    Bytes::from(buf)
}

/// Decodes a QUIC datagram frame and returns (tunnel_id, payload).
pub fn decode_udp_datagram(data: &[u8]) -> Option<(u32, &[u8])> {
    if data.len() < 8 || &data[0..4] != &UDP_DATAGRAM_MAGIC {
        return None;
    }
    let tunnel_id = u32::from_be_bytes(data[4..8].try_into().ok()?);
    Some((tunnel_id, &data[8..]))
}

/// Runs a client-side local UDP forward listener in a background task.
pub async fn run_udp_forward(
    rule: UdpRule,
    conn: MorshConnection,
    manager: TunnelManager,
    last_client_addr: Arc<Mutex<Option<SocketAddr>>>,
) -> Result<()> {
    let bind_addr = rule.bind_socket_addr_str();
    let socket = Arc::new(UdpSocket::bind(&bind_addr).await.map_err(|e| TunnelError::Io(e))?);

    let local_addr = socket.local_addr()?;
    info!(
        local = %local_addr,
        target = %rule.target_socket_addr_str(),
        "UDP forwarding active"
    );

    let tunnel_id = manager.next_tunnel_id();
    let rx = manager.register_tunnel_open(tunnel_id).await;

    let open_req = ControlMessage::TunnelOpenRequest {
        tunnel_id,
        tunnel_type: TunnelType::UdpForward,
        host: rule.target_host.clone(),
        port: rule.target_port,
    };

    manager.send_control(open_req).await?;

    let res = rx.await.map_err(|_| TunnelError::ChannelClosed)?;
    if !res.success {
        return Err(TunnelError::OpenFailed(res.message));
    }

    manager.register_udp_tunnel(tunnel_id, Arc::clone(&socket), None).await;

    let mut buf = [0u8; 65535];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, src_addr)) => {
                *last_client_addr.lock().await = Some(src_addr);
                debug!(tunnel_id, n, src = %src_addr, "Forwarding local UDP packet over QUIC datagram");
                let datagram = encode_udp_datagram(tunnel_id, &buf[..n]);
                if let Err(e) = conn.send_datagram(datagram) {
                    warn!(tunnel_id, error = %e, "Failed to send QUIC datagram for UDP tunnel");
                }
            }
            Err(e) => {
                warn!(tunnel_id, error = %e, "UDP socket recv_from error");
                break;
            }
        }
    }

    manager.remove_tunnel(tunnel_id).await;
    Ok(())
}

/// Server-side setup for handling a UDP tunnel request.
pub async fn setup_server_udp_tunnel(
    tunnel_id: u32,
    host: String,
    port: u16,
    conn: MorshConnection,
    manager: TunnelManager,
) -> Result<()> {
    let target = format!("{}:{}", host, port);
    let mut addrs = tokio::net::lookup_host(&target).await.map_err(|e| TunnelError::Io(e))?;
    let target_addr = addrs.next().ok_or_else(|| {
        TunnelError::OpenFailed(format!("Could not resolve UDP target: {}", target))
    })?;

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.map_err(|e| TunnelError::Io(e))?);
    info!(tunnel_id, target = %target_addr, "Server bound UDP forward socket");

    manager
        .register_udp_tunnel(tunnel_id, Arc::clone(&socket), Some(target_addr))
        .await;

    // Spawn a listener for return packets from the target destination
    let conn_clone = conn.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, remote_src)) => {
                    debug!(tunnel_id, n, remote_src = %remote_src, "Received UDP reply from target; forwarding via QUIC datagram");
                    let datagram = encode_udp_datagram(tunnel_id, &buf[..n]);
                    if let Err(e) = conn_clone.send_datagram(datagram) {
                        warn!(tunnel_id, error = %e, "Failed to send return QUIC datagram");
                        break;
                    }
                }
                Err(e) => {
                    debug!(tunnel_id, error = %e, "Server UDP tunnel socket closed");
                    break;
                }
            }
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_datagram_encoding_roundtrip() {
        let tunnel_id = 999;
        let payload = b"hello udp packet";
        let datagram = encode_udp_datagram(tunnel_id, payload);

        let decoded = decode_udp_datagram(&datagram).unwrap();
        assert_eq!(decoded.0, tunnel_id);
        assert_eq!(decoded.1, payload);

        // Invalid magic
        let mut invalid = datagram.to_vec();
        invalid[0] = b'X';
        assert!(decode_udp_datagram(&invalid).is_none());

        // Too short
        assert!(decode_udp_datagram(&[1, 2, 3]).is_none());
    }
}

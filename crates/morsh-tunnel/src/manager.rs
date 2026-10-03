use crate::error::{Result, TunnelError};
use morsh_core::protocol::ControlMessage;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::debug;

/// Channel sender type for dispatching ControlMessages over Stream 0.
pub type ControlSender = mpsc::Sender<ControlMessage>;

/// Response data for a pending TunnelOpenRequest.
#[derive(Debug, Clone)]
pub struct TunnelOpenResult {
    pub success: bool,
    pub message: String,
}

/// Response data for a pending RemoteForwardRequest.
#[derive(Debug, Clone)]
pub struct RemoteForwardResult {
    pub success: bool,
    pub message: String,
}

/// Manages tunnel lifecycles, pending handshake futures, and channel routing.
#[derive(Clone)]
pub struct TunnelManager {
    next_id: Arc<AtomicU32>,
    ctrl_tx: Option<ControlSender>,
    pending_open_requests: Arc<Mutex<HashMap<u32, oneshot::Sender<TunnelOpenResult>>>>,
    pending_remote_requests: Arc<Mutex<HashMap<u16, oneshot::Sender<RemoteForwardResult>>>>,
    pending_server_streams: Arc<Mutex<HashMap<u32, TcpStream>>>,
    udp_tunnels: Arc<Mutex<HashMap<u32, Arc<UdpSocket>>>>,
    udp_target_addrs: Arc<Mutex<HashMap<u32, SocketAddr>>>,
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new(None)
    }
}

impl TunnelManager {
    pub fn new(ctrl_tx: Option<ControlSender>) -> Self {
        Self {
            next_id: Arc::new(AtomicU32::new(1)),
            ctrl_tx,
            pending_open_requests: Arc::new(Mutex::new(HashMap::new())),
            pending_remote_requests: Arc::new(Mutex::new(HashMap::new())),
            pending_server_streams: Arc::new(Mutex::new(HashMap::new())),
            udp_tunnels: Arc::new(Mutex::new(HashMap::new())),
            udp_target_addrs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn set_control_sender(&mut self, ctrl_tx: ControlSender) {
        self.ctrl_tx = Some(ctrl_tx);
    }

    pub fn next_tunnel_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Sends a ControlMessage over Stream 0 via the control sender.
    pub async fn send_control(&self, msg: ControlMessage) -> Result<()> {
        if let Some(ref tx) = self.ctrl_tx {
            tx.send(msg)
                .await
                .map_err(|_| TunnelError::ChannelClosed)?;
            Ok(())
        } else {
            Err(TunnelError::ChannelClosed)
        }
    }

    /// Registers a pending TunnelOpenRequest and returns a receiver waiting for TunnelOpenResponse.
    pub async fn register_tunnel_open(
        &self,
        tunnel_id: u32,
    ) -> oneshot::Receiver<TunnelOpenResult> {
        let (tx, rx) = oneshot::channel();
        self.pending_open_requests.lock().await.insert(tunnel_id, tx);
        rx
    }

    /// Resolves a pending TunnelOpenRequest upon receipt of TunnelOpenResponse.
    pub async fn on_tunnel_open_response(
        &self,
        tunnel_id: u32,
        success: bool,
        message: String,
    ) {
        if let Some(tx) = self.pending_open_requests.lock().await.remove(&tunnel_id) {
            let _ = tx.send(TunnelOpenResult { success, message });
        } else {
            debug!(tunnel_id, "No pending listener for TunnelOpenResponse");
        }
    }

    /// Registers a pending RemoteForwardRequest and returns a receiver waiting for RemoteForwardResponse.
    pub async fn register_remote_forward(
        &self,
        bind_port: u16,
    ) -> oneshot::Receiver<RemoteForwardResult> {
        let (tx, rx) = oneshot::channel();
        self.pending_remote_requests.lock().await.insert(bind_port, tx);
        rx
    }

    /// Resolves a pending RemoteForwardRequest upon receipt of RemoteForwardResponse.
    pub async fn on_remote_forward_response(
        &self,
        bind_port: u16,
        success: bool,
        message: String,
    ) {
        if let Some(tx) = self.pending_remote_requests.lock().await.remove(&bind_port) {
            let _ = tx.send(RemoteForwardResult { success, message });
        } else {
            debug!(bind_port, "No pending listener for RemoteForwardResponse");
        }
    }

    /// Registers an established server-side TCP connection waiting for the corresponding QUIC stream.
    pub async fn register_server_stream(&self, tunnel_id: u32, stream: TcpStream) {
        self.pending_server_streams.lock().await.insert(tunnel_id, stream);
    }

    /// Takes the registered server-side TCP connection for a tunnel_id.
    pub async fn take_server_stream(&self, tunnel_id: u32) -> Option<TcpStream> {
        self.pending_server_streams.lock().await.remove(&tunnel_id)
    }

    /// Registers a UDP socket and optional target address for UDP tunnel.
    pub async fn register_udp_tunnel(
        &self,
        tunnel_id: u32,
        socket: Arc<UdpSocket>,
        target_addr: Option<SocketAddr>,
    ) {
        self.udp_tunnels.lock().await.insert(tunnel_id, socket);
        if let Some(addr) = target_addr {
            self.udp_target_addrs.lock().await.insert(tunnel_id, addr);
        }
    }

    pub async fn get_udp_tunnel(&self, tunnel_id: u32) -> Option<Arc<UdpSocket>> {
        self.udp_tunnels.lock().await.get(&tunnel_id).cloned()
    }

    pub async fn get_udp_target_addr(&self, tunnel_id: u32) -> Option<SocketAddr> {
        self.udp_target_addrs.lock().await.get(&tunnel_id).copied()
    }

    /// Removes all resources associated with a closed tunnel.
    pub async fn remove_tunnel(&self, tunnel_id: u32) {
        self.pending_open_requests.lock().await.remove(&tunnel_id);
        self.pending_server_streams.lock().await.remove(&tunnel_id);
        self.udp_tunnels.lock().await.remove(&tunnel_id);
        self.udp_target_addrs.lock().await.remove(&tunnel_id);
    }
}

//! Port forwarding (TCP/UDP) and SOCKS5 dynamic proxy engine for morsh.
//! Supports:
//! - Local TCP Forwarding (-L)
//! - Remote TCP Forwarding (-R)
//! - Dynamic SOCKS5 Proxy (-D)
//! - Native UDP Forwarding over QUIC Datagrams

pub mod bridge;
pub mod config;
pub mod error;
pub mod local;
pub mod manager;
pub mod remote;
pub mod socks5;
pub mod udp;

pub use bridge::bridge_tcp_and_quic;
pub use config::{DynamicRule, ForwardRule, UdpRule};
pub use error::{Result, TunnelError};
pub use local::{run_dynamic_socks5, run_local_forward};
pub use manager::{ControlSender, RemoteForwardResult, TunnelManager, TunnelOpenResult};
pub use remote::{bind_remote_forward_server, request_remote_forward};
pub use socks5::{
    handle_socks5_handshake, send_socks5_reply, Socks5Address, Socks5Request,
};
pub use udp::{
    decode_udp_datagram, encode_udp_datagram, run_udp_forward, setup_server_udp_tunnel,
    UDP_DATAGRAM_MAGIC,
};

pub fn tunnel_subsystem_version() -> &'static str {
    "0.3.0"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_subsystem_version() {
        assert_eq!(tunnel_subsystem_version(), "0.3.0");
    }
}

use crate::error::{Result, TunnelError};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const SOCKS5_VERSION: u8 = 0x05;
pub const SOCKS5_AUTH_NONE: u8 = 0x00;
pub const SOCKS5_AUTH_UNACCEPTABLE: u8 = 0xFF;

pub const SOCKS5_CMD_CONNECT: u8 = 0x01;

pub const SOCKS5_ATYP_IPV4: u8 = 0x01;
pub const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
pub const SOCKS5_ATYP_IPV6: u8 = 0x04;

pub const SOCKS5_REP_SUCCESS: u8 = 0x00;
pub const SOCKS5_REP_GENERAL_FAILURE: u8 = 0x01;
pub const SOCKS5_REP_CONNECTION_REFUSED: u8 = 0x05;
pub const SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const SOCKS5_REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Address {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

impl fmt::Display for Socks5Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Socks5Address::Ipv4(addr) => write!(f, "{}", addr),
            Socks5Address::Domain(domain) => write!(f, "{}", domain),
            Socks5Address::Ipv6(addr) => write!(f, "{}", addr),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Request {
    pub dest_addr: Socks5Address,
    pub dest_port: u16,
}

impl Socks5Request {
    pub fn host_string(&self) -> String {
        self.dest_addr.to_string()
    }
}

/// Executes RFC 1928 handshake with client (No Authentication) and parses the CONNECT request.
pub async fn handle_socks5_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<Socks5Request> {
    // 1. Negotiation
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| TunnelError::Socks5(format!("Failed to read greeting: {}", e)))?;

    if header[0] != SOCKS5_VERSION {
        return Err(TunnelError::Socks5(format!(
            "Unsupported SOCKS version: 0x{:02x} (expected 0x05)",
            header[0]
        )));
    }

    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|e| TunnelError::Socks5(format!("Failed to read auth methods: {}", e)))?;

    if !methods.contains(&SOCKS5_AUTH_NONE) {
        stream
            .write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_UNACCEPTABLE])
            .await?;
        return Err(TunnelError::Socks5(
            "Client does not support NO_AUTH method".into(),
        ));
    }

    // Acknowledge NO_AUTH
    stream
        .write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_NONE])
        .await?;
    stream.flush().await?;

    // 2. Request Details
    let mut req_header = [0u8; 4];
    stream
        .read_exact(&mut req_header)
        .await
        .map_err(|e| TunnelError::Socks5(format!("Failed to read request header: {}", e)))?;

    let version = req_header[0];
    let cmd = req_header[1];
    let _rsv = req_header[2];
    let atyp = req_header[3];

    if version != SOCKS5_VERSION {
        return Err(TunnelError::Socks5(format!(
            "Invalid version in request: 0x{:02x}",
            version
        )));
    }

    if cmd != SOCKS5_CMD_CONNECT {
        send_socks5_reply(stream, SOCKS5_REP_CMD_NOT_SUPPORTED).await?;
        return Err(TunnelError::Socks5(format!(
            "Unsupported SOCKS command: 0x{:02x} (only CONNECT 0x01 supported)",
            cmd
        )));
    }

    let dest_addr = match atyp {
        SOCKS5_ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream
                .read_exact(&mut octets)
                .await
                .map_err(|e| TunnelError::Socks5(format!("Failed to read IPv4 address: {}", e)))?;
            Socks5Address::Ipv4(Ipv4Addr::from(octets))
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream
                .read_exact(&mut len_buf)
                .await
                .map_err(|e| TunnelError::Socks5(format!("Failed to read domain length: {}", e)))?;
            let domain_len = len_buf[0] as usize;
            let mut domain_buf = vec![0u8; domain_len];
            stream
                .read_exact(&mut domain_buf)
                .await
                .map_err(|e| TunnelError::Socks5(format!("Failed to read domain name: {}", e)))?;
            let domain_str = String::from_utf8(domain_buf).map_err(|e| {
                TunnelError::Socks5(format!("Domain name is not valid UTF-8: {}", e))
            })?;
            Socks5Address::Domain(domain_str)
        }
        SOCKS5_ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream
                .read_exact(&mut octets)
                .await
                .map_err(|e| TunnelError::Socks5(format!("Failed to read IPv6 address: {}", e)))?;
            Socks5Address::Ipv6(Ipv6Addr::from(octets))
        }
        other => {
            send_socks5_reply(stream, SOCKS5_REP_ADDR_NOT_SUPPORTED).await?;
            return Err(TunnelError::Socks5(format!(
                "Unsupported address type: 0x{:02x}",
                other
            )));
        }
    };

    let mut port_buf = [0u8; 2];
    stream
        .read_exact(&mut port_buf)
        .await
        .map_err(|e| TunnelError::Socks5(format!("Failed to read destination port: {}", e)))?;
    let dest_port = u16::from_be_bytes(port_buf);

    Ok(Socks5Request {
        dest_addr,
        dest_port,
    })
}

/// Sends RFC 1928 SOCKS5 reply with specified response code.
pub async fn send_socks5_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    rep_code: u8,
) -> Result<()> {
    // [VER, REP, RSV, ATYP, BND.ADDR (4 bytes), BND.PORT (2 bytes)]
    let reply = [
        SOCKS5_VERSION,
        rep_code,
        0x00,
        SOCKS5_ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    stream.write_all(&reply).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_socks5_handshake_ipv4_connect() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let client_task = tokio::spawn(async move {
            // Send greeting
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            // Read response
            let mut rep = [0u8; 2];
            client.read_exact(&mut rep).await.unwrap();
            assert_eq!(rep, [0x05, 0x00]);

            // Send CONNECT 127.0.0.1:8080
            client
                .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90])
                .await
                .unwrap();
        });

        let req = handle_socks5_handshake(&mut server).await.unwrap();
        assert_eq!(req.dest_addr, Socks5Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(req.dest_port, 8080);
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_handshake_domain_connect() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let client_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();
            let mut rep = [0u8; 2];
            client.read_exact(&mut rep).await.unwrap();
            assert_eq!(rep, [0x05, 0x00]);

            let domain = b"example.com";
            let mut buf = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
            buf.extend_from_slice(domain);
            buf.extend_from_slice(&80u16.to_be_bytes());
            client.write_all(&buf).await.unwrap();
        });

        let req = handle_socks5_handshake(&mut server).await.unwrap();
        assert_eq!(req.dest_addr, Socks5Address::Domain("example.com".into()));
        assert_eq!(req.dest_port, 80);
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_handshake_ipv6_connect() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let client_task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut rep = [0u8; 2];
            client.read_exact(&mut rep).await.unwrap();
            assert_eq!(rep, [0x05, 0x00]);

            let buf = vec![
                0x05, 0x01, 0x00, 0x04,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // ::1
                0x01, 0xBB, // port 443
            ];
            client.write_all(&buf).await.unwrap();
        });

        let req = handle_socks5_handshake(&mut server).await.unwrap();
        assert_eq!(req.dest_addr, Socks5Address::Ipv6(Ipv6Addr::LOCALHOST));
        assert_eq!(req.dest_port, 443);
        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_handshake_unsupported_version() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            client.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
        });
        assert!(handle_socks5_handshake(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn test_socks5_send_reply() {
        let mut out = Vec::new();
        send_socks5_reply(&mut out, SOCKS5_REP_SUCCESS).await.unwrap();
        assert_eq!(out.len(), 10);
        assert_eq!(out[0], SOCKS5_VERSION);
        assert_eq!(out[1], SOCKS5_REP_SUCCESS);
    }
}

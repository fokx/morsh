pub mod client;
pub mod connection;
pub mod happy_eyeballs;
pub mod known_hosts;
pub mod server;
pub mod stream;
pub mod tcp;
pub mod tcp_mux;
pub mod tls;

pub use client::QuicClient;
pub use connection::{generate_session_id, MorshConnection};
pub use happy_eyeballs::{connect_happy_eyeballs, DEFAULT_FALLBACK_DELAY};
pub use known_hosts::{
    default_known_hosts_path, KnownHostEntry, KnownHostStatus, KnownHosts,
    StrictHostKeyCheckingMode, TofuServerCertVerifier, TofuSharedState,
};
pub use server::QuicServer;
pub use stream::{MorshRecvStream, MorshSendStream, MorshStreamId};
pub use tcp::{TcpClient, TcpServer};
pub use tcp_mux::TcpConnection;
pub use tls::{
    cert_fingerprint_sha256, generate_self_signed_cert, make_client_config,
    make_client_config_from_rustls, make_rustls_client_config, make_rustls_server_config,
    make_server_config, make_server_config_from_rustls, make_tofu_rustls_client_config,
    SkipServerVerification, TofuOptions,
};

#[cfg(test)]
mod tests {
    use super::*;
    use morsh_core::protocol::ControlMessage;
    use std::net::SocketAddr;
    use std::time::Duration;

    #[tokio::test]
    async fn test_quic_handshake_and_control_message_exchange() {
        let (certs, key) = generate_self_signed_cert(vec!["localhost".into()]).unwrap();
        let server_config = make_server_config(certs, key).unwrap();
        let client_config = make_client_config(true).unwrap();

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = QuicServer::bind(bind_addr, server_config).unwrap();
        let server_addr = server.local_addr().unwrap();

        // Spawn server accept task
        let server_handle = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();

            // Read client hello
            let msg = MorshConnection::read_control_message(&mut recv).await.unwrap();
            match msg {
                ControlMessage::ClientHello { version, client_software, .. } => {
                    assert_eq!(version, 1);
                    assert_eq!(client_software, "morsh-test");
                }
                other => panic!("Unexpected message: {:?}", other),
            }

            // Reply with server hello
            let reply = ControlMessage::ServerHello {
                version: 1,
                server_software: "morshd-test".into(),
                session_id: [7u8; 16],
                resumption_token: [0u8; 16],
                supported_auth: vec![],
                session_resumed: false,
            };
            MorshConnection::send_control_message(&mut send, &reply).await.unwrap();
            let _ = send.finish();
            let _ = conn.inner().closed().await;
        });

        // Client connect
        let client = QuicClient::new(client_config).unwrap();
        let conn = client.connect(server_addr, "localhost").await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        let client_hello = ControlMessage::ClientHello {
            version: 1,
            client_software: "morsh-test".into(),
            knock_path: None,
            resumption_session_id: None,
        };
        MorshConnection::send_control_message(&mut send, &client_hello).await.unwrap();

        let server_hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
        match server_hello {
            ControlMessage::ServerHello { version, server_software, session_id, .. } => {
                assert_eq!(version, 1);
                assert_eq!(server_software, "morshd-test");
                assert_eq!(session_id, [7u8; 16]);
            }
            other => panic!("Unexpected response: {:?}", other),
        }

        conn.close(0, "normal shutdown");
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_handshake_and_control_message_exchange() {
        let (certs, key) = generate_self_signed_cert(vec!["localhost".into()]).unwrap();
        let server_rustls_config = make_rustls_server_config(certs, key).unwrap();
        let client_rustls_config = make_rustls_client_config(true).unwrap();

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = TcpServer::bind(bind_addr, server_rustls_config).await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Spawn server accept task
        let server_handle = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().unwrap();
            assert!(conn.is_tcp());
            assert!(!conn.is_quic());
            assert_eq!(conn.transport_name(), "TLS/TCP");

            let (mut send, mut recv) = conn.accept_bi().await.unwrap();

            // Read client hello
            let msg = MorshConnection::read_control_message(&mut recv).await.unwrap();
            match msg {
                ControlMessage::ClientHello { version, client_software, .. } => {
                    assert_eq!(version, 1);
                    assert_eq!(client_software, "morsh-tcp-test");
                }
                other => panic!("Unexpected message: {:?}", other),
            }

            // Reply with server hello
            let reply = ControlMessage::ServerHello {
                version: 1,
                server_software: "morshd-tcp-test".into(),
                session_id: [42u8; 16],
                resumption_token: [0u8; 16],
                supported_auth: vec![],
                session_resumed: false,
            };
            MorshConnection::send_control_message(&mut send, &reply).await.unwrap();
            let _ = send.finish();

            // Receive datagram over TCP
            let dgram = conn.read_datagram().await.unwrap();
            assert_eq!(dgram.as_ref(), b"tcp-datagram-payload");

            // Echo datagram back
            conn.send_datagram(bytes::Bytes::from("tcp-datagram-reply")).unwrap();

            conn.closed().await;
        });

        // Client connect
        let conn = TcpClient::connect(server_addr, "localhost", client_rustls_config)
            .await
            .unwrap();
        assert!(conn.is_tcp());

        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        let client_hello = ControlMessage::ClientHello {
            version: 1,
            client_software: "morsh-tcp-test".into(),
            knock_path: None,
            resumption_session_id: None,
        };
        MorshConnection::send_control_message(&mut send, &client_hello).await.unwrap();

        let server_hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
        match server_hello {
            ControlMessage::ServerHello { version, server_software, session_id, .. } => {
                assert_eq!(version, 1);
                assert_eq!(server_software, "morshd-tcp-test");
                assert_eq!(session_id, [42u8; 16]);
            }
            other => panic!("Unexpected response: {:?}", other),
        }

        // Send datagram over TCP
        conn.send_datagram(bytes::Bytes::from("tcp-datagram-payload")).unwrap();

        // Receive echoed datagram
        let reply_dgram = conn.read_datagram().await.unwrap();
        assert_eq!(reply_dgram.as_ref(), b"tcp-datagram-reply");

        conn.close(0, "normal tcp shutdown");
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_happy_eyeballs_quic_winner() {
        let (certs, key) = generate_self_signed_cert(vec!["localhost".into()]).unwrap();
        let server_rustls = make_rustls_server_config(certs, key).unwrap();
        let quic_server_config = make_server_config_from_rustls(server_rustls.clone()).unwrap();
        let quic_client_config = make_client_config(true).unwrap();
        let rustls_client_config = make_rustls_client_config(true).unwrap();

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let quic_server = QuicServer::bind(bind_addr, quic_server_config).unwrap();
        let quic_addr = quic_server.local_addr().unwrap();

        // Spawn QUIC server
        let server_handle = tokio::spawn(async move {
            let conn = quic_server.accept().await.unwrap().unwrap();
            assert!(conn.is_quic());
            conn.close(0, "quic ok");
        });

        let quic_client = QuicClient::new(quic_client_config).unwrap();
        let conn = connect_happy_eyeballs(
            quic_addr,
            "localhost",
            &quic_client,
            rustls_client_config,
            Duration::from_millis(300),
            false,
        )
        .await
        .unwrap();

        assert!(conn.is_quic());
        conn.close(0, "client done");
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_happy_eyeballs_force_tcp() {
        let (certs, key) = generate_self_signed_cert(vec!["localhost".into()]).unwrap();
        let server_rustls = make_rustls_server_config(certs, key).unwrap();
        let quic_client_config = make_client_config(true).unwrap();
        let rustls_client_config = make_rustls_client_config(true).unwrap();

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let tcp_server = TcpServer::bind(bind_addr, server_rustls).await.unwrap();
        let tcp_addr = tcp_server.local_addr().unwrap();

        // Spawn TCP server
        let server_handle = tokio::spawn(async move {
            let conn = tcp_server.accept().await.unwrap().unwrap();
            assert!(conn.is_tcp());
            conn.close(0, "tcp ok");
        });

        let quic_client = QuicClient::new(quic_client_config).unwrap();
        let conn = connect_happy_eyeballs(
            tcp_addr,
            "localhost",
            &quic_client,
            rustls_client_config,
            Duration::from_millis(300),
            true, // force_tcp
        )
        .await
        .unwrap();

        assert!(conn.is_tcp());
        conn.close(0, "client done");
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_happy_eyeballs_tcp_fallback_when_quic_unavailable() {
        let (certs, key) = generate_self_signed_cert(vec!["localhost".into()]).unwrap();
        let server_rustls = make_rustls_server_config(certs, key).unwrap();
        let quic_client_config = make_client_config(true).unwrap();
        let rustls_client_config = make_rustls_client_config(true).unwrap();

        // Only TCP server is listening; UDP is not bound
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let tcp_server = TcpServer::bind(bind_addr, server_rustls).await.unwrap();
        let tcp_addr = tcp_server.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let conn = tcp_server.accept().await.unwrap().unwrap();
            assert!(conn.is_tcp());
            conn.close(0, "tcp ok");
        });

        let quic_client = QuicClient::new(quic_client_config).unwrap();
        // Fast fallback delay (50 ms) to quickly race TCP when QUIC gets ICMP unreachable or times out
        let conn = connect_happy_eyeballs(
            tcp_addr,
            "localhost",
            &quic_client,
            rustls_client_config,
            Duration::from_millis(50),
            false,
        )
        .await
        .unwrap();

        assert!(conn.is_tcp());
        conn.close(0, "client done");
        server_handle.await.unwrap();
    }
}

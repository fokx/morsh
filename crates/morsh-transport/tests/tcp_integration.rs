use bytes::Bytes;
use morsh_core::protocol::{AuthMethod, ControlMessage, PROTOCOL_VERSION};
use morsh_transport::{
    connect_happy_eyeballs, generate_self_signed_cert, generate_session_id,
    make_client_config, make_rustls_client_config, make_rustls_server_config,
    MorshConnection, QuicClient, TcpClient, TcpServer,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

/// Helper: starts a test TCP fallback server on ephemeral port (127.0.0.1:0).
async fn setup_test_tcp_server() -> (TcpServer, SocketAddr, Arc<rustls::ClientConfig>) {
    let (certs, key) = generate_self_signed_cert(vec!["localhost".into()]).unwrap();
    let server_config = make_rustls_server_config(certs, key).unwrap();
    let client_config = make_rustls_client_config(true).unwrap();

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = TcpServer::bind(bind_addr, server_config).await.unwrap();
    let local_addr = server.local_addr().unwrap();
    (server, local_addr, client_config)
}

#[tokio::test]
async fn test_tcp_full_handshake_flow_and_pings() {
    let (server, server_addr, client_config) = setup_test_tcp_server().await;

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        assert!(conn.is_tcp());
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();

        // 1. Receive ClientHello
        let hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
        match hello {
            ControlMessage::ClientHello { version, client_software, .. } => {
                assert_eq!(version, PROTOCOL_VERSION);
                assert_eq!(client_software, "morsh-tcp-agent");
            }
            other => panic!("Unexpected msg: {:?}", other),
        }

        // 2. Respond ServerHello
        let session_id = generate_session_id();
        let server_hello = ControlMessage::ServerHello {
            version: PROTOCOL_VERSION,
            server_software: "morshd-tcp-test".into(),
            session_id,
            resumption_token: [0u8; 16],
            supported_auth: vec![AuthMethod::None],
            session_resumed: false,
        };
        MorshConnection::send_control_message(&mut send, &server_hello).await.unwrap();

        // 3. Handle Ping
        let ping = MorshConnection::read_control_message(&mut recv).await.unwrap();
        match ping {
            ControlMessage::Ping { seq, timestamp_ms } => {
                let pong = ControlMessage::Pong { seq, echo_timestamp_ms: timestamp_ms };
                MorshConnection::send_control_message(&mut send, &pong).await.unwrap();
            }
            other => panic!("Expected Ping, got {:?}", other),
        }

        // 4. Handle Disconnect
        let disc = MorshConnection::read_control_message(&mut recv).await.unwrap();
        match disc {
            ControlMessage::Disconnect { reason_code, .. } => {
                assert_eq!(reason_code, 0);
            }
            other => panic!("Expected Disconnect, got {:?}", other),
        }

        let _ = send.finish();
        conn.close(0, "server close after disconnect");
    });

    let client_conn = TcpClient::connect(server_addr, "localhost", client_config)
        .await
        .unwrap();
    assert!(client_conn.is_tcp());
    assert_eq!(client_conn.transport_name(), "TLS/TCP");

    let (mut send, mut recv) = client_conn.open_bi().await.unwrap();

    let client_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "morsh-tcp-agent".into(),
        knock_path: None,
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut send, &client_hello).await.unwrap();

    let server_hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
    match server_hello {
        ControlMessage::ServerHello { version, server_software, .. } => {
            assert_eq!(version, PROTOCOL_VERSION);
            assert_eq!(server_software, "morshd-tcp-test");
        }
        other => panic!("Expected ServerHello, got {:?}", other),
    }

    let ping = ControlMessage::Ping { seq: 101, timestamp_ms: 123456789 };
    MorshConnection::send_control_message(&mut send, &ping).await.unwrap();

    let pong = MorshConnection::read_control_message(&mut recv).await.unwrap();
    match pong {
        ControlMessage::Pong { seq, echo_timestamp_ms } => {
            assert_eq!(seq, 101);
            assert_eq!(echo_timestamp_ms, 123456789);
        }
        other => panic!("Expected Pong, got {:?}", other),
    }

    let disconnect = ControlMessage::Disconnect { reason_code: 0, message: "client exit".into() };
    MorshConnection::send_control_message(&mut send, &disconnect).await.unwrap();
    let _ = send.finish();

    client_conn.close(0, "normal client disconnect");
    server_task.await.unwrap();
}

#[tokio::test]
async fn test_tcp_multiplexed_bidirectional_streams() {
    let (server, server_addr, client_config) = setup_test_tcp_server().await;

    let stream_count = 5usize;

    // Server accepts 5 streams concurrently and echoes with prefix
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let mut handles = Vec::new();

        for _ in 0..stream_count {
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            handles.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                let n = recv.read(&mut buf).await.unwrap().unwrap();
                let mut reply = b"echo:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                send.write_all(&reply).await.unwrap();
                let _ = send.finish();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        conn.closed().await;
    });

    let client_conn = TcpClient::connect(server_addr, "localhost", client_config)
        .await
        .unwrap();

    let mut client_handles = Vec::new();
    for i in 0..stream_count {
        let conn = client_conn.clone();
        client_handles.push(tokio::spawn(async move {
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            let payload = format!("stream-payload-{}", i);
            send.write_all(payload.as_bytes()).await.unwrap();
            let _ = send.finish();

            let mut out = [0u8; 1024];
            let n = recv.read(&mut out).await.unwrap().unwrap();
            let expected = format!("echo:stream-payload-{}", i);
            assert_eq!(&out[..n], expected.as_bytes());
        }));
    }

    for h in client_handles {
        h.await.unwrap();
    }

    client_conn.close(0, "finished multiplexing");
    server_task.await.unwrap();
}

#[tokio::test]
async fn test_tcp_unreliable_datagram_exchange() {
    let (server, server_addr, client_config) = setup_test_tcp_server().await;

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        for _i in 0..3 {
            let dgram = conn.read_datagram().await.unwrap();
            let mut reply = b"reply-dgram:".to_vec();
            reply.extend_from_slice(&dgram);
            conn.send_datagram(Bytes::from(reply)).unwrap();
        }
        conn.closed().await;
    });

    let client_conn = TcpClient::connect(server_addr, "localhost", client_config)
        .await
        .unwrap();

    for i in 0..3 {
        let msg = format!("msg-{}", i);
        client_conn.send_datagram(Bytes::from(msg.clone())).unwrap();

        let reply = client_conn.read_datagram().await.unwrap();
        let expected = format!("reply-dgram:msg-{}", i);
        assert_eq!(reply.as_ref(), expected.as_bytes());
    }

    client_conn.close(0, "finished datagrams");
    server_task.await.unwrap();
}

#[tokio::test]
async fn test_tcp_stealth_knock_authorization_flow() {
    let (server, server_addr, client_config) = setup_test_tcp_server().await;

    let required_knock = "/custom-secret-path-456";

    let server_task = tokio::spawn(async move {
        // Accept first client (invalid knock)
        let conn1 = server.accept().await.unwrap().unwrap();
        let (_send1, mut recv1) = conn1.accept_bi().await.unwrap();
        let msg1 = MorshConnection::read_control_message(&mut recv1).await.unwrap();
        match msg1 {
            ControlMessage::ClientHello { knock_path, .. } => {
                if knock_path.as_deref() != Some(required_knock) {
                    conn1.close(404, "Not Found");
                }
            }
            _ => panic!("Expected ClientHello"),
        }

        // Accept second client (valid knock)
        let conn2 = server.accept().await.unwrap().unwrap();
        let (mut send2, mut recv2) = conn2.accept_bi().await.unwrap();
        let msg2 = MorshConnection::read_control_message(&mut recv2).await.unwrap();
        match msg2 {
            ControlMessage::ClientHello { knock_path, .. } => {
                assert_eq!(knock_path.as_deref(), Some(required_knock));
                let reply = ControlMessage::ServerHello {
                    version: PROTOCOL_VERSION,
                    server_software: "morshd-tcp-stealth".into(),
                    session_id: [1u8; 16],
                    resumption_token: [0u8; 16],
                    supported_auth: vec![],
                    session_resumed: false,
                };
                MorshConnection::send_control_message(&mut send2, &reply).await.unwrap();
                let _ = send2.finish();
            }
            _ => panic!("Expected ClientHello"),
        }

        conn2.closed().await;
    });

    // Client 1: sends invalid knock path
    let bad_client = TcpClient::connect(server_addr, "localhost", client_config.clone())
        .await
        .unwrap();
    let (mut bad_send, mut bad_recv) = bad_client.open_bi().await.unwrap();
    let bad_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "scanner-probe".into(),
        knock_path: Some("/wrong-path".into()),
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut bad_send, &bad_hello).await.unwrap();
    // Server should close the connection without ServerHello
    let res = timeout(Duration::from_millis(500), MorshConnection::read_control_message(&mut bad_recv)).await;
    assert!(res.is_err() || res.unwrap().is_err());

    // Client 2: sends correct knock path
    let good_client = TcpClient::connect(server_addr, "localhost", client_config)
        .await
        .unwrap();
    let (mut good_send, mut good_recv) = good_client.open_bi().await.unwrap();
    let good_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "authorized-client".into(),
        knock_path: Some(required_knock.into()),
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut good_send, &good_hello).await.unwrap();
    let server_hello = MorshConnection::read_control_message(&mut good_recv).await.unwrap();
    match server_hello {
        ControlMessage::ServerHello { server_software, .. } => {
            assert_eq!(server_software, "morshd-tcp-stealth");
        }
        _ => panic!("Expected ServerHello"),
    }

    good_client.close(0, "done");
    server_task.await.unwrap();
}

#[tokio::test]
async fn test_tcp_version_mismatch_rejection() {
    let (server, server_addr, client_config) = setup_test_tcp_server().await;

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let msg = MorshConnection::read_control_message(&mut recv).await.unwrap();
        match msg {
            ControlMessage::ClientHello { version, .. } => {
                if version != PROTOCOL_VERSION {
                    let err = ControlMessage::Disconnect {
                        reason_code: 1,
                        message: "Version mismatch".into(),
                    };
                    MorshConnection::send_control_message(&mut send, &err).await.unwrap();
                    let _ = send.finish();
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    conn.close(1, "Version mismatch");
                }
            }
            _ => panic!("Expected ClientHello"),
        }
    });

    let client_conn = TcpClient::connect(server_addr, "localhost", client_config)
        .await
        .unwrap();
    let (mut send, mut recv) = client_conn.open_bi().await.unwrap();

    let old_hello = ControlMessage::ClientHello {
        version: 999, // Incompatible future/ancient version
        client_software: "ancient-client".into(),
        knock_path: None,
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut send, &old_hello).await.unwrap();

    let resp = MorshConnection::read_control_message(&mut recv).await.unwrap();
    match resp {
        ControlMessage::Disconnect { reason_code, message } => {
            assert_eq!(reason_code, 1);
            assert!(message.contains("Version mismatch"));
        }
        other => panic!("Expected Disconnect frame, got {:?}", other),
    }

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_happy_eyeballs_seamless_fallback_when_quic_blocked() {
    // Only TCP fallback server is running; UDP / QUIC is completely blocked / absent
    let (tcp_server, tcp_addr, rustls_client_config) = setup_test_tcp_server().await;

    let server_task = tokio::spawn(async move {
        let conn = tcp_server.accept().await.unwrap().unwrap();
        assert!(conn.is_tcp());
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();

        let hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
        match hello {
            ControlMessage::ClientHello { client_software, .. } => {
                assert_eq!(client_software, "morsh-happy-eyeballs");
            }
            _ => panic!("Expected ClientHello"),
        }

        let reply = ControlMessage::ServerHello {
            version: PROTOCOL_VERSION,
            server_software: "morshd-dual-stack".into(),
            session_id: [88u8; 16],
            resumption_token: [0u8; 16],
            supported_auth: vec![],
            session_resumed: false,
        };
        MorshConnection::send_control_message(&mut send, &reply).await.unwrap();
        let _ = send.finish();
        conn.closed().await;
    });

    // Client has a QuicClient configured
    let quic_client_config = make_client_config(true).unwrap();
    let quic_client = QuicClient::new(quic_client_config).unwrap();

    // Use Happy Eyeballs with a 100 ms fallback delay
    let conn = connect_happy_eyeballs(
        tcp_addr,
        "localhost",
        &quic_client,
        rustls_client_config,
        Duration::from_millis(100),
        false,
    )
    .await
    .unwrap();

    // Must have successfully connected via TCP fallback
    assert!(conn.is_tcp());
    assert_eq!(conn.transport_name(), "TLS/TCP");

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "morsh-happy-eyeballs".into(),
        knock_path: None,
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut send, &hello).await.unwrap();

    let server_hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
    match server_hello {
        ControlMessage::ServerHello { session_id, .. } => {
            assert_eq!(session_id, [88u8; 16]);
        }
        _ => panic!("Expected ServerHello"),
    }

    conn.close(0, "fallback success");
    server_task.await.unwrap();
}

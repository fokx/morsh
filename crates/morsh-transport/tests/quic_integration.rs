use bytes::Bytes;
use morsh_core::protocol::{AuthMethod, ControlMessage, PROTOCOL_VERSION};
use morsh_transport::{
    generate_self_signed_cert, generate_session_id, make_client_config, make_server_config,
    MorshConnection, QuicClient, QuicServer,
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;

/// Helper: starts a test QUIC server on ephemeral port (127.0.0.1:0).
fn setup_test_server() -> (QuicServer, SocketAddr) {
    let (certs, key) = generate_self_signed_cert(vec!["localhost".into()]).unwrap();
    let server_config = make_server_config(certs, key).unwrap();
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = QuicServer::bind(bind_addr, server_config).unwrap();
    let local_addr = server.local_addr().unwrap();
    (server, local_addr)
}

/// Helper: starts a test QUIC client with insecure verification for self-signed certs.
fn setup_test_client() -> QuicClient {
    let client_config = make_client_config(true).unwrap();
    QuicClient::new(client_config).unwrap()
}

#[tokio::test]
async fn test_full_handshake_flow_and_pings() {
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();

        // 1. Receive ClientHello
        let hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
        match hello {
            ControlMessage::ClientHello { version, client_software, .. } => {
                assert_eq!(version, PROTOCOL_VERSION);
                assert_eq!(client_software, "morsh-test-agent");
            }
            other => panic!("Unexpected msg: {:?}", other),
        }

        // 2. Respond ServerHello
        let session_id = generate_session_id();
        let server_hello = ControlMessage::ServerHello {
            version: PROTOCOL_VERSION,
            server_software: "morshd-test".into(),
            session_id,
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

    let client_conn = client.connect(server_addr, "localhost").await.unwrap();
    let (mut send, mut recv) = client_conn.open_bi().await.unwrap();

    // 1. Send ClientHello
    let client_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "morsh-test-agent".into(),
        knock_path: None,
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut send, &client_hello).await.unwrap();

    // 2. Read ServerHello
    let server_hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
    match server_hello {
        ControlMessage::ServerHello { version, session_id, .. } => {
            assert_eq!(version, PROTOCOL_VERSION);
            assert_ne!(session_id, [0u8; 16]);
        }
        other => panic!("Unexpected server response: {:?}", other),
    }

    // 3. Send Ping, await Pong
    let ping = ControlMessage::Ping { seq: 42, timestamp_ms: 1000 };
    MorshConnection::send_control_message(&mut send, &ping).await.unwrap();

    let pong = MorshConnection::read_control_message(&mut recv).await.unwrap();
    match pong {
        ControlMessage::Pong { seq, echo_timestamp_ms } => {
            assert_eq!(seq, 42);
            assert_eq!(echo_timestamp_ms, 1000);
        }
        other => panic!("Expected Pong, got {:?}", other),
    }

    // 4. Send graceful Disconnect
    let disc = ControlMessage::Disconnect { reason_code: 0, message: "test complete".into() };
    MorshConnection::send_control_message(&mut send, &disc).await.unwrap();
    let _ = send.finish();

    // Wait for server to close cleanly
    let _ = client_conn.inner().closed().await;
    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

#[tokio::test]
async fn test_unreliable_datagram_exchange() {
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        // Wait for incoming datagram
        let datagram = conn.read_datagram().await.unwrap();
        assert_eq!(&datagram[..], b"hello morsh datagram");

        // Echo datagram back
        conn.send_datagram(Bytes::from_static(b"pong datagram")).unwrap();
        let _ = conn.inner().closed().await;
    });

    let client_conn = client.connect(server_addr, "localhost").await.unwrap();

    // Send datagram from client
    client_conn.send_datagram(Bytes::from_static(b"hello morsh datagram")).unwrap();

    // Read echoed datagram
    let reply = client_conn.read_datagram().await.unwrap();
    assert_eq!(&reply[..], b"pong datagram");

    client_conn.close(0, "datagram test complete");
    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

#[tokio::test]
async fn test_multiplexed_bidirectional_streams() {
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let stream_count = 5;

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        for _ in 0..stream_count {
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            tokio::spawn(async move {
                let msg = MorshConnection::read_control_message(&mut recv).await.unwrap();
                // Echo back
                MorshConnection::send_control_message(&mut send, &msg).await.unwrap();
                let _ = send.finish();
            });
        }
        let _ = conn.inner().closed().await;
    });

    let client_conn = client.connect(server_addr, "localhost").await.unwrap();

    // Spawn 5 concurrent streams on the same QUIC connection
    let mut handles = Vec::new();
    for i in 0..stream_count {
        let conn_clone = client_conn.clone();
        handles.push(tokio::spawn(async move {
            let (mut send, mut recv) = conn_clone.open_bi().await.unwrap();
            let ping = ControlMessage::Ping { seq: i as u64, timestamp_ms: i as u64 * 100 };
            MorshConnection::send_control_message(&mut send, &ping).await.unwrap();

            let response = MorshConnection::read_control_message(&mut recv).await.unwrap();
            assert_eq!(response, ping);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    client_conn.close(0, "multiplex test complete");
    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

#[tokio::test]
async fn test_stealth_knock_authorization_flow() {
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();
    let expected_knock = "/vault/secret-gateway-v1";

    let server_task = tokio::spawn(async move {
        // Handle connection 1: unauthorized
        let conn1 = server.accept().await.unwrap().unwrap();
        let (_send1, mut recv1) = conn1.accept_bi().await.unwrap();
        let hello1 = MorshConnection::read_control_message(&mut recv1).await.unwrap();
        if let ControlMessage::ClientHello { knock_path, .. } = hello1 {
            if knock_path.as_deref() != Some(expected_knock) {
                // Reject unauthorized probe silently with 404
                conn1.close(404, "Not Found");
            }
        }

        // Handle connection 2: authorized
        let conn2 = server.accept().await.unwrap().unwrap();
        let (mut send2, mut recv2) = conn2.accept_bi().await.unwrap();
        let hello2 = MorshConnection::read_control_message(&mut recv2).await.unwrap();
        if let ControlMessage::ClientHello { knock_path, .. } = hello2 {
            assert_eq!(knock_path.as_deref(), Some(expected_knock));
            let s_hello = ControlMessage::ServerHello {
                version: PROTOCOL_VERSION,
                server_software: "morshd".into(),
                session_id: generate_session_id(),
                supported_auth: vec![],
                session_resumed: false,
            };
            MorshConnection::send_control_message(&mut send2, &s_hello).await.unwrap();
        }
        let _ = conn2.inner().closed().await;
    });

    // 1. Connection with wrong knock -> expect error/rejection
    let client_conn_unauth = client.connect(server_addr, "localhost").await.unwrap();
    let (mut send_unauth, mut recv_unauth) = client_conn_unauth.open_bi().await.unwrap();
    let bad_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "scanner".into(),
        knock_path: Some("/invalid-knock".into()),
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut send_unauth, &bad_hello).await.unwrap();
    let result = MorshConnection::read_control_message(&mut recv_unauth).await;
    assert!(result.is_err(), "Expected connection to be rejected by server");

    // 2. Connection with correct knock -> expect success
    let client_conn_auth = client.connect(server_addr, "localhost").await.unwrap();
    let (mut send_auth, mut recv_auth) = client_conn_auth.open_bi().await.unwrap();
    let good_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "morsh-client".into(),
        knock_path: Some(expected_knock.into()),
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut send_auth, &good_hello).await.unwrap();
    let reply = MorshConnection::read_control_message(&mut recv_auth).await.unwrap();
    assert!(matches!(reply, ControlMessage::ServerHello { .. }));

    client_conn_auth.close(0, "done");
    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

#[tokio::test]
async fn test_version_mismatch_rejection() {
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();

        let hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
        if let ControlMessage::ClientHello { version, .. } = hello {
            if version != PROTOCOL_VERSION {
                let rej = ControlMessage::Disconnect {
                    reason_code: 1,
                    message: "Incompatible protocol version".into(),
                };
                MorshConnection::send_control_message(&mut send, &rej).await.unwrap();
                let _ = send.finish();
                let _ = conn.inner().closed().await;
            }
        }
    });

    let client_conn = client.connect(server_addr, "localhost").await.unwrap();
    let (mut send, mut recv) = client_conn.open_bi().await.unwrap();

    let future_hello = ControlMessage::ClientHello {
        version: 9999, // Incompatible future version
        client_software: "morsh-future".into(),
        knock_path: None,
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut send, &future_hello).await.unwrap();

    let reply = MorshConnection::read_control_message(&mut recv).await.unwrap();
    match reply {
        ControlMessage::Disconnect { reason_code, message } => {
            assert_eq!(reason_code, 1);
            assert!(message.contains("Incompatible"));
        }
        other => panic!("Expected Disconnect for mismatched version, got {:?}", other),
    }

    client_conn.close(1, "client close");
    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

#[tokio::test]
async fn test_quic_connection_migration() {
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let initial_remote = conn.remote_address();

        let (mut send, mut recv) = conn.accept_bi().await.unwrap();

        // 1. Read first ping before migration
        let msg1 = MorshConnection::read_control_message(&mut recv).await.unwrap();
        assert_eq!(msg1, ControlMessage::Ping { seq: 1, timestamp_ms: 100 });
        MorshConnection::send_control_message(&mut send, &ControlMessage::Pong { seq: 1, echo_timestamp_ms: 100 }).await.unwrap();

        // 2. Read second ping after client rebind / migration
        let msg2 = MorshConnection::read_control_message(&mut recv).await.unwrap();
        assert_eq!(msg2, ControlMessage::Ping { seq: 2, timestamp_ms: 200 });
        MorshConnection::send_control_message(&mut send, &ControlMessage::Pong { seq: 2, echo_timestamp_ms: 200 }).await.unwrap();

        // Verify the connection migrated: remote address updated or matches new socket
        let final_remote = conn.remote_address();
        assert_ne!(initial_remote, final_remote, "Connection remote address should update upon client migration");

        let _ = send.finish();
        let _ = conn.inner().closed().await;
    });

    let client_conn = client.connect(server_addr, "localhost").await.unwrap();
    let initial_client_addr = client.local_addr().unwrap();
    let (mut send, mut recv) = client_conn.open_bi().await.unwrap();

    // Send first ping
    let ping1 = ControlMessage::Ping { seq: 1, timestamp_ms: 100 };
    MorshConnection::send_control_message(&mut send, &ping1).await.unwrap();
    let pong1 = MorshConnection::read_control_message(&mut recv).await.unwrap();
    assert_eq!(pong1, ControlMessage::Pong { seq: 1, echo_timestamp_ms: 100 });

    // Simulate IP/interface roaming: rebind client UDP endpoint to a new socket
    let new_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let new_client_addr = new_sock.local_addr().unwrap();
    assert_ne!(initial_client_addr, new_client_addr);

    client.rebind(new_sock).unwrap();
    assert_eq!(client.local_addr().unwrap(), new_client_addr);

    // Give a brief moment for socket swap
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send second ping over existing stream on existing connection
    let ping2 = ControlMessage::Ping { seq: 2, timestamp_ms: 200 };
    MorshConnection::send_control_message(&mut send, &ping2).await.unwrap();
    let pong2 = MorshConnection::read_control_message(&mut recv).await.unwrap();
    assert_eq!(pong2, ControlMessage::Pong { seq: 2, echo_timestamp_ms: 200 });

    // Clean disconnect
    let _ = send.finish();
    client_conn.close(0, "client done");

    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

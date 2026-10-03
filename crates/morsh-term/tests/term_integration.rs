use morsh_core::protocol::{AuthMethod, ControlMessage, PROTOCOL_VERSION};
use morsh_term::{PtyConfig, PtySession};
use morsh_transport::{
    generate_self_signed_cert, generate_session_id, make_client_config, make_server_config,
    MorshConnection, QuicClient, QuicServer,
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Helper: starts a test QUIC server on an ephemeral port.
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
async fn test_interactive_pty_over_quic_streams() {
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();

        // Accept Stream 0 (Control stream)
        let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await.unwrap();

        // Read ClientHello
        let hello = MorshConnection::read_control_message(&mut ctrl_recv).await.unwrap();
        match hello {
            ControlMessage::ClientHello { version, .. } => {
                assert_eq!(version, PROTOCOL_VERSION);
            }
            other => panic!("Unexpected msg: {:?}", other),
        }

        // Send ServerHello
        let server_hello = ControlMessage::ServerHello {
            version: PROTOCOL_VERSION,
            server_software: "morshd-test".into(),
            session_id: generate_session_id(),
            resumption_token: [0u8; 16],
            supported_auth: vec![AuthMethod::None],
            session_resumed: false,
        };
        MorshConnection::send_control_message(&mut ctrl_send, &server_hello).await.unwrap();

        // Read initial WindowResize
        let resize_msg = MorshConnection::read_control_message(&mut ctrl_recv).await.unwrap();
        let (init_cols, init_rows) = match resize_msg {
            ControlMessage::WindowResize { cols, rows, .. } => (cols, rows),
            other => panic!("Expected WindowResize, got: {:?}", other),
        };
        assert_eq!(init_cols, 80);
        assert_eq!(init_rows, 24);

        // Accept Stream 1 (PTY raw byte stream)
        let (mut pty_stream_send, mut pty_stream_recv) = conn.accept_bi().await.unwrap();

        let mut config = PtyConfig::default();
        config.cols = init_cols;
        config.rows = init_rows;
        config.command = Some(vec!["/bin/sh".into()]);

        let session = PtySession::spawn(&config).unwrap();
        let (handle, mut pty_reader, mut pty_writer) = session.split();

        // Pipe PTY reader -> Stream 1 writer
        let mut pty_out = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match pty_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if pty_stream_send.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = pty_stream_send.finish();
        });

        // Pipe Stream 1 reader -> PTY writer
        let pty_in = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match pty_stream_recv.read(&mut buf).await {
                    Ok(Some(n)) if n > 0 => {
                        if pty_writer.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        });

        // Control stream loop: handle dynamic WindowResize and Disconnect
        loop {
            tokio::select! {
                msg = MorshConnection::read_control_message(&mut ctrl_recv) => {
                    match msg {
                        Ok(ControlMessage::WindowResize { cols, rows, .. }) => {
                            assert!(handle.resize(cols, rows).is_ok());
                        }
                        Ok(ControlMessage::Disconnect { .. }) => {
                            break;
                        }
                        _ => break,
                    }
                }
                _ = &mut pty_out => {
                    break;
                }
            }
        }

        let _ = pty_in.await;
        let _ = handle.kill();
        let _ = ctrl_send.finish();
        let _ = conn.inner().closed().await;
    });

    let client_conn = client.connect(server_addr, "localhost").await.unwrap();

    // 1. Open Stream 0 (Control)
    let (mut ctrl_send, mut ctrl_recv) = client_conn.open_bi().await.unwrap();

    let client_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "morsh-test".into(),
        knock_path: None,
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut ctrl_send, &client_hello).await.unwrap();

    let server_hello = MorshConnection::read_control_message(&mut ctrl_recv).await.unwrap();
    assert!(matches!(server_hello, ControlMessage::ServerHello { .. }));

    // Send initial WindowResize
    let resize1 = ControlMessage::WindowResize {
        cols: 80,
        rows: 24,
        x_pixels: 0,
        y_pixels: 0,
    };
    MorshConnection::send_control_message(&mut ctrl_send, &resize1).await.unwrap();

    // 2. Open Stream 1 (PTY raw stream)
    let (mut pty_send, mut pty_recv) = client_conn.open_bi().await.unwrap();

    // Write shell command to Stream 1
    let command = b"echo 'morsh_pty_interactive_ok'\n";
    pty_send.write_all(command).await.unwrap();

    // Read response from Stream 1
    let mut response_bytes = Vec::new();
    let mut buf = [0u8; 1024];

    let timer = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(timer);

    loop {
        tokio::select! {
            res = pty_recv.read(&mut buf) => {
                match res {
                    Ok(Some(n)) if n > 0 => {
                        response_bytes.extend_from_slice(&buf[..n]);
                        if response_bytes.windows(b"morsh_pty_interactive_ok".len()).any(|w| w == b"morsh_pty_interactive_ok") {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            _ = &mut timer => {
                panic!("Timed out waiting for shell echo on PTY stream");
            }
        }
    }

    let response_str = String::from_utf8_lossy(&response_bytes);
    assert!(response_str.contains("morsh_pty_interactive_ok"));

    // 3. Test dynamic out-of-band WindowResize on Stream 0
    let resize2 = ControlMessage::WindowResize {
        cols: 132,
        rows: 43,
        x_pixels: 0,
        y_pixels: 0,
    };
    MorshConnection::send_control_message(&mut ctrl_send, &resize2).await.unwrap();

    // 4. Send exit to shell
    pty_send.write_all(b"exit\n").await.unwrap();
    let _ = pty_send.finish();

    // Disconnect control stream
    let disc = ControlMessage::Disconnect {
        reason_code: 0,
        message: "clean exit".into(),
    };
    MorshConnection::send_control_message(&mut ctrl_send, &disc).await.unwrap();
    let _ = ctrl_send.finish();

    client_conn.close(0, "done");
    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

#[tokio::test]
async fn test_pty_session_persists_across_quic_connection_migration() {
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let initial_remote = conn.remote_address();

        let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await.unwrap();
        let _hello = MorshConnection::read_control_message(&mut ctrl_recv).await.unwrap();
        let server_hello = ControlMessage::ServerHello {
            version: PROTOCOL_VERSION,
            server_software: "morshd-test".into(),
            session_id: generate_session_id(),
            resumption_token: [0u8; 16],
            supported_auth: vec![AuthMethod::None],
            session_resumed: false,
        };
        MorshConnection::send_control_message(&mut ctrl_send, &server_hello).await.unwrap();

        let (mut pty_stream_send, mut pty_stream_recv) = conn.accept_bi().await.unwrap();

        let mut config = PtyConfig::default();
        config.command = Some(vec!["/bin/cat".into()]);
        let session = PtySession::spawn(&config).unwrap();
        let (handle, mut pty_reader, mut pty_writer) = session.split();

        let pty_out = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match pty_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if pty_stream_send.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = pty_stream_send.finish();
        });

        let pty_in = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match pty_stream_recv.read(&mut buf).await {
                    Ok(Some(n)) if n > 0 => {
                        if pty_writer.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        });

        // Wait for control disconnect
        let _ = MorshConnection::read_control_message(&mut ctrl_recv).await;

        // Verify that the remote address migrated!
        let final_remote = conn.remote_address();
        assert_ne!(initial_remote, final_remote, "Server should observe migrated client IP/port");

        let _ = handle.kill();
        let _ = pty_out.await;
        let _ = pty_in.await;
        let _ = ctrl_send.finish();
    });

    let client_conn = client.connect(server_addr, "localhost").await.unwrap();
    let initial_client_addr = client.local_addr().unwrap();

    let (mut ctrl_send, mut ctrl_recv) = client_conn.open_bi().await.unwrap();
    let client_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "morsh-test".into(),
        knock_path: None,
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut ctrl_send, &client_hello).await.unwrap();
    let _ = MorshConnection::read_control_message(&mut ctrl_recv).await.unwrap();

    let (mut pty_send, mut pty_recv) = client_conn.open_bi().await.unwrap();

    // 1. Send data through PTY before migration
    let msg1 = b"test-pre-migration\n";
    pty_send.write_all(msg1).await.unwrap();

    let mut buf = [0u8; 256];
    let mut rec1_bytes = Vec::new();
    while !rec1_bytes
        .windows(b"test-pre-migration".len())
        .any(|w| w == b"test-pre-migration")
    {
        let n = pty_recv.read(&mut buf).await.unwrap().unwrap();
        rec1_bytes.extend_from_slice(&buf[..n]);
    }

    // 2. Perform connection migration: rebind client UDP endpoint to a new socket
    let new_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let new_client_addr = new_sock.local_addr().unwrap();
    assert_ne!(initial_client_addr, new_client_addr);

    client.rebind(new_sock).unwrap();
    assert_eq!(client.local_addr().unwrap(), new_client_addr);

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Send data through PTY AFTER migration on existing stream!
    let msg2 = b"test-post-migration\n";
    pty_send.write_all(msg2).await.unwrap();

    let mut rec2_bytes = Vec::new();
    while !rec2_bytes
        .windows(b"test-post-migration".len())
        .any(|w| w == b"test-post-migration")
    {
        let n = pty_recv.read(&mut buf).await.unwrap().unwrap();
        rec2_bytes.extend_from_slice(&buf[..n]);
    }
    let rec2 = String::from_utf8_lossy(&rec2_bytes);
    assert!(
        rec2.contains("test-post-migration"),
        "Interactive PTY stream should seamlessly persist after migration!"
    );

    // Clean disconnect
    let disc = ControlMessage::Disconnect {
        reason_code: 0,
        message: "migrated exit".into(),
    };
    MorshConnection::send_control_message(&mut ctrl_send, &disc).await.unwrap();
    let _ = pty_send.finish();
    let _ = ctrl_send.finish();

    client_conn.close(0, "done");
    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

#[tokio::test]
async fn test_session_persistence_detach_and_resume_with_snapshot() {
    use morsh_term::SessionRegistry;
    use std::sync::Arc;

    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let registry = SessionRegistry::new();
    let registry_server = registry.clone();

    let session_id_fixed = [42u8; 16];
    let token_fixed = [77u8; 16];

    let server_task = tokio::spawn(async move {
        // Connection 1: Initial session creation and detach
        let conn1 = server.accept().await.unwrap().unwrap();
        let (mut ctrl_send1, mut ctrl_recv1) = conn1.accept_bi().await.unwrap();

        let _hello1 = MorshConnection::read_control_message(&mut ctrl_recv1).await.unwrap();
        let s_hello1 = ControlMessage::ServerHello {
            version: PROTOCOL_VERSION,
            server_software: "morshd-test".into(),
            session_id: session_id_fixed,
            resumption_token: token_fixed,
            supported_auth: vec![AuthMethod::None],
            session_resumed: false,
        };
        MorshConnection::send_control_message(&mut ctrl_send1, &s_hello1).await.unwrap();

        // Create persistent session running cat
        let mut cfg = PtyConfig::default();
        cfg.command = Some(vec!["/bin/cat".into()]);
        let session = registry_server
            .create_session(session_id_fixed, token_fixed, "alice".into(), &cfg)
            .await
            .unwrap();

        let (mut pty_send1, mut pty_recv1) = conn1.accept_bi().await.unwrap();
        let (tx1, mut rx1) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        session.attach(tx1).await;

        let pty_out1 = tokio::spawn(async move {
            while let Some(chunk) = rx1.recv().await {
                if pty_send1.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });

        let session_in1 = Arc::clone(&session);
        let pty_in1 = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                match pty_recv1.read(&mut buf).await {
                    Ok(Some(n)) if n > 0 => {
                        let _ = session_in1.write_input(&buf[..n]).await;
                    }
                    _ => break,
                }
            }
        });

        // Wait for Detach request from client 1
        let detach_req = MorshConnection::read_control_message(&mut ctrl_recv1).await.unwrap();
        assert!(matches!(detach_req, ControlMessage::SessionDetachRequest));
        session.detach().await;
        pty_in1.abort();
        let _ = pty_out1.await;

        let detach_resp = ControlMessage::Disconnect {
            reason_code: 0,
            message: "detached".into(),
        };
        MorshConnection::send_control_message(&mut ctrl_send1, &detach_resp).await.unwrap();
        let _ = conn1.inner().closed().await;

        // Connection 2: Resumption of persistent session
        let conn2 = server.accept().await.unwrap().unwrap();
        let (mut ctrl_send2, mut ctrl_recv2) = conn2.accept_bi().await.unwrap();

        let hello2 = MorshConnection::read_control_message(&mut ctrl_recv2).await.unwrap();
        assert!(matches!(hello2, ControlMessage::ClientHello { resumption_session_id: Some(id), .. } if id == session_id_fixed));

        let s_hello2 = ControlMessage::ServerHello {
            version: PROTOCOL_VERSION,
            server_software: "morshd-test".into(),
            session_id: session_id_fixed,
            resumption_token: token_fixed,
            supported_auth: vec![AuthMethod::None],
            session_resumed: true,
        };
        MorshConnection::send_control_message(&mut ctrl_send2, &s_hello2).await.unwrap();

        // Handle SessionResumeRequest
        let resume_req = MorshConnection::read_control_message(&mut ctrl_recv2).await.unwrap();
        match resume_req {
            ControlMessage::SessionResumeRequest { session_id, resumption_token } => {
                let resumed = registry_server.resume(&session_id, &resumption_token).await.unwrap();
                let resume_resp = ControlMessage::SessionResumeResponse {
                    success: true,
                    session_id,
                    resumption_token,
                    message: "Resumed".into(),
                };
                MorshConnection::send_control_message(&mut ctrl_send2, &resume_resp).await.unwrap();

                // Send screen snapshot
                let snapshot = ControlMessage::ScreenSnapshot {
                    cols: 80,
                    rows: 24,
                    cursor_x: 0,
                    cursor_y: 0,
                    buffer: resumed.snapshot(),
                };
                MorshConnection::send_control_message(&mut ctrl_send2, &snapshot).await.unwrap();

                // Re-attach stream for resumed session
                let (mut pty_send2, mut pty_recv2) = conn2.accept_bi().await.unwrap();
                let (tx2, mut rx2) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
                resumed.attach(tx2).await;

                let pty_out2 = tokio::spawn(async move {
                    while let Some(chunk) = rx2.recv().await {
                        if pty_send2.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                });

                let session_in2 = Arc::clone(&resumed);
                let pty_in2 = tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    loop {
                        match pty_recv2.read(&mut buf).await {
                            Ok(Some(n)) if n > 0 => {
                                let _ = session_in2.write_input(&buf[..n]).await;
                            }
                            _ => break,
                        }
                    }
                });

                // Wait for client exit / disconnect
                let _ = MorshConnection::read_control_message(&mut ctrl_recv2).await;
                pty_in2.abort();
                let _ = resumed.kill();
                let _ = pty_out2.await;
            }
            other => panic!("Expected SessionResumeRequest, got {:?}", other),
        }

        let _ = conn2.inner().closed().await;
    });

    // 1. Client 1 connects, writes initial line to PTY, and voluntarily detaches
    let client_conn1 = client.connect(server_addr, "localhost").await.unwrap();
    let (mut ctrl_send1, mut ctrl_recv1) = client_conn1.open_bi().await.unwrap();

    let c_hello1 = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "morsh-client1".into(),
        knock_path: None,
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut ctrl_send1, &c_hello1).await.unwrap();
    let s_hello1 = MorshConnection::read_control_message(&mut ctrl_recv1).await.unwrap();
    assert!(matches!(s_hello1, ControlMessage::ServerHello { session_id, resumption_token, .. } if session_id == session_id_fixed && resumption_token == token_fixed));

    let (mut pty_send1, mut pty_recv1) = client_conn1.open_bi().await.unwrap();
    pty_send1.write_all(b"Hello persistent shell!\n").await.unwrap();

    let mut buf = [0u8; 256];
    let mut rec1 = Vec::new();
    while !rec1.windows(b"Hello persistent shell!".len()).any(|w| w == b"Hello persistent shell!") {
        let n = pty_recv1.read(&mut buf).await.unwrap().unwrap();
        rec1.extend_from_slice(&buf[..n]);
    }
    assert!(String::from_utf8_lossy(&rec1).contains("Hello persistent shell!"));

    // Client 1 voluntarily detaches
    MorshConnection::send_control_message(&mut ctrl_send1, &ControlMessage::SessionDetachRequest).await.unwrap();
    let detach_ack = MorshConnection::read_control_message(&mut ctrl_recv1).await.unwrap();
    assert!(matches!(detach_ack, ControlMessage::Disconnect { .. }));
    client_conn1.close(0, "detached");

    // Give a moment between connections
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 2. Client 2 connects to resume with session_id and resumption_token
    let client_conn2 = client.connect(server_addr, "localhost").await.unwrap();
    let (mut ctrl_send2, mut ctrl_recv2) = client_conn2.open_bi().await.unwrap();

    let c_hello2 = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "morsh-client2".into(),
        knock_path: None,
        resumption_session_id: Some(session_id_fixed),
    };
    MorshConnection::send_control_message(&mut ctrl_send2, &c_hello2).await.unwrap();
    let s_hello2 = MorshConnection::read_control_message(&mut ctrl_recv2).await.unwrap();
    assert!(matches!(s_hello2, ControlMessage::ServerHello { session_resumed: true, .. }));

    // Send SessionResumeRequest
    let resume_req = ControlMessage::SessionResumeRequest {
        session_id: session_id_fixed,
        resumption_token: token_fixed,
    };
    MorshConnection::send_control_message(&mut ctrl_send2, &resume_req).await.unwrap();

    let resume_ack = MorshConnection::read_control_message(&mut ctrl_recv2).await.unwrap();
    assert!(matches!(resume_ack, ControlMessage::SessionResumeResponse { success: true, .. }));

    // Receive ScreenSnapshot
    let snapshot_msg = MorshConnection::read_control_message(&mut ctrl_recv2).await.unwrap();
    match snapshot_msg {
        ControlMessage::ScreenSnapshot { buffer, .. } => {
            let snap_str = String::from_utf8_lossy(&buffer);
            assert!(
                snap_str.contains("Hello persistent shell!"),
                "ScreenSnapshot must restore the exact screen state recorded before detach! Got: {}",
                snap_str
            );
        }
        other => panic!("Expected ScreenSnapshot, got {:?}", other),
    }

    // Open Stream 1 on resumed connection and continue interactive I/O!
    let (mut pty_send2, mut pty_recv2) = client_conn2.open_bi().await.unwrap();
    pty_send2.write_all(b"Resumed command line\n").await.unwrap();

    let mut rec2 = Vec::new();
    while !rec2.windows(b"Resumed command line".len()).any(|w| w == b"Resumed command line") {
        let n = pty_recv2.read(&mut buf).await.unwrap().unwrap();
        rec2.extend_from_slice(&buf[..n]);
    }
    assert!(String::from_utf8_lossy(&rec2).contains("Resumed command line"));

    // Clean finish
    MorshConnection::send_control_message(
        &mut ctrl_send2,
        &ControlMessage::Disconnect { reason_code: 0, message: "done".into() },
    ).await.unwrap();
    client_conn2.close(0, "done");

    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

#[tokio::test]
async fn test_session_resume_token_mismatch_rejected() {
    use morsh_term::SessionRegistry;

    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let registry = SessionRegistry::new();
    let registry_server = registry.clone();

    let session_id = [55u8; 16];
    let legit_token = [88u8; 16];
    let rogue_token = [99u8; 16];

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await.unwrap();

        let _hello = MorshConnection::read_control_message(&mut ctrl_recv).await.unwrap();
        let s_hello = ControlMessage::ServerHello {
            version: PROTOCOL_VERSION,
            server_software: "morshd-test".into(),
            session_id,
            resumption_token: legit_token,
            supported_auth: vec![AuthMethod::None],
            session_resumed: false,
        };
        MorshConnection::send_control_message(&mut ctrl_send, &s_hello).await.unwrap();

        let mut cfg = PtyConfig::default();
        cfg.command = Some(vec!["/bin/cat".into()]);
        let sess = registry_server
            .create_session(session_id, legit_token, "bob".into(), &cfg)
            .await
            .unwrap();

        let req = MorshConnection::read_control_message(&mut ctrl_recv).await.unwrap();
        if let ControlMessage::SessionResumeRequest { session_id, resumption_token } = req {
            let res = registry_server.resume(&session_id, &resumption_token).await;
            assert!(res.is_err(), "Rogue token must be rejected");

            let err_resp = ControlMessage::SessionResumeResponse {
                success: false,
                session_id,
                resumption_token: [0u8; 16],
                message: "Session authentication token mismatch".into(),
            };
            MorshConnection::send_control_message(&mut ctrl_send, &err_resp).await.unwrap();
        }

        let _ = sess.kill();
        let _ = conn.inner().closed().await;
    });

    let client_conn = client.connect(server_addr, "localhost").await.unwrap();
    let (mut ctrl_send, mut ctrl_recv) = client_conn.open_bi().await.unwrap();

    let c_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "attacker".into(),
        knock_path: None,
        resumption_session_id: Some(session_id),
    };
    MorshConnection::send_control_message(&mut ctrl_send, &c_hello).await.unwrap();
    let _s_hello = MorshConnection::read_control_message(&mut ctrl_recv).await.unwrap();

    // Send ResumeRequest with rogue token
    let req = ControlMessage::SessionResumeRequest {
        session_id,
        resumption_token: rogue_token,
    };
    MorshConnection::send_control_message(&mut ctrl_send, &req).await.unwrap();

    let reply = MorshConnection::read_control_message(&mut ctrl_recv).await.unwrap();
    match reply {
        ControlMessage::SessionResumeResponse { success, message, .. } => {
            assert!(!success, "Resume must fail with invalid token");
            assert!(message.contains("mismatch"));
        }
        other => panic!("Expected SessionResumeResponse, got {:?}", other),
    }

    client_conn.close(1, "rejected");
    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

#[tokio::test]
async fn test_session_list_query() {
    use morsh_term::SessionRegistry;

    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let registry = SessionRegistry::new();
    let registry_server = registry.clone();

    let s1 = [11u8; 16];
    let t1 = [22u8; 16];

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await.unwrap();

        let _hello = MorshConnection::read_control_message(&mut ctrl_recv).await.unwrap();
        let s_hello = ControlMessage::ServerHello {
            version: PROTOCOL_VERSION,
            server_software: "morshd-test".into(),
            session_id: s1,
            resumption_token: t1,
            supported_auth: vec![AuthMethod::None],
            session_resumed: false,
        };
        MorshConnection::send_control_message(&mut ctrl_send, &s_hello).await.unwrap();

        let mut cfg = PtyConfig::default();
        cfg.cols = 100;
        cfg.rows = 35;
        cfg.command = Some(vec!["/bin/cat".into()]);
        let sess = registry_server
            .create_session(s1, t1, "carol".into(), &cfg)
            .await
            .unwrap();

        let req = MorshConnection::read_control_message(&mut ctrl_recv).await.unwrap();
        assert!(matches!(req, ControlMessage::SessionListRequest));

        let sessions = registry_server.list(Some("carol")).await;
        let resp = ControlMessage::SessionListResponse { sessions };
        MorshConnection::send_control_message(&mut ctrl_send, &resp).await.unwrap();

        let _ = sess.kill();
        let _ = conn.inner().closed().await;
    });

    let client_conn = client.connect(server_addr, "localhost").await.unwrap();
    let (mut ctrl_send, mut ctrl_recv) = client_conn.open_bi().await.unwrap();

    let c_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "lister".into(),
        knock_path: None,
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut ctrl_send, &c_hello).await.unwrap();
    let _s_hello = MorshConnection::read_control_message(&mut ctrl_recv).await.unwrap();

    MorshConnection::send_control_message(&mut ctrl_send, &ControlMessage::SessionListRequest).await.unwrap();
    let resp = MorshConnection::read_control_message(&mut ctrl_recv).await.unwrap();

    match resp {
        ControlMessage::SessionListResponse { sessions } => {
            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions[0].session_id, s1);
            assert_eq!(sessions[0].user, "carol");
            assert_eq!(sessions[0].cols, 100);
            assert_eq!(sessions[0].rows, 35);
            assert!(!sessions[0].is_attached);
        }
        other => panic!("Expected SessionListResponse, got {:?}", other),
    }

    client_conn.close(0, "done");
    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

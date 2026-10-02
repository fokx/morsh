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

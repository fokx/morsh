use morsh_core::protocol::{
    AuthMethod, ControlMessage, TunnelStreamPreamble, TunnelType, PROTOCOL_VERSION,
};
use morsh_transport::{
    generate_self_signed_cert, generate_session_id, make_client_config, make_server_config,
    MorshConnection, QuicClient, QuicServer,
};
use morsh_tunnel::{
    bind_remote_forward_server, bridge_tcp_and_quic, decode_udp_datagram,
    request_remote_forward, run_dynamic_socks5, run_local_forward, run_udp_forward,
    setup_server_udp_tunnel, DynamicRule, ForwardRule, TunnelManager, UdpRule,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::timeout;

/// Starts a test QUIC server on an ephemeral UDP port.
fn setup_test_server() -> (QuicServer, SocketAddr) {
    let (certs, key) = generate_self_signed_cert(vec!["localhost".into()]).unwrap();
    let server_config = make_server_config(certs, key).unwrap();
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = QuicServer::bind(bind_addr, server_config).unwrap();
    let local_addr = server.local_addr().unwrap();
    (server, local_addr)
}

/// Starts a test QUIC client with insecure verification.
fn setup_test_client() -> QuicClient {
    let client_config = make_client_config(true).unwrap();
    QuicClient::new(client_config).unwrap()
}

/// Runs a standard TCP echo server on an ephemeral port. Returns (server_task, local_addr).
async fn spawn_tcp_echo_server() -> (tokio::task::JoinHandle<()>, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });

    (task, local_addr)
}

/// Runs a standard UDP echo server on an ephemeral port. Returns (server_task, local_addr).
async fn spawn_udp_echo_server() -> (tokio::task::JoinHandle<()>, SocketAddr) {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let local_addr = socket.local_addr().unwrap();
    let s_clone = Arc::clone(&socket);

    let task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match s_clone.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    let _ = s_clone.send_to(&buf[..n], src).await;
                }
                Err(_) => break,
            }
        }
    });

    (task, local_addr)
}

/// Sets up a live morsh server daemon handler on a connection with tunnel & control loop.
fn spawn_morshd_connection_handler(
    conn: MorshConnection,
    server_manager: TunnelManager,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();

        // 1. Handshake
        let hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
        assert!(matches!(hello, ControlMessage::ClientHello { .. }));

        let server_hello = ControlMessage::ServerHello {
            version: PROTOCOL_VERSION,
            server_software: "morshd-test".into(),
            session_id: generate_session_id(),
            resumption_token: [0u8; 16],
            supported_auth: vec![AuthMethod::None],
            session_resumed: false,
        };
        MorshConnection::send_control_message(&mut send, &server_hello).await.unwrap();

        // 2. Control stream outbound channel
        let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<ControlMessage>(64);
        let mut mgr = server_manager;
        mgr.set_control_sender(ctrl_tx.clone());

        // Stream supervisor for incoming tunnel streams
        let conn_streams = conn.clone();
        let mgr_streams = mgr.clone();
        let stream_task = tokio::spawn(async move {
            while let Ok((stream_send, mut stream_recv)) = conn_streams.accept_bi().await {
                let m = mgr_streams.clone();
                tokio::spawn(async move {
                    let mut preamble_bytes = [0u8; 8];
                    if stream_recv.read_exact(&mut preamble_bytes).await.is_ok() {
                        if let Some(preamble) = TunnelStreamPreamble::from_bytes(&preamble_bytes) {
                            if let Some(tcp_stream) = m.take_server_stream(preamble.tunnel_id).await {
                                bridge_tcp_and_quic(tcp_stream, stream_send, stream_recv).await;
                            }
                        }
                    }
                });
            }
        });

        // Datagram supervisor for UDP tunnels
        let conn_datagram = conn.clone();
        let mgr_datagram = mgr.clone();
        let datagram_task = tokio::spawn(async move {
            while let Ok(data) = conn_datagram.read_datagram().await {
                if let Some((tunnel_id, payload)) = decode_udp_datagram(&data) {
                    if let Some(sock) = mgr_datagram.get_udp_tunnel(tunnel_id).await {
                        if let Some(target) = mgr_datagram.get_udp_target_addr(tunnel_id).await {
                            let _ = sock.send_to(payload, target).await;
                        }
                    }
                }
            }
        });

        // Main control loop
        loop {
            tokio::select! {
                Some(outbound) = ctrl_rx.recv() => {
                    let _ = MorshConnection::send_control_message(&mut send, &outbound).await;
                }
                msg_res = MorshConnection::read_control_message(&mut recv) => {
                    match msg_res {
                        Ok(ControlMessage::Ping { seq, timestamp_ms }) => {
                            let pong = ControlMessage::Pong { seq, echo_timestamp_ms: timestamp_ms };
                            let _ = ctrl_tx.send(pong).await;
                        }
                        Ok(ControlMessage::TunnelOpenRequest { tunnel_id, tunnel_type, host, port }) => {
                            match tunnel_type {
                                TunnelType::LocalTcp | TunnelType::Socks5 => {
                                    let target_addr = format!("{}:{}", host, port);
                                    match TcpStream::connect(&target_addr).await {
                                        Ok(tcp_stream) => {
                                            mgr.register_server_stream(tunnel_id, tcp_stream).await;
                                            let _ = ctrl_tx.send(ControlMessage::TunnelOpenResponse {
                                                tunnel_id,
                                                success: true,
                                                message: "Connected".into(),
                                            }).await;
                                        }
                                        Err(e) => {
                                            let _ = ctrl_tx.send(ControlMessage::TunnelOpenResponse {
                                                tunnel_id,
                                                success: false,
                                                message: e.to_string(),
                                            }).await;
                                        }
                                    }
                                }
                                TunnelType::UdpForward => {
                                    match setup_server_udp_tunnel(tunnel_id, host, port, conn.clone(), mgr.clone()).await {
                                        Ok(()) => {
                                            let _ = ctrl_tx.send(ControlMessage::TunnelOpenResponse {
                                                tunnel_id,
                                                success: true,
                                                message: "UDP bound".into(),
                                            }).await;
                                        }
                                        Err(e) => {
                                            let _ = ctrl_tx.send(ControlMessage::TunnelOpenResponse {
                                                tunnel_id,
                                                success: false,
                                                message: e.to_string(),
                                            }).await;
                                        }
                                    }
                                }
                                TunnelType::RemoteTcp => {}
                            }
                        }
                        Ok(ControlMessage::TunnelOpenResponse { tunnel_id, success, message }) => {
                            mgr.on_tunnel_open_response(tunnel_id, success, message).await;
                        }
                        Ok(ControlMessage::RemoteForwardRequest { bind_addr, bind_port, target_host, target_port }) => {
                            match bind_remote_forward_server(bind_addr, bind_port, target_host, target_port, conn.clone(), mgr.clone()).await {
                                Ok(actual_port) => {
                                    let _ = ctrl_tx.send(ControlMessage::RemoteForwardResponse {
                                        bind_port: actual_port,
                                        success: true,
                                        message: "OK".into(),
                                    }).await;
                                }
                                Err(e) => {
                                    let _ = ctrl_tx.send(ControlMessage::RemoteForwardResponse {
                                        bind_port,
                                        success: false,
                                        message: e.to_string(),
                                    }).await;
                                }
                            }
                        }
                        Ok(ControlMessage::TunnelClose { tunnel_id }) => {
                            mgr.remove_tunnel(tunnel_id).await;
                        }
                        Ok(ControlMessage::Disconnect { .. }) | Err(_) => {
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        stream_task.abort();
        datagram_task.abort();
    })
}

/// Sets up a live morsh client connection handler. Returns (client_manager, last_client_addr, client_task).
async fn setup_client_connection(
    client: &QuicClient,
    server_addr: SocketAddr,
) -> (MorshConnection, TunnelManager, Arc<Mutex<Option<SocketAddr>>>, tokio::task::JoinHandle<()>) {
    let client_conn = client.connect(server_addr, "localhost").await.unwrap();
    let (mut send, mut recv) = client_conn.open_bi().await.unwrap();

    let client_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "morsh-test".into(),
        knock_path: None,
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut send, &client_hello).await.unwrap();

    let server_hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
    assert!(matches!(server_hello, ControlMessage::ServerHello { .. }));

    let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<ControlMessage>(64);
    let client_manager = TunnelManager::new(Some(ctrl_tx.clone()));

    // Outbound control writer
    let mut ctrl_send_half = send;
    tokio::spawn(async move {
        while let Some(msg) = ctrl_rx.recv().await {
            let _ = MorshConnection::send_control_message(&mut ctrl_send_half, &msg).await;
        }
    });

    let last_client_addr = Arc::new(Mutex::new(None));
    let last_client_addr_clone = Arc::clone(&last_client_addr);
    let conn_datagram = client_conn.clone();
    let mgr_udp = client_manager.clone();
    tokio::spawn(async move {
        while let Ok(data) = conn_datagram.read_datagram().await {
            if let Some((tunnel_id, payload)) = decode_udp_datagram(&data) {
                if let Some(sock) = mgr_udp.get_udp_tunnel(tunnel_id).await {
                    if let Some(addr) = *last_client_addr_clone.lock().await {
                        let _ = sock.send_to(payload, addr).await;
                    }
                }
            }
        }
    });

    // Inbound streams from server (for -R remote forward)
    let conn_streams = client_conn.clone();
    let mgr_streams = client_manager.clone();
    tokio::spawn(async move {
        while let Ok((stream_send, mut stream_recv)) = conn_streams.accept_bi().await {
            let m = mgr_streams.clone();
            tokio::spawn(async move {
                let mut preamble_bytes = [0u8; 8];
                if stream_recv.read_exact(&mut preamble_bytes).await.is_ok() {
                    if let Some(preamble) = TunnelStreamPreamble::from_bytes(&preamble_bytes) {
                        if let Some(tcp_stream) = m.take_server_stream(preamble.tunnel_id).await {
                            bridge_tcp_and_quic(tcp_stream, stream_send, stream_recv).await;
                        }
                    }
                }
            });
        }
    });

    // Inbound control reader
    let mgr_inbound = client_manager.clone();
    let ctrl_tx_inbound = ctrl_tx.clone();
    let client_task = tokio::spawn(async move {
        while let Ok(msg) = MorshConnection::read_control_message(&mut recv).await {
            match msg {
                ControlMessage::TunnelOpenResponse { tunnel_id, success, message } => {
                    mgr_inbound.on_tunnel_open_response(tunnel_id, success, message).await;
                }
                ControlMessage::RemoteForwardResponse { bind_port, success, message } => {
                    mgr_inbound.on_remote_forward_response(bind_port, success, message).await;
                }
                ControlMessage::TunnelOpenRequest { tunnel_id, tunnel_type, host, port } => {
                    if tunnel_type == TunnelType::RemoteTcp {
                        let target_addr = format!("{}:{}", host, port);
                        match TcpStream::connect(&target_addr).await {
                            Ok(tcp_stream) => {
                                mgr_inbound.register_server_stream(tunnel_id, tcp_stream).await;
                                let _ = ctrl_tx_inbound.send(ControlMessage::TunnelOpenResponse {
                                    tunnel_id,
                                    success: true,
                                    message: "Connected to local target".into(),
                                }).await;
                            }
                            Err(e) => {
                                let _ = ctrl_tx_inbound.send(ControlMessage::TunnelOpenResponse {
                                    tunnel_id,
                                    success: false,
                                    message: e.to_string(),
                                }).await;
                            }
                        }
                    }
                }
                ControlMessage::TunnelClose { tunnel_id } => {
                    mgr_inbound.remove_tunnel(tunnel_id).await;
                }
                ControlMessage::Disconnect { .. } => break,
                _ => {}
            }
        }
    });

    (client_conn, client_manager, last_client_addr, client_task)
}

#[tokio::test]
async fn test_local_tcp_forwarding() {
    let (echo_task, echo_addr) = spawn_tcp_echo_server().await;
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let server_manager = TunnelManager::default();
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        spawn_morshd_connection_handler(conn, server_manager).await.unwrap();
    });

    let (client_conn, client_manager, _, _client_task) =
        setup_client_connection(&client, server_addr).await;

    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_bind_port = local_listener.local_addr().unwrap().port();
    drop(local_listener); // free port so run_local_forward can bind it

    let local_rule = ForwardRule::new("127.0.0.1", local_bind_port, "127.0.0.1", echo_addr.port());
    let conn_clone = client_conn.clone();
    let mgr_clone = client_manager.clone();
    let fwd_rule = local_rule.clone();
    tokio::spawn(async move {
        run_local_forward(fwd_rule, conn_clone, mgr_clone).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect a TCP client to the local forwarded port
    let mut tcp_client = TcpStream::connect(format!("127.0.0.1:{}", local_bind_port)).await.unwrap();

    let test_msg = b"HELLO_MORSH_LOCAL_FORWARD_TCP\n";
    tcp_client.write_all(test_msg).await.unwrap();

    let mut buf = [0u8; 128];
    let n = tcp_client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], test_msg);

    client_conn.close(0, "done");
    echo_task.abort();
    server_task.abort();
}

#[tokio::test]
async fn test_remote_tcp_forwarding() {
    let (echo_task, echo_addr) = spawn_tcp_echo_server().await;
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let server_manager = TunnelManager::default();
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        spawn_morshd_connection_handler(conn, server_manager).await.unwrap();
    });

    let (client_conn, client_manager, _, _client_task) =
        setup_client_connection(&client, server_addr).await;

    // Pick an ephemeral port for server to bind remotely
    let remote_port_temp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_bind_port = remote_port_temp.local_addr().unwrap().port();
    drop(remote_port_temp);

    // Request Remote Forward (-R): server binds remote_bind_port, forwards to client's echo_addr
    let rule = ForwardRule::new(
        "127.0.0.1",
        remote_bind_port,
        "127.0.0.1",
        echo_addr.port(),
    );

    request_remote_forward(&rule, &client_manager).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect directly to the server's remote-bound port
    let mut remote_client = TcpStream::connect(format!("127.0.0.1:{}", remote_bind_port)).await.unwrap();

    let test_msg = b"HELLO_MORSH_REMOTE_FORWARD_TCP\n";
    remote_client.write_all(test_msg).await.unwrap();

    let mut buf = [0u8; 128];
    let n = remote_client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], test_msg);

    client_conn.close(0, "done");
    echo_task.abort();
    server_task.abort();
}

#[tokio::test]
async fn test_dynamic_socks5_proxy() {
    let (echo_task, echo_addr) = spawn_tcp_echo_server().await;
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let server_manager = TunnelManager::default();
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        spawn_morshd_connection_handler(conn, server_manager).await.unwrap();
    });

    let (client_conn, client_manager, _, _client_task) =
        setup_client_connection(&client, server_addr).await;

    // Find ephemeral port for SOCKS5 proxy
    let socks5_temp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks5_port = socks5_temp.local_addr().unwrap().port();
    drop(socks5_temp);

    let dynamic_rule = DynamicRule::new("127.0.0.1", socks5_port);
    let c = client_conn.clone();
    let tm = client_manager.clone();
    let d_rule = dynamic_rule.clone();
    tokio::spawn(async move {
        run_dynamic_socks5(d_rule, c, tm).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect test client to SOCKS5 proxy port
    let mut socks_client = TcpStream::connect(format!("127.0.0.1:{}", socks5_port)).await.unwrap();

    // 1. SOCKS5 greeting
    socks_client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut rep = [0u8; 2];
    socks_client.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep, [0x05, 0x00]);

    // 2. SOCKS5 CONNECT to 127.0.0.1:echo_port
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    connect_req.extend_from_slice(&echo_addr.port().to_be_bytes());
    socks_client.write_all(&connect_req).await.unwrap();

    let mut connect_rep = [0u8; 10];
    socks_client.read_exact(&mut connect_rep).await.unwrap();
    assert_eq!(connect_rep[0], 0x05);
    assert_eq!(connect_rep[1], 0x00); // SUCCESS

    // 3. Send test data through the SOCKS5 proxy
    let test_msg = b"HELLO_SOCKS5_PROXY_TEST\n";
    socks_client.write_all(test_msg).await.unwrap();

    let mut buf = [0u8; 128];
    let n = socks_client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], test_msg);

    client_conn.close(0, "done");
    echo_task.abort();
    server_task.abort();
}

#[tokio::test]
async fn test_native_udp_forwarding() {
    let (echo_task, echo_addr) = spawn_udp_echo_server().await;
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let server_manager = TunnelManager::default();
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        spawn_morshd_connection_handler(conn, server_manager).await.unwrap();
    });

    let (client_conn, client_manager, last_client_addr, _client_task) =
        setup_client_connection(&client, server_addr).await;

    // Ephemeral port for local UDP listener
    let udp_temp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_udp_port = udp_temp.local_addr().unwrap().port();
    drop(udp_temp);

    let udp_rule = UdpRule::new("127.0.0.1", local_udp_port, "127.0.0.1", echo_addr.port());
    let c = client_conn.clone();
    let tm = client_manager.clone();
    let lca = Arc::clone(&last_client_addr);
    let u_rule = udp_rule.clone();
    tokio::spawn(async move {
        run_udp_forward(u_rule, c, tm, lca).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send UDP packet from an independent test UDP client
    let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let test_packet = b"HELLO_UDP_QUIC_DATAGRAM_TUNNEL";
    udp_client.send_to(test_packet, format!("127.0.0.1:{}", local_udp_port)).await.unwrap();

    let mut buf = [0u8; 256];
    let (n, from_addr) = timeout(Duration::from_secs(3), udp_client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&buf[..n], test_packet);
    assert_eq!(from_addr.port(), local_udp_port);

    client_conn.close(0, "done");
    echo_task.abort();
    server_task.abort();
}

#[tokio::test]
async fn test_no_shell_tunnel_mode() {
    let (echo_task, echo_addr) = spawn_tcp_echo_server().await;
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let server_manager = TunnelManager::default();
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        spawn_morshd_connection_handler(conn, server_manager).await.unwrap();
    });

    let (client_conn, client_manager, _, _client_task) =
        setup_client_connection(&client, server_addr).await;

    // Send NoShell frame over Stream 0
    client_manager.send_control(ControlMessage::NoShell).await.unwrap();

    let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_bind_port = local_listener.local_addr().unwrap().port();
    drop(local_listener);

    let local_rule = ForwardRule::new("127.0.0.1", local_bind_port, "127.0.0.1", echo_addr.port());
    let conn_clone = client_conn.clone();
    let mgr_clone = client_manager.clone();
    let fwd_rule = local_rule.clone();
    tokio::spawn(async move {
        run_local_forward(fwd_rule, conn_clone, mgr_clone).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect to tunnel and verify data exchange
    let mut tcp_client = TcpStream::connect(format!("127.0.0.1:{}", local_bind_port)).await.unwrap();
    let test_msg = b"NO_SHELL_FORWARD_TEST_DATA\n";
    tcp_client.write_all(test_msg).await.unwrap();

    let mut buf = [0u8; 128];
    let n = tcp_client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], test_msg);

    client_conn.close(0, "done");
    echo_task.abort();
    server_task.abort();
}

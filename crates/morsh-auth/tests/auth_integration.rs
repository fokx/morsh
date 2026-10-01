use morsh_auth::{
    generate_challenge, sign_challenge, AuthorizedKeys, MockPasswordVerifier, PasswordVerifier,
};
use morsh_core::protocol::{
    AuthMethod, AuthRequest, ControlMessage, PROTOCOL_VERSION,
};
use morsh_transport::{
    generate_self_signed_cert, generate_session_id, make_client_config, make_server_config,
    MorshConnection, QuicClient, QuicServer,
};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

fn setup_test_server() -> (QuicServer, SocketAddr) {
    let (certs, key) = generate_self_signed_cert(vec!["localhost".into()]).unwrap();
    let server_config = make_server_config(certs, key).unwrap();
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = QuicServer::bind(bind_addr, server_config).unwrap();
    let local_addr = server.local_addr().unwrap();
    (server, local_addr)
}

fn setup_test_client() -> QuicClient {
    let client_config = make_client_config(true).unwrap();
    QuicClient::new(client_config).unwrap()
}

#[tokio::test]
async fn test_ed25519_auth_flow_success() {
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let client_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let client_pk = client_key.public_key();

    let ak_entry = format!("{} test-user\n", client_pk.to_openssh().unwrap());
    let authorized_keys = Arc::new(AuthorizedKeys::parse(&ak_entry).unwrap());

    let ak_server = Arc::clone(&authorized_keys);
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();

        // 1. Recv ClientHello
        let hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
        assert!(matches!(hello, ControlMessage::ClientHello { .. }));

        // 2. Send ServerHello
        let session_id = generate_session_id();
        let server_hello = ControlMessage::ServerHello {
            version: PROTOCOL_VERSION,
            server_software: "morshd-test".into(),
            session_id,
            supported_auth: vec![AuthMethod::PublicKey {
                supported_algorithms: vec!["ssh-ed25519".into()],
            }],
            session_resumed: false,
        };
        MorshConnection::send_control_message(&mut send, &server_hello).await.unwrap();

        // 3. Send AuthChallenge
        let challenge = generate_challenge();
        let challenge_msg = ControlMessage::AuthChallenge { challenge };
        MorshConnection::send_control_message(&mut send, &challenge_msg).await.unwrap();

        // 4. Recv AuthRequest
        let req = MorshConnection::read_control_message(&mut recv).await.unwrap();
        match req {
            ControlMessage::AuthRequest(AuthRequest::PublicKey {
                username,
                algorithm,
                public_key,
                signature,
            }) => {
                let verify_res = ak_server.verify_challenge(
                    &username,
                    &session_id,
                    &challenge,
                    &algorithm,
                    &public_key,
                    &signature,
                );
                assert!(verify_res.is_ok());

                let ok_res = ControlMessage::AuthResult {
                    success: true,
                    message: "Welcome test-user".into(),
                };
                MorshConnection::send_control_message(&mut send, &ok_res).await.unwrap();
            }
            other => panic!("Expected AuthRequest::PublicKey, got {:?}", other),
        }

        // 5. Normal session interaction (Ping / Pong)
        let ping = MorshConnection::read_control_message(&mut recv).await.unwrap();
        if let ControlMessage::Ping { seq, timestamp_ms } = ping {
            let pong = ControlMessage::Pong { seq, echo_timestamp_ms: timestamp_ms };
            MorshConnection::send_control_message(&mut send, &pong).await.unwrap();
        }

        let _ = conn.inner().closed().await;
    });

    let client_conn = client.connect(server_addr, "localhost").await.unwrap();
    let (mut send, mut recv) = client_conn.open_bi().await.unwrap();

    // 1. Send ClientHello
    let client_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "morsh-test".into(),
        knock_path: None,
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut send, &client_hello).await.unwrap();

    // 2. Recv ServerHello
    let s_hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
    let session_id = match s_hello {
        ControlMessage::ServerHello { session_id, .. } => session_id,
        other => panic!("Expected ServerHello, got {:?}", other),
    };

    // 3. Recv AuthChallenge
    let ch_msg = MorshConnection::read_control_message(&mut recv).await.unwrap();
    let challenge = match ch_msg {
        ControlMessage::AuthChallenge { challenge } => challenge,
        other => panic!("Expected AuthChallenge, got {:?}", other),
    };

    // 4. Sign challenge and send AuthRequest
    let username = "test-user";
    let (algorithm, public_key, signature) =
        sign_challenge(&client_key, &session_id, &challenge, username).unwrap();

    let auth_req = ControlMessage::AuthRequest(AuthRequest::PublicKey {
        username: username.into(),
        algorithm,
        public_key,
        signature,
    });
    MorshConnection::send_control_message(&mut send, &auth_req).await.unwrap();

    // 5. Recv AuthResult
    let res_msg = MorshConnection::read_control_message(&mut recv).await.unwrap();
    match res_msg {
        ControlMessage::AuthResult { success, message } => {
            assert!(success);
            assert!(message.contains("Welcome"));
        }
        other => panic!("Expected AuthResult, got {:?}", other),
    }

    // 6. Send Ping to confirm active authenticated session
    let ping = ControlMessage::Ping { seq: 1, timestamp_ms: 500 };
    MorshConnection::send_control_message(&mut send, &ping).await.unwrap();
    let pong = MorshConnection::read_control_message(&mut recv).await.unwrap();
    assert!(matches!(pong, ControlMessage::Pong { seq: 1, .. }));

    client_conn.close(0, "clean shutdown");
    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

#[tokio::test]
async fn test_unauthorized_key_rejected() {
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let authorized_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let rogue_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();

    let ak_entry = format!("{} legit-user\n", authorized_key.public_key().to_openssh().unwrap());
    let authorized_keys = Arc::new(AuthorizedKeys::parse(&ak_entry).unwrap());

    let ak_server = Arc::clone(&authorized_keys);
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();

        let _ = MorshConnection::read_control_message(&mut recv).await.unwrap();
        let session_id = generate_session_id();
        let s_hello = ControlMessage::ServerHello {
            version: PROTOCOL_VERSION,
            server_software: "morshd-test".into(),
            session_id,
            supported_auth: vec![AuthMethod::PublicKey { supported_algorithms: vec![] }],
            session_resumed: false,
        };
        MorshConnection::send_control_message(&mut send, &s_hello).await.unwrap();

        let challenge = generate_challenge();
        MorshConnection::send_control_message(&mut send, &ControlMessage::AuthChallenge { challenge }).await.unwrap();

        let req = MorshConnection::read_control_message(&mut recv).await.unwrap();
        if let ControlMessage::AuthRequest(AuthRequest::PublicKey { username, algorithm, public_key, signature }) = req {
            let verify_res = ak_server.verify_challenge(&username, &session_id, &challenge, &algorithm, &public_key, &signature);
            assert!(verify_res.is_err(), "Rogue key must not verify against authorized_keys");

            let err_res = ControlMessage::AuthResult {
                success: false,
                message: "Unauthorized key".into(),
            };
            MorshConnection::send_control_message(&mut send, &err_res).await.unwrap();
            let _ = send.finish();
            tokio::time::sleep(Duration::from_millis(50)).await;
            conn.close(401, "Authentication failed");
        }

    });

    let client_conn = client.connect(server_addr, "localhost").await.unwrap();
    let (mut send, mut recv) = client_conn.open_bi().await.unwrap();

    let c_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "morsh-attacker".into(),
        knock_path: None,
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut send, &c_hello).await.unwrap();

    let s_hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
    let session_id = match s_hello {
        ControlMessage::ServerHello { session_id, .. } => session_id,
        _ => panic!(),
    };

    let ch_msg = MorshConnection::read_control_message(&mut recv).await.unwrap();
    let challenge = match ch_msg {
        ControlMessage::AuthChallenge { challenge } => challenge,
        _ => panic!(),
    };

    // Sign with rogue key
    let (algorithm, public_key, signature) =
        sign_challenge(&rogue_key, &session_id, &challenge, "legit-user").unwrap();

    let auth_req = ControlMessage::AuthRequest(AuthRequest::PublicKey {
        username: "legit-user".into(),
        algorithm,
        public_key,
        signature,
    });
    MorshConnection::send_control_message(&mut send, &auth_req).await.unwrap();

    let res_msg = MorshConnection::read_control_message(&mut recv).await;
    match res_msg {
        Ok(ControlMessage::AuthResult { success, message }) => {
            assert!(!success);
            assert!(message.contains("Unauthorized"));
        }
        Err(e) => {
            let s = e.to_string();
            assert!(s.contains("401") || s.contains("Authentication failed"));
        }
        other => panic!("Expected AuthResult, got {:?}", other),
    }


    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

#[tokio::test]
async fn test_password_auth_flow() {
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();

    let verifier = Arc::new(MockPasswordVerifier::new());
    verifier.add_user("admin", "correct-horse-battery-staple");

    let verifier_clone = Arc::clone(&verifier);
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();

        let _ = MorshConnection::read_control_message(&mut recv).await.unwrap();
        let session_id = generate_session_id();
        let s_hello = ControlMessage::ServerHello {
            version: PROTOCOL_VERSION,
            server_software: "morshd-test".into(),
            session_id,
            supported_auth: vec![AuthMethod::Password],
            session_resumed: false,
        };
        MorshConnection::send_control_message(&mut send, &s_hello).await.unwrap();

        let challenge = generate_challenge();
        MorshConnection::send_control_message(&mut send, &ControlMessage::AuthChallenge { challenge }).await.unwrap();

        let req = MorshConnection::read_control_message(&mut recv).await.unwrap();
        if let ControlMessage::AuthRequest(AuthRequest::Password { username, password }) = req {
            let pw_str = String::from_utf8(password).unwrap();
            let ok = verifier_clone.verify_password(&username, &pw_str).unwrap();

            let res = ControlMessage::AuthResult {
                success: ok,
                message: if ok { "Password OK".into() } else { "Password Failed".into() },
            };
            MorshConnection::send_control_message(&mut send, &res).await.unwrap();
        }
        let _ = conn.inner().closed().await;
    });

    let client_conn = client.connect(server_addr, "localhost").await.unwrap();
    let (mut send, mut recv) = client_conn.open_bi().await.unwrap();

    let c_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "morsh".into(),
        knock_path: None,
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut send, &c_hello).await.unwrap();
    let _s_hello = MorshConnection::read_control_message(&mut recv).await.unwrap();
    let _ch = MorshConnection::read_control_message(&mut recv).await.unwrap();

    // Send valid password
    let auth_req = ControlMessage::AuthRequest(AuthRequest::Password {
        username: "admin".into(),
        password: b"correct-horse-battery-staple".to_vec(),
    });
    MorshConnection::send_control_message(&mut send, &auth_req).await.unwrap();

    let result = MorshConnection::read_control_message(&mut recv).await.unwrap();
    match result {
        ControlMessage::AuthResult { success, message } => {
            assert!(success);
            assert_eq!(message, "Password OK");
        }
        other => panic!("Expected AuthResult, got {:?}", other),
    }

    client_conn.close(0, "done");
    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

#[tokio::test]
async fn test_stealth_knock_with_public_key_auth() {
    let (server, server_addr) = setup_test_server();
    let client = setup_test_client();
    let expected_knock = "/custom-stealth-subpath-42";

    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let ak_entry = format!("{} stealth-agent\n", key.public_key().to_openssh().unwrap());
    let authorized_keys = Arc::new(AuthorizedKeys::parse(&ak_entry).unwrap());

    let ak_server = Arc::clone(&authorized_keys);
    let server_task = tokio::spawn(async move {
        // Handle connection 1: unauthorized stealth probe -> rejected before auth
        let conn1 = server.accept().await.unwrap().unwrap();
        let (_send1, mut recv1) = conn1.accept_bi().await.unwrap();
        let hello1 = MorshConnection::read_control_message(&mut recv1).await.unwrap();
        if let ControlMessage::ClientHello { knock_path, .. } = hello1 {
            if knock_path.as_deref() != Some(expected_knock) {
                conn1.close(404, "Not Found");
            }
        }

        // Handle connection 2: authorized knock -> proceeds to public key auth
        let conn2 = server.accept().await.unwrap().unwrap();
        let (mut send2, mut recv2) = conn2.accept_bi().await.unwrap();
        let hello2 = MorshConnection::read_control_message(&mut recv2).await.unwrap();
        if let ControlMessage::ClientHello { knock_path, .. } = hello2 {
            assert_eq!(knock_path.as_deref(), Some(expected_knock));
            let session_id = generate_session_id();
            let s_hello = ControlMessage::ServerHello {
                version: PROTOCOL_VERSION,
                server_software: "morshd".into(),
                session_id,
                supported_auth: vec![AuthMethod::PublicKey { supported_algorithms: vec![] }],
                session_resumed: false,
            };
            MorshConnection::send_control_message(&mut send2, &s_hello).await.unwrap();

            let challenge = generate_challenge();
            MorshConnection::send_control_message(&mut send2, &ControlMessage::AuthChallenge { challenge }).await.unwrap();

            let req = MorshConnection::read_control_message(&mut recv2).await.unwrap();
            if let ControlMessage::AuthRequest(AuthRequest::PublicKey { username, algorithm, public_key, signature }) = req {
                ak_server.verify_challenge(&username, &session_id, &challenge, &algorithm, &public_key, &signature).unwrap();
                let ok = ControlMessage::AuthResult { success: true, message: "Welcome stealth user".into() };
                MorshConnection::send_control_message(&mut send2, &ok).await.unwrap();
            }
        }
        let _ = conn2.inner().closed().await;
    });

    // 1. Send with invalid knock
    let conn_unauth = client.connect(server_addr, "localhost").await.unwrap();
    let (mut send_unauth, mut recv_unauth) = conn_unauth.open_bi().await.unwrap();
    let bad_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "scanner".into(),
        knock_path: Some("/random-path".into()),
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut send_unauth, &bad_hello).await.unwrap();
    assert!(MorshConnection::read_control_message(&mut recv_unauth).await.is_err());

    // 2. Send with valid knock + public key auth
    let conn_auth = client.connect(server_addr, "localhost").await.unwrap();
    let (mut send_auth, mut recv_auth) = conn_auth.open_bi().await.unwrap();
    let good_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: "morsh".into(),
        knock_path: Some(expected_knock.into()),
        resumption_session_id: None,
    };
    MorshConnection::send_control_message(&mut send_auth, &good_hello).await.unwrap();
    let s_hello = MorshConnection::read_control_message(&mut recv_auth).await.unwrap();
    let session_id = match s_hello {
        ControlMessage::ServerHello { session_id, .. } => session_id,
        _ => panic!(),
    };

    let ch_msg = MorshConnection::read_control_message(&mut recv_auth).await.unwrap();
    let challenge = match ch_msg {
        ControlMessage::AuthChallenge { challenge } => challenge,
        _ => panic!(),
    };

    let (alg, pk, sig) = sign_challenge(&key, &session_id, &challenge, "stealth-agent").unwrap();
    let auth_req = ControlMessage::AuthRequest(AuthRequest::PublicKey {
        username: "stealth-agent".into(),
        algorithm: alg,
        public_key: pk,
        signature: sig,
    });
    MorshConnection::send_control_message(&mut send_auth, &auth_req).await.unwrap();

    let res = MorshConnection::read_control_message(&mut recv_auth).await.unwrap();
    match res {
        ControlMessage::AuthResult { success, message } => {
            assert!(success);
            assert!(message.contains("stealth"));
        }
        _ => panic!(),
    }

    conn_auth.close(0, "done");
    timeout(Duration::from_secs(5), server_task).await.unwrap().unwrap();
}

pub mod client;
pub mod connection;
pub mod server;
pub mod tls;

pub use client::QuicClient;
pub use connection::{generate_session_id, MorshConnection};
pub use server::QuicServer;
pub use tls::{
    cert_fingerprint_sha256, generate_self_signed_cert, make_client_config, make_server_config,
    SkipServerVerification,
};

#[cfg(test)]
mod tests {
    use super::*;
    use morsh_core::protocol::ControlMessage;
    use std::net::SocketAddr;

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
}

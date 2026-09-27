use anyhow::{Context, Result};
use clap::Parser;
use morsh_core::protocol::{AuthMethod, ControlMessage, PROTOCOL_VERSION};
use morsh_transport::{
    cert_fingerprint_sha256, generate_self_signed_cert, generate_session_id, make_server_config,
    MorshConnection, QuicServer,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "morshd",
    version = "0.1.0",
    about = "morshd - Next-generation resilient QUIC SSH daemon (combining Mosh & SSH3)"
)]
struct Args {
    /// Socket address to listen on for incoming UDP/QUIC traffic
    #[arg(short, long, default_value = "0.0.0.0:2222")]
    listen: String,

    /// Optional path to TLS certificate chain in PEM format
    #[arg(short = 'c', long)]
    cert: Option<PathBuf>,

    /// Optional path to TLS private key in PEM format (PKCS#8)
    #[arg(short = 'k', long)]
    key: Option<PathBuf>,

    /// Optional stealth knock path prefix (SSH3 style anti-scanning defense)
    #[arg(long)]
    stealth_knock: Option<String>,

    /// Enable verbose debug logging
    #[arg(short, long)]
    verbose: bool,
}

fn load_certs_and_key(
    cert_path: Option<&PathBuf>,
    key_path: Option<&PathBuf>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    if let (Some(cp), Some(kp)) = (cert_path, key_path) {
        let cert_file = File::open(cp).with_context(|| format!("Failed to open cert file {:?}", cp))?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("Failed to parse TLS certificates")?;

        let key_file = File::open(kp).with_context(|| format!("Failed to open key file {:?}", kp))?;
        let mut key_reader = BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)
            .context("Failed to parse TLS private key")?
            .context("No private key found in key file")?;

        Ok((certs, key))
    } else {
        info!("No certificate supplied; generating ephemeral self-signed host certificate");
        generate_self_signed_cert(vec!["localhost".to_string(), "0.0.0.0".to_string()])
    }
}

async fn handle_connection(
    conn: MorshConnection,
    stealth_knock: Option<String>,
) -> Result<()> {
    let peer_addr = conn.remote_address();
    info!(peer = %peer_addr, "Handling new client connection");

    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .context("Failed to accept control bidirectional stream")?;

    let hello_msg = MorshConnection::read_control_message(&mut recv)
        .await
        .context("Failed to read ClientHello")?;

    let client_name = match hello_msg {
        ControlMessage::ClientHello {
            version,
            client_software,
            knock_path,
            resumption_session_id,
        } => {
            if version != PROTOCOL_VERSION {
                warn!(
                    peer = %peer_addr,
                    client_version = version,
                    expected = PROTOCOL_VERSION,
                    "Incompatible protocol version"
                );
                let err_reply = ControlMessage::Disconnect {
                    reason_code: 1,
                    message: format!("Version mismatch: server speaks v{}", PROTOCOL_VERSION),
                };
                let _ = MorshConnection::send_control_message(&mut send, &err_reply).await;
                conn.close(1, "Incompatible protocol version");
                return Ok(());
            }

            // SSH3-style stealth check
            if let Some(expected_knock) = &stealth_knock {
                let knock_matches = knock_path.as_ref() == Some(expected_knock);
                if !knock_matches {
                    warn!(
                        peer = %peer_addr,
                        provided = ?knock_path,
                        "Stealth knock verification failed; closing connection silently"
                    );
                    conn.close(404, "Not Found");
                    return Ok(());
                }
                info!(peer = %peer_addr, "Stealth knock verified successfully");
            }

            debug!(
                peer = %peer_addr,
                client = %client_software,
                resumption = ?resumption_session_id,
                "Received valid ClientHello"
            );
            client_software
        }
        other => {
            warn!(peer = %peer_addr, msg = ?other, "Expected ClientHello frame first");
            conn.close(2, "Invalid handshake message");
            return Ok(());
        }
    };

    let session_id = generate_session_id();
    let session_hex = hex_encode(&session_id);

    info!(
        peer = %peer_addr,
        client = %client_name,
        session = %session_hex,
        "Established morsh session"
    );

    let server_hello = ControlMessage::ServerHello {
        version: PROTOCOL_VERSION,
        server_software: format!("morshd-{}", env!("CARGO_PKG_VERSION")),
        session_id,
        supported_auth: vec![AuthMethod::None],
        session_resumed: false,
    };

    MorshConnection::send_control_message(&mut send, &server_hello)
        .await
        .context("Failed to send ServerHello")?;

    // Control stream loop: handle heartbeats and control commands
    loop {
        tokio::select! {
            msg_res = MorshConnection::read_control_message(&mut recv) => {
                match msg_res {
                    Ok(ControlMessage::Ping { seq, timestamp_ms }) => {
                        debug!(peer = %peer_addr, seq, "Received ping; responding with pong");
                        let pong = ControlMessage::Pong { seq, echo_timestamp_ms: timestamp_ms };
                        if let Err(e) = MorshConnection::send_control_message(&mut send, &pong).await {
                            warn!(peer = %peer_addr, error = %e, "Failed to send pong");
                            break;
                        }
                    }
                    Ok(ControlMessage::Disconnect { reason_code, message }) => {
                        info!(
                            peer = %peer_addr,
                            code = reason_code,
                            message = %message,
                            "Client initiated graceful disconnect"
                        );
                        break;
                    }
                    Ok(other) => {
                        debug!(peer = %peer_addr, msg = ?other, "Received control message");
                    }
                    Err(e) => {
                        debug!(peer = %peer_addr, error = %e, "Control stream finished or disconnected");
                        break;
                    }
                }
            }
        }
    }

    let _ = send.finish();
    info!(peer = %peer_addr, session = %session_hex, "Session terminated");
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = if args.verbose {
        EnvFilter::new("morsh=debug,morshd=debug,morsh_transport=debug,quinn=info")
    } else {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("morshd=info,morsh_transport=info"))
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    info!("=== morshd v{} ===", env!("CARGO_PKG_VERSION"));

    let (certs, key) = load_certs_and_key(args.cert.as_ref(), args.key.as_ref())?;

    if let Some(first_cert) = certs.first() {
        let fingerprint = cert_fingerprint_sha256(first_cert);
        info!("Host Key Fingerprint (SHA-256): {}", fingerprint);
    }

    let server_config = make_server_config(certs, key)
        .context("Failed to construct server transport configuration")?;

    let listen_addr: SocketAddr = args
        .listen
        .parse()
        .with_context(|| format!("Invalid listen address: {}", args.listen))?;

    let server = QuicServer::bind(listen_addr, server_config)
        .context("Failed to start QUIC server listener")?;

    let local_addr = server.local_addr()?;
    info!("morshd listening on quic://{}", local_addr);
    if let Some(ref knock) = args.stealth_knock {
        info!("Stealth knock enabled: requires path '{}'", knock);
    }

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C received; shutting down morshd gracefully");
                server.close(0, b"daemon shutdown");
                break;
            }
            conn_res = server.accept() => {
                match conn_res {
                    Some(Ok(conn)) => {
                        let knock = args.stealth_knock.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(conn, knock).await {
                                error!("Connection handler error: {:#}", e);
                            }
                        });
                    }
                    Some(Err(e)) => {
                        warn!("Error accepting QUIC connection: {:#}", e);
                    }
                    None => {
                        info!("Server endpoint closed");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

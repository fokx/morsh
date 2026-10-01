use anyhow::{Context, Result};
use clap::Parser;
use morsh_auth::{generate_challenge, AuthorizedKeys, PamAuthenticator, PasswordVerifier};
use morsh_core::protocol::{AuthMethod, AuthRequest, ControlMessage, PROTOCOL_VERSION};
use morsh_transport::{
    cert_fingerprint_sha256, generate_self_signed_cert, generate_session_id, make_server_config,
    MorshConnection, QuicServer,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug, Clone)]
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

    /// Optional explicit path to authorized_keys file (defaults to ~/.ssh/authorized_keys per user)
    #[arg(long)]
    auth_keys: Option<PathBuf>,

    /// Allow Linux PAM / password authentication
    #[arg(long)]
    allow_password: bool,

    /// PAM service name to use for password authentication
    #[arg(long, default_value = "morsh")]
    pam_service: String,

    /// Permit unauthenticated connections (testing / development only)
    #[arg(long)]
    no_auth: bool,

    /// Enable verbose debug logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Clone)]
struct ServerAuthOptions {
    stealth_knock: Option<String>,
    auth_keys: Option<PathBuf>,
    allow_password: bool,
    pam_service: String,
    no_auth: bool,
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
    opts: Arc<ServerAuthOptions>,
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
            if let Some(ref expected_knock) = opts.stealth_knock {
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
        "Established morsh connection session"
    );

    // Determine supported auth methods
    let mut supported_auth = Vec::new();
    if opts.no_auth {
        supported_auth.push(AuthMethod::None);
    } else {
        supported_auth.push(AuthMethod::PublicKey {
            supported_algorithms: vec![
                "ssh-ed25519".into(),
                "ecdsa-sha2-nistp256".into(),
                "rsa-sha2-512".into(),
                "rsa-sha2-256".into(),
            ],
        });
        if opts.allow_password {
            supported_auth.push(AuthMethod::Password);
        }
    }

    let server_hello = ControlMessage::ServerHello {
        version: PROTOCOL_VERSION,
        server_software: format!("morshd-{}", env!("CARGO_PKG_VERSION")),
        session_id,
        supported_auth: supported_auth.clone(),
        session_resumed: false,
    };

    MorshConnection::send_control_message(&mut send, &server_hello)
        .await
        .context("Failed to send ServerHello")?;

    // Phase 2: Authentication Step
    let authenticated_user = if opts.no_auth {
        debug!(peer = %peer_addr, "Server running with --no-auth; skipping credential verification");
        "unauthenticated".to_string()
    } else {
        let challenge = generate_challenge();
        debug!(peer = %peer_addr, "Issuing 32-byte authentication challenge");
        MorshConnection::send_control_message(&mut send, &ControlMessage::AuthChallenge { challenge })
            .await
            .context("Failed to send AuthChallenge")?;

        let auth_msg = MorshConnection::read_control_message(&mut recv)
            .await
            .context("Failed to read AuthRequest from client")?;

        match auth_msg {
            ControlMessage::AuthRequest(AuthRequest::PublicKey {
                username,
                algorithm,
                public_key,
                signature,
            }) => {
                debug!(peer = %peer_addr, username = %username, algorithm = %algorithm, "Verifying public key authentication");

                let ak_res = if let Some(ref ak_path) = opts.auth_keys {
                    AuthorizedKeys::from_file(ak_path)
                } else {
                    AuthorizedKeys::for_user(&username)
                };

                let ak = match ak_res {
                    Ok(k) => k,
                    Err(e) => {
                        warn!(peer = %peer_addr, username = %username, error = %e, "Could not load authorized_keys");
                        let err_res = ControlMessage::AuthResult {
                            success: false,
                            message: format!("Could not load authorized keys: {}", e),
                        };
                        let _ = MorshConnection::send_control_message(&mut send, &err_res).await;
                        let _ = send.finish();
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        conn.close(401, "Authentication failed");
                        return Ok(());
                    }
                };

                match ak.verify_challenge(
                    &username,
                    &session_id,
                    &challenge,
                    &algorithm,
                    &public_key,
                    &signature,
                ) {
                    Ok(()) => {
                        info!(peer = %peer_addr, username = %username, "Public key authentication successful");
                        let ok_res = ControlMessage::AuthResult {
                            success: true,
                            message: format!("Authenticated as user '{}'", username),
                        };
                        MorshConnection::send_control_message(&mut send, &ok_res).await?;
                        username
                    }
                    Err(e) => {
                        warn!(peer = %peer_addr, username = %username, error = %e, "Public key verification rejected");
                        let err_res = ControlMessage::AuthResult {
                            success: false,
                            message: format!("Public key authentication failed: {}", e),
                        };
                        let _ = MorshConnection::send_control_message(&mut send, &err_res).await;
                        let _ = send.finish();
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        conn.close(401, "Authentication failed");
                        return Ok(());
                    }
                }
            }

            ControlMessage::AuthRequest(AuthRequest::Password { username, password }) => {
                if !opts.allow_password {
                    warn!(peer = %peer_addr, username = %username, "Password authentication rejected: disabled on server");
                    let err_res = ControlMessage::AuthResult {
                        success: false,
                        message: "Password authentication is disabled on this server".into(),
                    };
                    let _ = MorshConnection::send_control_message(&mut send, &err_res).await;
                    let _ = send.finish();
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    conn.close(401, "Password auth disabled");
                    return Ok(());
                }

                let pw_str = match String::from_utf8(password) {
                    Ok(s) => s,
                    Err(_) => {
                        let err_res = ControlMessage::AuthResult {
                            success: false,
                            message: "Password contains invalid UTF-8 bytes".into(),
                        };
                        let _ = MorshConnection::send_control_message(&mut send, &err_res).await;
                        let _ = send.finish();
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        conn.close(401, "Invalid password encoding");
                        return Ok(());
                    }
                };

                let pam = PamAuthenticator::new(&opts.pam_service);
                match pam.verify_password(&username, &pw_str) {
                    Ok(true) => {
                        info!(peer = %peer_addr, username = %username, "PAM password authentication successful");
                        let ok_res = ControlMessage::AuthResult {
                            success: true,
                            message: format!("Authenticated as user '{}'", username),
                        };
                        MorshConnection::send_control_message(&mut send, &ok_res).await?;
                        username
                    }
                    Ok(false) | Err(_) => {
                        warn!(peer = %peer_addr, username = %username, "PAM password authentication failed");
                        let err_res = ControlMessage::AuthResult {
                            success: false,
                            message: "Invalid username or password".into(),
                        };
                        let _ = MorshConnection::send_control_message(&mut send, &err_res).await;
                        let _ = send.finish();
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        conn.close(401, "Authentication failed");
                        return Ok(());
                    }
                }
            }

            ControlMessage::AuthRequest(AuthRequest::None { username: _ }) => {
                warn!(peer = %peer_addr, "Unauthenticated login attempted when authentication is required");
                let err_res = ControlMessage::AuthResult {
                    success: false,
                    message: "Server requires authentication".into(),
                };
                let _ = MorshConnection::send_control_message(&mut send, &err_res).await;
                let _ = send.finish();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                conn.close(401, "Authentication required");
                return Ok(());
            }


            other => {
                warn!(peer = %peer_addr, msg = ?other, "Expected AuthRequest frame");
                conn.close(2, "Invalid authentication frame");
                return Ok(());
            }
        }
    };

    info!(
        peer = %peer_addr,
        user = %authenticated_user,
        session = %session_hex,
        "User session authorized; entering control loop"
    );

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
    info!(peer = %peer_addr, session = %session_hex, user = %authenticated_user, "Session terminated");
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = if args.verbose {
        EnvFilter::new("morsh=debug,morshd=debug,morsh_transport=debug,morsh_auth=debug,quinn=info")
    } else {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("morshd=info,morsh_transport=info,morsh_auth=info"))
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
    if args.no_auth {
        warn!("SECURITY NOTICE: morshd running with --no-auth (unauthenticated login permitted)");
    } else {
        info!("Authentication required: SSH public keys accepted (Ed25519, RSA, ECDSA)");
        if args.allow_password {
            info!("Password / PAM authentication enabled (service: '{}')", args.pam_service);
        }
        if let Some(ref ak) = args.auth_keys {
            info!("Authorized keys file override: {}", ak.display());
        }
    }

    let auth_opts = Arc::new(ServerAuthOptions {
        stealth_knock: args.stealth_knock.clone(),
        auth_keys: args.auth_keys.clone(),
        allow_password: args.allow_password,
        pam_service: args.pam_service.clone(),
        no_auth: args.no_auth,
    });

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
                        let opts = Arc::clone(&auth_opts);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(conn, opts).await {
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

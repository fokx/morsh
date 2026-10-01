use anyhow::{bail, Context, Result};
use clap::Parser;
use morsh_auth::{
    find_first_default_private_key, load_private_key_file, sign_challenge, AgentClient,
};
use morsh_core::protocol::{AuthMethod, AuthRequest, ControlMessage, PROTOCOL_VERSION};
use morsh_transport::{make_client_config, MorshConnection, QuicClient};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;


#[derive(Parser, Debug)]
#[command(
    name = "morsh",
    version = "0.1.0",
    about = "morsh - Next-generation resilient QUIC SSH client (combining Mosh & SSH3)"
)]
struct Args {
    /// Remote destination in format [user@]host[:port]
    #[arg(value_name = "DESTINATION")]
    destination: String,

    /// Override remote port (defaults to 2222 or port from destination)
    #[arg(short = 'p', long)]
    port: Option<u16>,

    /// Path to SSH private key file (e.g. ~/.ssh/id_ed25519)
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// Password for password / PAM authentication
    #[arg(long)]
    password: Option<String>,

    /// Disable querying local ssh-agent ($SSH_AUTH_SOCK)
    #[arg(long)]
    no_agent: bool,

    /// Accept any server certificate without validation (insecure / testing mode)
    #[arg(short = 'k', long)]
    insecure: bool,

    /// TLS Server Name Indication (SNI) override
    #[arg(short = 's', long)]
    server_name: Option<String>,

    /// Optional stealth knock path prefix (SSH3 style anti-scanning defense)
    #[arg(long)]
    stealth_knock: Option<String>,

    /// Send N ping packets to measure round-trip latency over QUIC
    #[arg(long, default_value = "3")]
    ping: u64,

    /// Enable verbose debug logging
    #[arg(short, long)]
    verbose: bool,
}

struct ParsedDestination {
    user: Option<String>,
    host: String,
    port: u16,
}

fn parse_destination(dest: &str, port_override: Option<u16>) -> Result<ParsedDestination> {
    let (user, remainder) = if let Some(idx) = dest.find('@') {
        (Some(dest[..idx].to_string()), &dest[idx + 1..])
    } else {
        (None, dest)
    };

    let (host, port) = if remainder.starts_with('[') {
        // IPv6 address syntax [::1]:port
        if let Some(close_bracket) = remainder.find(']') {
            let host_part = &remainder[1..close_bracket];
            let rest = &remainder[close_bracket + 1..];
            let port_part = if let Some(stripped) = rest.strip_prefix(':') {
                stripped.parse::<u16>().context("Invalid IPv6 port")?
            } else {
                port_override.unwrap_or(2222)
            };
            (host_part.to_string(), port_part)
        } else {
            bail!("Mismatched IPv6 brackets in destination: {}", remainder);
        }
    } else if let Some(idx) = remainder.rfind(':') {
        let host_part = &remainder[..idx];
        let port_part = remainder[idx + 1..]
            .parse::<u16>()
            .context("Invalid port in destination")?;
        (host_part.to_string(), port_override.unwrap_or(port_part))
    } else {
        (remainder.to_string(), port_override.unwrap_or(2222))
    };

    if host.is_empty() {
        bail!("Host cannot be empty in destination: {}", dest);
    }

    Ok(ParsedDestination { user, host, port })
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = if args.verbose {
        EnvFilter::new("morsh=debug,morsh_transport=debug,morsh_auth=debug,quinn=info")
    } else {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("morsh=info,morsh_transport=info,morsh_auth=info"))
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let parsed = parse_destination(&args.destination, args.port)?;
    let target = format!("{}:{}", parsed.host, parsed.port);
    let sni_name = args.server_name.unwrap_or_else(|| parsed.host.clone());

    info!(
        destination = %target,
        user = ?parsed.user,
        sni = %sni_name,
        "Resolving server address"
    );

    let mut addrs = tokio::net::lookup_host(&target)
        .await
        .with_context(|| format!("Failed to resolve destination '{}'", target))?;

    let remote_addr: SocketAddr = addrs
        .next()
        .with_context(|| format!("Could not find any IP address for '{}'", target))?;

    info!(remote_addr = %remote_addr, "Connecting via QUIC (TLS 1.3)...");

    let client_config = make_client_config(args.insecure)
        .context("Failed to initialize QUIC client transport configuration")?;

    let client = QuicClient::new(client_config)
        .context("Failed to bind client endpoint")?;

    let conn_start = Instant::now();
    let conn = client
        .connect(remote_addr, &sni_name)
        .await
        .context("Failed to establish QUIC connection with morsh server")?;
    let conn_elapsed = conn_start.elapsed();

    info!(
        remote = %conn.remote_address(),
        handshake_time_ms = conn_elapsed.as_millis(),
        initial_rtt_ms = conn.rtt().as_millis(),
        "QUIC handshake successful"
    );

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open control bidirectional stream")?;

    // Send ClientHello
    let client_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: format!("morsh-{}", env!("CARGO_PKG_VERSION")),
        knock_path: args.stealth_knock.clone(),
        resumption_session_id: None,
    };

    debug!("Sending ClientHello frame");
    MorshConnection::send_control_message(&mut send, &client_hello).await?;

    debug!("Waiting for ServerHello frame");
    let server_hello = MorshConnection::read_control_message(&mut recv)
        .await
        .context("Failed to receive ServerHello response")?;

    let (session_id, supported_auth) = match server_hello {
        ControlMessage::ServerHello {
            version,
            server_software,
            session_id,
            supported_auth,
            session_resumed,
        } => {
            println!("========================================================");
            println!(" Connected to morshd server!");
            println!("   Server Software : {}", server_software);
            println!("   Protocol Version: v{}", version);
            println!("   Session ID      : {}", hex_encode(&session_id));
            println!("   Session Resumed : {}", session_resumed);
            println!("   Auth Supported  : {:?}", supported_auth);
            println!("   Round-Trip Time : {:.2} ms", conn.rtt().as_secs_f64() * 1000.0);
            println!("========================================================");
            (session_id, supported_auth)
        }
        ControlMessage::Disconnect { reason_code, message } => {
            eprintln!("Server disconnected during handshake (code {}): {}", reason_code, message);
            conn.close(reason_code, &message);
            bail!("Connection rejected by server: {}", message);
        }
        other => {
            bail!("Unexpected response from server: {:?}", other);
        }
    };

    // Phase 2: Perform Authentication if required by server
    let requires_auth = !(supported_auth.len() == 1 && supported_auth[0] == AuthMethod::None
        && args.identity.is_none() && args.password.is_none());

    if requires_auth {
        debug!("Waiting for AuthChallenge frame from server...");
        let challenge_msg = MorshConnection::read_control_message(&mut recv)
            .await
            .context("Failed to receive AuthChallenge from server")?;

        let challenge = match challenge_msg {
            ControlMessage::AuthChallenge { challenge } => challenge,
            ControlMessage::Disconnect { reason_code, message } => {
                bail!("Server disconnected before auth challenge (code {}): {}", reason_code, message);
            }
            other => bail!("Expected AuthChallenge, got {:?}", other),
        };

        let username = parsed.user.clone().unwrap_or_else(|| {
            std::env::var("USER").unwrap_or_else(|_| "root".into())
        });

        info!(username = %username, "Authenticating with server...");

        // Select credentials
        let auth_req = if let Some(ref key_path) = args.identity {
            info!(path = %key_path.display(), "Using specified SSH private key");
            let sk = load_private_key_file(key_path, None)?;
            let (algorithm, public_key, signature) =
                sign_challenge(&sk, &session_id, &challenge, &username)?;
            AuthRequest::PublicKey { username, algorithm, public_key, signature }
        } else if !args.no_agent && AgentClient::is_available() {
            info!("Querying ssh-agent for credentials...");
            match AgentClient::connect_env() {
                Ok(mut agent) => {
                    let identities = agent.list_identities()?;
                    if let Some(first_id) = identities.first() {
                        info!(key = %first_id.to_openssh().unwrap_or_default(), "Signing challenge with ssh-agent identity");
                        let (algorithm, public_key, signature) =
                            agent.sign_challenge(first_id, &session_id, &challenge, &username)?;
                        AuthRequest::PublicKey { username, algorithm, public_key, signature }
                    } else if let Some(def_key) = find_first_default_private_key() {
                        info!(path = %def_key.display(), "ssh-agent has no identities; using default SSH private key");
                        let sk = load_private_key_file(&def_key, None)?;
                        let (algorithm, public_key, signature) =
                            sign_challenge(&sk, &session_id, &challenge, &username)?;
                        AuthRequest::PublicKey { username, algorithm, public_key, signature }
                    } else if let Some(ref pw) = args.password {
                        AuthRequest::Password { username, password: pw.as_bytes().to_vec() }
                    } else if supported_auth.contains(&AuthMethod::None) {
                        AuthRequest::None { username }
                    } else {
                        bail!("ssh-agent has no keys and no default keys found in ~/.ssh/");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to connect to ssh-agent; falling back to file search");
                    if let Some(def_key) = find_first_default_private_key() {
                        info!(path = %def_key.display(), "Using default SSH private key");
                        let sk = load_private_key_file(&def_key, None)?;
                        let (algorithm, public_key, signature) =
                            sign_challenge(&sk, &session_id, &challenge, &username)?;
                        AuthRequest::PublicKey { username, algorithm, public_key, signature }
                    } else if let Some(ref pw) = args.password {
                        AuthRequest::Password { username, password: pw.as_bytes().to_vec() }
                    } else {
                        bail!("Could not connect to ssh-agent and no default key found: {}", e);
                    }
                }
            }
        } else if let Some(def_key) = find_first_default_private_key() {
            info!(path = %def_key.display(), "Using default SSH private key");
            let sk = load_private_key_file(&def_key, None)?;
            let (algorithm, public_key, signature) =
                sign_challenge(&sk, &session_id, &challenge, &username)?;
            AuthRequest::PublicKey { username, algorithm, public_key, signature }
        } else if let Some(ref pw) = args.password {
            AuthRequest::Password { username, password: pw.as_bytes().to_vec() }
        } else if supported_auth.contains(&AuthMethod::None) {
            AuthRequest::None { username }
        } else {
            bail!("No SSH keys found, ssh-agent not available, and no password supplied");
        };

        debug!("Sending AuthRequest frame");
        MorshConnection::send_control_message(&mut send, &ControlMessage::AuthRequest(auth_req)).await?;

        debug!("Awaiting AuthResult frame");
        let result_msg = MorshConnection::read_control_message(&mut recv)
            .await
            .context("Failed to receive AuthResult from server")?;

        match result_msg {
            ControlMessage::AuthResult { success: true, message } => {
                println!(">> Authentication Successful: {}", message);
            }
            ControlMessage::AuthResult { success: false, message } => {
                eprintln!(">> Authentication FAILED: {}", message);
                conn.close(401, "Authentication failed");
                bail!("Authentication rejected by server: {}", message);
            }
            ControlMessage::Disconnect { reason_code, message } => {
                bail!("Server disconnected during authentication (code {}): {}", reason_code, message);
            }
            other => bail!("Expected AuthResult, got {:?}", other),
        }
    }

    // Ping test if requested
    if args.ping > 0 {
        println!("Sending {} liveness ping probes...", args.ping);
        for seq in 1..=args.ping {
            let start = Instant::now();
            let send_ts = current_timestamp_ms();
            let ping = ControlMessage::Ping {
                seq,
                timestamp_ms: send_ts,
            };

            MorshConnection::send_control_message(&mut send, &ping).await?;
            let reply = MorshConnection::read_control_message(&mut recv).await?;

            match reply {
                ControlMessage::Pong { seq: pong_seq, .. } => {
                    let rtt = start.elapsed();
                    println!("  [Ping #{}] acknowledged (seq={}) RTT: {:.2} ms", seq, pong_seq, rtt.as_secs_f64() * 1000.0);
                }
                other => {
                    println!("  [Ping #{}] unexpected response: {:?}", seq, other);
                    break;
                }
            }

            if seq < args.ping {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }

    // Graceful disconnect
    debug!("Sending graceful Disconnect frame");
    let disconnect = ControlMessage::Disconnect {
        reason_code: 0,
        message: "client finished".into(),
    };
    let _ = MorshConnection::send_control_message(&mut send, &disconnect).await;
    let _ = send.finish();

    conn.close(0, "normal client exit");
    println!("Session cleanly terminated.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_destination_various_formats() {
        // Standard host only
        let d1 = parse_destination("example.com", None).unwrap();
        assert_eq!(d1.user, None);
        assert_eq!(d1.host, "example.com");
        assert_eq!(d1.port, 2222);

        // Host and port
        let d2 = parse_destination("example.com:4444", None).unwrap();
        assert_eq!(d2.user, None);
        assert_eq!(d2.host, "example.com");
        assert_eq!(d2.port, 4444);

        // User and host
        let d3 = parse_destination("alice@example.com", None).unwrap();
        assert_eq!(d3.user, Some("alice".into()));
        assert_eq!(d3.host, "example.com");
        assert_eq!(d3.port, 2222);

        // User, host, and port
        let d4 = parse_destination("bob@192.168.1.50:2022", None).unwrap();
        assert_eq!(d4.user, Some("bob".into()));
        assert_eq!(d4.host, "192.168.1.50");
        assert_eq!(d4.port, 2022);

        // Port override takes precedence when port omitted in dest
        let d5 = parse_destination("srv", Some(3333)).unwrap();
        assert_eq!(d5.port, 3333);

        // Port override takes precedence over dest port
        let d6 = parse_destination("srv:2222", Some(9999)).unwrap();
        assert_eq!(d6.port, 9999);

        // IPv6 bracket syntax
        let d7 = parse_destination("[::1]:8080", None).unwrap();
        assert_eq!(d7.user, None);
        assert_eq!(d7.host, "::1");
        assert_eq!(d7.port, 8080);

        // IPv6 with user
        let d8 = parse_destination("carol@[fe80::1]", None).unwrap();
        assert_eq!(d8.user, Some("carol".into()));
        assert_eq!(d8.host, "fe80::1");
        assert_eq!(d8.port, 2222);
    }

    #[test]
    fn test_parse_destination_invalid() {
        assert!(parse_destination("", None).is_err());
        assert!(parse_destination("@", None).is_err());
        assert!(parse_destination("[::1", None).is_err()); // Unclosed bracket
        assert!(parse_destination("host:notaport", None).is_err());
    }
}

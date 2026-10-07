use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser};
use morsh_auth::{
    find_first_default_private_key, load_private_key_file, sign_challenge, AgentClient,
};
use morsh_core::protocol::{
    AuthMethod, AuthRequest, ControlMessage, TunnelStreamPreamble, TunnelType, PTY_STREAM_MAGIC,
    PROTOCOL_VERSION,
};
use morsh_transport::{
    connect_happy_eyeballs, default_known_hosts_path, make_client_config_from_rustls,
    make_tofu_rustls_client_config, MorshConnection, QuicClient, StrictHostKeyCheckingMode,
    TofuOptions,
};
use morsh_tunnel::{
    decode_udp_datagram, request_remote_forward, run_dynamic_socks5, run_local_forward,
    run_udp_forward, DynamicRule, ForwardRule, TunnelManager, UdpRule,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

mod config;
use config::{ClientConfig, OpenSshOptions};

#[derive(Parser, Debug)]
#[command(
    name = "morsh",
    version = "0.1.0",
    about = "morsh - Next-generation resilient QUIC SSH client (combining Mosh & SSH3)"
)]
struct Args {
    /// Remote destination in format [user@]host[:port]
    #[arg(value_name = "DESTINATION")]
    destination: Option<String>,

    /// Optional command to execute on remote host
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    command: Vec<String>,

    /// Override remote port (defaults to 2222 or port from destination / config)
    #[arg(short = 'p', long)]
    port: Option<u16>,

    /// Path to SSH private key file (e.g. ~/.ssh/id_ed25519)
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// Path to alternative client configuration file (defaults to ~/.morsh/config.toml)
    #[arg(short = 'F', long = "config", value_name = "CONFIG")]
    config_file: Option<PathBuf>,

    /// OpenSSH compatibility options in format Option=Value
    #[arg(short = 'o', long = "option", value_name = "KEY=VALUE")]
    options: Vec<String>,

    /// Request stream compression
    #[arg(short = 'C', long = "compress")]
    compress: bool,

    /// Force IPv4 address resolution only
    #[arg(short = '4', long = "ipv4")]
    ipv4: bool,

    /// Force IPv6 address resolution only
    #[arg(short = '6', long = "ipv6")]
    ipv6: bool,

    /// Increase verbosity level (-v: info, -vv: debug, -vvv: trace)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// Generate shell completions for the specified shell (bash, zsh, fish) and exit
    #[arg(long, value_name = "SHELL")]
    completions: Option<clap_complete::Shell>,

    /// Generate man page (roff format) to stdout and exit
    #[arg(long)]
    man: bool,

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

    /// Force TLS 1.3 over TCP fallback (bypasses QUIC/UDP)
    #[arg(long)]
    force_tcp: bool,

    /// Happy Eyeballs TCP fallback threshold in milliseconds (default: 300 ms)
    #[arg(long, default_value = "300", value_name = "MS")]
    tcp_fallback_timeout: u64,

    /// Local TCP port forwarding [bind_addr:]bind_port:target_host:target_port (-L)
    #[arg(short = 'L', long = "local-forward", value_name = "SPEC")]
    local_forward: Vec<String>,

    /// Remote TCP port forwarding [bind_addr:]bind_port:target_host:target_port (-R)
    #[arg(short = 'R', long = "remote-forward", value_name = "SPEC")]
    remote_forward: Vec<String>,

    /// Dynamic SOCKS5 proxy port [bind_addr:]bind_port (-D)
    #[arg(short = 'D', long = "dynamic-forward", value_name = "SPEC")]
    dynamic_forward: Vec<String>,

    /// Native UDP port forwarding [bind_addr:]bind_port:target_host:target_port (-U)
    #[arg(short = 'U', long = "udp-forward", value_name = "SPEC")]
    udp_forward: Vec<String>,

    /// Do not allocate an interactive PTY shell (tunnel-only mode)
    #[arg(short = 'N', long = "no-shell")]
    no_shell: bool,

    /// Resume an existing detached persistent session by 128-bit session ID (hex string)
    #[arg(long, value_name = "SESSION_ID")]
    resume: Option<String>,

    /// Cryptographic 128-bit resumption token (hex string) for session resumption
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,

    /// List active persistent sessions on the server and exit
    #[arg(long)]
    list_sessions: bool,

    /// Send N ping packets to measure round-trip latency over QUIC (0 starts interactive terminal session)
    #[arg(long, default_value = "0")]
    ping: u64,

    /// Predictive local echo mode: auto, always, or never
    #[arg(long, default_value = "auto", value_name = "MODE")]
    predict: String,

    /// Predictive local echo visual style: underline, dim, or none
    #[arg(long, default_value = "underline", value_name = "STYLE")]
    predict_style: String,
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

fn hex_decode(s: &str) -> Option<[u8; 16]> {
    let s = s.trim();
    if s.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

fn get_session_cache_path(session_id_hex: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".morsh").join("sessions").join(session_id_hex))
}

fn save_session_token(session_id: &[u8; 16], token: &[u8; 16], destination: &str) {
    let id_hex = hex_encode(session_id);
    let token_hex = hex_encode(token);
    if let Some(path) = get_session_cache_path(&id_hex) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let content = format!("{}\n{}\n", token_hex, destination);
        let _ = std::fs::write(&path, content);
    }
}

fn load_session_token(session_id_hex: &str) -> Option<[u8; 16]> {
    let path = get_session_cache_path(session_id_hex)?;
    let content = std::fs::read_to_string(path).ok()?;
    let first_line = content.lines().next()?.trim();
    hex_decode(first_line)
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

    if let Some(shell) = args.completions {
        let mut cmd = Args::command();
        clap_complete::generate(shell, &mut cmd, "morsh", &mut std::io::stdout());
        return Ok(());
    }

    if args.man {
        let cmd = Args::command();
        let man = clap_mangen::Man::new(cmd);
        man.render(&mut std::io::stdout())?;
        return Ok(());
    }

    let filter = match args.verbose {
        0 => EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("morsh=info,morsh_transport=info,morsh_auth=info")),
        1 => EnvFilter::new("morsh=debug,morsh_transport=debug,morsh_auth=debug,quinn=info"),
        _ => EnvFilter::new("morsh=trace,morsh_transport=trace,morsh_auth=trace,morsh_predict=trace,quinn=debug"),
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let dest_str = match args.destination {
        Some(ref d) => d.as_str(),
        None => {
            eprintln!("Error: Destination required: [user@]host[:port]");
            eprintln!("Usage: morsh [OPTIONS] [DESTINATION] [COMMAND]...");
            eprintln!("Try 'morsh --help' for more information.");
            bail!("Missing destination argument");
        }
    };

    // Load configuration files and OpenSSH options
    let client_cfg = ClientConfig::load(args.config_file.as_deref())?;
    let openssh_opts = OpenSshOptions::parse_options(&args.options)?;
    let initial_parsed = parse_destination(dest_str, args.port)?;
    let matched_rule = client_cfg.match_host(&initial_parsed.host);

    let target_host = matched_rule.host_name.unwrap_or(initial_parsed.host);

    let target_port = if let Some(p) = args.port {
        p
    } else if let Some(p) = openssh_opts.port {
        p
    } else if dest_str.contains(':') && initial_parsed.port != 2222 {
        initial_parsed.port
    } else if let Some(p) = matched_rule.port {
        p
    } else if let Some(p) = client_cfg.port {
        p
    } else {
        initial_parsed.port
    };

    let target_user = if let Some(ref u) = initial_parsed.user {
        Some(u.clone())
    } else if let Some(ref u) = openssh_opts.user {
        Some(u.clone())
    } else if let Some(ref u) = matched_rule.user {
        Some(u.clone())
    } else if let Some(ref u) = client_cfg.user {
        Some(u.clone())
    } else {
        std::env::var("USER").ok()
    };

    let target_identity = args.identity
        .or(openssh_opts.identity_file)
        .or(matched_rule.identity_file)
        .or(client_cfg.identity_file);

    let effective_insecure = args.insecure
        || openssh_opts.strict_host_key_checking == Some(StrictHostKeyCheckingMode::No)
        || matched_rule.insecure.unwrap_or(false)
        || client_cfg.insecure.unwrap_or(false);

    let effective_strict_host_key_checking = if effective_insecure {
        StrictHostKeyCheckingMode::No
    } else if let Some(mode) = openssh_opts.strict_host_key_checking {
        mode
    } else if let Some(mode) = matched_rule.strict_host_key_checking {
        mode
    } else if let Some(mode) = client_cfg.strict_host_key_checking {
        mode
    } else {
        StrictHostKeyCheckingMode::Ask
    };

    let effective_no_agent = args.no_agent
        || openssh_opts.forward_agent == Some(false)
        || matched_rule.forward_agent == Some(false)
        || client_cfg.forward_agent == Some(false);

    let effective_stealth_knock = args.stealth_knock
        .or(openssh_opts.stealth_knock)
        .or(matched_rule.stealth_knock)
        .or(client_cfg.stealth_knock);

    let effective_force_tcp = args.force_tcp
        || openssh_opts.force_tcp.unwrap_or(false)
        || matched_rule.force_tcp.unwrap_or(false)
        || client_cfg.force_tcp.unwrap_or(false);

    let effective_tcp_timeout = if args.tcp_fallback_timeout != 300 {
        args.tcp_fallback_timeout
    } else {
        openssh_opts.tcp_fallback_timeout
            .or(matched_rule.tcp_fallback_timeout)
            .or(client_cfg.tcp_fallback_timeout)
            .unwrap_or(300)
    };

    let effective_predict = if args.predict != "auto" {
        args.predict.clone()
    } else {
        openssh_opts.predict_mode
            .or(matched_rule.predict_mode)
            .or(client_cfg.predict_mode)
            .unwrap_or_else(|| "auto".into())
    };

    let effective_predict_style = if args.predict_style != "underline" {
        args.predict_style.clone()
    } else {
        openssh_opts.predict_style
            .or(matched_rule.predict_style)
            .or(client_cfg.predict_style)
            .unwrap_or_else(|| "underline".into())
    };

    let mut all_local_forwards = args.local_forward.clone();
    all_local_forwards.extend(openssh_opts.local_forward);
    all_local_forwards.extend(matched_rule.local_forward);

    let mut all_remote_forwards = args.remote_forward.clone();
    all_remote_forwards.extend(openssh_opts.remote_forward);
    all_remote_forwards.extend(matched_rule.remote_forward);

    let mut all_dynamic_forwards = args.dynamic_forward.clone();
    all_dynamic_forwards.extend(openssh_opts.dynamic_forward);
    all_dynamic_forwards.extend(matched_rule.dynamic_forward);

    let mut all_udp_forwards = args.udp_forward.clone();
    all_udp_forwards.extend(openssh_opts.udp_forward);
    all_udp_forwards.extend(matched_rule.udp_forward);

    let target = format!("{}:{}", target_host, target_port);
    let sni_name = args.server_name.unwrap_or_else(|| target_host.clone());

    info!(
        destination = %target,
        user = ?target_user,
        sni = %sni_name,
        "Resolving server address"
    );

    let mut addrs = tokio::net::lookup_host(&target)
        .await
        .with_context(|| format!("Failed to resolve destination '{}'", target))?;

    let remote_addr: SocketAddr = if args.ipv4 {
        addrs.find(|a| a.is_ipv4())
            .with_context(|| format!("No IPv4 address found for '{}'", target))?
    } else if args.ipv6 {
        addrs.find(|a| a.is_ipv6())
            .with_context(|| format!("No IPv6 address found for '{}'", target))?
    } else {
        addrs.next()
            .with_context(|| format!("Could not find any IP address for '{}'", target))?
    };

    let tofu_options = TofuOptions {
        target_host: target_host.clone(),
        target_port,
        remote_addr: Some(remote_addr),
        known_hosts_path: default_known_hosts_path(),
        strict_mode: effective_strict_host_key_checking,
        insecure: effective_insecure,
    };

    let rustls_client_config = make_tofu_rustls_client_config(tofu_options)
        .context("Failed to initialize client TLS transport configuration")?;
    let quic_client_config = make_client_config_from_rustls(rustls_client_config.clone())
        .context("Failed to initialize QUIC client transport configuration")?;

    let client = QuicClient::new(quic_client_config)
        .context("Failed to bind client endpoint")?;

    let fallback_delay = Duration::from_millis(effective_tcp_timeout);

    let conn_start = Instant::now();
    let conn = connect_happy_eyeballs(
        remote_addr,
        &sni_name,
        &client,
        rustls_client_config,
        fallback_delay,
        effective_force_tcp,
    )
    .await
    .context("Failed to establish connection with morsh server")?;
    let conn_elapsed = conn_start.elapsed();

    info!(
        remote = %conn.remote_address(),
        transport = conn.transport_name(),
        handshake_time_ms = conn_elapsed.as_millis(),
        initial_rtt_ms = conn.rtt().as_millis(),
        "Transport handshake successful"
    );

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open control bidirectional stream")?;

    let resume_session_id = if let Some(ref r_hex) = args.resume {
        Some(hex_decode(r_hex).context("Invalid --resume session ID hex string (expected 32 hex chars)")?)
    } else {
        None
    };

    // Send ClientHello
    let client_hello = ControlMessage::ClientHello {
        version: PROTOCOL_VERSION,
        client_software: format!("morsh-{}", env!("CARGO_PKG_VERSION")),
        knock_path: effective_stealth_knock.clone(),
        resumption_session_id: resume_session_id,
    };

    debug!("Sending ClientHello frame");
    MorshConnection::send_control_message(&mut send, &client_hello).await?;

    debug!("Waiting for ServerHello frame");
    let server_hello = MorshConnection::read_control_message(&mut recv)
        .await
        .context("Failed to receive ServerHello response")?;

    let (session_id, resumption_token, supported_auth) = match server_hello {
        ControlMessage::ServerHello {
            version,
            server_software,
            session_id,
            resumption_token,
            supported_auth,
            session_resumed,
        } => {
            println!("========================================================");
            println!(" Connected to morshd server!");
            println!("   Server Software : {}", server_software);
            println!("   Protocol Version: v{}", version);
            println!("   Transport       : {}", conn.transport_name());
            println!("   Session ID      : {}", hex_encode(&session_id));
            println!("   Resumption Token: {}", hex_encode(&resumption_token));
            println!("   Session Resumed : {}", session_resumed);
            println!("   Auth Supported  : {:?}", supported_auth);
            println!("   Round-Trip Time : {:.2} ms", conn.rtt().as_secs_f64() * 1000.0);
            println!("========================================================");
            (session_id, resumption_token, supported_auth)
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
        && target_identity.is_none() && args.password.is_none());

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

        let username = target_user.unwrap_or_else(|| {
            std::env::var("USER").unwrap_or_else(|_| "root".into())
        });

        info!(username = %username, "Authenticating with server...");

        // Select credentials
        let auth_req = if let Some(ref key_path) = target_identity {
            info!(path = %key_path.display(), "Using specified SSH private key");
            let sk = load_private_key_file(key_path, None)?;
            let (algorithm, public_key, signature) =
                sign_challenge(&sk, &session_id, &challenge, &username)?;
            AuthRequest::PublicKey { username, algorithm, public_key, signature }
        } else if !effective_no_agent && AgentClient::is_available() {
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

    // Cache session token for future resumption
    save_session_token(&session_id, &resumption_token, dest_str);

    // If client requested --list-sessions, query server and exit immediately
    if args.list_sessions {
        debug!("Requesting session list from server");
        MorshConnection::send_control_message(&mut send, &ControlMessage::SessionListRequest).await?;
        let resp = MorshConnection::read_control_message(&mut recv).await?;
        match resp {
            ControlMessage::SessionListResponse { sessions } => {
                println!();
                println!("Active persistent sessions on {}:", dest_str);
                if sessions.is_empty() {
                    println!("  No active persistent sessions.");
                } else {
                    println!("{:<34} {:<16} {:<12} {:<10}", "SESSION ID", "USER", "DIMENSIONS", "STATUS");
                    println!("{}", "-".repeat(74));
                    for s in sessions {
                        let status = if s.is_attached { "attached" } else { "detached" };
                        println!("{:<34} {:<16} {}x{:<9} {:<10}", hex_encode(&s.session_id), s.user, s.cols, s.rows, status);
                    }
                }
                println!();
            }
            other => {
                warn!("Unexpected response to SessionListRequest: {:?}", other);
            }
        }
        let _ = MorshConnection::send_control_message(
            &mut send,
            &ControlMessage::Disconnect {
                reason_code: 0,
                message: "list_sessions done".into(),
            },
        ).await;
        conn.close(0, "list_sessions complete");
        return Ok(());
    }

    // If client requested --resume, request session resumption and receive ScreenSnapshot
    let mut initial_snapshot: Option<Vec<u8>> = None;
    if let Some(ref resume_id_hex) = args.resume {
        let resume_id = hex_decode(resume_id_hex)
            .context("Invalid --resume session ID hex string (expected 32 hex chars)")?;
        let resume_tok = if let Some(ref t_hex) = args.token {
            hex_decode(t_hex).context("Invalid --token hex string (expected 32 hex chars)")?
        } else if let Some(cached_tok) = load_session_token(resume_id_hex) {
            debug!("Loaded resumption token from local session cache");
            cached_tok
        } else {
            bail!("Resumption token required to resume session {}. Provide with --token <HEX>", resume_id_hex);
        };

        debug!("Sending SessionResumeRequest for session {}", resume_id_hex);
        let resume_req = ControlMessage::SessionResumeRequest {
            session_id: resume_id,
            resumption_token: resume_tok,
        };
        MorshConnection::send_control_message(&mut send, &resume_req).await?;

        let resume_resp = MorshConnection::read_control_message(&mut recv).await?;
        match resume_resp {
            ControlMessage::SessionResumeResponse { success, message, .. } => {
                if !success {
                    bail!("Failed to resume session {}: {}", resume_id_hex, message);
                }
                println!("Session {} resumed successfully!", resume_id_hex);
            }
            other => bail!("Expected SessionResumeResponse, got {:?}", other),
        }

        let snapshot_msg = MorshConnection::read_control_message(&mut recv).await?;
        match snapshot_msg {
            ControlMessage::ScreenSnapshot { buffer, cols, rows, .. } => {
                debug!(cols, rows, buf_len = buffer.len(), "Received ScreenSnapshot from server");
                initial_snapshot = Some(buffer);
            }
            other => bail!("Expected ScreenSnapshot, got {:?}", other),
        }
    }

    use std::io::IsTerminal;
    let is_tty = std::io::stdin().is_terminal() && args.command.is_empty();

    // Channel for asynchronous control frame transmissions over Stream 0
    let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<ControlMessage>(64);
    let tunnel_manager = TunnelManager::new(Some(ctrl_tx.clone()));

    let mut send_stream = send;
    let ctrl_write_task = tokio::spawn(async move {
        while let Some(msg) = ctrl_rx.recv().await {
            let is_disconnect = matches!(msg, ControlMessage::Disconnect { .. });
            if let Err(e) = MorshConnection::send_control_message(&mut send_stream, &msg).await {
                debug!(error = %e, "Outbound control stream closed");
                break;
            }
            if is_disconnect {
                debug!("Outbound Disconnect sent; exiting control write loop");
                break;
            }
        }
        let _ = send_stream.finish();
    });

    // Accept server-initiated streams (for remote TCP forward -R)
    let conn_stream_accept = conn.clone();
    let tunnel_manager_stream = tunnel_manager.clone();
    let stream_accept_task = tokio::spawn(async move {
        while let Ok((stream_send, mut stream_recv)) = conn_stream_accept.accept_bi().await {
            let mgr = tunnel_manager_stream.clone();
            tokio::spawn(async move {
                let mut preamble_bytes = [0u8; 8];
                if stream_recv.read_exact(&mut preamble_bytes).await.is_ok() {
                    if let Some(preamble) = TunnelStreamPreamble::from_bytes(&preamble_bytes) {
                        if let Some(tcp_stream) = mgr.take_server_stream(preamble.tunnel_id).await {
                            morsh_tunnel::bridge_tcp_and_quic(tcp_stream, stream_send, stream_recv).await;
                        }
                    }
                }
            });
        }
    });

    // Datagram supervisor for UDP forwarding return packets
    let last_client_addr = Arc::new(tokio::sync::Mutex::new(None));
    let last_client_addr_clone = Arc::clone(&last_client_addr);
    let conn_datagram = conn.clone();
    let tunnel_manager_udp = tunnel_manager.clone();
    let datagram_task = tokio::spawn(async move {
        while let Ok(data) = conn_datagram.read_datagram().await {
            if let Some((tunnel_id, payload)) = decode_udp_datagram(&data) {
                if let Some(sock) = tunnel_manager_udp.get_udp_tunnel(tunnel_id).await {
                    if let Some(addr) = *last_client_addr_clone.lock().await {
                        let _ = sock.send_to(payload, addr).await;
                    }
                }
            }
        }
    });

    // Notify server if running in tunnel-only mode (-N)
    if args.no_shell {
        let _ = ctrl_tx.send(ControlMessage::NoShell).await;
    }

    // Launch configured tunnels
    for spec in &all_local_forwards {
        let rule = ForwardRule::parse(spec)?;
        let c = conn.clone();
        let tm = tunnel_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = run_local_forward(rule, c, tm).await {
                warn!(error = %e, "Local forward failed");
            }
        });
    }

    for spec in &all_dynamic_forwards {
        let rule = DynamicRule::parse(spec)?;
        let c = conn.clone();
        let tm = tunnel_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = run_dynamic_socks5(rule, c, tm).await {
                warn!(error = %e, "Dynamic SOCKS5 forward failed");
            }
        });
    }

    for spec in &all_remote_forwards {
        let rule = ForwardRule::parse(spec)?;
        request_remote_forward(&rule, &tunnel_manager).await?;
    }

    for spec in &all_udp_forwards {
        let rule = UdpRule::parse(spec)?;
        let c = conn.clone();
        let tm = tunnel_manager.clone();
        let lca = Arc::clone(&last_client_addr);
        tokio::spawn(async move {
            if let Err(e) = run_udp_forward(rule, c, tm, lca).await {
                warn!(error = %e, "UDP forward failed");
            }
        });
    }

    // Ping test if explicitly requested
    if args.ping > 0 {
        println!("Sending {} liveness ping probes...", args.ping);
        for seq in 1..=args.ping {
            let start = Instant::now();
            let send_ts = current_timestamp_ms();
            let ping = ControlMessage::Ping {
                seq,
                timestamp_ms: send_ts,
            };

            let _ = ctrl_tx.send(ping).await;
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
    } else if args.no_shell {
        println!("Tunnels established. Running in background (-N / no-shell). Press Ctrl+C to exit.");
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl+C received; terminating tunnels");
                    break;
                }
                ctrl_res = MorshConnection::read_control_message(&mut recv) => {
                    match ctrl_res {
                        Ok(ControlMessage::Disconnect { reason_code, message }) => {
                            info!(code = reason_code, %message, "Server disconnected");
                            break;
                        }
                        Ok(msg) => {
                            handle_client_control_msg(msg, &ctrl_tx, &tunnel_manager).await;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    } else {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
        debug!(cols, rows, "Initial client terminal dimensions");

        // Inform server of initial terminal window dimensions over Stream 0
        let resize_msg = ControlMessage::WindowResize {
            cols,
            rows,
            x_pixels: 0,
            y_pixels: 0,
        };
        let _ = ctrl_tx.send(resize_msg).await;

        if !args.command.is_empty() {
            let cmd_str = args.command.join(" ");
            debug!(command = %cmd_str, "Sending ExecRequest to server");
            let exec_req = ControlMessage::ExecRequest { command: cmd_str };
            let _ = ctrl_tx.send(exec_req).await;

            // Wait for server to acknowledge ExecRequest so that command is set before Stream 1 is accepted
            match MorshConnection::read_control_message(&mut recv).await? {
                ControlMessage::ExecResponse { success, message } => {
                    if !success {
                        bail!("Failed to execute command on server: {}", message);
                    }
                    debug!("Server acknowledged ExecRequest: {}", message);
                }
                other => {
                    debug!("Received control frame while awaiting ExecResponse: {:?}", other);
                }
            }
        }

        // Open Stream 1 for raw bidirectional PTY byte streaming
        let (mut pty_send, mut pty_recv) = conn
            .open_bi()
            .await
            .context("Failed to open interactive PTY stream")?;

        // Send PTY stream magic preamble immediately so that QUIC transmits a STREAM frame
        // and server can immediately accept Stream 1 and spawn the interactive shell without waiting for input.
        pty_send.write_all(&PTY_STREAM_MAGIC).await?;
        pty_send.flush().await?;

        let _guard = if is_tty {
            Some(RawModeGuard::enter()?)
        } else {
            None
        };

        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();

        if let Some(ref snapshot) = initial_snapshot {
            let _ = stdout.write_all(snapshot).await;
            let _ = stdout.flush().await;
        }

        #[cfg(unix)]
        let mut sigwinch =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                .context("Failed to register SIGWINCH listener")?;

        let mut in_buf = [0u8; 4096];
        let mut out_buf = [0u8; 4096];
        let mut stdin_eof = false;
        let mut saw_detach_prefix = false;
        let mut detached_by_user = false;

        let predict_mode = effective_predict.parse::<morsh_predict::PredictMode>().unwrap_or_default();
        let predict_style = effective_predict_style.parse::<morsh_predict::PredictStyle>().unwrap_or_default();
        let mut predict_engine = morsh_predict::PredictionEngine::new(predict_mode, predict_style);
        predict_engine.set_rtt(conn.rtt());

        loop {
            tokio::select! {
                // Remote PTY stdout -> local stdout
                out_res = pty_recv.read(&mut out_buf) => {
                    match out_res {
                        Ok(Some(n)) if n > 0 => {
                            predict_engine.set_rtt(conn.rtt());
                            let srv_res = predict_engine.process_server_output(&out_buf[..n]);
                            if stdout.write_all(&srv_res.output_to_render).await.is_err() {
                                break;
                            }
                            let _ = stdout.flush().await;
                        }
                        _ => {
                            debug!("Remote PTY closed output (EOF)");
                            break;
                        }
                    }
                }

                // Local stdin -> remote PTY stdin (with Ctrl-^ d escape detection and speculative echo)
                in_res = stdin.read(&mut in_buf), if !stdin_eof => {
                    match in_res {
                        Ok(n) if n > 0 => {
                            let mut write_bytes = Vec::with_capacity(n);
                            let mut detach_triggered = false;

                            for &b in &in_buf[..n] {
                                if saw_detach_prefix {
                                    saw_detach_prefix = false;
                                    if b == b'd' || b == b'D' || b == b'.' {
                                        detach_triggered = true;
                                        break;
                                    } else if b == 0x1e {
                                        write_bytes.push(0x1e);
                                    } else {
                                        write_bytes.push(0x1e);
                                        write_bytes.push(b);
                                    }
                                } else if b == 0x1e {
                                    saw_detach_prefix = true;
                                } else {
                                    write_bytes.push(b);
                                }
                            }

                            if detach_triggered {
                                detached_by_user = true;
                                debug!("User triggered session detach escape sequence (Ctrl-^ d)");
                                let _ = ctrl_tx.send(ControlMessage::SessionDetachRequest).await;
                                break;
                            }

                            if !write_bytes.is_empty() {
                                if is_tty {
                                    let input_res = predict_engine.process_input(&write_bytes);
                                    if !input_res.speculative_render.is_empty() {
                                        let _ = stdout.write_all(&input_res.speculative_render).await;
                                        let _ = stdout.flush().await;
                                    }
                                    if let Some(seq) = input_res.highest_seq {
                                        let _ = ctrl_tx
                                            .send(ControlMessage::PredictInputSeq {
                                                seq,
                                                len: input_res.predictions.len() as u32,
                                            })
                                            .await;
                                    }
                                }

                                if pty_send.write_all(&write_bytes).await.is_err() {
                                    stdin_eof = true;
                                }
                            }
                        }
                        _ => {
                            debug!("Local stdin EOF reached; finished PTY send stream");
                            stdin_eof = true;
                            let _ = pty_send.finish();
                        }
                    }
                }

                // Terminal window resize signal (SIGWINCH on Unix)
                _ = sigwinch.recv() => {
                    let (new_cols, new_rows) = crossterm::terminal::size().unwrap_or((80, 24));
                    let resize_event = ControlMessage::WindowResize {
                        cols: new_cols,
                        rows: new_rows,
                        x_pixels: 0,
                        y_pixels: 0,
                    };
                    let _ = ctrl_tx.send(resize_event).await;
                }

                // Control stream notifications (e.g. Disconnect, Ping, Tunnel responses, PredictAck)
                ctrl_res = MorshConnection::read_control_message(&mut recv) => {
                    match ctrl_res {
                        Ok(ControlMessage::Disconnect { reason_code, message }) => {
                            debug!(code = reason_code, %message, "Server notified disconnect");
                            break;
                        }
                        Ok(ControlMessage::PredictAck { ack_seq }) => {
                            predict_engine.handle_ack(ack_seq);
                        }
                        Ok(msg) => {
                            handle_client_control_msg(msg, &ctrl_tx, &tunnel_manager).await;
                        }
                        Err(_) => {
                            break;
                        }
                    }
                }
            }
        }

        let cleanup_bytes = predict_engine.reset();
        if !cleanup_bytes.is_empty() {
            let _ = stdout.write_all(&cleanup_bytes).await;
            let _ = stdout.flush().await;
        }

        drop(_guard);
        if detached_by_user {
            stream_accept_task.abort();
            datagram_task.abort();
            println!("\r\n[morsh: detached session {}]", hex_encode(&session_id));
            println!("[To resume, run: morsh {} --resume {}]\r\n", dest_str, hex_encode(&session_id));
            drop(ctrl_tx);
            conn.close(0, "session detached");
            std::process::exit(0);
        }
    }

    stream_accept_task.abort();
    datagram_task.abort();

    // Graceful disconnect
    debug!("Sending graceful Disconnect frame");
    let disconnect = ControlMessage::Disconnect {
        reason_code: 0,
        message: "client finished".into(),
    };
    let _ = ctrl_tx.send(disconnect).await;
    drop(tunnel_manager);
    drop(ctrl_tx);
    let _ = tokio::time::timeout(Duration::from_millis(500), ctrl_write_task).await;

    conn.close(0, "normal client exit");
    if !is_tty && args.ping > 0 {
        println!("Session cleanly terminated.");
    }
    std::process::exit(0);
}

async fn handle_client_control_msg(
    msg: ControlMessage,
    ctrl_tx: &tokio::sync::mpsc::Sender<ControlMessage>,
    tunnel_manager: &TunnelManager,
) {
    match msg {
        ControlMessage::Ping { seq, timestamp_ms } => {
            let pong = ControlMessage::Pong {
                seq,
                echo_timestamp_ms: timestamp_ms,
            };
            let _ = ctrl_tx.send(pong).await;
        }
        ControlMessage::TunnelOpenResponse {
            tunnel_id,
            success,
            message,
        } => {
            tunnel_manager
                .on_tunnel_open_response(tunnel_id, success, message)
                .await;
        }
        ControlMessage::RemoteForwardResponse {
            bind_port,
            success,
            message,
        } => {
            tunnel_manager
                .on_remote_forward_response(bind_port, success, message)
                .await;
        }
        ControlMessage::TunnelOpenRequest {
            tunnel_id,
            tunnel_type,
            host,
            port,
        } => {
            if tunnel_type == TunnelType::RemoteTcp {
                let target_addr = format!("{}:{}", host, port);
                match tokio::net::TcpStream::connect(&target_addr).await {
                    Ok(tcp_stream) => {
                        tunnel_manager
                            .register_server_stream(tunnel_id, tcp_stream)
                            .await;
                        let resp = ControlMessage::TunnelOpenResponse {
                            tunnel_id,
                            success: true,
                            message: "Connected to local target".into(),
                        };
                        let _ = ctrl_tx.send(resp).await;
                    }
                    Err(e) => {
                        warn!(
                            tunnel_id,
                            target = %target_addr,
                            error = %e,
                            "Failed to connect to local target for -R"
                        );
                        let resp = ControlMessage::TunnelOpenResponse {
                            tunnel_id,
                            success: false,
                            message: e.to_string(),
                        };
                        let _ = ctrl_tx.send(resp).await;
                    }
                }
            }
        }
        ControlMessage::TunnelClose { tunnel_id } => {
            tunnel_manager.remove_tunnel(tunnel_id).await;
        }
        _ => {}
    }
}

/// RAII guard ensuring terminal raw mode is cleanly disabled when dropped.
struct RawModeGuard {
    active: bool,
}

impl RawModeGuard {
    fn enter() -> Result<Self> {
        crossterm::terminal::enable_raw_mode().context("Failed to enable raw terminal mode")?;
        let default_panic = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = crossterm::terminal::disable_raw_mode();
            default_panic(info);
        }));
        Ok(Self { active: true })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
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

    #[test]
    fn test_args_parsing_openssh_flags() {
        let args = Args::try_parse_from([
            "morsh",
            "-p", "2222",
            "-i", "/tmp/id_test",
            "-C",
            "-4",
            "-vv",
            "-o", "User=alice",
            "-o", "StrictHostKeyChecking=no",
            "srv.example.com",
            "ls", "-la",
        ]).unwrap();

        assert_eq!(args.destination, Some("srv.example.com".into()));
        assert_eq!(args.port, Some(2222));
        assert_eq!(args.identity, Some(PathBuf::from("/tmp/id_test")));
        assert!(args.compress);
        assert!(args.ipv4);
        assert!(!args.ipv6);
        assert_eq!(args.verbose, 2);
        assert_eq!(args.options.len(), 2);
        assert_eq!(args.command, vec!["ls".to_string(), "-la".to_string()]);
    }
}

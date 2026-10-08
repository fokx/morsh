use serde::{Deserialize, Serialize};

/// Protocol magic identifier at the start of control connections.
pub const PROTOCOL_MAGIC: [u8; 4] = *b"MRSH";

/// Current morsh protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Application-Layer Protocol Negotiation (ALPN) token for morsh QUIC connections.
pub const ALPN_MORSH: &[u8] = b"morsh-v1";

/// Maximum permitted single frame payload size (16 MiB).
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Supported authentication methods communicated during handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    /// No authentication required (development / testing).
    None,
    /// Public key authentication (Ed25519, RSA, ECDSA).
    PublicKey { supported_algorithms: Vec<String> },
    /// Password / PAM based authentication.
    Password,
    /// Pre-shared secret / knock token authentication.
    KnockToken,
}

/// Authentication request submitted by the client during handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthRequest {
    /// No authentication credentials (permitted only if server advertises AuthMethod::None).
    None { username: String },

    /// SSH Public key authentication (Ed25519, RSA, ECDSA).
    PublicKey {
        username: String,
        algorithm: String,
        public_key: Vec<u8>,
        signature: Vec<u8>,
    },

    /// Password / PAM based authentication.
    Password {
        username: String,
        password: Vec<u8>,
    },
}

/// Control message payload exchanged over Stream 0 (Control Stream).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Initiated by the client upon connecting.
    ClientHello {
        /// Protocol version spoken by the client.
        version: u32,
        /// Client identifier string (e.g. "morsh-0.2.0").
        client_software: String,
        /// Optional stealth knock path or secret token (SSH3 style).
        knock_path: Option<String>,
        /// Optional session resumption token if reconnecting (Mosh style).
        resumption_session_id: Option<[u8; 16]>,
    },

    /// Reply from the server acknowledging or rejecting connection.
    ServerHello {
        /// Protocol version spoken by the server.
        version: u32,
        /// Server identifier string (e.g. "morshd-0.2.0").
        server_software: String,
        /// Unique session identifier generated or resumed for this connection.
        session_id: [u8; 16],
        /// Cryptographic 128-bit session resumption token (Mosh style).
        resumption_token: [u8; 16],
        /// Authentication methods accepted by this server.
        supported_auth: Vec<AuthMethod>,
        /// Whether this is a successfully resumed persistent session.
        session_resumed: bool,
    },

    /// Cryptographic authentication challenge sent by the server to the client.
    AuthChallenge {
        /// 32-byte cryptographically secure random challenge.
        challenge: [u8; 32],
    },

    /// Authentication attempt submitted by the client.
    AuthRequest(AuthRequest),

    /// Server authentication outcome acknowledging or denying access.
    AuthResult {
        /// True if credentials were accepted, false otherwise.
        success: bool,
        /// Informational or error message.
        message: String,
    },

    /// Liveness heartbeat ping.
    Ping {
        seq: u64,
        timestamp_ms: u64,
    },

    /// Liveness heartbeat pong response.
    Pong {
        seq: u64,
        echo_timestamp_ms: u64,
    },

    /// Out-of-band terminal window resize event to update remote PTY dimensions.
    WindowResize {
        cols: u16,
        rows: u16,
        x_pixels: u16,
        y_pixels: u16,
    },

    /// Explicit request to allocate a PTY session with specified terminal environment.
    PtyRequest {
        term: String,
        cols: u16,
        rows: u16,
        x_pixels: u16,
        y_pixels: u16,
    },

    /// Request to execute a remote command instead of an interactive login shell.
    ExecRequest {
        command: String,
    },

    /// Response acknowledging remote command execution request.
    ExecResponse {
        success: bool,
        message: String,
    },

    /// Client indicates that no interactive PTY shell should be allocated (-N / tunnel-only mode).
    NoShell,

    /// Voluntary detach request from client: leaves server PTY running in background.
    SessionDetachRequest,

    /// Request to resume an existing detached persistent session.
    SessionResumeRequest {
        session_id: [u8; 16],
        resumption_token: [u8; 16],
    },

    /// Server response acknowledging or rejecting session resumption.
    SessionResumeResponse {
        success: bool,
        session_id: [u8; 16],
        resumption_token: [u8; 16],
        message: String,
    },

    /// Request to list all active persistent sessions for the authenticated user.
    SessionListRequest,

    /// List of active persistent sessions on the server.
    SessionListResponse {
        sessions: Vec<SessionInfo>,
    },

    /// Full terminal screen state snapshot transmitted on reconnection to restore terminal display.
    ScreenSnapshot {
        cols: u16,
        rows: u16,
        cursor_x: u16,
        cursor_y: u16,
        buffer: Vec<u8>,
    },

    /// Incremental screen update delta.
    ScreenDelta {
        seq: u64,
        delta: Vec<u8>,
    },

    /// Request to initiate a new forwarded tunnel channel.
    TunnelOpenRequest {
        tunnel_id: u32,
        tunnel_type: TunnelType,
        host: String,
        port: u16,
    },

    /// Response acknowledging or rejecting a tunnel open request.
    TunnelOpenResponse {
        tunnel_id: u32,
        success: bool,
        message: String,
    },

    /// Notification that a tunnel channel has been terminated.
    TunnelClose {
        tunnel_id: u32,
    },

    /// Request by client for server to bind a remote port for remote forwarding (-R).
    RemoteForwardRequest {
        bind_addr: String,
        bind_port: u16,
        target_host: String,
        target_port: u16,
    },

    /// Response acknowledging or rejecting remote port binding (-R).
    RemoteForwardResponse {
        bind_port: u16,
        success: bool,
        message: String,
    },

    /// Predictive local echo input sequence notification sent by client.
    PredictInputSeq {
        seq: u64,
        len: u32,
    },

    /// Predictive local echo sequence acknowledgement sent by server.
    PredictAck {
        ack_seq: u64,
    },

    /// Graceful disconnect notification.
    Disconnect {
        reason_code: u32,
        message: String,
    },
}

/// Metadata describing an active persistent session on the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: [u8; 16],
    pub user: String,
    pub created_at_secs: u64,
    pub cols: u16,
    pub rows: u16,
    pub is_attached: bool,
}

/// Type of network tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TunnelType {
    /// Local TCP forward (-L): client listens locally, server connects to remote target.
    LocalTcp,
    /// Remote TCP forward (-R): server listens remotely, client connects to local network target.
    RemoteTcp,
    /// Dynamic SOCKS5 proxy (-D): client runs SOCKS5 proxy, server connects to requested destination.
    Socks5,
    /// Native UDP forward: bidirectional packet forwarding over QUIC Datagrams.
    UdpForward,
}

/// 4-byte magic preamble for tunnel QUIC streams.
pub const TUNNEL_STREAM_MAGIC: [u8; 4] = *b"MTUN";

/// 4-byte magic preamble for interactive PTY QUIC streams.
pub const PTY_STREAM_MAGIC: [u8; 4] = *b"MPTY";

/// Preamble sent at the start of a forwarded QUIC stream.
/// Identifies which tunnel_id the stream belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelStreamPreamble {
    pub magic: [u8; 4],
    pub tunnel_id: u32,
}

impl TunnelStreamPreamble {
    pub fn new(tunnel_id: u32) -> Self {
        Self {
            magic: TUNNEL_STREAM_MAGIC,
            tunnel_id,
        }
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&self.magic);
        bytes[4..8].copy_from_slice(&self.tunnel_id.to_be_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8; 8]) -> Option<Self> {
        if &bytes[0..4] != &TUNNEL_STREAM_MAGIC {
            return None;
        }
        let tunnel_id = u32::from_be_bytes(bytes[4..8].try_into().ok()?);
        Some(Self {
            magic: TUNNEL_STREAM_MAGIC,
            tunnel_id,
        })
    }
}

/// Helper to construct the canonical challenge payload to be signed by SSH key or agent.
/// Binds protocol version domain separator, session_id, challenge bytes, and username.
pub fn make_challenge_payload(
    session_id: &[u8; 16],
    challenge: &[u8; 32],
    username: &str,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16 + 16 + 32 + username.len());
    payload.extend_from_slice(b"morsh-auth-v1:");
    payload.extend_from_slice(session_id);
    payload.extend_from_slice(challenge);
    payload.extend_from_slice(username.as_bytes());
    payload
}


/// Identifiers for multiplexed QUIC streams within a morsh session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum StreamChannelKind {
    /// Primary control and session management stream.
    Control = 0,
    /// Interactive terminal PTY stream (stdin/stdout).
    Pty = 1,
    /// TCP port forwarding channel.
    TcpForward = 2,
    /// Native UDP port forwarding channel.
    UdpForward = 3,
    /// Mosh-style screen state synchronization diffs.
    StateSync = 4,
}

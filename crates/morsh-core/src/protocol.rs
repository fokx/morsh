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

/// Control message payload exchanged over Stream 0 (Control Stream).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Initiated by the client upon connecting.
    ClientHello {
        /// Protocol version spoken by the client.
        version: u32,
        /// Client identifier string (e.g. "morsh-0.1.0").
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
        /// Server identifier string (e.g. "morshd-0.1.0").
        server_software: String,
        /// Unique session identifier generated or resumed for this connection.
        session_id: [u8; 16],
        /// Authentication methods accepted by this server.
        supported_auth: Vec<AuthMethod>,
        /// Whether this is a successfully resumed persistent session.
        session_resumed: bool,
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

    /// Graceful disconnect notification.
    Disconnect {
        reason_code: u32,
        message: String,
    },
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

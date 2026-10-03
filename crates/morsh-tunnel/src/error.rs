use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Core protocol error: {0}")]
    Core(#[from] morsh_core::error::CoreError),

    #[error("Invalid tunnel rule configuration: {0}")]
    InvalidRule(String),

    #[error("SOCKS5 protocol error: {0}")]
    Socks5(String),

    #[error("Tunnel open failed: {0}")]
    OpenFailed(String),

    #[error("Remote forward bind failed on port {port}: {reason}")]
    RemoteBindFailed { port: u16, reason: String },

    #[error("Tunnel not found: {0}")]
    NotFound(u32),

    #[error("Tunnel timeout: {0}")]
    Timeout(String),

    #[error("Channel closed")]
    ChannelClosed,
}

pub type Result<T> = std::result::Result<T, TunnelError>;

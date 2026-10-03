use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Serialization failed: {0}")]
    Serialization(String),

    #[error("Deserialization failed: {0}")]
    Deserialization(String),

    #[error("Frame size {size} exceeds maximum allowable size of {max}")]
    FrameTooLarge { size: usize, max: usize },

    #[error("Unexpected end of stream")]
    UnexpectedEof,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid protocol magic header: expected {expected:?}, got {actual:?}")]
    InvalidMagic {
        expected: [u8; 4],
        actual: [u8; 4],
    },

    #[error("Incompatible protocol version: client v{client}, server v{server}")]
    IncompatibleVersion { client: u32, server: u32 },

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Tunnel error: {0}")]
    Tunnel(String),

    #[error("Session error: {0}")]
    Session(String),
}


pub type Result<T> = std::result::Result<T, CoreError>;

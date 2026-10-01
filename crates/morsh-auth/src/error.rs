use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("SSH key parsing error: {0}")]
    KeyParse(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("Key is not authorized")]
    UnauthorizedKey,

    #[error("SSH agent error: {0}")]
    Agent(String),

    #[error("PAM / system authentication error: {0}")]
    Pam(String),

    #[error("User '{0}' not found on system")]
    UserNotFound(String),

    #[error("Invalid challenge payload: {0}")]
    InvalidChallenge(String),

    #[error("Unsupported algorithm: '{0}'")]
    UnsupportedAlgorithm(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cryptographic error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;

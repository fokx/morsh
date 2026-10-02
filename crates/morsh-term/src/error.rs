use thiserror::Error;

/// Error types for the PTY and terminal subsystem.
#[derive(Error, Debug)]
pub enum TermError {
    #[error("Failed to allocate pseudo-terminal: {0}")]
    PtyAlloc(String),

    #[error("Failed to spawn process in PTY: {0}")]
    Spawn(String),

    #[error("Failed to resize PTY: {0}")]
    Resize(String),

    #[error("PTY child process already terminated")]
    Terminated,

    #[error("Underlying IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, TermError>;

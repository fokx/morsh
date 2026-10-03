//! Error types for the morsh predictive local echo engine.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PredictError {
    #[error("Invalid prediction sequence: expected {expected}, received {received}")]
    InvalidSequence { expected: u64, received: u64 },

    #[error("Terminal mode error: {0}")]
    TerminalMode(String),

    #[error("Internal prediction error: {0}")]
    Internal(String),
}

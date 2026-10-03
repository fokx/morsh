//! Prediction record representations.

use crate::keystroke::Keystroke;

/// A speculative prediction for an individual user keystroke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prediction {
    /// Unique incrementing sequence identifier.
    pub id: u64,
    /// The parsed keystroke.
    pub keystroke: Keystroke,
    /// Raw bytes transmitted to the server.
    pub raw_input: Vec<u8>,
    /// Expected raw echo output from the remote shell.
    pub predicted_echo: Vec<u8>,
    /// Styled visual feedback rendered immediately on the local terminal.
    pub speculative_display: Vec<u8>,
    /// Column displacement caused by this prediction on the local display.
    pub cols_advanced: isize,
}

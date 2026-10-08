//! Predictive local echo engine for morsh (Mosh style).
//!
//! Provides zero-latency speculative keystroke rendering, visual styling (underline/dim),
//! confidence tracking heuristics (password prompts, alternate screen buffer suppression),
//! and 1-RTT divergence rollback.

pub mod confidence;
pub mod engine;
pub mod error;
pub mod keystroke;
pub mod prediction;
pub mod rollback;
pub mod style;

pub use confidence::{ConfidenceLevel, ConfidenceTracker};
pub use engine::{InputProcessResult, PredictionEngine, ServerOutputResult};
pub use error::PredictError;
pub use keystroke::{parse_keystrokes, Keystroke};
pub use prediction::Prediction;
pub use rollback::generate_rollback;
pub use style::{PredictMode, PredictStyle};

pub fn predict_subsystem_version() -> &'static str {
    "0.3.0"
}

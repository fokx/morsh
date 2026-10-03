//! Predictive local echo state machine and coordination engine.

use std::collections::VecDeque;
use crate::confidence::ConfidenceTracker;
use crate::keystroke::{parse_keystrokes, Keystroke};
use crate::prediction::Prediction;
use crate::rollback::generate_rollback;
use crate::style::{PredictMode, PredictStyle};

/// Outcome of processing local user input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputProcessResult {
    /// Newly created predictions for this input chunk.
    pub predictions: Vec<Prediction>,
    /// Styled speculative characters to render immediately to local stdout.
    pub speculative_render: Vec<u8>,
    /// Raw bytes to transmit to the server over Stream 1.
    pub raw_input: Vec<u8>,
    /// Highest prediction sequence allocated in this batch.
    pub highest_seq: Option<u64>,
}

/// Outcome of processing remote server PTY output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerOutputResult {
    /// Sequence number of confirmed predictions, if any.
    pub confirmed_seq: Option<u64>,
    /// Whether server output diverged from speculative local predictions.
    pub had_divergence: bool,
    /// Bytes to write to local stdout (including any rollback erase sequences).
    pub output_to_render: Vec<u8>,
}

/// Core prediction engine coordinating speculative local echo, confidence tracking, and rollback.
#[derive(Debug)]
pub struct PredictionEngine {
    mode: PredictMode,
    style: PredictStyle,
    confidence: ConfidenceTracker,
    next_seq: u64,
    pending_predictions: VecDeque<Prediction>,
    active_speculative_cols: usize,
}

impl Default for PredictionEngine {
    fn default() -> Self {
        Self::new(PredictMode::Auto, PredictStyle::Underline)
    }
}

impl PredictionEngine {
    /// Creates a new engine with the specified mode and visual style.
    pub fn new(mode: PredictMode, style: PredictStyle) -> Self {
        Self {
            mode,
            style,
            confidence: ConfidenceTracker::new(),
            next_seq: 0,
            pending_predictions: VecDeque::new(),
            active_speculative_cols: 0,
        }
    }

    /// Operational prediction mode.
    pub fn mode(&self) -> PredictMode {
        self.mode
    }

    /// Visual feedback style.
    pub fn style(&self) -> PredictStyle {
        self.style
    }

    /// Access to confidence tracker.
    pub fn confidence(&self) -> &ConfidenceTracker {
        &self.confidence
    }

    /// Mutable access to confidence tracker.
    pub fn confidence_mut(&mut self) -> &mut ConfidenceTracker {
        &mut self.confidence
    }

    /// Number of active speculative columns currently rendered on the local terminal.
    pub fn active_speculative_cols(&self) -> usize {
        self.active_speculative_cols
    }

    /// Number of pending predictions awaiting server confirmation.
    pub fn pending_count(&self) -> usize {
        self.pending_predictions.len()
    }

    /// Processes user input from local stdin.
    pub fn process_input(&mut self, input: &[u8]) -> InputProcessResult {
        let keystrokes = parse_keystrokes(input);
        let mut predictions = Vec::new();
        let mut speculative_render = Vec::new();
        let mut raw_input = Vec::new();
        let mut highest_seq = None;

        let can_predict = self.confidence.can_predict(self.mode);

        for stroke in keystrokes {
            let stroke_bytes = stroke.raw_bytes();
            raw_input.extend_from_slice(&stroke_bytes);

            if !can_predict {
                continue;
            }

            match stroke {
                Keystroke::Printable(c) => {
                    self.next_seq += 1;
                    let seq = self.next_seq;
                    highest_seq = Some(seq);

                    let c_str = c.to_string();
                    let styled_bytes = self.style.render(&c_str);
                    speculative_render.extend_from_slice(&styled_bytes);

                    let prediction = Prediction {
                        id: seq,
                        keystroke: Keystroke::Printable(c),
                        raw_input: stroke_bytes,
                        predicted_echo: c_str.into_bytes(),
                        speculative_display: styled_bytes,
                        cols_advanced: 1,
                    };

                    self.active_speculative_cols += 1;
                    self.pending_predictions.push_back(prediction.clone());
                    predictions.push(prediction);
                }

                Keystroke::Backspace => {
                    if self.active_speculative_cols > 0 {
                        // Optimistically erase the last speculative character locally
                        speculative_render.extend_from_slice(b"\x08 \x08");
                        self.active_speculative_cols = self.active_speculative_cols.saturating_sub(1);

                        // If the last prediction was a printable char, pop it
                        if let Some(back) = self.pending_predictions.back() {
                            if matches!(back.keystroke, Keystroke::Printable(_)) {
                                self.pending_predictions.pop_back();
                            }
                        }
                    }
                }

                Keystroke::CursorLeft => {
                    self.next_seq += 1;
                    let seq = self.next_seq;
                    highest_seq = Some(seq);

                    speculative_render.extend_from_slice(b"\x1b[D");
                    let prediction = Prediction {
                        id: seq,
                        keystroke: Keystroke::CursorLeft,
                        raw_input: stroke_bytes,
                        predicted_echo: b"\x1b[D".to_vec(),
                        speculative_display: b"\x1b[D".to_vec(),
                        cols_advanced: -1,
                    };
                    self.pending_predictions.push_back(prediction.clone());
                    predictions.push(prediction);
                }

                Keystroke::CursorRight => {
                    self.next_seq += 1;
                    let seq = self.next_seq;
                    highest_seq = Some(seq);

                    speculative_render.extend_from_slice(b"\x1b[C");
                    let prediction = Prediction {
                        id: seq,
                        keystroke: Keystroke::CursorRight,
                        raw_input: stroke_bytes,
                        predicted_echo: b"\x1b[C".to_vec(),
                        speculative_display: b"\x1b[C".to_vec(),
                        cols_advanced: 1,
                    };
                    self.pending_predictions.push_back(prediction.clone());
                    predictions.push(prediction);
                }

                Keystroke::Newline => {
                    // Enter commits the command line; reset speculative column counter
                    self.active_speculative_cols = 0;
                    self.pending_predictions.clear();
                }

                Keystroke::Unpredicted(_) => {
                    // Control keys (Ctrl-C, Tab, Esc) disrupt inline echo
                    if self.active_speculative_cols > 0 {
                        let rollback = generate_rollback(self.active_speculative_cols);
                        speculative_render.extend_from_slice(&rollback);
                        self.active_speculative_cols = 0;
                        self.pending_predictions.clear();
                    }
                }
            }
        }

        InputProcessResult {
            predictions,
            speculative_render,
            raw_input,
            highest_seq,
        }
    }

    /// Processes remote server PTY output, validating predictions and rolling back upon divergence.
    pub fn process_server_output(&mut self, output: &[u8]) -> ServerOutputResult {
        // 1. Detect terminal alternate screen buffer enter/exit sequences
        if output.windows(8).any(|w| w == b"\x1b[?1049h" || w == b"\x1b[?1047h")
            || output.windows(6).any(|w| w == b"\x1b[?47h")
        {
            self.confidence.set_alt_screen(true);
            self.pending_predictions.clear();
            self.active_speculative_cols = 0;
            return ServerOutputResult {
                confirmed_seq: None,
                had_divergence: false,
                output_to_render: output.to_vec(),
            };
        }

        if output.windows(8).any(|w| w == b"\x1b[?1049l" || w == b"\x1b[?1047l")
            || output.windows(6).any(|w| w == b"\x1b[?47l")
        {
            self.confidence.set_alt_screen(false);
            return ServerOutputResult {
                confirmed_seq: None,
                had_divergence: false,
                output_to_render: output.to_vec(),
            };
        }

        // 2. Detect password prompts in server output
        let out_str = String::from_utf8_lossy(output);
        let out_lower = out_str.to_lowercase();
        if out_lower.contains("password:") || out_lower.contains("passphrase:") {
            self.confidence.set_no_echo(true);
        } else if self.confidence.is_no_echo() && (out_str.contains("$ ") || out_str.contains("# ") || out_str.contains("> ")) {
            self.confidence.set_no_echo(false);
        }

        // 3. If no predictions are pending, render output directly
        if self.pending_predictions.is_empty() {
            return ServerOutputResult {
                confirmed_seq: None,
                had_divergence: false,
                output_to_render: output.to_vec(),
            };
        }

        // 4. Match server output against pending predictions
        let mut confirmed_seq = None;
        let mut matched_count = 0;
        let mut offset = 0;
        let mut diverged = false;

        for p in self.pending_predictions.iter() {
            let echo_bytes = &p.predicted_echo;
            if offset + echo_bytes.len() <= output.len() {
                if &output[offset..offset + echo_bytes.len()] == echo_bytes.as_slice() {
                    offset += echo_bytes.len();
                    matched_count += 1;
                    confirmed_seq = Some(p.id);
                } else {
                    diverged = true;
                    break;
                }
            } else {
                // Partial match or output ends before this prediction completes
                break;
            }
        }

        if matched_count > 0 {
            for _ in 0..matched_count {
                if let Some(p) = self.pending_predictions.pop_front() {
                    if p.cols_advanced > 0 {
                        self.active_speculative_cols =
                            self.active_speculative_cols.saturating_sub(p.cols_advanced as usize);
                    }
                }
            }
            self.confidence.on_success();
        }

        // If divergence occurred or server produced unexpected non-matching output while predictions exist
        if diverged || (matched_count == 0 && !output.is_empty() && self.active_speculative_cols > 0) {
            let rollback = generate_rollback(self.active_speculative_cols);
            self.active_speculative_cols = 0;
            self.pending_predictions.clear();
            self.confidence.on_divergence();

            let mut output_to_render = Vec::with_capacity(rollback.len() + output.len());
            output_to_render.extend_from_slice(&rollback);
            output_to_render.extend_from_slice(output);

            return ServerOutputResult {
                confirmed_seq,
                had_divergence: true,
                output_to_render,
            };
        }

        ServerOutputResult {
            confirmed_seq,
            had_divergence: false,
            output_to_render: output.to_vec(),
        }
    }

    /// Handles sequence acknowledgement from server.
    pub fn handle_ack(&mut self, ack_seq: u64) {
        while let Some(front) = self.pending_predictions.front() {
            if front.id <= ack_seq {
                if let Some(p) = self.pending_predictions.pop_front() {
                    if p.cols_advanced > 0 {
                        self.active_speculative_cols =
                            self.active_speculative_cols.saturating_sub(p.cols_advanced as usize);
                    }
                }
                self.confidence.on_success();
            } else {
                break;
            }
        }
    }

    /// Resets engine state, generating any necessary rollback escape sequences.
    pub fn reset(&mut self) -> Vec<u8> {
        let rollback = generate_rollback(self.active_speculative_cols);
        self.active_speculative_cols = 0;
        self.pending_predictions.clear();
        self.confidence.reset();
        rollback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_printable_prediction_and_confirmation() {
        let mut engine = PredictionEngine::new(PredictMode::Auto, PredictStyle::Underline);

        // User types 'ls'
        let input_res = engine.process_input(b"ls");
        assert_eq!(input_res.predictions.len(), 2);
        assert_eq!(input_res.raw_input, b"ls");
        assert_eq!(input_res.speculative_render, b"\x1b[4ml\x1b[24m\x1b[4ms\x1b[24m");
        assert_eq!(engine.active_speculative_cols(), 2);
        assert_eq!(engine.pending_count(), 2);

        // Server echoes 'ls'
        let out_res = engine.process_server_output(b"ls");
        assert_eq!(out_res.had_divergence, false);
        assert_eq!(out_res.confirmed_seq, Some(2));
        assert_eq!(out_res.output_to_render, b"ls");
        assert_eq!(engine.active_speculative_cols(), 0);
        assert_eq!(engine.pending_count(), 0);
    }

    #[test]
    fn test_divergence_and_rollback() {
        let mut engine = PredictionEngine::new(PredictMode::Auto, PredictStyle::Dim);

        // User types 'cat'
        let input_res = engine.process_input(b"cat");
        assert_eq!(input_res.predictions.len(), 3);
        assert_eq!(engine.active_speculative_cols(), 3);

        // Server outputs error bell instead of echo
        let out_res = engine.process_server_output(b"\x07");
        assert_eq!(out_res.had_divergence, true);
        assert_eq!(engine.active_speculative_cols(), 0);
        assert_eq!(engine.pending_count(), 0);

        // Should include rollback sequences (\x1b[3D\x1b[K) followed by the server bell
        assert_eq!(out_res.output_to_render, b"\x1b[3D\x1b[K\x07");
    }

    #[test]
    fn test_backspace_speculative_erase() {
        let mut engine = PredictionEngine::new(PredictMode::Auto, PredictStyle::Underline);

        // Type 'a', then Backspace
        engine.process_input(b"a");
        assert_eq!(engine.active_speculative_cols(), 1);

        let input_res = engine.process_input(b"\x7f");
        assert_eq!(input_res.speculative_render, b"\x08 \x08");
        assert_eq!(engine.active_speculative_cols(), 0);
    }

    #[test]
    fn test_fullscreen_alt_screen_suppression() {
        let mut engine = PredictionEngine::new(PredictMode::Auto, PredictStyle::Underline);

        // Server enters alt screen (vim/htop)
        engine.process_server_output(b"\x1b[?1049h");
        assert!(engine.confidence().is_alt_screen());

        // Now user types while in vim
        let input_res = engine.process_input(b":w\r");
        assert_eq!(input_res.predictions.len(), 0);
        assert_eq!(input_res.speculative_render, Vec::<u8>::new());
        assert_eq!(input_res.raw_input, b":w\r");

        // Server exits alt screen
        engine.process_server_output(b"\x1b[?1049l");
        assert!(!engine.confidence().is_alt_screen());

        // Now typing predicts again
        let input_res2 = engine.process_input(b"ls");
        assert_eq!(input_res2.predictions.len(), 2);
    }

    #[test]
    fn test_password_prompt_suppression() {
        let mut engine = PredictionEngine::new(PredictMode::Auto, PredictStyle::Underline);

        // Server outputs password prompt
        engine.process_server_output(b"Password: ");
        assert!(engine.confidence().is_no_echo());

        // User enters secret password
        let input_res = engine.process_input(b"secret\r");
        assert_eq!(input_res.predictions.len(), 0);
        assert_eq!(input_res.speculative_render, Vec::<u8>::new());
    }

    #[test]
    fn test_sequence_ack_handling() {
        let mut engine = PredictionEngine::new(PredictMode::Auto, PredictStyle::Underline);

        engine.process_input(b"abc");
        assert_eq!(engine.pending_count(), 3);

        // Server acknowledges seq 2
        engine.handle_ack(2);
        assert_eq!(engine.pending_count(), 1);

        // Server acknowledges seq 3
        engine.handle_ack(3);
        assert_eq!(engine.pending_count(), 0);
    }
}

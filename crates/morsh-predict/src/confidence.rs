//! Confidence tracking and suppression heuristics for predictive local echo.

use std::time::{Duration, Instant};
use crate::style::PredictMode;

/// Confidence level indicating reliability of predictive local echo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfidenceLevel {
    /// High confidence: standard shell prompt with reliable server echo. Default.
    #[default]
    High,
    /// Tentative confidence: recovering from divergence or high jitter.
    Tentative,
    /// Suppressed: speculative echo paused due to divergence, password prompt, or fullscreen mode.
    Suppressed,
}

/// Adaptive confidence tracker evaluating prediction accuracy and terminal mode states.
#[derive(Debug)]
pub struct ConfidenceTracker {
    level: ConfidenceLevel,
    consecutive_successes: u32,
    consecutive_divergences: u32,
    alt_screen_active: bool,
    no_echo_active: bool,
    last_divergence_time: Option<Instant>,
    cooldown_duration: Duration,
    current_rtt: Option<Duration>,
}

impl Default for ConfidenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfidenceTracker {
    /// Constructs a new tracker with default high confidence.
    pub fn new() -> Self {
        Self {
            level: ConfidenceLevel::High,
            consecutive_successes: 0,
            consecutive_divergences: 0,
            alt_screen_active: false,
            no_echo_active: false,
            last_divergence_time: None,
            cooldown_duration: Duration::from_millis(500),
            current_rtt: None,
        }
    }

    /// Sets the current round-trip time for latency-adaptive prediction heuristics.
    pub fn set_rtt(&mut self, rtt: Duration) {
        self.current_rtt = Some(rtt);
    }

    /// Current round-trip time if set.
    pub fn rtt(&self) -> Option<Duration> {
        self.current_rtt
    }

    /// Custom cooldown constructor for testing or latency-adaptive tuning.
    pub fn with_cooldown(cooldown: Duration) -> Self {
        Self {
            cooldown_duration: cooldown,
            ..Self::new()
        }
    }

    /// Current confidence level.
    pub fn level(&self) -> ConfidenceLevel {
        self.level
    }

    /// Whether alternate screen buffer (fullscreen app like vim/nano/htop) is active.
    pub fn is_alt_screen(&self) -> bool {
        self.alt_screen_active
    }

    /// Whether no-echo mode (e.g. password prompt) is active.
    pub fn is_no_echo(&self) -> bool {
        self.no_echo_active
    }

    /// Determines whether the engine should perform speculative local echo.
    pub fn can_predict(&mut self, mode: PredictMode) -> bool {
        if mode == PredictMode::Never {
            return false;
        }

        // Fullscreen apps have arbitrary non-linear cursor movements; never predict
        if self.alt_screen_active {
            return false;
        }

        // Password entries or no-echo modes must never echo speculative characters
        if self.no_echo_active {
            return false;
        }

        if mode == PredictMode::Always {
            return true;
        }

        // Auto mode heuristics
        // On low-latency links (< 50ms RTT), predictive local echo is unnecessary
        // and can cause visual collisions with complex shell prompts, autosuggestions, or syntax highlighters.
        if let Some(rtt) = self.current_rtt {
            if rtt < Duration::from_millis(50) {
                return false;
            }
        }

        match self.level {
            ConfidenceLevel::High => true,
            ConfidenceLevel::Tentative => true,
            ConfidenceLevel::Suppressed => {
                if let Some(t) = self.last_divergence_time {
                    if t.elapsed() >= self.cooldown_duration {
                        // Cooldown elapsed; cautiously enter tentative mode
                        self.level = ConfidenceLevel::Tentative;
                        self.consecutive_successes = 0;
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Records a confirmed prediction where server output matched local speculation.
    pub fn on_success(&mut self) {
        self.consecutive_successes += 1;
        self.consecutive_divergences = 0;

        if self.level == ConfidenceLevel::Tentative && self.consecutive_successes >= 3 {
            self.level = ConfidenceLevel::High;
        }
    }

    /// Records a divergence where server output differed from local speculation.
    pub fn on_divergence(&mut self) {
        self.consecutive_divergences += 1;
        self.consecutive_successes = 0;
        self.last_divergence_time = Some(Instant::now());

        match self.level {
            ConfidenceLevel::High => {
                self.level = ConfidenceLevel::Tentative;
            }
            ConfidenceLevel::Tentative | ConfidenceLevel::Suppressed => {
                self.level = ConfidenceLevel::Suppressed;
            }
        }
    }

    /// Sets whether the terminal is in alternate screen buffer mode (fullscreen app).
    pub fn set_alt_screen(&mut self, active: bool) {
        self.alt_screen_active = active;
        if active {
            self.consecutive_successes = 0;
        }
    }

    /// Sets whether no-echo mode (e.g. password entry) is active.
    pub fn set_no_echo(&mut self, active: bool) {
        self.no_echo_active = active;
        if active {
            self.level = ConfidenceLevel::Suppressed;
            self.last_divergence_time = Some(Instant::now());
        } else if self.level == ConfidenceLevel::Suppressed {
            self.level = ConfidenceLevel::Tentative;
        }
    }

    /// Manually reset tracker state.
    pub fn reset(&mut self) {
        self.level = ConfidenceLevel::High;
        self.consecutive_successes = 0;
        self.consecutive_divergences = 0;
        self.alt_screen_active = false;
        self.no_echo_active = false;
        self.last_divergence_time = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_initial_state() {
        let mut tracker = ConfidenceTracker::new();
        assert_eq!(tracker.level(), ConfidenceLevel::High);
        assert!(tracker.can_predict(PredictMode::Auto));
    }

    #[test]
    fn test_confidence_degradation_and_recovery() {
        let mut tracker = ConfidenceTracker::with_cooldown(Duration::from_millis(50));

        // First divergence: High -> Tentative
        tracker.on_divergence();
        assert_eq!(tracker.level(), ConfidenceLevel::Tentative);
        assert!(tracker.can_predict(PredictMode::Auto));

        // Second divergence: Tentative -> Suppressed
        tracker.on_divergence();
        assert_eq!(tracker.level(), ConfidenceLevel::Suppressed);
        assert!(!tracker.can_predict(PredictMode::Auto));

        // Wait for cooldown
        std::thread::sleep(Duration::from_millis(60));
        assert!(tracker.can_predict(PredictMode::Auto));
        assert_eq!(tracker.level(), ConfidenceLevel::Tentative);

        // 3 consecutive successes restore High confidence
        tracker.on_success();
        tracker.on_success();
        assert_eq!(tracker.level(), ConfidenceLevel::Tentative);
        tracker.on_success();
        assert_eq!(tracker.level(), ConfidenceLevel::High);
    }

    #[test]
    fn test_alt_screen_suppression() {
        let mut tracker = ConfidenceTracker::new();
        assert!(tracker.can_predict(PredictMode::Auto));

        tracker.set_alt_screen(true);
        assert!(!tracker.can_predict(PredictMode::Auto));
        assert!(!tracker.can_predict(PredictMode::Always));

        tracker.set_alt_screen(false);
        assert!(tracker.can_predict(PredictMode::Auto));
    }

    #[test]
    fn test_no_echo_suppression() {
        let mut tracker = ConfidenceTracker::new();
        assert!(tracker.can_predict(PredictMode::Auto));

        tracker.set_no_echo(true);
        assert_eq!(tracker.level(), ConfidenceLevel::Suppressed);
        assert!(!tracker.can_predict(PredictMode::Auto));

        tracker.set_no_echo(false);
        assert_eq!(tracker.level(), ConfidenceLevel::Tentative);
        assert!(tracker.can_predict(PredictMode::Auto));
    }

    #[test]
    fn test_latency_adaptive_prediction() {
        let mut tracker = ConfidenceTracker::new();
        // Under 50ms RTT, auto mode suppresses prediction
        tracker.set_rtt(Duration::from_millis(10));
        assert!(!tracker.can_predict(PredictMode::Auto));
        // But Always mode still predicts
        assert!(tracker.can_predict(PredictMode::Always));

        // At or above 50ms RTT, auto mode predicts
        tracker.set_rtt(Duration::from_millis(50));
        assert!(tracker.can_predict(PredictMode::Auto));
        tracker.set_rtt(Duration::from_millis(150));
        assert!(tracker.can_predict(PredictMode::Auto));
    }
}

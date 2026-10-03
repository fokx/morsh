//! Speculative local echo visual styling and modes.

use std::str::FromStr;
use serde::{Deserialize, Serialize};

/// Visual feedback styling applied to speculatively echoed characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PredictStyle {
    /// Underline speculative characters (`\x1b[4m ... \x1b[24m`). Default.
    #[default]
    Underline,
    /// Dim / faint speculative characters (`\x1b[2m ... \x1b[22m`).
    Dim,
    /// Plain output with no visual style applied.
    None,
}

impl PredictStyle {
    /// ANSI escape sequence to start styling.
    pub fn start_code(&self) -> &'static str {
        match self {
            PredictStyle::Underline => "\x1b[4m",
            PredictStyle::Dim => "\x1b[2m",
            PredictStyle::None => "",
        }
    }

    /// ANSI escape sequence to stop styling without clearing existing color attributes.
    pub fn end_code(&self) -> &'static str {
        match self {
            PredictStyle::Underline => "\x1b[24m",
            PredictStyle::Dim => "\x1b[22m",
            PredictStyle::None => "",
        }
    }

    /// Renders text wrapped in this visual style.
    pub fn render(&self, text: &str) -> Vec<u8> {
        match self {
            PredictStyle::None => text.as_bytes().to_vec(),
            _ => {
                let mut out = Vec::with_capacity(self.start_code().len() + text.len() + self.end_code().len());
                out.extend_from_slice(self.start_code().as_bytes());
                out.extend_from_slice(text.as_bytes());
                out.extend_from_slice(self.end_code().as_bytes());
                out
            }
        }
    }
}

impl FromStr for PredictStyle {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "underline" => Ok(PredictStyle::Underline),
            "dim" | "faint" => Ok(PredictStyle::Dim),
            "none" | "plain" => Ok(PredictStyle::None),
            other => Err(format!("Unknown predict style '{}', expected 'underline', 'dim', or 'none'", other)),
        }
    }
}

/// Operational prediction mode for the client session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PredictMode {
    /// Automatic prediction using latency, terminal modes, and confidence tracking. Default.
    #[default]
    Auto,
    /// Always speculatively echo printable characters (except in alternate screen buffer).
    Always,
    /// Completely disable speculative local echo.
    Never,
}

impl FromStr for PredictMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(PredictMode::Auto),
            "always" | "on" | "true" => Ok(PredictMode::Always),
            "never" | "off" | "false" => Ok(PredictMode::Never),
            other => Err(format!("Unknown predict mode '{}', expected 'auto', 'always', or 'never'", other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predict_style_render() {
        let text = "hello";
        let underline = PredictStyle::Underline.render(text);
        assert_eq!(underline, b"\x1b[4mhello\x1b[24m");

        let dim = PredictStyle::Dim.render(text);
        assert_eq!(dim, b"\x1b[2mhello\x1b[22m");

        let none = PredictStyle::None.render(text);
        assert_eq!(none, b"hello");
    }

    #[test]
    fn test_predict_style_parsing() {
        assert_eq!(PredictStyle::from_str("underline").unwrap(), PredictStyle::Underline);
        assert_eq!(PredictStyle::from_str("dim").unwrap(), PredictStyle::Dim);
        assert_eq!(PredictStyle::from_str("none").unwrap(), PredictStyle::None);
        assert!(PredictStyle::from_str("invalid").is_err());
    }

    #[test]
    fn test_predict_mode_parsing() {
        assert_eq!(PredictMode::from_str("auto").unwrap(), PredictMode::Auto);
        assert_eq!(PredictMode::from_str("always").unwrap(), PredictMode::Always);
        assert_eq!(PredictMode::from_str("never").unwrap(), PredictMode::Never);
        assert!(PredictMode::from_str("invalid").is_err());
    }
}

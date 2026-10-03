//! Rollback sequence generation for speculative prediction divergence.

/// Generates the ANSI escape sequences required to undo speculative display modifications.
///
/// Moves cursor back by `cols` positions and clears to the end of the line (`\x1b[K`).
pub fn generate_rollback(cols: usize) -> Vec<u8> {
    if cols == 0 {
        return Vec::new();
    }

    let mut seq = Vec::new();
    if cols == 1 {
        seq.extend_from_slice(b"\x08 \x08");
    } else {
        seq.extend_from_slice(format!("\x1b[{}D\x1b[K", cols).as_bytes());
    }
    seq
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rollback_zero() {
        assert_eq!(generate_rollback(0), Vec::<u8>::new());
    }

    #[test]
    fn test_generate_rollback_single_col() {
        assert_eq!(generate_rollback(1), b"\x08 \x08");
    }

    #[test]
    fn test_generate_rollback_multi_cols() {
        assert_eq!(generate_rollback(5), b"\x1b[5D\x1b[K");
    }
}

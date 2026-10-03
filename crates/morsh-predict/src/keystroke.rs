//! Keystroke classification and parser for predictive local echo.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Keystroke {
    /// Printable Unicode character (e.g. 'a', 'Z', '9', ' ', '$').
    Printable(char),
    /// Backspace (0x08 or 0x7F).
    Backspace,
    /// Cursor navigation: Left arrow (\x1b[D or \x1bOD).
    CursorLeft,
    /// Cursor navigation: Right arrow (\x1b[C or \x1bOC).
    CursorRight,
    /// Newline / Enter (\r or \n).
    Newline,
    /// Unpredicted sequence (Ctrl keys, Tab, Escape, function keys, etc.).
    Unpredicted(Vec<u8>),
}

impl Keystroke {
    /// Whether this keystroke can be speculatively predicted.
    pub fn is_predictable(&self) -> bool {
        matches!(
            self,
            Keystroke::Printable(_)
                | Keystroke::Backspace
                | Keystroke::CursorLeft
                | Keystroke::CursorRight
        )
    }

    /// The raw bytes corresponding to this keystroke.
    pub fn raw_bytes(&self) -> Vec<u8> {
        match self {
            Keystroke::Printable(c) => {
                let mut buf = [0u8; 4];
                c.encode_utf8(&mut buf).as_bytes().to_vec()
            }
            Keystroke::Backspace => vec![0x7f],
            Keystroke::CursorLeft => b"\x1b[D".to_vec(),
            Keystroke::CursorRight => b"\x1b[C".to_vec(),
            Keystroke::Newline => vec![b'\r'],
            Keystroke::Unpredicted(bytes) => bytes.clone(),
        }
    }
}

/// Parses a byte buffer into a sequence of classified keystrokes.
pub fn parse_keystrokes(input: &[u8]) -> Vec<Keystroke> {
    let mut results = Vec::new();
    let mut i = 0;

    while i < input.len() {
        let b = input[i];

        // Check for ANSI escape sequences starting with 0x1b
        if b == 0x1b {
            if i + 2 < input.len() && input[i + 1] == b'[' {
                match input[i + 2] {
                    b'D' => {
                        results.push(Keystroke::CursorLeft);
                        i += 3;
                        continue;
                    }
                    b'C' => {
                        results.push(Keystroke::CursorRight);
                        i += 3;
                        continue;
                    }
                    _ => {}
                }
            } else if i + 2 < input.len() && input[i + 1] == b'O' {
                match input[i + 2] {
                    b'D' => {
                        results.push(Keystroke::CursorLeft);
                        i += 3;
                        continue;
                    }
                    b'C' => {
                        results.push(Keystroke::CursorRight);
                        i += 3;
                        continue;
                    }
                    _ => {}
                }
            }

            // Other escape sequences are treated as unpredicted
            let start = i;
            i += 1;
            while i < input.len() {
                let next = input[i];
                i += 1;
                // Sequences usually terminate with a letter or ~
                if (next >= b'A' && next <= b'Z') || (next >= b'a' && next <= b'z') || next == b'~' {
                    break;
                }
            }
            results.push(Keystroke::Unpredicted(input[start..i].to_vec()));
            continue;
        }

        // Backspace
        if b == 0x08 || b == 0x7f {
            results.push(Keystroke::Backspace);
            i += 1;
            continue;
        }

        // Newline
        if b == b'\r' || b == b'\n' {
            results.push(Keystroke::Newline);
            i += 1;
            continue;
        }

        // Control characters (< 0x20)
        if b < 0x20 {
            results.push(Keystroke::Unpredicted(vec![b]));
            i += 1;
            continue;
        }

        // UTF-8 sequence decoding: decode a single character per iteration
        let remaining = &input[i..];
        match std::str::from_utf8(remaining) {
            Ok(valid_str) => {
                if let Some(c) = valid_str.chars().next() {
                    let c_len = c.len_utf8();
                    results.push(Keystroke::Printable(c));
                    i += c_len;
                } else {
                    break;
                }
            }
            Err(e) => {
                let valid_up_to = e.valid_up_to();
                if valid_up_to > 0 {
                    let valid_str = std::str::from_utf8(&remaining[..valid_up_to]).unwrap();
                    if let Some(c) = valid_str.chars().next() {
                        let c_len = c.len_utf8();
                        results.push(Keystroke::Printable(c));
                        i += c_len;
                    }
                } else if let Some(error_len) = e.error_len() {
                    results.push(Keystroke::Unpredicted(input[i..i + error_len].to_vec()));
                    i += error_len;
                } else {
                    // Incomplete sequence at end of buffer
                    results.push(Keystroke::Unpredicted(input[i..].to_vec()));
                    i = input.len();
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_printable_ascii() {
        let strokes = parse_keystrokes(b"ls -la\r");
        assert_eq!(
            strokes,
            vec![
                Keystroke::Printable('l'),
                Keystroke::Printable('s'),
                Keystroke::Printable(' '),
                Keystroke::Printable('-'),
                Keystroke::Printable('l'),
                Keystroke::Printable('a'),
                Keystroke::Newline,
            ]
        );
    }

    #[test]
    fn test_parse_unicode_utf8() {
        let strokes = parse_keystrokes("echo 你好".as_bytes());
        assert_eq!(
            strokes,
            vec![
                Keystroke::Printable('e'),
                Keystroke::Printable('c'),
                Keystroke::Printable('h'),
                Keystroke::Printable('o'),
                Keystroke::Printable(' '),
                Keystroke::Printable('你'),
                Keystroke::Printable('好'),
            ]
        );
    }

    #[test]
    fn test_parse_backspace_and_arrows() {
        let strokes = parse_keystrokes(b"\x7f\x1b[D\x1b[C\x08");
        assert_eq!(
            strokes,
            vec![
                Keystroke::Backspace,
                Keystroke::CursorLeft,
                Keystroke::CursorRight,
                Keystroke::Backspace,
            ]
        );
    }

    #[test]
    fn test_parse_unpredicted_controls() {
        let strokes = parse_keystrokes(b"\x03\t\x1b[15~");
        assert_eq!(
            strokes,
            vec![
                Keystroke::Unpredicted(vec![0x03]),
                Keystroke::Unpredicted(vec![0x09]),
                Keystroke::Unpredicted(b"\x1b[15~".to_vec()),
            ]
        );
    }
}

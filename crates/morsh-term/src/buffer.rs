//! Virtual terminal state tracking and snapshot recovery (vt100 based).
//! Maintains an active grid model of screen cells, cursor positions, and ANSI attributes.

use std::sync::{Arc, Mutex};

/// Virtual terminal state buffer backed by `vt100::Parser`.
/// Tracks terminal screen cells, cursor coordinates, and scrollback.
pub struct TerminalStateBuffer {
    parser: vt100::Parser,
    cols: u16,
    rows: u16,
}

impl TerminalStateBuffer {
    /// Creates a new terminal state buffer with given columns, rows, and scrollback capacity.
    pub fn new(cols: u16, rows: u16, scrollback: usize) -> Self {
        let parser = vt100::Parser::new(rows, cols, scrollback);
        Self { parser, cols, rows }
    }

    /// Processes raw terminal escape sequences and characters output from a PTY.
    pub fn process(&mut self, data: &[u8]) {
        self.parser.process(data);
    }

    /// Resizes the virtual terminal grid.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
        self.parser.set_size(rows, cols);
    }

    /// Current terminal dimensions as `(cols, rows)`.
    pub fn size(&self) -> (u16, u16) {
        let (rows, cols) = self.parser.screen().size();
        (cols, rows)
    }

    /// Current cursor position as `(cursor_x, cursor_y)` (0-indexed: col, row).
    pub fn cursor_position(&self) -> (u16, u16) {
        let (row, col) = self.parser.screen().cursor_position();
        (col, row)
    }

    /// Returns whether the cursor is currently marked hidden.
    pub fn hide_cursor(&self) -> bool {
        self.parser.screen().hide_cursor()
    }

    /// Returns plain text contents of the active screen without formatting.
    pub fn text_contents(&self) -> String {
        self.parser.screen().contents()
    }

    /// Returns ANSI formatted contents representing all screen rows.
    pub fn contents_formatted(&self) -> Vec<u8> {
        self.parser.screen().contents_formatted()
    }

    /// Generates a complete ANSI snapshot sequence to immediately redraw the screen.
    /// Resets formatting, clears screen, writes formatted cells, and repositions cursor.
    pub fn snapshot(&self) -> Vec<u8> {
        let mut snapshot = Vec::with_capacity(4096);

        // 1. Hide cursor while drawing
        snapshot.extend_from_slice(b"\x1b[?25l");

        // 2. Reset text attributes, clear entire screen, and move cursor to home (1,1)
        snapshot.extend_from_slice(b"\x1b[0m\x1b[2J\x1b[H");

        // 3. Write formatted contents
        let formatted = self.parser.screen().contents_formatted();
        snapshot.extend_from_slice(&formatted);

        // 4. Position cursor at the active coordinates (ANSI 1-indexed)
        let (row, col) = self.parser.screen().cursor_position();
        let cursor_cmd = format!("\x1b[{};{}H", row + 1, col + 1);
        snapshot.extend_from_slice(cursor_cmd.as_bytes());

        // 5. Restore cursor visibility if not explicitly hidden
        if !self.parser.screen().hide_cursor() {
            snapshot.extend_from_slice(b"\x1b[?25h");
        }

        snapshot
    }
}

/// Thread-safe shared terminal state buffer handle.
pub type SharedTerminalBuffer = Arc<Mutex<TerminalStateBuffer>>;

/// Helper to construct a new thread-safe shared terminal buffer.
pub fn new_shared_buffer(cols: u16, rows: u16, scrollback: usize) -> SharedTerminalBuffer {
    Arc::new(Mutex::new(TerminalStateBuffer::new(cols, rows, scrollback)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_creation_and_size() {
        let buffer = TerminalStateBuffer::new(80, 24, 1000);
        assert_eq!(buffer.size(), (80, 24));
        assert_eq!(buffer.cursor_position(), (0, 0));
    }

    #[test]
    fn test_buffer_processing_and_text_contents() {
        let mut buffer = TerminalStateBuffer::new(80, 24, 1000);
        buffer.process(b"Hello morsh persistence!\r\nSecond line");
        let text = buffer.text_contents();
        assert!(text.contains("Hello morsh persistence!"));
        assert!(text.contains("Second line"));
        let (col, row) = buffer.cursor_position();
        assert_eq!(row, 1);
        assert_eq!(col, "Second line".len() as u16);
    }

    #[test]
    fn test_buffer_resize() {
        let mut buffer = TerminalStateBuffer::new(80, 24, 1000);
        buffer.process(b"Testing resize");
        buffer.resize(120, 40);
        assert_eq!(buffer.size(), (120, 40));
    }

    #[test]
    fn test_buffer_snapshot_reproduction() {
        let mut original = TerminalStateBuffer::new(80, 24, 1000);
        original.process(b"\x1b[1;32mGreen Text\x1b[0m\r\nLine 2");

        let snapshot_bytes = original.snapshot();
        assert!(!snapshot_bytes.is_empty());

        // Parse snapshot in a fresh parser to ensure it accurately reproduces the screen
        let mut target = TerminalStateBuffer::new(80, 24, 1000);
        target.process(&snapshot_bytes);

        assert!(target.text_contents().contains("Green Text"));
        assert!(target.text_contents().contains("Line 2"));
        assert_eq!(target.cursor_position(), original.cursor_position());
    }
}

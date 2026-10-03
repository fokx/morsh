//! PTY and Terminal Emulation subsystem for morsh.
//! Implements server-side pseudo-terminal allocation (portable-pty), async I/O bridging,
//! and window resize signaling.

pub mod buffer;
pub mod config;
pub mod error;
pub mod io;
pub mod pty;
pub mod session;

pub use buffer::{new_shared_buffer, SharedTerminalBuffer, TerminalStateBuffer};
pub use config::{resolve_shell, PtyConfig};
pub use error::{Result as TermResult, TermError};
pub use io::{AsyncPtyReader, AsyncPtyWriter};
pub use portable_pty::ExitStatus;
pub use pty::{PtyHandle, PtySession};
pub use session::{PersistentSession, SessionRegistry};

pub fn term_subsystem_version() -> &'static str {
    "0.1.0"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_vt100_api() {
        let mut parser = vt100::Parser::new(24, 80, 1000);
        parser.process(b"Hello world!\r\nLine 2");
        let screen = parser.screen();
        assert_eq!(screen.size(), (24, 80));
        let (row, col) = screen.cursor_position();
        assert_eq!(row, 1);
        assert_eq!(col, 6);
        let formatted = screen.contents_formatted();
        assert!(!formatted.is_empty());
    }

    #[test]
    fn test_resolve_default_shell() {
        let shell = resolve_shell(None, None);
        assert!(!shell.is_empty());
        assert!(std::path::Path::new(&shell).exists());

        // Explicit shell takes priority
        let explicit = resolve_shell(None, Some("/bin/sh"));
        assert_eq!(explicit, "/bin/sh");
    }

    #[tokio::test]
    async fn test_pty_spawn_and_read_output() {
        let mut config = PtyConfig::default();
        config.command = Some(vec![
            "/bin/sh".into(),
            "-c".into(),
            "echo 'morsh-pty-test-output'".into(),
        ]);

        let session = PtySession::spawn(&config).unwrap();
        let (_handle, mut reader, _writer) = session.split();

        let mut output = Vec::new();
        let mut buf = [0u8; 1024];

        let timeout = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                res = reader.read(&mut buf) => {
                    match res {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            output.extend_from_slice(&buf[..n]);
                            if output.windows(b"morsh-pty-test-output".len()).any(|w| w == b"morsh-pty-test-output") {
                                break;
                            }
                        }
                        Err(e) => panic!("Read error: {}", e),
                    }
                }
                _ = &mut timeout => {
                    panic!("Timed out waiting for PTY output");
                }
            }
        }

        let output_str = String::from_utf8_lossy(&output);
        assert!(
            output_str.contains("morsh-pty-test-output"),
            "Expected output to contain 'morsh-pty-test-output', got: {}",
            output_str
        );
    }

    #[tokio::test]
    async fn test_pty_write_and_echo() {
        let mut config = PtyConfig::default();
        config.command = Some(vec!["/bin/cat".into()]);

        let session = PtySession::spawn(&config).unwrap();
        let (handle, mut reader, mut writer) = session.split();

        // Write input to cat
        let test_payload = b"echo-ping-12345\n";
        writer.write_all(test_payload).await.unwrap();

        let mut output = Vec::new();
        let mut buf = [0u8; 1024];

        let timeout = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                res = reader.read(&mut buf) => {
                    match res {
                        Ok(0) => break,
                        Ok(n) => {
                            output.extend_from_slice(&buf[..n]);
                            if output.windows(b"echo-ping-12345".len()).any(|w| w == b"echo-ping-12345") {
                                break;
                            }
                        }
                        Err(e) => panic!("Read error: {}", e),
                    }
                }
                _ = &mut timeout => {
                    panic!("Timed out waiting for echoed data from cat");
                }
            }
        }

        let output_str = String::from_utf8_lossy(&output);
        assert!(output_str.contains("echo-ping-12345"));

        // Clean up child
        let _ = handle.kill();
    }

    #[test]
    fn test_pty_resize() {
        let mut config = PtyConfig::default();
        config.cols = 80;
        config.rows = 24;
        config.command = Some(vec!["/bin/sleep".into(), "10".into()]);

        let session = PtySession::spawn(&config).unwrap();
        let handle = session.handle();

        // Test resizing
        assert!(handle.resize(120, 40).is_ok());
        assert!(handle.resize_pixels(140, 50, 1920, 1080).is_ok());

        let _ = handle.kill();
    }

    #[test]
    fn test_pty_kill_and_status() {
        let mut config = PtyConfig::default();
        config.command = Some(vec!["/bin/sleep".into(), "60".into()]);

        let session = PtySession::spawn(&config).unwrap();
        let handle = session.handle();

        assert!(handle.process_id().is_some());
        assert!(handle.kill().is_ok());

        // Process should exit shortly
        std::thread::sleep(Duration::from_millis(100));
        let status = handle.try_wait().unwrap();
        assert!(status.is_some());
    }
}

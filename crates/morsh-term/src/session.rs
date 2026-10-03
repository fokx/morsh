//! Detached session persistence and registry (Mosh style).
//! Manages persistent PTY lifecycles decoupled from transport connections.

use crate::buffer::{new_shared_buffer, SharedTerminalBuffer};
use crate::config::PtyConfig;
use crate::error::{Result, TermError};
use crate::io::AsyncPtyWriter;
use crate::pty::{PtyHandle, PtySession};
use morsh_core::protocol::SessionInfo;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};

/// Represents an active or detached persistent terminal session on the server.
pub struct PersistentSession {
    session_id: [u8; 16],
    resumption_token: [u8; 16],
    user: String,
    created_at_secs: u64,
    handle: PtyHandle,
    buffer: SharedTerminalBuffer,
    writer: Arc<Mutex<Option<AsyncPtyWriter>>>,
    attached_tx: Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>>,
    exited: Arc<AtomicBool>,
}

impl PersistentSession {
    /// Spawns a new persistent PTY session.
    pub fn spawn(
        session_id: [u8; 16],
        resumption_token: [u8; 16],
        user: String,
        config: &PtyConfig,
    ) -> Result<Self> {
        let pty_session = PtySession::spawn(config)?;
        let (handle, mut reader, writer) = pty_session.split();

        let buffer = new_shared_buffer(config.cols, config.rows, 2000);
        let buffer_for_reader = Arc::clone(&buffer);

        let attached_tx: Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>> = Arc::new(Mutex::new(None));
        let attached_tx_for_reader = Arc::clone(&attached_tx);

        let exited = Arc::new(AtomicBool::new(false));
        let exited_for_reader = Arc::clone(&exited);

        // Spawn background reader loop that continuously updates the virtual terminal buffer
        // and broadcasts live output to any attached client.
        tokio::spawn(async move {
            while let Some(chunk) = reader.read_chunk().await {
                // 1. Process output into vt100 virtual terminal state buffer
                if let Ok(mut buf) = buffer_for_reader.lock() {
                    buf.process(&chunk);
                }

                // 2. Forward to currently attached client if present
                if let Some(ref tx) = *attached_tx_for_reader.lock().await {
                    if tx.send(chunk).await.is_err() {
                        debug!("Attached client receiver dropped");
                    }
                }
            }

            debug!("Persistent PTY output closed; marking session exited");
            exited_for_reader.store(true, Ordering::SeqCst);

            // Close attached client channel if active
            *attached_tx_for_reader.lock().await = None;
        });

        let created_at_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            session_id,
            resumption_token,
            user,
            created_at_secs,
            handle,
            buffer,
            writer: Arc::new(Mutex::new(Some(writer))),
            attached_tx,
            exited,
        })
    }

    /// 128-bit session identifier.
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// 128-bit cryptographic resumption token.
    pub fn resumption_token(&self) -> [u8; 16] {
        self.resumption_token
    }

    /// User owning this persistent session.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// UNIX timestamp when the session was created.
    pub fn created_at_secs(&self) -> u64 {
        self.created_at_secs
    }

    /// Control handle for PTY (process status, signals, resizing).
    pub fn handle(&self) -> &PtyHandle {
        &self.handle
    }

    /// Whether the underlying shell/process has terminated.
    pub fn has_exited(&self) -> bool {
        self.exited.load(Ordering::SeqCst) || self.handle.try_wait().ok().flatten().is_some()
    }

    /// Whether a client is currently attached.
    pub async fn is_attached(&self) -> bool {
        self.attached_tx.lock().await.is_some()
    }

    /// Attaches a client to receive real-time PTY output.
    /// Replaces any existing attached client (e.g. upon connection migration / takeover).
    pub async fn attach(&self, output_tx: mpsc::Sender<Vec<u8>>) {
        let mut guard = self.attached_tx.lock().await;
        *guard = Some(output_tx);
        debug!("Attached client to persistent session");
    }

    /// Detaches the current client, leaving the PTY running in the background.
    pub async fn detach(&self) {
        let mut guard = self.attached_tx.lock().await;
        *guard = None;
        info!("Detached client from persistent session; PTY continues in background");
    }

    /// Writes raw input bytes from an attached client into the PTY stdin.
    pub async fn write_input(&self, data: &[u8]) -> std::io::Result<()> {
        if let Some(ref writer) = *self.writer.lock().await {
            writer.write_bytes(data).await
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "PTY writer is closed",
            ))
        }
    }

    /// Resizes both the OS pseudo-terminal and the virtual terminal state buffer.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.handle.resize(cols, rows)?;
        if let Ok(mut buf) = self.buffer.lock() {
            buf.resize(cols, rows);
        }
        Ok(())
    }

    /// Generates the complete ANSI screen snapshot sequence for fast client recovery.
    pub fn snapshot(&self) -> Vec<u8> {
        if let Ok(buf) = self.buffer.lock() {
            buf.snapshot()
        } else {
            Vec::new()
        }
    }

    /// Returns the plain text contents of the screen grid.
    pub fn text_contents(&self) -> String {
        if let Ok(buf) = self.buffer.lock() {
            buf.text_contents()
        } else {
            String::new()
        }
    }

    /// Current cursor position `(cursor_x, cursor_y)`.
    pub fn cursor_position(&self) -> (u16, u16) {
        if let Ok(buf) = self.buffer.lock() {
            buf.cursor_position()
        } else {
            (0, 0)
        }
    }

    /// Current terminal grid dimensions `(cols, rows)`.
    pub fn size(&self) -> (u16, u16) {
        if let Ok(buf) = self.buffer.lock() {
            buf.size()
        } else {
            (80, 24)
        }
    }

    /// Terminates the child process.
    pub fn kill(&self) -> Result<()> {
        self.handle.kill()
    }

    /// Exports session metadata for list queries.
    pub async fn to_session_info(&self) -> SessionInfo {
        let (cols, rows) = self.size();
        let is_attached = self.is_attached().await;
        SessionInfo {
            session_id: self.session_id,
            user: self.user.clone(),
            created_at_secs: self.created_at_secs,
            cols,
            rows,
            is_attached,
        }
    }
}

/// Global registry of persistent sessions on the server.
#[derive(Clone, Default)]
pub struct SessionRegistry {
    sessions: Arc<RwLock<HashMap<[u8; 16], Arc<PersistentSession>>>>,
}

impl SessionRegistry {
    /// Creates a new empty session registry.
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Spawns and registers a new persistent session.
    pub async fn create_session(
        &self,
        session_id: [u8; 16],
        resumption_token: [u8; 16],
        user: String,
        config: &PtyConfig,
    ) -> Result<Arc<PersistentSession>> {
        let session = Arc::new(PersistentSession::spawn(
            session_id,
            resumption_token,
            user,
            config,
        )?);

        let mut map = self.sessions.write().await;
        map.insert(session_id, Arc::clone(&session));
        info!(
            session_id = %hex_encode(&session_id),
            "Registered new persistent session in registry"
        );
        Ok(session)
    }

    /// Retrieves an existing session by ID without checking credentials.
    pub async fn get(&self, session_id: &[u8; 16]) -> Option<Arc<PersistentSession>> {
        let map = self.sessions.read().await;
        map.get(session_id).cloned()
    }

    /// Validates resumption credentials and returns the persistent session.
    pub async fn resume(
        &self,
        session_id: &[u8; 16],
        token: &[u8; 16],
    ) -> Result<Arc<PersistentSession>> {
        let map = self.sessions.read().await;
        let session = map.get(session_id).cloned().ok_or_else(|| {
            TermError::SessionNotFound(format!("Session {} not found", hex_encode(session_id)))
        })?;

        if session.has_exited() {
            return Err(TermError::Terminated);
        }

        if &session.resumption_token() != token {
            warn!(
                session_id = %hex_encode(session_id),
                "Resumption rejected: cryptographic token mismatch"
            );
            return Err(TermError::SessionTokenMismatch);
        }

        info!(
            session_id = %hex_encode(session_id),
            "Cryptographic token validated; resuming persistent session"
        );
        Ok(session)
    }

    /// Detaches the client from the specified session.
    pub async fn detach(&self, session_id: &[u8; 16]) -> Result<()> {
        let map = self.sessions.read().await;
        if let Some(session) = map.get(session_id) {
            session.detach().await;
            Ok(())
        } else {
            Err(TermError::SessionNotFound(hex_encode(session_id)))
        }
    }

    /// Removes a session from the registry and terminates its process.
    pub async fn remove(&self, session_id: &[u8; 16]) -> Option<Arc<PersistentSession>> {
        let mut map = self.sessions.write().await;
        if let Some(session) = map.remove(session_id) {
            let _ = session.kill();
            info!(session_id = %hex_encode(session_id), "Removed persistent session");
            Some(session)
        } else {
            None
        }
    }

    /// Lists active persistent sessions, optionally filtering by username.
    pub async fn list(&self, user_filter: Option<&str>) -> Vec<SessionInfo> {
        let map = self.sessions.read().await;
        let mut list = Vec::new();
        for session in map.values() {
            if !session.has_exited() {
                if let Some(filter) = user_filter {
                    if session.user() != filter && filter != "unauthenticated" {
                        continue;
                    }
                }
                list.push(session.to_session_info().await);
            }
        }
        list
    }

    /// Reaps sessions where the shell process has already exited.
    pub async fn reap_dead_sessions(&self) {
        let mut map = self.sessions.write().await;
        map.retain(|id, session| {
            let dead = session.has_exited();
            if dead {
                debug!(session_id = %hex_encode(id), "Reaping terminated persistent session");
            }
            !dead
        });
    }

    /// Total count of registered sessions.
    pub async fn count(&self) -> usize {
        let map = self.sessions.read().await;
        map.len()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_persistent_session_spawn_and_background_execution() {
        let session_id = [10u8; 16];
        let token = [20u8; 16];

        let mut config = PtyConfig::default();
        config.command = Some(vec![
            "/bin/sh".into(),
            "-c".into(),
            "echo 'STARTED'; sleep 0.1; echo 'BACKGROUND_OUTPUT'; sleep 5".into(),
        ]);

        let session =
            PersistentSession::spawn(session_id, token, "test_user".into(), &config).unwrap();

        // Initially no client is attached
        assert!(!session.is_attached().await);

        // Wait a bit for the script to print output in background
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Terminal buffer should have captured the background output even though no client was attached!
        let text = session.text_contents();
        assert!(text.contains("STARTED"), "Expected 'STARTED' in text, got: {}", text);
        assert!(
            text.contains("BACKGROUND_OUTPUT"),
            "Expected 'BACKGROUND_OUTPUT' in text, got: {}",
            text
        );

        let snapshot = session.snapshot();
        assert!(!snapshot.is_empty());

        let _ = session.kill();
    }

    #[tokio::test]
    async fn test_session_registry_workflow() {
        let registry = SessionRegistry::new();
        let session_id = [1u8; 16];
        let token = [2u8; 16];

        let mut config = PtyConfig::default();
        config.command = Some(vec!["/bin/cat".into()]);

        let session = registry
            .create_session(session_id, token, "alice".into(), &config)
            .await
            .unwrap();

        assert_eq!(registry.count().await, 1);

        // Positive resume
        let resumed = registry.resume(&session_id, &token).await.unwrap();
        assert_eq!(resumed.session_id(), session_id);

        // Resume with invalid token
        let wrong_token = [9u8; 16];
        let err = registry.resume(&session_id, &wrong_token).await;
        assert!(matches!(err, Err(TermError::SessionTokenMismatch)));

        // Resume nonexistent session
        let nonexistent = [99u8; 16];
        let err = registry.resume(&nonexistent, &token).await;
        assert!(matches!(err, Err(TermError::SessionNotFound(_))));

        // List sessions
        let list = registry.list(Some("alice")).await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].user, "alice");

        // Detach & Remove
        registry.detach(&session_id).await.unwrap();
        let removed = registry.remove(&session_id).await;
        assert!(removed.is_some());
        assert_eq!(registry.count().await, 0);

        let _ = session.kill();
    }
}

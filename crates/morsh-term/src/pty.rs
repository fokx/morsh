use crate::config::{resolve_shell, PtyConfig};
use crate::error::{TermError, Result};
use crate::io::{AsyncPtyReader, AsyncPtyWriter};
use portable_pty::{
    native_pty_system, Child, ChildKiller, CommandBuilder, ExitStatus, MasterPty, PtySize,
};
use std::sync::{Arc, Mutex};
use tracing::{debug, info};

/// Cloneable handle to manage an active PTY session (resizing, signaling, process monitoring).
#[derive(Clone)]
pub struct PtyHandle {
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    child: Arc<Mutex<Box<dyn Child + Send + Sync>>>,
    killer: Arc<Mutex<Box<dyn ChildKiller + Send + Sync>>>,
    process_id: Option<u32>,
}

impl PtyHandle {
    /// Resizes the pseudo-terminal window columns and rows.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.resize_pixels(cols, rows, 0, 0)
    }

    /// Resizes the pseudo-terminal with explicit pixel dimensions.
    pub fn resize_pixels(
        &self,
        cols: u16,
        rows: u16,
        pixel_width: u16,
        pixel_height: u16,
    ) -> Result<()> {
        let size = PtySize {
            rows,
            cols,
            pixel_width,
            pixel_height,
        };
        let master = self
            .master
            .lock()
            .map_err(|e| TermError::Resize(format!("Mutex lock error: {}", e)))?;
        master
            .resize(size)
            .map_err(|e| TermError::Resize(e.to_string()))?;
        debug!(cols, rows, "Propagated PTY window resize");
        Ok(())
    }

    /// Checks if the child process has exited without blocking.
    pub fn try_wait(&self) -> Result<Option<ExitStatus>> {
        let mut child = self
            .child
            .lock()
            .map_err(|e| TermError::Other(format!("Mutex lock error: {}", e)))?;
        child.try_wait().map_err(TermError::Io)
    }

    /// Waits for the child process to terminate, blocking the current thread.
    pub fn wait(&self) -> Result<ExitStatus> {
        let mut child = self
            .child
            .lock()
            .map_err(|e| TermError::Other(format!("Mutex lock error: {}", e)))?;
        child.wait().map_err(TermError::Io)
    }

    /// Sends a termination signal to the child process.
    pub fn kill(&self) -> Result<()> {
        let mut killer = self
            .killer
            .lock()
            .map_err(|e| TermError::Other(format!("Mutex lock error: {}", e)))?;
        killer.kill().map_err(TermError::Io)
    }

    /// Returns the OS process ID of the child process if available.
    pub fn process_id(&self) -> Option<u32> {
        self.process_id
    }
}

/// Represents an active interactive PTY session on the server.
pub struct PtySession {
    handle: PtyHandle,
    reader: Option<AsyncPtyReader>,
    writer: Option<AsyncPtyWriter>,
}

impl PtySession {
    /// Spawns a new pseudo-terminal process with the given configuration.
    pub fn spawn(config: &PtyConfig) -> Result<Self> {
        let shell = resolve_shell(config.user.as_deref(), config.shell.as_deref());
        debug!(shell = %shell, user = ?config.user, "Resolved shell executable");

        let mut cmd = if let Some(ref command_args) = config.command {
            if command_args.is_empty() {
                CommandBuilder::new(&shell)
            } else {
                let mut cb = CommandBuilder::new(&command_args[0]);
                cb.args(&command_args[1..]);
                cb
            }
        } else {
            CommandBuilder::new(&shell)
        };

        cmd.env("TERM", &config.term);
        cmd.env("COLORTERM", "truecolor");
        cmd.env("SHELL", &shell);

        if let Some(ref user) = config.user {
            cmd.env("USER", user);
            cmd.env("LOGNAME", user);
        }

        for (k, v) in &config.env {
            cmd.env(k, v);
        }

        if let Some(ref cwd) = config.working_dir {
            cmd.cwd(cwd);
        }

        let pty_system = native_pty_system();
        let pty_size = PtySize {
            rows: config.rows,
            cols: config.cols,
            pixel_width: config.pixel_width,
            pixel_height: config.pixel_height,
        };

        let pair = pty_system
            .openpty(pty_size)
            .map_err(|e| TermError::PtyAlloc(e.to_string()))?;

        info!(cols = config.cols, rows = config.rows, "Allocated master/slave PTY pair");

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| TermError::Spawn(e.to_string()))?;

        let pid = child.process_id();
        info!(pid = ?pid, "Spawned child process inside PTY slave");

        let killer = child.clone_killer();

        let raw_writer = pair
            .master
            .take_writer()
            .map_err(|e| TermError::Other(e.to_string()))?;

        let raw_reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| TermError::Other(e.to_string()))?;

        let reader = AsyncPtyReader::new(raw_reader);
        let writer = AsyncPtyWriter::new(raw_writer);

        let handle = PtyHandle {
            master: Arc::new(Mutex::new(pair.master)),
            child: Arc::new(Mutex::new(child)),
            killer: Arc::new(Mutex::new(killer)),
            process_id: pid,
        };

        Ok(Self {
            handle,
            reader: Some(reader),
            writer: Some(writer),
        })
    }

    /// Access the cloneable handle for controlling the PTY.
    pub fn handle(&self) -> &PtyHandle {
        &self.handle
    }

    /// Splits the session into its control handle, asynchronous reader, and writer.
    pub fn split(mut self) -> (PtyHandle, AsyncPtyReader, AsyncPtyWriter) {
        let reader = self.reader.take().expect("reader already taken");
        let writer = self.writer.take().expect("writer already taken");
        (self.handle, reader, writer)
    }

    /// Convenience forwarder to resize the PTY.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.handle.resize(cols, rows)
    }

    /// Convenience forwarder to kill the child process.
    pub fn kill(&self) -> Result<()> {
        self.handle.kill()
    }

    /// Convenience forwarder to check if the child has finished.
    pub fn try_wait(&self) -> Result<Option<ExitStatus>> {
        self.handle.try_wait()
    }
}

use crate::config::{resolve_shell, PtyConfig};
use crate::error::{TermError, Result};
use crate::io::{AsyncPtyReader, AsyncPtyWriter};
use portable_pty::{
    native_pty_system, Child, ChildKiller, CommandBuilder, ExitStatus, MasterPty, PtySize,
};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

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
        #[cfg(unix)]
        {
            let current_euid = unsafe { libc::geteuid() };
            let is_root = current_euid == 0;

            if let Some(ref target_user) = config.user {
                return Self::spawn_unix_as_user(config, target_user, is_root, current_euid);
            }
        }

        Self::spawn_generic(config)
    }

    #[cfg(unix)]
    fn spawn_unix_as_user(
        config: &PtyConfig,
        target_user: &str,
        is_root: bool,
        current_euid: libc::uid_t,
    ) -> Result<Self> {
        use crate::user::UserInfo;
        use std::ffi::CString;
        use std::os::unix::process::CommandExt;

        let user_info = UserInfo::lookup(target_user)?;

        if !is_root && user_info.uid != current_euid {
            return Err(TermError::Spawn(format!(
                "Permission denied: morshd is running as UID {} and cannot switch to user '{}' (UID {}) without root privileges",
                current_euid, target_user, user_info.uid
            )));
        }

        let working_dir = if let Some(ref cwd) = config.working_dir {
            cwd.clone()
        } else if user_info.dir.is_dir() {
            user_info.dir.clone()
        } else {
            std::path::PathBuf::from("/")
        };

        let shell = if let Some(ref s) = config.shell {
            if !s.is_empty() && std::path::Path::new(s).exists() {
                s.clone()
            } else {
                resolve_shell(Some(&user_info.username), None)
            }
        } else if !user_info.shell.is_empty() && std::path::Path::new(&user_info.shell).exists() {
            user_info.shell.clone()
        } else {
            resolve_shell(Some(&user_info.username), None)
        };

        debug!(
            target_user = %user_info.username,
            uid = user_info.uid,
            gid = user_info.gid,
            shell = %shell,
            working_dir = ?working_dir,
            is_root,
            "Configuring user-authenticated PTY session"
        );

        let mut cmd = if let Some(ref command_args) = config.command {
            if command_args.is_empty() {
                let mut c = std::process::Command::new(&shell);
                let basename = shell.rsplit('/').next().unwrap_or(&shell);
                c.arg0(format!("-{}", basename));
                c
            } else {
                let mut c = std::process::Command::new(&command_args[0]);
                c.args(&command_args[1..]);
                c
            }
        } else {
            let mut c = std::process::Command::new(&shell);
            let basename = shell.rsplit('/').next().unwrap_or(&shell);
            c.arg0(format!("-{}", basename));
            c
        };

        cmd.env("TERM", &config.term);
        cmd.env("COLORTERM", "truecolor");
        cmd.env("SHELL", &shell);
        cmd.env("USER", &user_info.username);
        cmd.env("LOGNAME", &user_info.username);
        cmd.env("HOME", &user_info.dir);
        cmd.env("PWD", &working_dir);

        if is_root {
            cmd.env_remove("SUDO_USER");
            cmd.env_remove("SUDO_UID");
            cmd.env_remove("SUDO_GID");
            cmd.env_remove("SUDO_COMMAND");

            let xdg_runtime = format!("/run/user/{}", user_info.uid);
            if std::path::Path::new(&xdg_runtime).is_dir() {
                cmd.env("XDG_RUNTIME_DIR", xdg_runtime);
            } else {
                cmd.env_remove("XDG_RUNTIME_DIR");
            }
        }

        if std::env::var("PATH").is_err() {
            cmd.env(
                "PATH",
                "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/sbin:/usr/sbin:/sbin",
            );
        }

        for (k, v) in &config.env {
            cmd.env(k, v);
        }

        cmd.current_dir(&working_dir);

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

        let slave_path = pair.master.tty_name().ok_or_else(|| {
            TermError::Spawn("Master PTY did not provide slave device path".to_string())
        })?;

        if is_root {
            let c_path = CString::new(slave_path.to_str().unwrap_or_default())
                .map_err(|e| TermError::Spawn(format!("Invalid slave path {:?}: {}", slave_path, e)))?;
            unsafe {
                if libc::chown(c_path.as_ptr(), user_info.uid, user_info.gid) != 0 {
                    warn!(
                        path = ?slave_path,
                        error = %std::io::Error::last_os_error(),
                        "Failed to chown slave PTY device"
                    );
                }
                if libc::chmod(c_path.as_ptr(), 0o620) != 0 {
                    warn!(
                        path = ?slave_path,
                        error = %std::io::Error::last_os_error(),
                        "Failed to chmod slave PTY device"
                    );
                }
            }
        }

        let slave_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&slave_path)
            .map_err(|e| TermError::Spawn(format!("Failed to open slave PTY {:?}: {}", slave_path, e)))?;
        let slave_out = slave_file.try_clone().map_err(TermError::Io)?;
        let slave_err = slave_file.try_clone().map_err(TermError::Io)?;

        cmd.stdin(std::process::Stdio::from(slave_file));
        cmd.stdout(std::process::Stdio::from(slave_out));
        cmd.stderr(std::process::Stdio::from(slave_err));

        drop(pair.slave);

        let drop_privileges = is_root;
        let uid = user_info.uid;
        let gid = user_info.gid;
        let groups = user_info.groups.clone();
        let username_for_exec = user_info.username.clone();

        unsafe {
            cmd.pre_exec(move || {
                for signo in &[
                    libc::SIGCHLD,
                    libc::SIGHUP,
                    libc::SIGINT,
                    libc::SIGQUIT,
                    libc::SIGTERM,
                    libc::SIGALRM,
                ] {
                    libc::signal(*signo, libc::SIG_DFL);
                }

                let empty_set: libc::sigset_t = std::mem::zeroed();
                libc::sigprocmask(libc::SIG_SETMASK, &empty_set, std::ptr::null_mut());

                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }

                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }

                if drop_privileges {
                    if !groups.is_empty() {
                        #[cfg(target_os = "linux")]
                        let res = libc::setgroups(groups.len(), groups.as_ptr());
                        #[cfg(not(target_os = "linux"))]
                        let res = libc::setgroups(groups.len() as libc::c_int, groups.as_ptr());
                        if res != 0 {
                            if let Ok(c_user) = std::ffi::CString::new(username_for_exec.as_str()) {
                                let _ = libc::initgroups(c_user.as_ptr(), gid);
                            }
                        }
                    } else if let Ok(c_user) = std::ffi::CString::new(username_for_exec.as_str()) {
                        let _ = libc::initgroups(c_user.as_ptr(), gid);
                    }

                    if libc::setgid(gid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }

                    if libc::setuid(uid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }

                Ok(())
            });
        }

        let child = cmd.spawn().map_err(TermError::Io)?;
        let pid = Some(child.id());
        info!(
            pid = ?pid,
            user = %user_info.username,
            uid = user_info.uid,
            "Spawned child process inside PTY slave"
        );

        let killer = child.clone_killer();
        let child_box: Box<dyn Child + Send + Sync> = Box::new(child);

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
            child: Arc::new(Mutex::new(child_box)),
            killer: Arc::new(Mutex::new(killer)),
            process_id: pid,
        };

        Ok(Self {
            handle,
            reader: Some(reader),
            writer: Some(writer),
        })
    }

    fn spawn_generic(config: &PtyConfig) -> Result<Self> {
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

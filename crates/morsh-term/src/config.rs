use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Configuration options for allocating a PTY session.
#[derive(Debug, Clone)]
pub struct PtyConfig {
    /// Number of terminal columns (default: 80).
    pub cols: u16,
    /// Number of terminal rows (lines) (default: 24).
    pub rows: u16,
    /// Optional cell width in pixels.
    pub pixel_width: u16,
    /// Optional cell height in pixels.
    pub pixel_height: u16,
    /// Terminal type string (default: "xterm-256color").
    pub term: String,
    /// Explicit shell path (e.g. "/bin/bash"). If None, discovers user login shell.
    pub shell: Option<String>,
    /// Target Unix user for the session.
    pub user: Option<String>,
    /// Working directory for the shell session.
    pub working_dir: Option<PathBuf>,
    /// Additional environment variables to set in the child process.
    pub env: HashMap<String, String>,
    /// Custom command arguments to run instead of an interactive login shell.
    pub command: Option<Vec<String>>,
}

impl Default for PtyConfig {
    fn default() -> Self {
        Self {
            cols: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
            term: "xterm-256color".into(),
            shell: None,
            user: None,
            working_dir: None,
            env: HashMap::new(),
            command: None,
        }
    }
}

/// Resolves the preferred login shell for the specified user or current environment.
pub fn resolve_shell(user: Option<&str>, explicit_shell: Option<&str>) -> String {
    if let Some(shell) = explicit_shell
        && !shell.is_empty()
        && Path::new(shell).exists()
    {
        return shell.to_string();
    }

    #[cfg(unix)]
    if let Some(uname) = user {
        use std::ffi::{CStr, CString};
        if let Ok(c_user) = CString::new(uname) {
            unsafe {
                let pwd = libc::getpwnam(c_user.as_ptr());
                if !pwd.is_null() && !(*pwd).pw_shell.is_null() {
                    let shell_cstr = CStr::from_ptr((*pwd).pw_shell);
                    if let Ok(shell_str) = shell_cstr.to_str()
                        && !shell_str.is_empty()
                        && Path::new(shell_str).exists()
                    {
                        return shell_str.to_string();
                    }
                }
            }
        }
    }

    if let Ok(shell) = std::env::var("SHELL")
        && !shell.is_empty()
        && Path::new(&shell).exists()
    {
        return shell;
    }

    for candidate in ["/bin/bash", "/usr/bin/bash", "/bin/zsh", "/usr/bin/zsh", "/bin/sh"] {
        if Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }

    "/bin/sh".to_string()
}

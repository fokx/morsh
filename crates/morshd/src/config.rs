use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Expands leading `~` or `~/` to `$HOME` directory.
pub fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if let Some(rest) = path_str.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if path_str == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    }
    path.to_path_buf()
}

/// Server daemon configuration file structure (`/etc/morsh/morshd.toml`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
    /// Socket address to listen on for UDP/QUIC (e.g. "0.0.0.0:2222")
    pub listen: Option<String>,

    /// Socket address to listen on for TLS 1.3 over TCP fallback
    pub tcp_listen: Option<String>,

    /// Path to TLS certificate chain in PEM format
    pub cert: Option<PathBuf>,

    /// Path to TLS private key in PEM format (PKCS#8)
    pub key: Option<PathBuf>,

    /// Optional stealth knock path prefix (SSH3 style defense)
    pub stealth_knock: Option<String>,

    /// Explicit path to authorized_keys file
    pub auth_keys: Option<PathBuf>,

    /// Allow password / PAM authentication
    pub allow_password: Option<bool>,

    /// Linux PAM service name (default: "morsh")
    pub pam_service: Option<String>,

    /// Permit unauthenticated logins (development only)
    pub no_auth: Option<bool>,

    /// Enable verbose logging
    pub verbose: Option<bool>,
}

impl ServerConfig {
    /// Discovers and loads the server configuration file.
    pub fn load(explicit_path: Option<&Path>) -> Result<(Self, Option<PathBuf>)> {
        let candidate_paths = if let Some(p) = explicit_path {
            vec![expand_tilde(p)]
        } else {
            let mut list = vec![PathBuf::from("/etc/morsh/morshd.toml")];
            if let Ok(home) = std::env::var("HOME") {
                list.push(PathBuf::from(home).join(".morsh").join("morshd.toml"));
            }
            list
        };

        for path in candidate_paths {
            if path.exists() {
                let content = std::fs::read_to_string(&path)
                    .with_context(|| format!("Failed to read server config file {:?}", path))?;
                let mut config: Self = toml::from_str(&content)
                    .with_context(|| format!("Failed to parse server config file {:?}", path))?;

                // Expand tildes in paths
                if let Some(ref c) = config.cert {
                    config.cert = Some(expand_tilde(c));
                }
                if let Some(ref k) = config.key {
                    config.key = Some(expand_tilde(k));
                }
                if let Some(ref ak) = config.auth_keys {
                    config.auth_keys = Some(expand_tilde(ak));
                }

                return Ok((config, Some(path)));
            }
        }

        // Return default empty config if no file found
        Ok((Self::default(), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_toml_parsing() {
        let toml_str = r#"
listen = "127.0.0.1:4444"
tcp_listen = "127.0.0.1:4445"
cert = "/etc/morsh/server.crt"
key = "/etc/morsh/server.key"
stealth_knock = "/stealth-entry"
auth_keys = "/etc/morsh/authorized_keys"
allow_password = true
pam_service = "sshd"
no_auth = false
verbose = true
"#;

        let cfg: ServerConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.listen.as_deref(), Some("127.0.0.1:4444"));
        assert_eq!(cfg.tcp_listen.as_deref(), Some("127.0.0.1:4445"));
        assert_eq!(cfg.cert, Some(PathBuf::from("/etc/morsh/server.crt")));
        assert_eq!(cfg.key, Some(PathBuf::from("/etc/morsh/server.key")));
        assert_eq!(cfg.stealth_knock.as_deref(), Some("/stealth-entry"));
        assert_eq!(cfg.auth_keys, Some(PathBuf::from("/etc/morsh/authorized_keys")));
        assert_eq!(cfg.allow_password, Some(true));
        assert_eq!(cfg.pam_service.as_deref(), Some("sshd"));
        assert_eq!(cfg.no_auth, Some(false));
        assert_eq!(cfg.verbose, Some(true));
    }
}

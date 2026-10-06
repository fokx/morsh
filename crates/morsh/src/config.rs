use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Matches a pattern against text supporting standard wildcards:
/// - `*`: matches zero or more characters
/// - `?`: matches exactly one character
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (p_len, t_len) = (p.len(), t.len());

    let mut dp = vec![vec![false; t_len + 1]; p_len + 1];
    dp[0][0] = true;

    for i in 1..=p_len {
        if p[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }

    for i in 1..=p_len {
        for j in 1..=t_len {
            if p[i - 1] == '*' {
                dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
            } else if p[i - 1] == '?' || p[i - 1] == t[j - 1] {
                dp[i][j] = dp[i - 1][j - 1];
            }
        }
    }

    dp[p_len][t_len]
}

/// Matches a host against OpenSSH-style patterns:
/// - Space-separated list of patterns
/// - Negation prefix `!` (e.g. `!internal.corp *.corp`)
pub fn host_matches(pattern_str: &str, host: &str) -> bool {
    let mut matched = false;
    for token in pattern_str.split_whitespace() {
        if let Some(neg) = token.strip_prefix('!') {
            if wildcard_match(neg, host) {
                return false; // Negated match takes immediate precedence
            }
        } else if wildcard_match(token, host) {
            matched = true;
        }
    }
    matched
}

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

/// Host block configuration matching OpenSSH `Host` directives.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRule {
    /// Host pattern(s) to match, e.g. `*`, `*.internal`, `bastion`
    #[serde(default)]
    pub pattern: String,

    /// Real hostname or IP address override (SSH HostName)
    pub host_name: Option<String>,

    /// Port override
    pub port: Option<u16>,

    /// Username override
    pub user: Option<String>,

    /// Path to SSH private key
    pub identity_file: Option<PathBuf>,

    /// Stealth knock path prefix
    pub stealth_knock: Option<String>,

    /// Force TLS 1.3 over TCP fallback
    pub force_tcp: Option<bool>,

    /// Fallback delay in milliseconds
    pub tcp_fallback_timeout: Option<u64>,

    /// Predictive local echo mode ("auto", "always", "never")
    pub predict_mode: Option<String>,

    /// Predictive echo styling ("underline", "dim", "none")
    pub predict_style: Option<String>,

    /// Accept self-signed / unverified server certs
    pub insecure: Option<bool>,

    /// Query ssh-agent
    pub forward_agent: Option<bool>,

    /// Request compression
    pub compress: Option<bool>,

    /// Local port forwards
    #[serde(default)]
    pub local_forward: Vec<String>,

    /// Remote port forwards
    #[serde(default)]
    pub remote_forward: Vec<String>,

    /// Dynamic SOCKS5 forwards
    #[serde(default)]
    pub dynamic_forward: Vec<String>,

    /// Native UDP forwards
    #[serde(default)]
    pub udp_forward: Vec<String>,
}

/// Client configuration file structure (`~/.morsh/config.toml`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientConfig {
    /// Default port
    pub port: Option<u16>,

    /// Default username
    pub user: Option<String>,

    /// Default identity file
    pub identity_file: Option<PathBuf>,

    /// Default stealth knock
    pub stealth_knock: Option<String>,

    /// Default force TCP
    pub force_tcp: Option<bool>,

    /// Default fallback delay in milliseconds
    pub tcp_fallback_timeout: Option<u64>,

    /// Default predict mode
    pub predict_mode: Option<String>,

    /// Default predict style
    pub predict_style: Option<String>,

    /// Default insecure certificate acceptance
    pub insecure: Option<bool>,

    /// Default agent query
    pub forward_agent: Option<bool>,

    /// Default compress request
    pub compress: Option<bool>,

    /// Default local forwards
    #[serde(default)]
    pub local_forward: Vec<String>,

    /// Default remote forwards
    #[serde(default)]
    pub remote_forward: Vec<String>,

    /// Default dynamic forwards
    #[serde(default)]
    pub dynamic_forward: Vec<String>,

    /// Default UDP forwards
    #[serde(default)]
    pub udp_forward: Vec<String>,

    /// Host matching blocks
    #[serde(default)]
    pub host: Vec<HostRule>,
}

impl ClientConfig {
    /// Loads client configuration from the specified path or default `~/.morsh/config.toml`.
    pub fn load(explicit_path: Option<&Path>) -> Result<Self> {
        let path = if let Some(p) = explicit_path {
            expand_tilde(p)
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".morsh").join("config.toml")
        } else {
            return Ok(Self::default());
        };

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read client config file {:?}", path))?;

        let mut config: Self = toml::from_str(&content)
            .with_context(|| format!("Failed to parse client config file {:?}", path))?;

        // Expand tilde in identity files
        if let Some(ref id) = config.identity_file {
            config.identity_file = Some(expand_tilde(id));
        }
        for h in &mut config.host {
            if let Some(ref id) = h.identity_file {
                h.identity_file = Some(expand_tilde(id));
            }
        }

        Ok(config)
    }

    /// Finds matching host rules for the given host and merges them in order.
    pub fn match_host(&self, host: &str) -> HostRule {
        let mut merged = HostRule {
            pattern: host.to_string(),
            host_name: None,
            port: self.port,
            user: self.user.clone(),
            identity_file: self.identity_file.clone(),
            stealth_knock: self.stealth_knock.clone(),
            force_tcp: self.force_tcp,
            tcp_fallback_timeout: self.tcp_fallback_timeout,
            predict_mode: self.predict_mode.clone(),
            predict_style: self.predict_style.clone(),
            insecure: self.insecure,
            forward_agent: self.forward_agent,
            compress: self.compress,
            local_forward: self.local_forward.clone(),
            remote_forward: self.remote_forward.clone(),
            dynamic_forward: self.dynamic_forward.clone(),
            udp_forward: self.udp_forward.clone(),
        };

        for rule in &self.host {
            if host_matches(&rule.pattern, host) {
                if let Some(ref hn) = rule.host_name {
                    merged.host_name = Some(hn.clone());
                }
                if let Some(p) = rule.port {
                    merged.port = Some(p);
                }
                if let Some(ref u) = rule.user {
                    merged.user = Some(u.clone());
                }
                if let Some(ref id) = rule.identity_file {
                    merged.identity_file = Some(id.clone());
                }
                if let Some(ref sk) = rule.stealth_knock {
                    merged.stealth_knock = Some(sk.clone());
                }
                if let Some(ft) = rule.force_tcp {
                    merged.force_tcp = Some(ft);
                }
                if let Some(to) = rule.tcp_fallback_timeout {
                    merged.tcp_fallback_timeout = Some(to);
                }
                if let Some(ref pm) = rule.predict_mode {
                    merged.predict_mode = Some(pm.clone());
                }
                if let Some(ref ps) = rule.predict_style {
                    merged.predict_style = Some(ps.clone());
                }
                if let Some(ins) = rule.insecure {
                    merged.insecure = Some(ins);
                }
                if let Some(fa) = rule.forward_agent {
                    merged.forward_agent = Some(fa);
                }
                if let Some(c) = rule.compress {
                    merged.compress = Some(c);
                }
                merged.local_forward.extend(rule.local_forward.clone());
                merged.remote_forward.extend(rule.remote_forward.clone());
                merged.dynamic_forward.extend(rule.dynamic_forward.clone());
                merged.udp_forward.extend(rule.udp_forward.clone());
            }
        }

        merged
    }
}

/// Parsed OpenSSH `-o Key=Value` options.
#[derive(Debug, Clone, Default)]
pub struct OpenSshOptions {
    pub port: Option<u16>,
    pub user: Option<String>,
    pub identity_file: Option<PathBuf>,
    pub forward_agent: Option<bool>,
    pub strict_host_key_checking: Option<bool>,
    pub server_alive_interval: Option<u64>,
    pub connect_timeout: Option<u64>,
    pub compress: Option<bool>,
    pub local_forward: Vec<String>,
    pub remote_forward: Vec<String>,
    pub dynamic_forward: Vec<String>,
    pub udp_forward: Vec<String>,
    pub stealth_knock: Option<String>,
    pub force_tcp: Option<bool>,
    pub tcp_fallback_timeout: Option<u64>,
    pub predict_mode: Option<String>,
    pub predict_style: Option<String>,
}

impl OpenSshOptions {
    /// Parses a sequence of `-o Key=Value` or `-o Key Value` arguments.
    pub fn parse_options(options: &[String]) -> Result<Self> {
        let mut parsed = Self::default();

        for opt in options {
            let (key, val) = if let Some(idx) = opt.find('=') {
                (&opt[..idx], opt[idx + 1..].trim())
            } else if let Some(idx) = opt.find(' ') {
                (&opt[..idx], opt[idx + 1..].trim())
            } else {
                (opt.as_str(), "")
            };

            let key_lower = key.trim().to_lowercase();
            match key_lower.as_str() {
                "port" => {
                    let p: u16 = val
                        .parse()
                        .with_context(|| format!("Invalid port value '{}' in -o option", val))?;
                    parsed.port = Some(p);
                }
                "user" => {
                    parsed.user = Some(val.to_string());
                }
                "identityfile" => {
                    let path = expand_tilde(Path::new(val));
                    parsed.identity_file = Some(path);
                }
                "forwardagent" => {
                    parsed.forward_agent = Some(matches_bool_str(val));
                }
                "stricthostkeychecking" => {
                    // "no" means insecure certificate validation
                    let strict = val.eq_ignore_ascii_case("yes");
                    parsed.strict_host_key_checking = Some(strict);
                }
                "compression" => {
                    parsed.compress = Some(matches_bool_str(val));
                }
                "serveraliveinterval" => {
                    if let Ok(sec) = val.parse::<u64>() {
                        parsed.server_alive_interval = Some(sec);
                    }
                }
                "connecttimeout" => {
                    if let Ok(sec) = val.parse::<u64>() {
                        parsed.connect_timeout = Some(sec);
                    }
                }
                "localforward" => {
                    parsed.local_forward.push(val.to_string());
                }
                "remoteforward" => {
                    parsed.remote_forward.push(val.to_string());
                }
                "dynamicforward" => {
                    parsed.dynamic_forward.push(val.to_string());
                }
                "udpforward" => {
                    parsed.udp_forward.push(val.to_string());
                }
                "stealthknock" => {
                    parsed.stealth_knock = Some(val.to_string());
                }
                "forcetcp" => {
                    parsed.force_tcp = Some(matches_bool_str(val));
                }
                "tcpfallbacktimeout" => {
                    if let Ok(ms) = val.parse::<u64>() {
                        parsed.tcp_fallback_timeout = Some(ms);
                    }
                }
                "predictmode" => {
                    parsed.predict_mode = Some(val.to_string());
                }
                "predictstyle" => {
                    parsed.predict_style = Some(val.to_string());
                }
                other => {
                    tracing::debug!(option = %other, value = %val, "Ignored unrecognized OpenSSH -o directive");
                }
            }
        }

        Ok(parsed)
    }
}

fn matches_bool_str(s: &str) -> bool {
    let lower = s.trim().to_lowercase();
    matches!(lower.as_str(), "yes" | "true" | "1" | "on")
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_wildcard_matching() {
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("*.internal", "prod.internal"));
        assert!(!wildcard_match("*.internal", "prod.external"));
        assert!(wildcard_match("web-??.corp", "web-01.corp"));
        assert!(!wildcard_match("web-??.corp", "web-001.corp"));
        assert!(wildcard_match("exact", "exact"));
        assert!(!wildcard_match("exact", "other"));
    }

    #[test]
    fn test_host_matches_space_and_negation() {
        // Space separated
        assert!(host_matches("*.internal *.corp", "api.internal"));
        assert!(host_matches("*.internal *.corp", "db.corp"));
        assert!(!host_matches("*.internal *.corp", "bad.com"));

        // Negation: !bad.internal *.internal
        assert!(!host_matches("!bad.internal *.internal", "bad.internal"));
        assert!(host_matches("!bad.internal *.internal", "good.internal"));
    }

    #[test]
    fn test_client_config_toml_parsing() {
        let toml_str = r#"
port = 2222
user = "globaluser"
force_tcp = false
stealth_knock = "/knock1"

[[host]]
pattern = "*.prod.corp"
user = "admin"
port = 4433
stealth_knock = "/prod-knock"
force_tcp = true

[[host]]
pattern = "bastion"
host_name = "10.0.0.1"
port = 2200
"#;

        let cfg: ClientConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.port, Some(2222));
        assert_eq!(cfg.user.as_deref(), Some("globaluser"));
        assert_eq!(cfg.host.len(), 2);

        // Matching *.prod.corp
        let matched = cfg.match_host("app.prod.corp");
        assert_eq!(matched.user.as_deref(), Some("admin"));
        assert_eq!(matched.port, Some(4433));
        assert_eq!(matched.stealth_knock.as_deref(), Some("/prod-knock"));
        assert_eq!(matched.force_tcp, Some(true));

        // Matching bastion
        let matched_bastion = cfg.match_host("bastion");
        assert_eq!(matched_bastion.host_name.as_deref(), Some("10.0.0.1"));
        assert_eq!(matched_bastion.port, Some(2200));
        assert_eq!(matched_bastion.user.as_deref(), Some("globaluser")); // inherited from global

        // Matching unmatched host
        let matched_other = cfg.match_host("other.org");
        assert_eq!(matched_other.port, Some(2222));
        assert_eq!(matched_other.user.as_deref(), Some("globaluser"));
    }

    #[test]
    fn test_parse_open_ssh_options() {
        let opts = vec![
            "Port=2222".to_string(),
            "User=testuser".to_string(),
            "ForwardAgent=yes".to_string(),
            "StrictHostKeyChecking=no".to_string(),
            "Compression=yes".to_string(),
            "StealthKnock=/myknock".to_string(),
            "ForceTcp=true".to_string(),
            "PredictMode=always".to_string(),
            "PredictStyle=dim".to_string(),
            "LocalForward=8080:127.0.0.1:80".to_string(),
        ];

        let parsed = OpenSshOptions::parse_options(&opts).unwrap();
        assert_eq!(parsed.port, Some(2222));
        assert_eq!(parsed.user.as_deref(), Some("testuser"));
        assert_eq!(parsed.forward_agent, Some(true));
        assert_eq!(parsed.strict_host_key_checking, Some(false));
        assert_eq!(parsed.compress, Some(true));
        assert_eq!(parsed.stealth_knock.as_deref(), Some("/myknock"));
        assert_eq!(parsed.force_tcp, Some(true));
        assert_eq!(parsed.predict_mode.as_deref(), Some("always"));
        assert_eq!(parsed.predict_style.as_deref(), Some("dim"));
        assert_eq!(parsed.local_forward, vec!["8080:127.0.0.1:80"]);
    }
}

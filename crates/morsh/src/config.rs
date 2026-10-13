use anyhow::{bail, Context, Result};
use morsh_transport::StrictHostKeyCheckingMode;
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
/// - Space-separated or comma-separated list of patterns
/// - Negation prefix `!` (e.g. `!internal.corp *.corp`)
pub fn host_matches(pattern_str: &str, host: &str) -> bool {
    let mut matched = false;
    for token in pattern_str.split(|c: char| c.is_whitespace() || c == ',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let token = token.trim_matches('"');
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
    } else if path_str == "~"
        && let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home);
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

    /// Host key checking mode ("ask", "accept-new", "yes", "no")
    pub strict_host_key_checking: Option<StrictHostKeyCheckingMode>,

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

    /// Force TCP
    pub force_tcp: Option<bool>,

    /// Default fallback delay in milliseconds
    pub tcp_fallback_timeout: Option<u64>,

    /// Default predict mode
    pub predict_mode: Option<String>,

    /// Default predict style
    pub predict_style: Option<String>,

    /// Default insecure certificate acceptance
    pub insecure: Option<bool>,

    /// Default host key checking mode
    pub strict_host_key_checking: Option<StrictHostKeyCheckingMode>,

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

        Self::parse_str(&content, &path)
    }

    /// Parses client configuration from TOML string.
    pub fn parse_str(content: &str, path: &Path) -> Result<Self> {
        let mut config: Self = toml::from_str(content)
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
            strict_host_key_checking: self.strict_host_key_checking,
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
                    merged.host_name = Some(hn.replace("%h", host));
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
                if let Some(shkc) = rule.strict_host_key_checking {
                    merged.strict_host_key_checking = Some(shkc);
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

/// A single section from an OpenSSH configuration file (`Host` or `Match`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshSection {
    pub pattern: String,
    pub rule: HostRule,
}

/// OpenSSH configuration file representation (`~/.ssh/config`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshConfigFile {
    pub sections: Vec<SshSection>,
}

/// Normalizes forward rule argument: replaces whitespace with `:` if necessary.
pub fn normalize_forward_spec(val: &str) -> String {
    let trimmed = val.trim();
    if let Some(idx) = trimmed.find(' ') {
        let first = &trimmed[..idx];
        let second = trimmed[idx + 1..].trim();
        format!("{}:{}", first, second)
    } else {
        trimmed.to_string()
    }
}

/// Tokenizes a single line from an SSH config file into `(Key, Value)`.
pub fn tokenize_ssh_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    // Find first separator: whitespace or '='
    let mut key_end = trimmed.len();
    for (i, c) in trimmed.char_indices() {
        if c.is_whitespace() || c == '=' {
            key_end = i;
            break;
        }
    }

    let key = trimmed[..key_end].trim().to_string();
    let mut rest = trimmed[key_end..].trim_start();
    if rest.starts_with('=') {
        rest = rest[1..].trim_start();
    }

    let mut val = rest.trim();
    // Strip trailing unquoted comment if present (e.g. "val # comment")
    if !val.starts_with('"')
        && let Some(comment_pos) = val.find(" #") {
        val = val[..comment_pos].trim();
    }

    // Strip surrounding double quotes if present
    let val_str = if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
        &val[1..val.len() - 1]
    } else {
        val
    };

    Some((key, val_str.to_string()))
}

impl SshConfigFile {
    /// Loads SSH config from the specified path or default `~/.ssh/config`.
    pub fn load(explicit_path: Option<&Path>) -> Result<Self> {
        let path = if let Some(p) = explicit_path {
            expand_tilde(p)
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".ssh").join("config")
        } else {
            return Ok(Self::default());
        };

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read SSH config file {:?}", path))?;

        let mut visited = std::collections::HashSet::new();
        visited.insert(path.canonicalize().unwrap_or_else(|_| path.clone()));
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        Self::parse_internal(&content, base_dir, &mut visited)
    }

    /// Parses SSH config from string content.
    #[allow(dead_code)]
    pub fn parse(content: &str) -> Result<Self> {
        let mut visited = std::collections::HashSet::new();
        let base_dir = if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".ssh")
        } else {
            PathBuf::from(".")
        };
        Self::parse_internal(content, &base_dir, &mut visited)
    }

    pub fn parse_internal(
        content: &str,
        base_dir: &Path,
        visited: &mut std::collections::HashSet<PathBuf>,
    ) -> Result<Self> {
        let mut sections: Vec<SshSection> = Vec::new();
        let mut current_section = SshSection {
            pattern: "*".to_string(),
            rule: HostRule::default(),
        };

        for line in content.lines() {
            let Some((key, val)) = tokenize_ssh_line(line) else {
                continue;
            };

            let key_lower = key.to_lowercase();
            match key_lower.as_str() {
                "host" => {
                    sections.push(current_section);
                    current_section = SshSection {
                        pattern: val,
                        rule: HostRule::default(),
                    };
                }
                "match" => {
                    sections.push(current_section);
                    let val_lower = val.to_lowercase();
                    let pattern = if let Some(rest) = val_lower.strip_prefix("host ") {
                        rest.trim().to_string()
                    } else if val_lower.trim() == "all" {
                        "*".to_string()
                    } else {
                        "!*".to_string()
                    };
                    current_section = SshSection {
                        pattern,
                        rule: HostRule::default(),
                    };
                }
                "hostname" => {
                    current_section.rule.host_name = Some(val);
                }
                "user" => {
                    current_section.rule.user = Some(val);
                }
                "port" => {
                    if let Ok(p) = val.parse::<u16>() {
                        current_section.rule.port = Some(p);
                    } else {
                        tracing::warn!("Invalid port value '{}' in SSH config", val);
                    }
                }
                "identityfile" => {
                    let path = expand_tilde(Path::new(&val));
                    current_section.rule.identity_file = Some(path);
                }
                "forwardagent" => {
                    current_section.rule.forward_agent = Some(matches_bool_str(&val));
                }
                "stricthostkeychecking" => {
                    let mode = match val.to_lowercase().as_str() {
                        "no" | "off" | "false" => StrictHostKeyCheckingMode::No,
                        "accept-new" => StrictHostKeyCheckingMode::AcceptNew,
                        "yes" | "on" | "true" => StrictHostKeyCheckingMode::Yes,
                        "ask" => StrictHostKeyCheckingMode::Ask,
                        _ => {
                            tracing::warn!("Unknown StrictHostKeyChecking value: '{}', defaulting to ask", val);
                            StrictHostKeyCheckingMode::Ask
                        }
                    };
                    current_section.rule.strict_host_key_checking = Some(mode);
                }
                "compression" => {
                    current_section.rule.compress = Some(matches_bool_str(&val));
                }
                "localforward" => {
                    current_section.rule.local_forward.push(normalize_forward_spec(&val));
                }
                "remoteforward" => {
                    current_section.rule.remote_forward.push(normalize_forward_spec(&val));
                }
                "dynamicforward" => {
                    current_section.rule.dynamic_forward.push(val);
                }
                "udpforward" => {
                    current_section.rule.udp_forward.push(normalize_forward_spec(&val));
                }
                "stealthknock" => {
                    current_section.rule.stealth_knock = Some(val);
                }
                "forcetcp" => {
                    current_section.rule.force_tcp = Some(matches_bool_str(&val));
                }
                "tcpfallbacktimeout" => {
                    if let Ok(ms) = val.parse::<u64>() {
                        current_section.rule.tcp_fallback_timeout = Some(ms);
                    }
                }
                "predictmode" => {
                    current_section.rule.predict_mode = Some(val);
                }
                "predictstyle" => {
                    current_section.rule.predict_style = Some(val);
                }
                "insecure" => {
                    current_section.rule.insecure = Some(matches_bool_str(&val));
                }
                "include" => {
                    for token in val.split_whitespace() {
                        let token_unquoted = token.trim_matches('"');
                        let path_pat = expand_tilde(Path::new(token_unquoted));
                        let resolved = if path_pat.is_relative() {
                            base_dir.join(&path_pat)
                        } else {
                            path_pat
                        };

                        let resolved_str = resolved.to_string_lossy();
                        if resolved_str.contains('*') || resolved_str.contains('?') {
                            if let (Some(parent), Some(file_pat)) = (resolved.parent(), resolved.file_name())
                                && parent.is_dir()
                                && let Ok(entries) = std::fs::read_dir(parent) {
                                let pat_str = file_pat.to_string_lossy();
                                let mut matched_files = Vec::new();
                                for entry in entries.flatten() {
                                    if let Ok(ft) = entry.file_type()
                                        && (ft.is_file() || ft.is_symlink()) {
                                        let name = entry.file_name();
                                        if wildcard_match(&pat_str, &name.to_string_lossy()) {
                                            matched_files.push(entry.path());
                                        }
                                    }
                                }
                                matched_files.sort();
                                for f in matched_files {
                                    let canonical = f.canonicalize().unwrap_or_else(|_| f.clone());
                                    if visited.insert(canonical)
                                        && let Ok(inc_content) = std::fs::read_to_string(&f) {
                                        let inc_base = f.parent().unwrap_or(base_dir);
                                        if let Ok(inc_cfg) = Self::parse_internal(&inc_content, inc_base, visited) {
                                            sections.extend(inc_cfg.sections);
                                        }
                                    }
                                }
                            }
                        } else if resolved.is_file() {
                            let canonical = resolved.canonicalize().unwrap_or_else(|_| resolved.clone());
                            if visited.insert(canonical)
                                && let Ok(inc_content) = std::fs::read_to_string(&resolved) {
                                let inc_base = resolved.parent().unwrap_or(base_dir);
                                if let Ok(inc_cfg) = Self::parse_internal(&inc_content, inc_base, visited) {
                                    sections.extend(inc_cfg.sections);
                                }
                            }
                        }
                    }
                }
                other => {
                    tracing::debug!(directive = %other, value = %val, "Ignored unrecognized SSH config directive");
                }
            }
        }

        sections.push(current_section);
        Ok(Self { sections })
    }

    /// Matches host against all sections in order using OpenSSH "first match wins" semantics for scalars.
    pub fn match_host(&self, host: &str) -> HostRule {
        let mut merged = HostRule {
            pattern: host.to_string(),
            ..Default::default()
        };

        for section in &self.sections {
            if host_matches(&section.pattern, host) {
                if merged.host_name.is_none()
                    && let Some(ref hn) = section.rule.host_name {
                    merged.host_name = Some(hn.replace("%h", host));
                }
                if merged.port.is_none() && section.rule.port.is_some() {
                    merged.port = section.rule.port;
                }
                if merged.user.is_none() && section.rule.user.is_some() {
                    merged.user = section.rule.user.clone();
                }
                if merged.identity_file.is_none() && section.rule.identity_file.is_some() {
                    merged.identity_file = section.rule.identity_file.clone();
                }
                if merged.stealth_knock.is_none() && section.rule.stealth_knock.is_some() {
                    merged.stealth_knock = section.rule.stealth_knock.clone();
                }
                if merged.force_tcp.is_none() && section.rule.force_tcp.is_some() {
                    merged.force_tcp = section.rule.force_tcp;
                }
                if merged.tcp_fallback_timeout.is_none() && section.rule.tcp_fallback_timeout.is_some() {
                    merged.tcp_fallback_timeout = section.rule.tcp_fallback_timeout;
                }
                if merged.predict_mode.is_none() && section.rule.predict_mode.is_some() {
                    merged.predict_mode = section.rule.predict_mode.clone();
                }
                if merged.predict_style.is_none() && section.rule.predict_style.is_some() {
                    merged.predict_style = section.rule.predict_style.clone();
                }
                if merged.insecure.is_none() && section.rule.insecure.is_some() {
                    merged.insecure = section.rule.insecure;
                }
                if merged.strict_host_key_checking.is_none() && section.rule.strict_host_key_checking.is_some() {
                    merged.strict_host_key_checking = section.rule.strict_host_key_checking;
                }
                if merged.forward_agent.is_none() && section.rule.forward_agent.is_some() {
                    merged.forward_agent = section.rule.forward_agent;
                }
                if merged.compress.is_none() && section.rule.compress.is_some() {
                    merged.compress = section.rule.compress;
                }

                merged.local_forward.extend(section.rule.local_forward.clone());
                merged.remote_forward.extend(section.rule.remote_forward.clone());
                merged.dynamic_forward.extend(section.rule.dynamic_forward.clone());
                merged.udp_forward.extend(section.rule.udp_forward.clone());
            }
        }

        merged
    }
}

/// Loads configuration files with support for ~/.morsh/config.toml, ~/.ssh/config, or an explicit -F path.
pub fn load_configs(explicit_path: Option<&Path>) -> Result<(ClientConfig, SshConfigFile)> {
    if let Some(path) = explicit_path {
        let expanded = expand_tilde(path);
        if !expanded.exists() {
            bail!("Configuration file not found: {:?}", expanded);
        }
        let content = std::fs::read_to_string(&expanded)
            .with_context(|| format!("Failed to read configuration file {:?}", expanded))?;

        // If file extension is .toml, parse as TOML
        if expanded.extension().and_then(|s| s.to_str()) == Some("toml") {
            let client_cfg = ClientConfig::parse_str(&content, &expanded)?;
            return Ok((client_cfg, SshConfigFile::default()));
        }

        // If content contains TOML table markers or parses as TOML, try TOML first
        if content.contains('[')
            && let Ok(client_cfg) = ClientConfig::parse_str(&content, &expanded) {
            return Ok((client_cfg, SshConfigFile::default()));
        }

        // Otherwise parse as SSH config
        let mut visited = std::collections::HashSet::new();
        visited.insert(expanded.canonicalize().unwrap_or_else(|_| expanded.clone()));
        let base_dir = expanded.parent().unwrap_or_else(|| Path::new("."));
        let ssh_cfg = SshConfigFile::parse_internal(&content, base_dir, &mut visited)?;
        return Ok((ClientConfig::default(), ssh_cfg));
    }

    let client_cfg = ClientConfig::load(None)?;
    let ssh_cfg = SshConfigFile::load(None)?;
    Ok((client_cfg, ssh_cfg))
}

/// Parsed OpenSSH `-o Key=Value` options.
#[derive(Debug, Clone, Default)]
pub struct OpenSshOptions {
    pub port: Option<u16>,
    pub user: Option<String>,
    pub identity_file: Option<PathBuf>,
    pub forward_agent: Option<bool>,
    pub strict_host_key_checking: Option<StrictHostKeyCheckingMode>,
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
                    let mode = match val.to_lowercase().as_str() {
                        "no" | "off" | "false" => StrictHostKeyCheckingMode::No,
                        "accept-new" => StrictHostKeyCheckingMode::AcceptNew,
                        "yes" | "on" | "true" => StrictHostKeyCheckingMode::Yes,
                        "ask" => StrictHostKeyCheckingMode::Ask,
                        _ => {
                            tracing::warn!("Unknown StrictHostKeyChecking value: '{}', defaulting to ask", val);
                            StrictHostKeyCheckingMode::Ask
                        }
                    };
                    parsed.strict_host_key_checking = Some(mode);
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
        assert_eq!(parsed.strict_host_key_checking, Some(StrictHostKeyCheckingMode::No));
        assert_eq!(parsed.compress, Some(true));
        assert_eq!(parsed.stealth_knock.as_deref(), Some("/myknock"));
        assert_eq!(parsed.force_tcp, Some(true));
        assert_eq!(parsed.predict_mode.as_deref(), Some("always"));
        assert_eq!(parsed.predict_style.as_deref(), Some("dim"));
        assert_eq!(parsed.local_forward, vec!["8080:127.0.0.1:80"]);
    }

    #[test]
    fn test_tokenize_ssh_line() {
        assert_eq!(tokenize_ssh_line("# comment"), None);
        assert_eq!(tokenize_ssh_line("   # indented comment"), None);
        assert_eq!(tokenize_ssh_line(""), None);

        assert_eq!(
            tokenize_ssh_line("Host bastion"),
            Some(("Host".to_string(), "bastion".to_string()))
        );
        assert_eq!(
            tokenize_ssh_line("Host = bastion"),
            Some(("Host".to_string(), "bastion".to_string()))
        );
        assert_eq!(
            tokenize_ssh_line("Host=bastion"),
            Some(("Host".to_string(), "bastion".to_string()))
        );
        assert_eq!(
            tokenize_ssh_line("Port 2222 # custom port"),
            Some(("Port".to_string(), "2222".to_string()))
        );
        assert_eq!(
            tokenize_ssh_line("IdentityFile \"~/keys/id with space\""),
            Some(("IdentityFile".to_string(), "~/keys/id with space".to_string()))
        );
        assert_eq!(
            tokenize_ssh_line("LocalForward 8080 127.0.0.1:80"),
            Some(("LocalForward".to_string(), "8080 127.0.0.1:80".to_string()))
        );
    }

    #[test]
    fn test_ssh_config_first_match_semantics() {
        let ssh_conf = r#"
# Global / top-level defaults
ForwardAgent yes
StrictHostKeyChecking ask

Host bastion
    HostName 10.0.0.1
    Port 2200
    User admin
    LocalForward 8080 127.0.0.1:80

Host *.prod.corp
    User ops
    Port 4433
    StealthKnock /prod-knock
    ForceTcp yes

Host *
    User defaultuser
    Port 2222
    LocalForward 9090 127.0.0.1:90
"#;

        let parsed = SshConfigFile::parse(ssh_conf).unwrap();

        // 1. Matching 'bastion'
        let rule_bastion = parsed.match_host("bastion");
        assert_eq!(rule_bastion.host_name.as_deref(), Some("10.0.0.1"));
        assert_eq!(rule_bastion.port, Some(2200)); // First match 2200 wins over Host * (2222)
        assert_eq!(rule_bastion.user.as_deref(), Some("admin")); // First match admin wins over defaultuser
        assert_eq!(rule_bastion.forward_agent, Some(true)); // Inherited from global
        assert_eq!(rule_bastion.strict_host_key_checking, Some(StrictHostKeyCheckingMode::Ask));
        // LocalForward accumulates from both Host bastion and Host *
        assert_eq!(
            rule_bastion.local_forward,
            vec!["8080:127.0.0.1:80", "9090:127.0.0.1:90"]
        );

        // 2. Matching 'web01.prod.corp'
        let rule_prod = parsed.match_host("web01.prod.corp");
        assert_eq!(rule_prod.host_name, None);
        assert_eq!(rule_prod.port, Some(4433));
        assert_eq!(rule_prod.user.as_deref(), Some("ops"));
        assert_eq!(rule_prod.stealth_knock.as_deref(), Some("/prod-knock"));
        assert_eq!(rule_prod.force_tcp, Some(true));
        assert_eq!(rule_prod.forward_agent, Some(true));

        // 3. Matching an unknown host 'random.org'
        let rule_random = parsed.match_host("random.org");
        assert_eq!(rule_random.port, Some(2222)); // Matches Host *
        assert_eq!(rule_random.user.as_deref(), Some("defaultuser"));
        assert_eq!(rule_random.forward_agent, Some(true));
    }

    #[test]
    fn test_ssh_config_token_replacement_and_comma_hosts() {
        let conf = r#"
Host web1,web2,*.dmz !bad.dmz
    HostName %h.internal.net
    Port 2202
    User service
"#;
        let parsed = SshConfigFile::parse(conf).unwrap();

        // Matches web1
        let r1 = parsed.match_host("web1");
        assert_eq!(r1.host_name.as_deref(), Some("web1.internal.net"));
        assert_eq!(r1.port, Some(2202));
        assert_eq!(r1.user.as_deref(), Some("service"));

        // Matches web2
        let r2 = parsed.match_host("web2");
        assert_eq!(r2.host_name.as_deref(), Some("web2.internal.net"));

        // Matches app.dmz
        let r3 = parsed.match_host("app.dmz");
        assert_eq!(r3.host_name.as_deref(), Some("app.dmz.internal.net"));

        // Negated bad.dmz should NOT match
        let r4 = parsed.match_host("bad.dmz");
        assert_eq!(r4.host_name, None);
        assert_eq!(r4.port, None);
    }

    #[test]
    fn test_ssh_config_includes() {
        let temp_dir = std::env::temp_dir().join(format!("morsh_include_test_{}", std::process::id()));
        let conf_d = temp_dir.join("config.d");
        let _ = std::fs::create_dir_all(&conf_d);

        let sub_conf = r#"
Host included-host
    HostName 192.168.10.5
    Port 3333
"#;
        std::fs::write(conf_d.join("sub.conf"), sub_conf).unwrap();

        let main_conf = format!(
            r#"
Include {}/*.conf

Host *
    User defaultuser
"#,
            conf_d.to_string_lossy()
        );
        let main_path = temp_dir.join("config");
        std::fs::write(&main_path, main_conf).unwrap();

        let parsed = SshConfigFile::load(Some(&main_path)).unwrap();
        let matched = parsed.match_host("included-host");
        assert_eq!(matched.host_name.as_deref(), Some("192.168.10.5"));
        assert_eq!(matched.port, Some(3333));
        assert_eq!(matched.user.as_deref(), Some("defaultuser"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_load_configs_dispatch() {
        let temp_dir = std::env::temp_dir().join(format!("morsh_dispatch_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        // 1. Dispatch TOML file
        let toml_file = temp_dir.join("client.toml");
        std::fs::write(&toml_file, "port = 2222\nuser = \"tom\"").unwrap();
        let (toml_cfg, _) = load_configs(Some(&toml_file)).unwrap();
        assert_eq!(toml_cfg.port, Some(2222));
        assert_eq!(toml_cfg.user.as_deref(), Some("tom"));

        // 2. Dispatch SSH config file
        let ssh_file = temp_dir.join("ssh_config");
        std::fs::write(&ssh_file, "Host srv\n  HostName 1.2.3.4\n  Port 2200").unwrap();
        let (_, ssh_cfg) = load_configs(Some(&ssh_file)).unwrap();
        let matched = ssh_cfg.match_host("srv");
        assert_eq!(matched.host_name.as_deref(), Some("1.2.3.4"));
        assert_eq!(matched.port, Some(2200));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

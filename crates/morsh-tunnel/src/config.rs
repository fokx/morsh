use crate::error::{Result, TunnelError};
use std::fmt;

/// Rule for TCP port forwarding (-L local or -R remote).
/// Syntax: [bind_addr:]bind_port:target_host:target_port
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardRule {
    pub bind_addr: String,
    pub bind_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

impl ForwardRule {
    pub fn new(bind_addr: impl Into<String>, bind_port: u16, target_host: impl Into<String>, target_port: u16) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            bind_port,
            target_host: target_host.into(),
            target_port,
        }
    }

    /// Parses OpenSSH format: `[bind_addr:]bind_port:target_host:target_port`
    pub fn parse(spec: &str) -> Result<Self> {
        let parts = split_port_forward_spec(spec)?;
        match parts.len() {
            3 => {
                // bind_port:target_host:target_port
                let bind_port = parts[0]
                    .parse::<u16>()
                    .map_err(|_| TunnelError::InvalidRule(format!("Invalid bind port: '{}'", parts[0])))?;
                let target_host = parts[1].clone();
                let target_port = parts[2]
                    .parse::<u16>()
                    .map_err(|_| TunnelError::InvalidRule(format!("Invalid target port: '{}'", parts[2])))?;
                Ok(Self {
                    bind_addr: "127.0.0.1".to_string(),
                    bind_port,
                    target_host,
                    target_port,
                })
            }
            4 => {
                // bind_addr:bind_port:target_host:target_port
                let bind_addr = parts[0].clone();
                let bind_port = parts[1]
                    .parse::<u16>()
                    .map_err(|_| TunnelError::InvalidRule(format!("Invalid bind port: '{}'", parts[1])))?;
                let target_host = parts[2].clone();
                let target_port = parts[3]
                    .parse::<u16>()
                    .map_err(|_| TunnelError::InvalidRule(format!("Invalid target port: '{}'", parts[3])))?;
                Ok(Self {
                    bind_addr,
                    bind_port,
                    target_host,
                    target_port,
                })
            }
            _ => Err(TunnelError::InvalidRule(format!(
                "Invalid forwarding specification '{}'. Expected [bind_addr:]bind_port:target_host:target_port",
                spec
            ))),
        }
    }

    pub fn bind_socket_addr_str(&self) -> String {
        format!("{}:{}", self.bind_addr, self.bind_port)
    }

    pub fn target_socket_addr_str(&self) -> String {
        format!("{}:{}", self.target_host, self.target_port)
    }
}

impl fmt::Display for ForwardRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.bind_addr, self.bind_port, self.target_host, self.target_port
        )
    }
}

/// Rule for dynamic SOCKS5 proxy (-D).
/// Syntax: [bind_addr:]bind_port
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicRule {
    pub bind_addr: String,
    pub bind_port: u16,
}

impl DynamicRule {
    pub fn new(bind_addr: impl Into<String>, bind_port: u16) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            bind_port,
        }
    }

    /// Parses OpenSSH format: `[bind_addr:]bind_port`
    pub fn parse(spec: &str) -> Result<Self> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Err(TunnelError::InvalidRule("Empty dynamic forward specification".into()));
        }

        if let Ok(port) = trimmed.parse::<u16>() {
            return Ok(Self {
                bind_addr: "127.0.0.1".into(),
                bind_port: port,
            });
        }

        // Could be [::1]:port or addr:port
        if trimmed.starts_with('[') {
            if let Some(close_idx) = trimmed.find(']') {
                let addr = &trimmed[1..close_idx];
                let rest = &trimmed[close_idx + 1..];
                let port_str = rest.strip_prefix(':').ok_or_else(|| {
                    TunnelError::InvalidRule(format!("Missing port in IPv6 dynamic forward: '{}'", spec))
                })?;
                let port = port_str
                    .parse::<u16>()
                    .map_err(|_| TunnelError::InvalidRule(format!("Invalid port: '{}'", port_str)))?;
                return Ok(Self {
                    bind_addr: addr.into(),
                    bind_port: port,
                });
            }
        }

        if let Some(idx) = trimmed.rfind(':') {
            let addr = &trimmed[..idx];
            let port = trimmed[idx + 1..]
                .parse::<u16>()
                .map_err(|_| TunnelError::InvalidRule(format!("Invalid port in: '{}'", spec)))?;
            Ok(Self {
                bind_addr: addr.into(),
                bind_port: port,
            })
        } else {
            Err(TunnelError::InvalidRule(format!(
                "Invalid dynamic forward specification '{}'",
                spec
            )))
        }
    }

    pub fn bind_socket_addr_str(&self) -> String {
        format!("{}:{}", self.bind_addr, self.bind_port)
    }
}

impl fmt::Display for DynamicRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.bind_addr, self.bind_port)
    }
}

/// Rule for UDP port forwarding.
/// Syntax: [bind_addr:]bind_port:target_host:target_port
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpRule {
    pub bind_addr: String,
    pub bind_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

impl UdpRule {
    pub fn new(bind_addr: impl Into<String>, bind_port: u16, target_host: impl Into<String>, target_port: u16) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            bind_port,
            target_host: target_host.into(),
            target_port,
        }
    }

    pub fn parse(spec: &str) -> Result<Self> {
        let f = ForwardRule::parse(spec)?;
        Ok(Self {
            bind_addr: f.bind_addr,
            bind_port: f.bind_port,
            target_host: f.target_host,
            target_port: f.target_port,
        })
    }

    pub fn bind_socket_addr_str(&self) -> String {
        format!("{}:{}", self.bind_addr, self.bind_port)
    }

    pub fn target_socket_addr_str(&self) -> String {
        format!("{}:{}", self.target_host, self.target_port)
    }
}

impl fmt::Display for UdpRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.bind_addr, self.bind_port, self.target_host, self.target_port
        )
    }
}

/// Splits a colon-separated forwarding specification, respecting bracketed IPv6 addresses [::1].
fn split_port_forward_spec(spec: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_bracket = false;

    for ch in spec.chars() {
        match ch {
            '[' => {
                in_bracket = true;
            }
            ']' => {
                in_bracket = false;
            }
            ':' if !in_bracket => {
                parts.push(current);
                current = String::new();
            }
            _ => {
                current.push(ch);
            }
        }
    }
    parts.push(current);

    if in_bracket {
        return Err(TunnelError::InvalidRule(format!(
            "Unclosed IPv6 bracket in specification '{}'",
            spec
        )));
    }

    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_forward_rule_three_parts() {
        let rule = ForwardRule::parse("8080:localhost:80").unwrap();
        assert_eq!(rule.bind_addr, "127.0.0.1");
        assert_eq!(rule.bind_port, 8080);
        assert_eq!(rule.target_host, "localhost");
        assert_eq!(rule.target_port, 80);
    }

    #[test]
    fn test_parse_forward_rule_four_parts() {
        let rule = ForwardRule::parse("0.0.0.0:8080:192.168.1.5:443").unwrap();
        assert_eq!(rule.bind_addr, "0.0.0.0");
        assert_eq!(rule.bind_port, 8080);
        assert_eq!(rule.target_host, "192.168.1.5");
        assert_eq!(rule.target_port, 443);
    }

    #[test]
    fn test_parse_forward_rule_ipv6() {
        let rule = ForwardRule::parse("[::1]:8080:[fe80::1]:80").unwrap();
        assert_eq!(rule.bind_addr, "::1");
        assert_eq!(rule.bind_port, 8080);
        assert_eq!(rule.target_host, "fe80::1");
        assert_eq!(rule.target_port, 80);
    }

    #[test]
    fn test_parse_forward_rule_invalid() {
        assert!(ForwardRule::parse("invalid").is_err());
        assert!(ForwardRule::parse("8080:localhost").is_err());
        assert!(ForwardRule::parse("notaport:localhost:80").is_err());
        assert!(ForwardRule::parse("8080:localhost:notaport").is_err());
        assert!(ForwardRule::parse("[::1:8080:localhost:80").is_err());
    }

    #[test]
    fn test_parse_dynamic_rule() {
        let r1 = DynamicRule::parse("1080").unwrap();
        assert_eq!(r1.bind_addr, "127.0.0.1");
        assert_eq!(r1.bind_port, 1080);

        let r2 = DynamicRule::parse("0.0.0.0:1080").unwrap();
        assert_eq!(r2.bind_addr, "0.0.0.0");
        assert_eq!(r2.bind_port, 1080);

        let r3 = DynamicRule::parse("[::1]:1080").unwrap();
        assert_eq!(r3.bind_addr, "::1");
        assert_eq!(r3.bind_port, 1080);

        assert!(DynamicRule::parse("").is_err());
        assert!(DynamicRule::parse("invalid").is_err());
    }

    #[test]
    fn test_parse_udp_rule() {
        let rule = UdpRule::parse("5353:1.1.1.1:53").unwrap();
        assert_eq!(rule.bind_addr, "127.0.0.1");
        assert_eq!(rule.bind_port, 5353);
        assert_eq!(rule.target_host, "1.1.1.1");
        assert_eq!(rule.target_port, 53);
    }
}

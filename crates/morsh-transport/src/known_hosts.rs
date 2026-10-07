use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{debug, info};

use crate::tls::cert_fingerprint_sha256;

/// Modes for checking remote host identification (matching OpenSSH `StrictHostKeyChecking`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StrictHostKeyCheckingMode {
    /// Prompt user on first connection; reject if host identification changes.
    #[default]
    Ask,
    /// Automatically accept and add new host keys; reject if host identification changes.
    AcceptNew,
    /// Refuse connection if host is not already present in known_hosts; reject if key changes.
    Yes,
    /// Accept any host key without verification.
    No,
}

/// Result of checking a remote host against `known_hosts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnownHostStatus {
    /// Host is present in known_hosts and its fingerprint matches.
    Matched,
    /// Host is present in known_hosts, but fingerprint DOES NOT match (potential MITM attack).
    Mismatch { expected: String, found: String },
    /// Host was not found in known_hosts.
    NotFound,
}

/// An entry in the `known_hosts` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostEntry {
    /// Host specifications, e.g. ["localhost:2222", "127.0.0.1:2222"]
    pub hosts: Vec<String>,
    /// Colon-delimited SHA-256 fingerprint
    pub fingerprint: String,
}

/// In-memory representation of known host keys (`~/.morsh/known_hosts`).
#[derive(Debug, Clone, Default)]
pub struct KnownHosts {
    pub entries: Vec<KnownHostEntry>,
}

impl KnownHosts {
    /// Loads known hosts entries from the specified file.
    /// If the file does not exist, returns an empty set of entries.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read known_hosts file {:?}", path))?;

        let mut entries = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let hosts: Vec<String> = parts[0]
                    .split(',')
                    .map(|h| h.trim().to_lowercase())
                    .filter(|h| !h.is_empty())
                    .collect();
                let fingerprint = parts[1].trim().to_lowercase();
                if !hosts.is_empty() && !fingerprint.is_empty() {
                    entries.push(KnownHostEntry { hosts, fingerprint });
                }
            }
        }

        Ok(Self { entries })
    }

    /// Checks if a target host and port match an existing entry in known_hosts.
    pub fn check(
        &self,
        host: &str,
        port: u16,
        remote_addr: &Option<SocketAddr>,
        fingerprint: &str,
    ) -> KnownHostStatus {
        let norm_fp = fingerprint.trim().to_lowercase();

        let mut candidate_names = vec![
            format!("{}:{}", host.trim().to_lowercase(), port),
            host.trim().to_lowercase(),
        ];

        if let Some(addr) = remote_addr {
            candidate_names.push(format!("{}:{}", addr.ip(), port));
            candidate_names.push(format!("[{}]:{}", addr.ip(), port));
            candidate_names.push(addr.ip().to_string());
        }

        for entry in &self.entries {
            let matches_host = entry.hosts.iter().any(|h| {
                candidate_names.iter().any(|cand| cand == h)
            });

            if matches_host {
                if entry.fingerprint == norm_fp {
                    return KnownHostStatus::Matched;
                } else {
                    return KnownHostStatus::Mismatch {
                        expected: entry.fingerprint.clone(),
                        found: norm_fp,
                    };
                }
            }
        }

        KnownHostStatus::NotFound
    }

    /// Appends a new host fingerprint entry to `known_hosts`.
    pub fn add_entry(
        path: &Path,
        host: &str,
        port: u16,
        remote_addr: Option<SocketAddr>,
        fingerprint: &str,
    ) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {:?}", parent))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open known_hosts file {:?}", path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

        let norm_host = host.trim().to_lowercase();
        let norm_fp = fingerprint.trim().to_lowercase();

        let host_field = if let Some(addr) = remote_addr {
            let ip_str = addr.ip().to_string();
            if ip_str != norm_host {
                format!("{}:{},{}:{}", norm_host, port, ip_str, port)
            } else {
                format!("{}:{}", norm_host, port)
            }
        } else {
            format!("{}:{}", norm_host, port)
        };

        writeln!(file, "{} {}", host_field, norm_fp)
            .with_context(|| format!("Failed to write to known_hosts file {:?}", path))?;

        file.flush()?;
        Ok(())
    }
}

/// Returns the default known_hosts file path (`~/.morsh/known_hosts`).
pub fn default_known_hosts_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".morsh").join("known_hosts")
    } else {
        PathBuf::from(".known_hosts")
    }
}

/// Prompts the user on interactive terminal for host key verification.
fn prompt_user_for_host_key(
    target_host: &str,
    target_port: u16,
    remote_addr: Option<SocketAddr>,
    fingerprint: &str,
) -> bool {
    let addr_info = if let Some(addr) = remote_addr {
        format!(" ({}:{})", addr.ip(), target_port)
    } else {
        String::new()
    };

    let prompt = format!(
        "The authenticity of host '{}:{}{}' can't be established.\n\
         SHA-256 certificate fingerprint is {}.\n\
         Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
        target_host, target_port, addr_info, fingerprint
    );

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::{BufRead, BufReader, Write};

        // Try /dev/tty first for direct interactive user control
        if let Ok(mut tty_out) = OpenOptions::new().write(true).open("/dev/tty") {
            if let Ok(tty_in) = OpenOptions::new().read(true).open("/dev/tty") {
                let _ = write!(tty_out, "{}", prompt);
                let _ = tty_out.flush();
                let mut reader = BufReader::new(tty_in);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    let ans = line.trim().to_lowercase();
                    return ans == "yes" || ans == "y" || ans == fingerprint.to_lowercase();
                }
            }
        }
    }

    // Fall back to stdin / stderr if stdin is an interactive terminal
    if std::io::stdin().is_terminal() {
        use std::io::Write;
        let _ = eprint!("{}", prompt);
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_ok() {
            let ans = line.trim().to_lowercase();
            return ans == "yes" || ans == "y" || ans == fingerprint.to_lowercase();
        }
    }

    // Non-interactive terminal: cannot ask user
    eprintln!(
        "The authenticity of host '{}:{}{}' can't be established.\n\
         SHA-256 certificate fingerprint is {}.\n\
         Host key verification failed (terminal is not interactive; use -k / --insecure or -o StrictHostKeyChecking=accept-new).",
        target_host, target_port, addr_info, fingerprint
    );
    false
}

/// Shared decision state between QUIC and TCP fallback handshakes.
#[derive(Debug, Default)]
pub struct TofuSharedState {
    pub decisions: HashMap<String, bool>,
}

/// A rustls `ServerCertVerifier` that performs Trust-On-First-Use (TOFU) host verification
/// with OpenSSH-compatible `known_hosts` semantics.
#[derive(Debug)]
pub struct TofuServerCertVerifier {
    pub target_host: String,
    pub target_port: u16,
    pub remote_addr: Option<SocketAddr>,
    pub known_hosts_path: PathBuf,
    pub strict_mode: StrictHostKeyCheckingMode,
    pub insecure: bool,
    pub webpki_verifier: Option<Arc<rustls::client::WebPkiServerVerifier>>,
    pub shared_state: Arc<Mutex<TofuSharedState>>,
}

impl ServerCertVerifier for TofuServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 1. Insecure flag or StrictHostKeyChecking=no bypass
        if self.insecure || self.strict_mode == StrictHostKeyCheckingMode::No {
            debug!("Insecure mode active: bypassing server certificate verification");
            return Ok(ServerCertVerified::assertion());
        }

        // 2. Try Web PKI verification first (if server uses CA-signed certs)
        if let Some(ref webpki) = self.webpki_verifier {
            if webpki
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .is_ok()
            {
                debug!("Server certificate verified successfully via Web PKI root store");
                return Ok(ServerCertVerified::assertion());
            }
        }

        // 3. TOFU / known_hosts verification
        let fingerprint = cert_fingerprint_sha256(end_entity);

        let known_hosts = KnownHosts::load_from_file(&self.known_hosts_path)
            .unwrap_or_default();

        match known_hosts.check(
            &self.target_host,
            self.target_port,
            &self.remote_addr,
            &fingerprint,
        ) {
            KnownHostStatus::Matched => {
                info!(
                    host = %self.target_host,
                    port = self.target_port,
                    %fingerprint,
                    "Host certificate fingerprint verified against known_hosts"
                );
                Ok(ServerCertVerified::assertion())
            }
            KnownHostStatus::Mismatch { expected, found } => {
                let mut state = self.shared_state.lock().unwrap();
                if state.decisions.get(&found) == Some(&false) {
                    return Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ));
                }
                state.decisions.insert(found.clone(), false);

                eprintln!(
                    "\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                     @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
                     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\
                     IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n\
                     Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n\
                     The SHA-256 host key fingerprint for {}:{} has changed.\n\
                     Existing known fingerprint : {}\n\
                     Received server fingerprint: {}\n\
                     Host key verification failed.\n",
                    self.target_host, self.target_port, expected, found
                );
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ))
            }
            KnownHostStatus::NotFound => {
                match self.strict_mode {
                    StrictHostKeyCheckingMode::Yes => {
                        eprintln!(
                            "Host key verification failed: {}:{} not found in known_hosts and StrictHostKeyChecking=yes",
                            self.target_host, self.target_port
                        );
                        Err(rustls::Error::InvalidCertificate(
                            rustls::CertificateError::ApplicationVerificationFailure,
                        ))
                    }
                    StrictHostKeyCheckingMode::AcceptNew => {
                        let _ = KnownHosts::add_entry(
                            &self.known_hosts_path,
                            &self.target_host,
                            self.target_port,
                            self.remote_addr,
                            &fingerprint,
                        );
                        eprintln!(
                            "Warning: Permanently added '{}:{}' (SHA-256) to the list of known hosts.",
                            self.target_host, self.target_port
                        );
                        Ok(ServerCertVerified::assertion())
                    }
                    StrictHostKeyCheckingMode::Ask => {
                        let mut state = self.shared_state.lock().unwrap();
                        if let Some(&cached_ok) = state.decisions.get(&fingerprint) {
                            if cached_ok {
                                return Ok(ServerCertVerified::assertion());
                            } else {
                                return Err(rustls::Error::InvalidCertificate(
                                    rustls::CertificateError::ApplicationVerificationFailure,
                                ));
                            }
                        }

                        let accepted = prompt_user_for_host_key(
                            &self.target_host,
                            self.target_port,
                            self.remote_addr,
                            &fingerprint,
                        );
                        state.decisions.insert(fingerprint.clone(), accepted);

                        if accepted {
                            let _ = KnownHosts::add_entry(
                                &self.known_hosts_path,
                                &self.target_host,
                                self.target_port,
                                self.remote_addr,
                                &fingerprint,
                            );
                            eprintln!(
                                "Warning: Permanently added '{}:{}' (SHA-256) to the list of known hosts.",
                                self.target_host, self.target_port
                            );
                            Ok(ServerCertVerified::assertion())
                        } else {
                            eprintln!("Host key verification failed.");
                            Err(rustls::Error::InvalidCertificate(
                                rustls::CertificateError::ApplicationVerificationFailure,
                            ))
                        }
                    }
                    StrictHostKeyCheckingMode::No => Ok(ServerCertVerified::assertion()),
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_hosts_load_and_check() {
        let temp_dir = std::env::temp_dir().join("morsh_kh_test_load");
        let _ = std::fs::create_dir_all(&temp_dir);
        let kh_file = temp_dir.join("known_hosts");

        let test_fp = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";
        let other_fp = "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00";

        KnownHosts::add_entry(
            &kh_file,
            "example.com",
            2222,
            Some("1.2.3.4:2222".parse().unwrap()),
            test_fp,
        )
        .unwrap();

        let kh = KnownHosts::load_from_file(&kh_file).unwrap();

        // 1. Match by hostname
        assert_eq!(
            kh.check("example.com", 2222, &None, test_fp),
            KnownHostStatus::Matched
        );

        // 2. Match by IP
        let ip_addr: SocketAddr = "1.2.3.4:2222".parse().unwrap();
        assert_eq!(
            kh.check("1.2.3.4", 2222, &Some(ip_addr), test_fp),
            KnownHostStatus::Matched
        );

        // 3. Mismatch detection
        assert_eq!(
            kh.check("example.com", 2222, &None, other_fp),
            KnownHostStatus::Mismatch {
                expected: test_fp.to_string(),
                found: other_fp.to_string(),
            }
        );

        // 4. Not found
        assert_eq!(
            kh.check("unknown.host", 2222, &None, test_fp),
            KnownHostStatus::NotFound
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_tofu_verifier_accept_new_and_verify() {
        use crate::tls::generate_self_signed_cert;

        let temp_dir = std::env::temp_dir().join("morsh_tofu_test_verifier");
        let _ = std::fs::create_dir_all(&temp_dir);
        let kh_file = temp_dir.join("known_hosts");

        let (certs1, _key1) = generate_self_signed_cert(vec!["localhost".into()]).unwrap();
        let (certs2, _key2) = generate_self_signed_cert(vec!["localhost".into()]).unwrap();

        let cert1 = &certs1[0];
        let cert2 = &certs2[0];
        let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();

        // 1. StrictHostKeyChecking=accept-new should automatically add cert1
        let verifier = TofuServerCertVerifier {
            target_host: "localhost".to_string(),
            target_port: 2222,
            remote_addr: Some("127.0.0.1:2222".parse().unwrap()),
            known_hosts_path: kh_file.clone(),
            strict_mode: StrictHostKeyCheckingMode::AcceptNew,
            insecure: false,
            webpki_verifier: None,
            shared_state: Arc::new(Mutex::new(TofuSharedState::default())),
        };

        let res = verifier.verify_server_cert(
            cert1,
            &[],
            &server_name,
            &[],
            UnixTime::now(),
        );
        assert!(res.is_ok(), "accept-new should succeed for new host");

        // 2. StrictHostKeyChecking=yes should now succeed for cert1 because it's in known_hosts
        let verifier_strict = TofuServerCertVerifier {
            target_host: "localhost".to_string(),
            target_port: 2222,
            remote_addr: Some("127.0.0.1:2222".parse().unwrap()),
            known_hosts_path: kh_file.clone(),
            strict_mode: StrictHostKeyCheckingMode::Yes,
            insecure: false,
            webpki_verifier: None,
            shared_state: Arc::new(Mutex::new(TofuSharedState::default())),
        };

        let res_strict = verifier_strict.verify_server_cert(
            cert1,
            &[],
            &server_name,
            &[],
            UnixTime::now(),
        );
        assert!(res_strict.is_ok(), "strict yes should succeed for known host");

        // 3. StrictHostKeyChecking=yes should reject cert2 (host key changed!)
        let res_mismatch = verifier_strict.verify_server_cert(
            cert2,
            &[],
            &server_name,
            &[],
            UnixTime::now(),
        );
        assert!(res_mismatch.is_err(), "strict yes should reject changed host key");

        // 4. StrictHostKeyChecking=no should accept even changed cert2
        let verifier_no = TofuServerCertVerifier {
            target_host: "localhost".to_string(),
            target_port: 2222,
            remote_addr: Some("127.0.0.1:2222".parse().unwrap()),
            known_hosts_path: kh_file.clone(),
            strict_mode: StrictHostKeyCheckingMode::No,
            insecure: false,
            webpki_verifier: None,
            shared_state: Arc::new(Mutex::new(TofuSharedState::default())),
        };

        let res_no = verifier_no.verify_server_cert(
            cert2,
            &[],
            &server_name,
            &[],
            UnixTime::now(),
        );
        assert!(res_no.is_ok(), "strict no should accept any key");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

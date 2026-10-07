use anyhow::{Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::DigitallySignedStruct;
use std::sync::Arc;

/// Generates an ephemeral self-signed X.509 certificate and private key.
pub fn generate_self_signed_cert(
    subject_alt_names: Vec<String>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let subject_names = if subject_alt_names.is_empty() {
        vec!["localhost".to_string()]
    } else {
        subject_alt_names
    };

    let certified_key = rcgen::generate_simple_self_signed(subject_names)
        .context("Failed to generate self-signed certificate")?;

    let cert_der = certified_key.cert.der().to_owned();
    let key_der = PrivateKeyDer::Pkcs8(certified_key.signing_key.serialize_der().into());

    Ok((vec![cert_der], key_der))
}

/// Generates a self-signed X.509 certificate and private key in PEM format.
pub fn generate_self_signed_cert_pem(
    subject_alt_names: Vec<String>,
) -> Result<(String, String)> {
    let subject_names = if subject_alt_names.is_empty() {
        vec!["localhost".to_string(), "0.0.0.0".to_string(), "127.0.0.1".to_string()]
    } else {
        subject_alt_names
    };

    let certified_key = rcgen::generate_simple_self_signed(subject_names)
        .context("Failed to generate self-signed certificate")?;

    let cert_pem = certified_key.cert.pem();
    let key_pem = certified_key.signing_key.serialize_pem();

    Ok((cert_pem, key_pem))
}

/// Computes the SHA-256 fingerprint of a certificate for TOFU / host verification.
pub fn cert_fingerprint_sha256(cert: &CertificateDer) -> String {
    use ring::digest::{digest, SHA256};
    let hash = digest(&SHA256, cert.as_ref());
    let hex_chars: Vec<String> = hash.as_ref().iter().map(|b| format!("{:02x}", b)).collect();
    hex_chars.join(":")
}

/// Builds a rustls ServerConfig with TLS 1.3 and ALPN negotiated for morsh.
pub fn make_rustls_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>> {
    let mut rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("Failed to configure TLS server certificate")?;

    rustls_config.alpn_protocols = vec![morsh_core::ALPN_MORSH.to_vec()];
    Ok(Arc::new(rustls_config))
}

/// Builds a Quinn ServerConfig from an existing rustls ServerConfig.
pub fn make_server_config_from_rustls(
    rustls_config: Arc<rustls::ServerConfig>,
) -> Result<ServerConfig> {
    let quic_server_config = QuicServerConfig::try_from(rustls_config)
        .context("Failed to create QUIC server crypto config")?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

    // Enable connection migration and sensible transport defaults
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into()?));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

/// Builds a Quinn ServerConfig with TLS 1.3 and ALPN negotiated for morsh.
pub fn make_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    let rustls_config = make_rustls_server_config(cert_chain, private_key)?;
    make_server_config_from_rustls(rustls_config)
}

/// A certificate verifier that accepts any certificate (used for development or TOFU mode).
#[derive(Debug)]
pub struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Builds a rustls ClientConfig with ALPN and custom/insecure verifier.
pub fn make_rustls_client_config(insecure: bool) -> Result<Arc<rustls::ClientConfig>> {
    let mut rustls_config = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        // Load system native certs
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = root_store.add(cert);
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    rustls_config.alpn_protocols = vec![morsh_core::ALPN_MORSH.to_vec()];
    Ok(Arc::new(rustls_config))
}

use crate::known_hosts::{StrictHostKeyCheckingMode, TofuServerCertVerifier, TofuSharedState};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Options for Trust-On-First-Use (TOFU) host certificate verification.
#[derive(Debug, Clone)]
pub struct TofuOptions {
    pub target_host: String,
    pub target_port: u16,
    pub remote_addr: Option<SocketAddr>,
    pub known_hosts_path: PathBuf,
    pub strict_mode: StrictHostKeyCheckingMode,
    pub insecure: bool,
}

/// Builds a rustls ClientConfig that uses OpenSSH-compatible TOFU host key verification.
pub fn make_tofu_rustls_client_config(options: TofuOptions) -> Result<Arc<rustls::ClientConfig>> {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = root_store.add(cert);
    }
    let webpki_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .ok();

    let verifier = TofuServerCertVerifier {
        target_host: options.target_host,
        target_port: options.target_port,
        remote_addr: options.remote_addr,
        known_hosts_path: options.known_hosts_path,
        strict_mode: options.strict_mode,
        insecure: options.insecure,
        webpki_verifier,
        shared_state: Arc::new(std::sync::Mutex::new(TofuSharedState::default())),
    };

    let mut rustls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    rustls_config.alpn_protocols = vec![morsh_core::ALPN_MORSH.to_vec()];
    Ok(Arc::new(rustls_config))
}

/// Builds a Quinn ClientConfig from an existing rustls ClientConfig.
pub fn make_client_config_from_rustls(
    rustls_config: Arc<rustls::ClientConfig>,
) -> Result<ClientConfig> {
    let quic_client_config = QuicClientConfig::try_from(rustls_config)
        .context("Failed to create QUIC client crypto config")?;

    let mut client_config = ClientConfig::new(Arc::new(quic_client_config));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into()?));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}

/// Builds a Quinn ClientConfig with ALPN and custom/insecure verifier.
pub fn make_client_config(insecure: bool) -> Result<ClientConfig> {
    let rustls_config = make_rustls_client_config(insecure)?;
    make_client_config_from_rustls(rustls_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed_cert_and_fingerprint() {
        let (certs, _key) = generate_self_signed_cert(vec!["localhost".into()]).unwrap();
        assert!(!certs.is_empty());

        let fingerprint = cert_fingerprint_sha256(&certs[0]);
        // SHA-256 fingerprint: 32 hex bytes separated by ':' -> 32*2 + 31 = 95 chars
        assert_eq!(fingerprint.len(), 95);
        assert_eq!(fingerprint.matches(':').count(), 31);
    }

    #[test]
    fn test_configs_construct_with_alpn() {
        let (certs, key) = generate_self_signed_cert(vec!["127.0.0.1".into()]).unwrap();
        let server_cfg = make_server_config(certs, key);
        assert!(server_cfg.is_ok());

        let client_cfg = make_client_config(true);
        assert!(client_cfg.is_ok());
    }
}

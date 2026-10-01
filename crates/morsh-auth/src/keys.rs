use crate::error::{AuthError, Result};
use morsh_core::protocol::make_challenge_payload;
use signature::{SignatureEncoding, Signer};
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::debug;

/// Loads an SSH private key from disk (supports unencrypted and password-protected keys).
pub fn load_private_key_file<P: AsRef<Path>>(
    path: P,
    passphrase: Option<&str>,
) -> Result<PrivateKey> {
    let path = path.as_ref();
    let content = fs::read_to_string(path).map_err(|e| {
        AuthError::KeyParse(format!("Failed to read private key from {}: {}", path.display(), e))
    })?;

    let key = PrivateKey::from_openssh(&content).map_err(|e| {
        AuthError::KeyParse(format!(
            "Failed to parse private key from {}: {}",
            path.display(),
            e
        ))
    })?;

    if key.is_encrypted() {
        if let Some(pass) = passphrase {
            key.decrypt(pass).map_err(|e| {
                AuthError::KeyParse(format!(
                    "Failed to decrypt encrypted private key from {}: {}",
                    path.display(),
                    e
                ))
            })
        } else {
            Err(AuthError::KeyParse(format!(
                "Private key {} is encrypted but no passphrase was provided",
                path.display()
            )))
        }
    } else {
        Ok(key)
    }
}


/// Discovers candidate default SSH private key paths in `~/.ssh/` in priority order.
pub fn discover_default_private_keys() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        let ssh_dir = PathBuf::from(home).join(".ssh");
        let default_names = ["id_ed25519", "id_ecdsa", "id_rsa"];
        for name in default_names {
            let key_path = ssh_dir.join(name);
            if key_path.exists() {
                candidates.push(key_path);
            }
        }
    }
    candidates
}

/// Returns the highest-priority existing default SSH private key if available.
pub fn find_first_default_private_key() -> Option<PathBuf> {
    discover_default_private_keys().into_iter().next()
}

/// Signs a morsh authentication challenge with the given SSH private key.
///
/// Returns `(algorithm_name, public_key_bytes, signature_bytes)` ready for `AuthRequest::PublicKey`.
pub fn sign_challenge(
    sk: &PrivateKey,
    session_id: &[u8; 16],
    challenge: &[u8; 32],
    username: &str,
) -> Result<(String, Vec<u8>, Vec<u8>)> {
    let payload = make_challenge_payload(session_id, challenge, username);
    let pk = sk.public_key();
    let pk_bytes = pk
        .to_bytes()
        .map_err(|e| AuthError::KeyParse(format!("Failed to serialize public key: {}", e)))?;

    match sk.key_data() {
        ssh_key::private::KeypairData::Ed25519(_) => {
            let sig: Signature = Signer::try_sign(sk, payload.as_slice())
                .map_err(|e| AuthError::Crypto(format!("Ed25519 signing failed: {}", e)))?;
            Ok((sig.algorithm().to_string(), pk_bytes, sig.as_bytes().to_vec()))
        }

        ssh_key::private::KeypairData::Ecdsa(_) => {
            let sig: Signature = Signer::try_sign(sk, payload.as_slice())
                .map_err(|e| AuthError::Crypto(format!("ECDSA signing failed: {}", e)))?;
            Ok((sig.algorithm().to_string(), pk_bytes, sig.as_bytes().to_vec()))
        }

        ssh_key::private::KeypairData::Rsa(rsa_kp) => {
            // Note: In ssh-key 0.6.7, RsaKeypair::try_into() contains an upstream bug passing vec![p, p]
            // instead of vec![p, q]. We directly construct the RSA signing key with the correct components.
            let n = rsa::BigUint::try_from(&rsa_kp.public.n)
                .map_err(|e| AuthError::Crypto(format!("Invalid RSA modulus: {}", e)))?;
            let e = rsa::BigUint::try_from(&rsa_kp.public.e)
                .map_err(|e| AuthError::Crypto(format!("Invalid RSA exponent: {}", e)))?;
            let d = rsa::BigUint::try_from(&rsa_kp.private.d)
                .map_err(|e| AuthError::Crypto(format!("Invalid RSA d: {}", e)))?;
            let p = rsa::BigUint::try_from(&rsa_kp.private.p)
                .map_err(|e| AuthError::Crypto(format!("Invalid RSA p: {}", e)))?;
            let q = rsa::BigUint::try_from(&rsa_kp.private.q)
                .map_err(|e| AuthError::Crypto(format!("Invalid RSA q: {}", e)))?;

            let priv_key = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])
                .map_err(|e| AuthError::Crypto(format!("Failed to build RSA private key: {}", e)))?;

            let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(priv_key);
            let sig_data = Signer::try_sign(&signing_key, payload.as_slice())
                .map_err(|e| AuthError::Crypto(format!("RSA signing failed: {}", e)))?;

            let rsa_sig = Signature::new(
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
                sig_data.to_vec(),
            )
            .map_err(|e| AuthError::Crypto(format!("Failed to format RSA signature: {}", e)))?;

            debug!("Signed challenge with RSA-SHA512 key");
            Ok((rsa_sig.algorithm().to_string(), pk_bytes, rsa_sig.as_bytes().to_vec()))
        }

        _ => Err(AuthError::UnsupportedAlgorithm(
            sk.algorithm().to_string(),
        )),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorized_keys::AuthorizedKeys;
    use ssh_key::rand_core::OsRng;

    #[test]
    fn test_sign_and_verify_ed25519_challenge() {
        let sk = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let session_id = [0x11u8; 16];
        let challenge = [0x22u8; 32];
        let username = "tester";

        let (alg, pk_bytes, sig_bytes) = sign_challenge(&sk, &session_id, &challenge, username).unwrap();
        assert_eq!(alg, "ssh-ed25519");

        let entry_str = format!("{} test\n", sk.public_key().to_openssh().unwrap());
        let ak = AuthorizedKeys::parse(&entry_str).unwrap();

        let res = ak.verify_challenge(username, &session_id, &challenge, &alg, &pk_bytes, &sig_bytes);
        assert!(res.is_ok());
    }

    #[test]
    fn test_sign_and_verify_ecdsa_challenge() {
        use ssh_key::EcdsaCurve;
        let sk = PrivateKey::random(&mut OsRng, Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }).unwrap();
        let session_id = [0x33u8; 16];
        let challenge = [0x44u8; 32];
        let username = "tester";

        let (alg, pk_bytes, sig_bytes) = sign_challenge(&sk, &session_id, &challenge, username).unwrap();
        assert!(alg.contains("ecdsa"));

        let entry_str = format!("{} test\n", sk.public_key().to_openssh().unwrap());
        let ak = AuthorizedKeys::parse(&entry_str).unwrap();

        let res = ak.verify_challenge(username, &session_id, &challenge, &alg, &pk_bytes, &sig_bytes);
        assert!(res.is_ok());
    }
}


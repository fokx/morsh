use crate::error::{AuthError, Result};
use morsh_core::protocol::make_challenge_payload;
use signature::Verifier;
use ssh_key::authorized_keys::Entry;
use ssh_key::{Algorithm, PublicKey, Signature};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::{debug, warn};

/// Collection of authorized SSH public keys.
#[derive(Debug, Clone, Default)]
pub struct AuthorizedKeys {
    entries: Vec<Entry>,
}

impl AuthorizedKeys {
    /// Creates an empty AuthorizedKeys container.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Appends a parsed entry to the list of authorized keys.
    pub fn add_entry(&mut self, entry: Entry) {
        self.entries.push(entry);
    }

    /// Returns the number of authorized keys loaded.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if no authorized keys are loaded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Parses an `authorized_keys` formatted string.
    pub fn parse(content: &str) -> Result<Self> {
        let mut entries = Vec::new();
        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            match Entry::from_str(trimmed) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    warn!(line = line_num + 1, error = %e, "Skipping invalid authorized_keys line");
                }
            }
        }
        Ok(Self { entries })
    }

    /// Loads authorized keys from an arbitrary file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(AuthError::KeyParse(format!(
                "authorized_keys file not found: {}",
                path.display()
            )));
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for (line_num, line_res) in reader.lines().enumerate() {
            let line = line_res?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            match Entry::from_str(trimmed) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    warn!(line = line_num + 1, error = %e, "Skipping invalid authorized_keys line");
                }
            }
        }

        debug!(path = %path.display(), count = entries.len(), "Loaded authorized keys");
        Ok(Self { entries })
    }

    /// Attempts to locate and load `~/.ssh/authorized_keys` for the given Unix user.
    pub fn for_user(username: &str) -> Result<Self> {
        let path = Self::locate_authorized_keys_for_user(username)?;
        Self::from_file(&path)
    }

    /// Resolves the candidate path for a user's `authorized_keys` file.
    pub fn locate_authorized_keys_for_user(username: &str) -> Result<PathBuf> {
        // If current user matches requested user, check $HOME/.ssh/authorized_keys
        if let Ok(current_user) = std::env::var("USER")
            && current_user == username
            && let Ok(home) = std::env::var("HOME")
        {
            let p = PathBuf::from(home).join(".ssh").join("authorized_keys");
            if p.exists() {
                return Ok(p);
            }
        }

        // Check common Unix user home directory locations
        let candidate = if username == "root" {
            PathBuf::from("/root/.ssh/authorized_keys")
        } else {
            PathBuf::from(format!("/home/{}/.ssh/authorized_keys", username))
        };

        if candidate.exists() {
            return Ok(candidate);
        }

        Err(AuthError::KeyParse(format!(
            "Could not locate authorized_keys for user '{}' at {}",
            username,
            candidate.display()
        )))
    }

    /// Checks if a given public key is in the authorized keys list.
    pub fn is_authorized(&self, key: &PublicKey) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.public_key().key_data() == key.key_data())
    }

    /// Verifies an incoming authentication challenge signed with an SSH key.
    ///
    /// 1. Reconstructs the canonical challenge buffer: `morsh-auth-v1: <session_id> <challenge> <username>`
    /// 2. Validates that the public key is present in this `authorized_keys` collection.
    /// 3. Validates the signature against the challenge buffer using the public key.
    pub fn verify_challenge(
        &self,
        username: &str,
        session_id: &[u8; 16],
        challenge: &[u8; 32],
        algorithm: &str,
        public_key_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<()> {
        let pk = PublicKey::from_bytes(public_key_bytes)
            .map_err(|e| AuthError::KeyParse(format!("Failed to parse public key bytes: {}", e)))?;

        if !self.is_authorized(&pk) {
            warn!(username, "Public key not present in authorized_keys");
            return Err(AuthError::UnauthorizedKey);
        }

        let alg = Algorithm::from_str(algorithm).map_err(|e| {
            AuthError::UnsupportedAlgorithm(format!("Invalid algorithm '{}': {}", algorithm, e))
        })?;

        let sig = Signature::new(alg, signature_bytes.to_vec()).map_err(|e| {
            AuthError::SignatureVerification(format!("Failed to construct signature: {}", e))
        })?;

        let payload = make_challenge_payload(session_id, challenge, username);

        Verifier::verify(&pk, &payload, &sig).map_err(|e| {
            AuthError::SignatureVerification(format!("Cryptographic verification failed: {}", e))
        })?;

        debug!(username, algorithm, "Public key signature verified successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;
    use ssh_key::PrivateKey;

    #[test]
    fn test_parse_authorized_keys_entries() {
        let sk1 = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let sk2 = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();

        let line1 = format!("{} user1@machine\n", sk1.public_key().to_openssh().unwrap());
        let line2 = format!("# This is a comment\n\n{} user2@machine\n", sk2.public_key().to_openssh().unwrap());
        let content = format!("{}{}", line1, line2);

        let ak = AuthorizedKeys::parse(&content).unwrap();
        assert_eq!(ak.len(), 2);
        assert!(ak.is_authorized(sk1.public_key()));
        assert!(ak.is_authorized(sk2.public_key()));

        let sk_unauth = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        assert!(!ak.is_authorized(sk_unauth.public_key()));
    }

    #[test]
    fn test_verify_challenge_success_and_failure() {
        let sk = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pk = sk.public_key();

        let line = format!("{} test@morsh\n", pk.to_openssh().unwrap());
        let ak = AuthorizedKeys::parse(&line).unwrap();

        let session_id = [1u8; 16];
        let challenge = [2u8; 32];
        let username = "alice";

        let payload = make_challenge_payload(&session_id, &challenge, username);
        let sig: Signature = signature::Signer::try_sign(&sk, payload.as_slice()).unwrap();

        let pk_bytes = pk.to_bytes().unwrap();
        let sig_bytes = sig.as_bytes().to_vec();
        let alg = sig.algorithm().to_string();

        // 1. Success case
        let res = ak.verify_challenge(
            username,
            &session_id,
            &challenge,
            &alg,
            &pk_bytes,
            &sig_bytes,
        );
        assert!(res.is_ok());

        // 2. Wrong username (challenge binding mismatch)
        let res_wrong_user = ak.verify_challenge(
            "bob",
            &session_id,
            &challenge,
            &alg,
            &pk_bytes,
            &sig_bytes,
        );
        assert!(matches!(res_wrong_user, Err(AuthError::SignatureVerification(_))));

        // 3. Wrong challenge
        let wrong_challenge = [9u8; 32];
        let res_wrong_ch = ak.verify_challenge(
            username,
            &session_id,
            &wrong_challenge,
            &alg,
            &pk_bytes,
            &sig_bytes,
        );
        assert!(matches!(res_wrong_ch, Err(AuthError::SignatureVerification(_))));

        // 4. Unauthorized key
        let unauth_sk = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let unauth_pk_bytes = unauth_sk.public_key().to_bytes().unwrap();
        let unauth_sig: Signature = signature::Signer::try_sign(&unauth_sk, payload.as_slice()).unwrap();
        let res_unauth = ak.verify_challenge(
            username,
            &session_id,
            &challenge,
            &alg,
            &unauth_pk_bytes,
            unauth_sig.as_bytes(),
        );
        assert!(matches!(res_unauth, Err(AuthError::UnauthorizedKey)));
    }
}

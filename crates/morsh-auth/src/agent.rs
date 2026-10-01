use crate::error::{AuthError, Result};
use morsh_core::protocol::make_challenge_payload;
use ssh_agent_client_rs::Client;
use ssh_key::PublicKey;
use std::path::{Path, PathBuf};
use tracing::debug;

/// Client interacting with the local OpenSSH agent via Unix domain socket (`$SSH_AUTH_SOCK`).
pub struct AgentClient {
    client: Client,
    socket_path: PathBuf,
}

impl AgentClient {
    /// Checks if the `$SSH_AUTH_SOCK` environment variable is defined and exists.
    pub fn is_available() -> bool {
        match std::env::var("SSH_AUTH_SOCK") {
            Ok(val) if !val.is_empty() => Path::new(&val).exists(),
            _ => false,
        }
    }

    /// Connects to the agent specified in `$SSH_AUTH_SOCK`.
    pub fn connect_env() -> Result<Self> {
        let sock_str = std::env::var("SSH_AUTH_SOCK").map_err(|_| {
            AuthError::Agent("SSH_AUTH_SOCK environment variable is not set".into())
        })?;
        Self::connect_path(Path::new(&sock_str))
    }

    /// Connects to an SSH agent at the specified socket path.
    pub fn connect_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_buf = path.as_ref().to_path_buf();
        let client = Client::connect(&path_buf).map_err(|e| {
            AuthError::Agent(format!(
                "Failed to connect to ssh-agent socket at {}: {}",
                path_buf.display(),
                e
            ))
        })?;

        debug!(socket = %path_buf.display(), "Connected to ssh-agent");
        Ok(Self {
            client,
            socket_path: path_buf,
        })
    }

    /// Path to the socket used by this client.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Queries the SSH agent for all stored public keys / identities.
    pub fn list_identities(&mut self) -> Result<Vec<PublicKey>> {
        let identities = self.client.list_all_identities().map_err(|e| {
            AuthError::Agent(format!("Failed to query identities from ssh-agent: {}", e))
        })?;

        let keys = identities
            .into_iter()
            .filter_map(|id| match id {
                ssh_agent_client_rs::Identity::PublicKey(pk) => Some(pk.into_owned()),
                _ => None,
            })
            .collect();

        Ok(keys)
    }


    /// Requests the SSH agent to sign a morsh authentication challenge with one of its stored identities.
    ///
    /// Returns `(algorithm_name, public_key_bytes, signature_bytes)` ready for `AuthRequest::PublicKey`.
    pub fn sign_challenge(
        &mut self,
        identity: &PublicKey,
        session_id: &[u8; 16],
        challenge: &[u8; 32],
        username: &str,
    ) -> Result<(String, Vec<u8>, Vec<u8>)> {
        let payload = make_challenge_payload(session_id, challenge, username);

        let sig = self
            .client
            .sign(identity, &payload)
            .map_err(|e| AuthError::Agent(format!("Agent signature failed: {}", e)))?;

        let pk_bytes = identity
            .to_bytes()
            .map_err(|e| AuthError::KeyParse(format!("Failed to serialize identity public key: {}", e)))?;

        let alg = sig.algorithm().to_string();
        let sig_bytes = sig.as_bytes().to_vec();

        debug!(algorithm = %alg, "Successfully signed challenge via ssh-agent");
        Ok((alg, pk_bytes, sig_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_availability_detection() {
        // If not in an active session with an agent, should return false gracefully
        let available = AgentClient::is_available();
        if !available {
            let res = AgentClient::connect_path("/tmp/nonexistent-agent.sock");
            assert!(matches!(res, Err(AuthError::Agent(_))));
        }
    }
}

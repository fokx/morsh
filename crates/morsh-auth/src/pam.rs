use crate::error::{AuthError, Result};
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{debug, warn};

/// Trait defining system or password-based authentication.
pub trait PasswordVerifier: Send + Sync {
    /// Verifies the given username and password. Returns Ok(true) on success, Ok(false) or Err on failure.
    fn verify_password(&self, username: &str, password: &str) -> Result<bool>;
}

/// Linux PAM-based password authenticator.
pub struct PamAuthenticator {
    service_name: String,
}

impl PamAuthenticator {
    /// Constructs a PAM authenticator using the specified PAM service name (e.g. "morsh", "sshd", "login").
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }
}

impl Default for PamAuthenticator {
    fn default() -> Self {
        Self::new("morsh")
    }
}

impl PasswordVerifier for PamAuthenticator {
    fn verify_password(&self, username: &str, password: &str) -> Result<bool> {
        let mut client = pam::Client::with_password(&self.service_name).map_err(|e| {
            AuthError::Pam(format!(
                "Failed to initialize PAM client for service '{}': {:?}",
                self.service_name, e
            ))
        })?;

        client.conversation_mut().set_credentials(username, password);

        match client.authenticate() {
            Ok(_) => {
                debug!(username, service = %self.service_name, "PAM authentication succeeded");
                // Optionally open PAM session if required
                let _ = client.open_session();
                Ok(true)
            }
            Err(e) => {
                warn!(username, service = %self.service_name, error = ?e, "PAM authentication failed");
                Ok(false)
            }
        }
    }
}

/// In-memory password verifier designed for unit tests, development, and standalone testing.
#[derive(Default)]
pub struct MockPasswordVerifier {
    credentials: RwLock<HashMap<String, String>>,
}

impl MockPasswordVerifier {
    pub fn new() -> Self {
        Self {
            credentials: RwLock::new(HashMap::new()),
        }
    }

    /// Adds an allowed user and password combination.
    pub fn add_user(&self, username: impl Into<String>, password: impl Into<String>) {
        self.credentials
            .write()
            .unwrap()
            .insert(username.into(), password.into());
    }
}

impl PasswordVerifier for MockPasswordVerifier {
    fn verify_password(&self, username: &str, password: &str) -> Result<bool> {
        let creds = self.credentials.read().unwrap();
        if let Some(expected_pw) = creds.get(username) {
            Ok(expected_pw == password)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_password_verifier() {
        let verifier = MockPasswordVerifier::new();
        verifier.add_user("alice", "s3cr3t");

        assert!(verifier.verify_password("alice", "s3cr3t").unwrap());
        assert!(!verifier.verify_password("alice", "wrongpass").unwrap());
        assert!(!verifier.verify_password("bob", "s3cr3t").unwrap());
    }
}

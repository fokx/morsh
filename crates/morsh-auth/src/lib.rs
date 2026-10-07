//! Authentication subsystem for morsh.
//!
//! Provides Phase 2 functionality:
//! - SSH Public Key authentication against `~/.ssh/authorized_keys` (Ed25519, RSA, ECDSA)
//! - Local `ssh-agent` UNIX domain socket client integration
//! - Linux PAM and configurable password authentication
//! - Cryptographically bound challenge-response verification

pub mod agent;
pub mod authorized_keys;
pub mod challenge;
pub mod error;
pub mod keys;
pub mod pam;

pub use agent::AgentClient;
pub use authorized_keys::AuthorizedKeys;
pub use challenge::generate_challenge;
pub use error::{AuthError, Result as AuthResult};
pub use keys::{
    discover_default_private_keys, find_first_default_private_key, load_private_key_file,
    sign_challenge,
};
pub use pam::{MockPasswordVerifier, PamAuthenticator, PasswordVerifier};
pub use ssh_key::{self, Algorithm, PrivateKey, PublicKey, Signature};

/// Returns the current authentication subsystem version string.
pub fn auth_subsystem_version() -> &'static str {
    "0.2.0-phase2"
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;
    use ssh_key::EcdsaCurve;


    #[test]
    fn test_auth_subsystem_version() {
        assert_eq!(auth_subsystem_version(), "0.2.0-phase2");
    }

    #[test]
    fn test_end_to_end_ed25519_flow() {
        // 1. Generate client key
        let sk = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pk = sk.public_key();

        // 2. Configure authorized_keys on server
        let ak_content = format!("{} test-user@morsh\n", pk.to_openssh().unwrap());
        let ak = AuthorizedKeys::parse(&ak_content).unwrap();

        // 3. Server issues challenge
        let session_id = [0xabu8; 16];
        let challenge = generate_challenge();
        let username = "alice";

        // 4. Client signs challenge
        let (alg, pk_bytes, sig_bytes) =
            sign_challenge(&sk, &session_id, &challenge, username).unwrap();

        // 5. Server verifies challenge
        let res = ak.verify_challenge(
            username,
            &session_id,
            &challenge,
            &alg,
            &pk_bytes,
            &sig_bytes,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_end_to_end_ecdsa_flow() {
        let sk = PrivateKey::random(&mut OsRng, Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }).unwrap();
        let pk = sk.public_key();

        let ak_content = format!("{} ecdsa-user@morsh\n", pk.to_openssh().unwrap());
        let ak = AuthorizedKeys::parse(&ak_content).unwrap();

        let session_id = [0x55u8; 16];
        let challenge = generate_challenge();
        let username = "bob";

        let (alg, pk_bytes, sig_bytes) =
            sign_challenge(&sk, &session_id, &challenge, username).unwrap();

        let res = ak.verify_challenge(
            username,
            &session_id,
            &challenge,
            &alg,
            &pk_bytes,
            &sig_bytes,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_end_to_end_rsa_flow() {
        // Static pre-generated 3072-bit test key to avoid expensive prime search in test
        let rsa_pem = concat!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n",
            "NhAAAAAwEAAQAAAYEApo5HjJvJNyZDa39enm+aRuG3O+wejLd1TeLGpbbEVfLwEqclmvz5\n",
            "QYHWnpXTmjSeTStIKlNysolDcx23XHPOe9nuyFAQyUv65WlgEYki+GqLNlWzV9JOemec2K\n",
            "fZv26uZvf5pW/j0JDQYyIYpoKWDYqtk8AYmHgOrS2+/XD7RwNHF+QS5P2uaFKS7IkeJCP3\n",
            "/kPfL1QymrCl11YeWC5C6G667gwenq9gPXznCFBdDuCQkS4fw3NetYBN30K2EzEHp26aWc\n",
            "38a2X0PGMCz7yo56pvl0V/qW07Wibo9BIE0s1CvhGcaEsPAjcImaca48HnEzFUPMP7K0Jo\n",
            "eAARrk6pNMD/B3CO4YPn6Qb+5Ino4eV/znocbfj7rvObvRlV29WtGr/74Sb1AgXLiErwgP\n",
            "89cFSdMXS4W9f2Ykw3U88jW2UNDkIo8yvntUpZDYaft3hlWbt6TWb506acCF798IOpFdR6\n",
            "HZFhoIdWsmOwbnOdmfKJA2KryWreQszo+TmkDa/5AAAFiD9lruM/Za7jAAAAB3NzaC1yc2\n",
            "EAAAGBAKaOR4ybyTcmQ2t/Xp5vmkbhtzvsHoy3dU3ixqW2xFXy8BKnJZr8+UGB1p6V05o0\n",
            "nk0rSCpTcrKJQ3Mdt1xzznvZ7shQEMlL+uVpYBGJIvhqizZVs1fSTnpnnNin2b9urmb3+a\n",
            "Vv49CQ0GMiGKaClg2KrZPAGJh4Dq0tvv1w+0cDRxfkEuT9rmhSkuyJHiQj9/5D3y9UMpqw\n",
            "pddWHlguQuhuuu4MHp6vYD185whQXQ7gkJEuH8NzXrWATd9CthMxB6dumlnN/Gtl9DxjAs\n",
            "+8qOeqb5dFf6ltO1om6PQSBNLNQr4RnGhLDwI3CJmnGuPB5xMxVDzD+ytCaHgAEa5OqTTA\n",
            "/wdwjuGD5+kG/uSJ6OHlf856HG34+67zm70ZVdvVrRq/++Em9QIFy4hK8ID/PXBUnTF0uF\n",
            "vX9mJMN1PPI1tlDQ5CKPMr57VKWQ2Gn7d4ZVm7ek1m+dOmnAhe/fCDqRXUeh2RYaCHVrJj\n",
            "sG5znZnyiQNiq8lq3kLM6Pk5pA2v+QAAAAMBAAEAAAGAa2MLEMaVCsDZ8WJzEDYmw5LewH\n",
            "zyCYpz0J7ps4jOuBfl4DDy1yZKU4kyZpd1klRgyKKiad/Z8PD9kyhSxAJK3KHcCj1NRWx+\n",
            "vRGfBk9kQ8T2Mzc4ZeRMAzHw9+PpSjtDqVIzHQ6yVRQ5t+ERAbLqqpqCZeQSN6QY2mHHZc\n",
            "NF0Dh1yxqbcBd8Lvkmj+msjGLAj6kVKn/gDMrecqOs9vAE5bYXQkqAJ5ItvBdfIoYmKeRy\n",
            "cZjKlAs7wkySaOOrX15ZZbg4fhRwZ5s+poCWX4FZPLFBMQ1MQVaeJbN2otxO2S+RSbdelw\n",
            "6CJHMJRswg81H4EVsbv8uzj2vQbGIEcrdtZB01gCre8VIgq5sqV+NZGP4n4TgRnMpWqYzP\n",
            "PA/Gg6GfJyGodm7N2cV2d2YmVvPT4FMl8/s3MmYj277GOz2YSDCy3Se+u2vS7VNF3/8Y3x\n",
            "gGrevO2phFgElokwaBrD5SMTjFIWyxNZl+PhQ6eBasw9h0HqzsfhX1PaDwgQaRcI2dAAAA\n",
            "wFRAWqZjrp4IADWnEAL0w1HX0ALDUgByXm3A/22QGjBLEDouoBZQeZbTGTWLW+pP60CY9T\n",
            "BSjxK5jFDH3fyF/Er5JXuvmqcjXN9GdzSbd+UqQKXi9EEi0YzkCUGRTpkWnEi3CImNKYaW\n",
            "VmB7fi62NUHgu9Vo5Pd0vsMTfQKlkcjHey4Yjdb3Lu9c/xknzeVzpMoNQ8K2xqlXIURRIu\n",
            "HPaqXwW2XLnIYST595+inwXj8G87g+3KmUH1cWUOD7RoquTAAAAMEA0R564khkDTsgKTaR\n",
            "iGVEzf4HeamqtWyPlia/HmZIv9mIvbCsfRGnPjQFYzbUrTkA/3GE7kBLhLrrEaKjAvmC2U\n",
            "7vt1cDDsbXfZEV6u+Aq1dJoPW1kLKZ/96U+ZMN7bqyrzMwlbCKUEubMPERLc5R837QDQQz\n",
            "Q9Qg0uL7iL1/iBt8iZDki5P9HShPzIwcB/vvwE0CklsvFZqan1Zwc+HJT9xuRy9IljvhbF\n",
            "xUU4Vq0r95FuQsNudaUBiRDY2tA41zAAAAwQDL5Q5+zfXiyG52ypS+iwwFsJBB0rzd7rRn\n",
            "LnEg6syDgOXWt3yFWDxQj47o1VfKvLbfroxyOF8PaTRevBWl3+yUnAdw0C15Rd01klYtpz\n",
            "iGYuBTxUVNJpDeKmPMVV4aAQ4toK4wfRwR+FKpx1aOAvk9SbKo+Se3mUOykgytMhqiCEEJ\n",
            "0TbQhcHQXDn0w2z4n9w8ZqdV5j9EbhYwKxNZlADwqDMhoua5FT3wLwPeMY6gkDkoKFPyAR\n",
            "4JBdEVdmfK8eMAAAAQdXNlckBleGFtcGxlLmNvbQECAw==\n",
            "-----END OPENSSH PRIVATE KEY-----\n"
        );
        let sk = PrivateKey::from_openssh(rsa_pem).unwrap();
        let pk = sk.public_key();

        let ak_content = format!("{} rsa-user@morsh\n", pk.to_openssh().unwrap());
        let ak = AuthorizedKeys::parse(&ak_content).unwrap();

        let session_id = [0x77u8; 16];
        let challenge = generate_challenge();
        let username = "carol";

        let (alg, pk_bytes, sig_bytes) =
            sign_challenge(&sk, &session_id, &challenge, username).unwrap();
        assert_eq!(alg, "rsa-sha2-512");

        let res = ak.verify_challenge(
            username,
            &session_id,
            &challenge,
            &alg,
            &pk_bytes,
            &sig_bytes,
        );
        assert!(res.is_ok());
    }
}

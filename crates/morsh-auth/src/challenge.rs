use ring::rand::{SecureRandom, SystemRandom};

/// Generates a cryptographically secure 32-byte challenge for authentication.
pub fn generate_challenge() -> [u8; 32] {
    let rng = SystemRandom::new();
    let mut challenge = [0u8; 32];
    rng.fill(&mut challenge)
        .expect("System entropy source failed while generating challenge");
    challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge_uniqueness() {
        let c1 = generate_challenge();
        let c2 = generate_challenge();
        assert_ne!(c1, [0u8; 32]);
        assert_ne!(c2, [0u8; 32]);
        assert_ne!(c1, c2);
    }
}

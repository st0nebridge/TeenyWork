/// Tests for challenge issuance and verification.

#[cfg(test)]
mod tests {
    use crate::challenge::issue::issue_challenge;
    use crate::challenge::verify::verify_challenge;

    #[test]
    fn test_issue_challenge() {
        let secret = [0u8; 32];
        let challenge = issue_challenge(&secret, "test/resource", 12).unwrap();

        assert_eq!(challenge.required_work_units, 12);
        assert_eq!(challenge.algorithm, "sha256d-leading-zero-bits");
        assert_eq!(challenge.resource, "test/resource");
    }

    #[test]
    fn test_verify_challenge() {
        let secret = [0u8; 32];
        let challenge = issue_challenge(&secret, "test/resource", 12).unwrap();
        let result = verify_challenge(&secret, &challenge);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_challenge_invalid_secret() {
        let secret = [0u8; 32];
        let challenge = issue_challenge(&secret, "test/resource", 12).unwrap();
        let result = verify_challenge(&[1u8; 32], &challenge);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenges_are_unique_and_signed() {
        let secret = [7u8; 32];
        let first = issue_challenge(&secret, "same-resource", 12).unwrap();
        let second = issue_challenge(&secret, "same-resource", 12).unwrap();
        assert_ne!(first.challenge_id, second.challenge_id);
        assert_ne!(first.nonce, second.nonce);
        assert!(verify_challenge(&secret, &first).is_ok());
    }

    #[test]
    fn test_verify_challenge_rejects_tampering() {
        let secret = [9u8; 32];
        let mut challenge = issue_challenge(&secret, "test/resource", 12).unwrap();
        challenge.resource.push_str("/changed");
        assert!(verify_challenge(&secret, &challenge).is_err());
    }
}

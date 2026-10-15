/// Tests for access-token issuance.

#[cfg(test)]
mod tests {
    use crate::token::access_token::{
        issue_access_token, ACCESS_TOKEN_LIFETIME_SECONDS, TOKEN_ID_BYTES,
    };
    use std::collections::HashSet;

    #[test]
    fn test_issue_token() {
        let token = issue_access_token().unwrap();

        assert_eq!(token.token_id.len(), TOKEN_ID_BYTES * 2);
        assert!(token
            .token_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_eq!(
            (token.expires_at - token.issued_at).num_seconds(),
            ACCESS_TOKEN_LIFETIME_SECONDS
        );
    }

    #[test]
    fn token_ids_are_unique_random_values() {
        let ids: HashSet<String> = (0..1000)
            .map(|_| issue_access_token().unwrap().token_id)
            .collect();
        assert_eq!(ids.len(), 1000, "no two of 1000 token IDs collide");
        let issued_at = issue_access_token().unwrap().issued_at.timestamp();
        assert!(
            ids.iter().all(|id| !id.contains(&issued_at.to_string())),
            "token IDs do not embed the issue time"
        );
    }
}

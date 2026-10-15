use crate::challenge::issue::Challenge;
/// Challenge verification module.
/// Verifies challenge signatures and resource binding.
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Verify a challenge is valid and authentic.
pub fn verify_challenge(server_secret: &[u8], challenge: &Challenge) -> Result<(), String> {
    let mut mac = HmacSha256::new_from_slice(server_secret)
        .map_err(|e| format!("Invalid challenge signing key: {e}"))?;
    mac.update(challenge.challenge_id.as_bytes());
    mac.update(challenge.resource.as_bytes());
    mac.update(&challenge.required_work_units.to_be_bytes());
    mac.update(&challenge.nonce);
    mac.update(
        &challenge
            .issued_at
            .timestamp_nanos_opt()
            .unwrap_or_default()
            .to_be_bytes(),
    );
    mac.update(
        &challenge
            .expires_at
            .timestamp_nanos_opt()
            .unwrap_or_default()
            .to_be_bytes(),
    );
    if mac.verify_slice(&challenge.signature).is_err() {
        return Err("Invalid challenge signature".to_string());
    }

    let now = Utc::now();
    if challenge.expires_at <= challenge.issued_at
        || now < challenge.issued_at
        || now >= challenge.expires_at
    {
        return Err("Challenge is expired or not yet valid".to_string());
    }

    Ok(())
}

use chrono::{TimeDelta, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};

type HmacSha256 = Hmac<Sha256>;
static CHALLENGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct Challenge {
    pub challenge_id: String,
    pub resource: String,
    pub issued_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
    pub required_work_units: u64,
    pub algorithm: String,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn issue_challenge(
    server_secret: &[u8],
    resource: &str,
    work_units: u64,
) -> Result<Challenge, String> {
    let now = Utc::now();
    let expires = now + TimeDelta::seconds(900); // 15 minutes

    let sequence = CHALLENGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut nonce_mac = HmacSha256::new_from_slice(server_secret)
        .map_err(|e| format!("Invalid challenge signing key: {e}"))?;
    nonce_mac.update(resource.as_bytes());
    nonce_mac.update(&now.timestamp_nanos_opt().unwrap_or_default().to_be_bytes());
    nonce_mac.update(&sequence.to_be_bytes());
    let nonce = nonce_mac.finalize().into_bytes().to_vec();
    let challenge_id = format!("{}-{}", now.timestamp_micros(), hex::encode(&nonce[..8]));
    let mut signature_mac = HmacSha256::new_from_slice(server_secret)
        .map_err(|e| format!("Invalid challenge signing key: {e}"))?;
    signature_mac.update(challenge_id.as_bytes());
    signature_mac.update(resource.as_bytes());
    signature_mac.update(&work_units.to_be_bytes());
    signature_mac.update(&nonce);
    signature_mac.update(&now.timestamp_nanos_opt().unwrap_or_default().to_be_bytes());
    signature_mac.update(
        &expires
            .timestamp_nanos_opt()
            .unwrap_or_default()
            .to_be_bytes(),
    );
    let signature = signature_mac.finalize().into_bytes().to_vec();

    Ok(Challenge {
        challenge_id,
        resource: resource.to_string(),
        issued_at: now,
        expires_at: expires,
        required_work_units: work_units,
        algorithm: "sha256d-leading-zero-bits".to_string(),
        nonce,
        signature,
    })
}

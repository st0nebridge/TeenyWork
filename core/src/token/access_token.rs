//! Access-token issuance: an unguessable identifier and an expiry.
//!
//! Purpose: give each successful proof of work a token that cannot be derived
//! from anything a third party can see (such as the challenge ID or the time).
//! Authorization state (resource scope, single use) is held by the server's
//! grant table, keyed by this identifier; the token itself carries no claims.
//! Depends on: `getrandom` (the operating system's CSPRNG), `hex`, `chrono`.

use chrono::{DateTime, TimeDelta, Utc};

/// Random bytes in a token identifier (256 bits).
pub const TOKEN_ID_BYTES: usize = 32;
/// How long an issued token stays valid.
pub const ACCESS_TOKEN_LIFETIME_SECONDS: i64 = 3600;

/// A newly issued access token.
pub struct AccessToken {
    /// 64 lowercase hex characters from the operating system's CSPRNG.
    pub token_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Issues a token with a fresh random identifier that expires after
/// [`ACCESS_TOKEN_LIFETIME_SECONDS`].
pub fn issue_access_token() -> Result<AccessToken, String> {
    let mut random = [0u8; TOKEN_ID_BYTES];
    getrandom::getrandom(&mut random)
        .map_err(|error| format!("The system random number generator failed: {error}"))?;
    let issued_at = Utc::now();
    Ok(AccessToken {
        token_id: hex::encode(random),
        issued_at,
        expires_at: issued_at + TimeDelta::seconds(ACCESS_TOKEN_LIFETIME_SECONDS),
    })
}

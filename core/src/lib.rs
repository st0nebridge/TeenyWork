//! Shared logic for the TeenyWork Challenger server.
//!
//! Purpose: challenge issuance and verification, access-token issuance,
//! Bitcoin SHA-256d header reconstruction and target checks, and the Stratum
//! V1 request builders and `mining.notify` parser. The browser solver
//! (`wasm-challenger`) does not depend on this crate; it is built for the
//! server only.

pub mod challenge;
pub mod proof;
pub mod stratum;
pub mod token;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub use challenge::issue::{issue_challenge, Challenge};
pub use challenge::verify::verify_challenge;
pub use proof::bitcoin::{sha256d, BlockHeader};
pub use stratum::client::StratumClient;
pub use stratum::job::StratumJob;
pub use token::access_token::{issue_access_token, AccessToken};

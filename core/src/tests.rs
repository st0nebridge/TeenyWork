/// Core test module.
/// Includes tests for the challenge, proof, token and stratum modules.

#[cfg(test)]
mod tests {
    // Import all test modules
    #[path = "../challenge/tests.rs"]
    mod challenge_tests;

    #[path = "../proof/tests.rs"]
    mod proof_tests;

    #[path = "../token/tests.rs"]
    mod token_tests;

    #[path = "../stratum/tests.rs"]
    mod stratum_tests;
}

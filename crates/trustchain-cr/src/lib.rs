//! Trustchain Challenge-Response protocol functionality for dDID attestation.
pub mod attestation_encryption_utils;
pub mod attestation_utils;
// TODO: Business logic (not touching axum) to be moved here from trustchain-http:
// pub mod attestor;
#[cfg(test)]
pub(crate) mod data;

/// Fragment for service ID of Trustchain attestion
pub const ATTESTATION_FRAGMENT: &str = "#TrustchainAttestation";

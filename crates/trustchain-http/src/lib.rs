//! Trustchain HTTP server functionality.
pub mod attestation_encryption_utils;
pub mod attestation_utils;
pub mod attestor;
pub mod config;
#[cfg(test)]
pub(crate) mod data;
pub mod errors;
pub mod ion;
pub mod issuer;
pub mod middleware;
pub mod qrcode;
pub mod requester;
pub mod resolver;
pub mod root;
pub mod server;
pub mod state;
pub mod static_handlers;
pub mod store;
pub mod verifier;

/// Fragment for service ID of Trustchain attestion
pub(crate) const ATTESTATION_FRAGMENT: &str = "#TrustchainAttestation";

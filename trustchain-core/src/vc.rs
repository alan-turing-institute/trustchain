//! Verifiable credential functionality for Trustchain.
use crate::verifier::VerifierError;
use ssi::vc::VerificationResult;
use thiserror::Error;

/// An error relating to verifiable credentials and presentations.
#[derive(Error, Debug)]
pub enum CredentialError {
    /// No issuer present in credential.
    #[error("No issuer.")]
    NoIssuerPresent,
    /// No proof present in credential.
    #[error("No proof.")]
    NoProofPresent,
    /// Missing verification method in credential proof.
    #[error("Missing verification method in credential proof.")]
    MissingVerificationMethod,
    /// Failed to decode JWT error.
    #[error("Failed to decode JWT.")]
    FailedToDecodeJWT,
    /// Wrapped error for Verifier error.
    #[error("A wrapped Verifier error: {0}")]
    VerifierError(VerifierError),
    /// Wrapped verification result with errors.
    #[error("A wrapped verification result error: {0:?}")]
    VerificationResultError(VerificationResult),
}

/// An error relating to a verifiable credential for a dataset.
#[derive(Error, Debug)]
pub enum DataCredentialError {
    /// Wrapped CredentialError
    #[error("Credential error: {0:?}")]
    CredentialError(CredentialError),
    /// Hash digests do not match.
    #[error("Hash digests do not match. Expected: {0}. Actual: {1}.")]
    MismatchedHashDigests(String, String),
}

impl From<CredentialError> for DataCredentialError {
    fn from(err: CredentialError) -> Self {
        DataCredentialError::CredentialError(err)
    }
}

impl From<VerifierError> for CredentialError {
    fn from(err: VerifierError) -> Self {
        CredentialError::VerifierError(err)
    }
}

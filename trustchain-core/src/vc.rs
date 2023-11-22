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

impl From<VerifierError> for CredentialError {
    fn from(err: VerifierError) -> Self {
        CredentialError::VerifierError(err)
    }
}

#[cfg(test)]
mod tests {}

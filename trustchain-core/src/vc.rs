//! Verifiable credential and presentation functionality for Trustchain.
use thiserror::Error;

use crate::verifier::VerifierError;

/// An error relating to verifiable credentials and presentations.
#[derive(Error, Debug)]
pub enum CredentialError {
    /// No issuer present in credential.
    #[error("No issuer.")]
    NoIssuerPresent,
    /// Wrapped error for Verifier error.
    #[error("A wrapped Verifier error: {0}")]
    VerifierError(VerifierError),
}

impl From<VerifierError> for CredentialError {
    fn from(err: VerifierError) -> Self {
        CredentialError::VerifierError(err)
    }
}

#[cfg(test)]
mod tests {}

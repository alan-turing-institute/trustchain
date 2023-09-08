//! Verifiable presentation functionality for Trustchain.
use crate::{holder::HolderError, vc::CredentialError, verifier::VerifierError};
use ssi::vc::VerificationResult;
use thiserror::Error;

/// An error relating to verifiable presentations.
#[derive(Error, Debug)]
pub enum PresentationError {
    /// No credentials present in presentation.
    #[error("No credentials.")]
    NoCredentialsPresent,
    /// No holder present in presentation.
    #[error("No holder.")]
    NoHolderPresent,
    /// Wrapped variant for Trustchain holder.
    #[error("A wrapped Trustchain holder error: {0}")]
    HolderError(HolderError),
    /// Wrapped variant for Crediential Error.
    #[error("A wrapped Credential error: {0}")]
    CredentialError(CredentialError),
    /// Wrapped variant for Verifier Error.
    #[error("A wrapped Verifier error: {0}")]
    VerifierError(VerifierError),
    /// Credentials verified, but holder failed to authenticate with invalid or missing presentation
    /// proof.
    #[error("Credentials verified for an unauthenticated holder: {0:?}")]
    VerifiedHolderUnauthenticated(VerificationResult),
}

impl From<HolderError> for PresentationError {
    fn from(err: HolderError) -> Self {
        PresentationError::HolderError(err)
    }
}

impl From<CredentialError> for PresentationError {
    fn from(err: CredentialError) -> Self {
        PresentationError::CredentialError(err)
    }
}

impl From<VerifierError> for PresentationError {
    fn from(err: VerifierError) -> Self {
        PresentationError::VerifierError(err)
    }
}

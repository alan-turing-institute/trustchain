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
    /// Wrapped error for ssi-vc error.
    #[error("A wrapped variant for an SSI VC error: {0}")]
    VC(ssi::vc::Error),
    /// Wrapped error for ssi-ldp error.
    #[error("A wrapped variant for an SSI LDP error: {0}")]
    LDP(ssi::ldp::Error),
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

impl From<ssi::vc::Error> for PresentationError {
    fn from(err: ssi::vc::Error) -> Self {
        PresentationError::VC(err)
    }
}

impl From<ssi::ldp::Error> for PresentationError {
    fn from(err: ssi::ldp::Error) -> Self {
        PresentationError::LDP(err)
    }
}

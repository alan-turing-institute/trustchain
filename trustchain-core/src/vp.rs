//! Verifiable presentation functionality for Trustchain.
use crate::{holder::HolderError, vc::CredentialError};
use thiserror::Error;

/// An error relating to verifiable credentials and presentations.
#[derive(Error, Debug)]
pub enum PresentationError {
    /// No credentials present in presentation.
    #[error("No credentials.")]
    NoCredentialsPresent,
    /// Wrapped variant for Trustchain holder.
    #[error("A wrapped Trustchain holder error: {0}")]
    HolderError(HolderError),
    /// Wrapped variant for Crediential Error.
    #[error("A wrapped Credential error: {0}")]
    CredentialError(CredentialError),
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

#[cfg(test)]
mod tests {}

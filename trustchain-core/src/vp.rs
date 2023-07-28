//! Verifiable presentation functionality for Trustchain.
use thiserror::Error;

use crate::holder::HolderError;

/// An error relating to verifiable credentials and presentations.
#[derive(Error, Debug)]
pub enum PresentationError {
    /// No credentials present in presentation.
    #[error("No credentials.")]
    NoCredentialsPresent,
    /// Wrapped variant for Trustchain holder.
    #[error("A wrapped Trustchain holder error: {0}")]
    HolderError(HolderError),
}

impl From<HolderError> for PresentationError {
    fn from(err: HolderError) -> Self {
        PresentationError::HolderError(err)
    }
}

#[cfg(test)]
mod tests {}

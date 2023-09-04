//! DID issuer API.
use crate::key_manager::KeyManagerError;
use crate::subject::Subject;
use async_trait::async_trait;
use ssi::did_resolve::DIDResolver;
use ssi::vc::{LinkedDataProofOptions, Presentation};
use thiserror::Error;

/// An error relating to a Trustchain holder.
#[derive(Error, Debug)]
pub enum HolderError {
    /// Wrapped error for SSI error.
    #[error("A wrapped variant for an SSI error: {0}")]
    SSI(ssi::error::Error),
    /// Wrapped error for key manager error.
    #[error("A wrapped variant for a key manager error: {0}")]
    KeyManager(KeyManagerError),
}

impl From<ssi::error::Error> for HolderError {
    fn from(err: ssi::error::Error) -> Self {
        HolderError::SSI(err)
    }
}

impl From<KeyManagerError> for HolderError {
    fn from(err: KeyManagerError) -> Self {
        HolderError::KeyManager(err)
    }
}

/// A holder signs a presentation to generate a verifiable presentation.
#[async_trait]
pub trait Holder: Subject {
    /// Attests to a given presentation of one or many credentials returning the presentation with a
    /// proof. The `@context` of the presentation has linked-data fields strictly checked as part of
    /// proof generation.
    async fn sign_presentation<T: DIDResolver>(
        &self,
        presentation: &Presentation,
        key_id: Option<&str>,
        resolver: &T,
        ldp_options: Option<LinkedDataProofOptions>,
    ) -> Result<Presentation, HolderError>;
}

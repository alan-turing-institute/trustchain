//! DID issuer API.
use crate::key_manager::KeyManagerError;
use crate::subject::Subject;
use async_trait::async_trait;
use ssi::did_resolve::DIDResolver;
use ssi::jsonld::ContextLoader;
use ssi::vc::{LinkedDataProofOptions, Presentation};
use thiserror::Error;

/// An error relating to a Trustchain holder.
#[derive(Error, Debug)]
pub enum HolderError {
    /// Wrapped error for ssi-vc error.
    #[error("A wrapped variant for an SSI VC error: {0}")]
    VC(ssi::vc::Error),
    /// Wrapped error for ssi-ldp error.
    #[error("A wrapped variant for an SSI LDP error: {0}")]
    LDP(ssi::ldp::Error),
    /// Wrapped error for key manager error.
    #[error("A wrapped variant for a key manager error: {0}")]
    KeyManager(KeyManagerError),
    /// Holder field mismatched with attestor DID.
    #[error("Holder field mismatched with attestor DID.")]
    MismatchedHolder,
}

impl From<ssi::vc::Error> for HolderError {
    fn from(err: ssi::vc::Error) -> Self {
        HolderError::VC(err)
    }
}

impl From<ssi::ldp::Error> for HolderError {
    fn from(err: ssi::ldp::Error) -> Self {
        HolderError::LDP(err)
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
        linked_data_proof_options: Option<LinkedDataProofOptions>,
        key_id: Option<&str>,
        resolver: &T,
        context_loader: &mut ContextLoader,
    ) -> Result<Presentation, HolderError>;
}

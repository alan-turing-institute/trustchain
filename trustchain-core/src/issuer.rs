//! DID issuer API.
use crate::key_manager::KeyManagerError;
use crate::subject::Subject;
use async_trait::async_trait;
use ssi::did_resolve::DIDResolver;
use ssi::vc::{Credential, LinkedDataProofOptions};
use thiserror::Error;

/// An error relating to a Trustchain Issuer.
#[derive(Error, Debug)]
pub enum IssuerError {
    /// Wrapped error for SSI error.
    #[error("A wrapped variant for an SSI error: {0}")]
    SSI(ssi::error::Error),
    /// Wrapped error for key manager error.
    #[error("A wrapped variant for a key manager error: {0}")]
    KeyManager(KeyManagerError),
}

impl From<ssi::error::Error> for IssuerError {
    fn from(err: ssi::error::Error) -> Self {
        IssuerError::SSI(err)
    }
}

impl From<KeyManagerError> for IssuerError {
    fn from(err: KeyManagerError) -> Self {
        IssuerError::KeyManager(err)
    }
}

/// A credential issuer signs a credential to generate a verifiable credential.
#[async_trait]
pub trait Issuer: Subject {
    /// Signs a credential. An issuer attests to a credential by signing the credential with one of their private signing keys.
    async fn sign<T: DIDResolver>(
        &self,
        credential: &Credential,
        linked_data_proof_options: Option<LinkedDataProofOptions>,
        key_id: Option<&str>,
        resolver: &T,
    ) -> Result<Credential, IssuerError>;
}

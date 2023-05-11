use crate::key_manager::KeyManagerError;
use crate::subject::Subject;
use async_trait::async_trait;
use ssi::did_resolve::DIDResolver;
use ssi::vc::Credential;
use thiserror::Error;

/// An error relating to a Trustchain Issuer.
#[derive(Error, Debug)]
pub enum IssuerError {
    /// Wrapped error for ssi-vc error.
    #[error("A wrapped variant for an SSI VC error.")]
    VC(ssi::vc::Error),
    /// Wrapped error for ssi-ldp error.
    #[error("A wrapped variant for an SSI LDP error.")]
    LDP(ssi::ldp::Error),
    /// Wrapped error for key manager error.
    #[error("A wrapped variant for a key manager error.")]
    KeyManager(KeyManagerError),
}

impl From<ssi::vc::Error> for IssuerError {
    fn from(err: ssi::vc::Error) -> Self {
        IssuerError::VC(err)
    }
}

impl From<ssi::ldp::Error> for IssuerError {
    fn from(err: ssi::ldp::Error) -> Self {
        IssuerError::LDP(err)
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
        key_id: Option<&str>,
        resolver: &T,
    ) -> Result<Credential, IssuerError>;
}

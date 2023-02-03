use crate::key_manager::KeyManagerError;
use crate::subject::Subject;
use async_trait::async_trait;
use ssi::did::Document;
use ssi::did_resolve::DIDResolver;
use ssi::vc::Credential;
use thiserror::Error;

/// An error relating to a Trustchain Attestor.
#[derive(Error, Debug)]
pub enum AttestorError {
    /// No trustchain subject.
    #[error("DID: {0} as Trustchain subject does not exist.")]
    NoTrustchainSubject(String),
    /// No signing key available.
    #[error("No signing key available for DID {0}.")]
    NoSigningKey(String),
    /// No signing key with specified ID.
    #[error("DID: {0} with signing key idx {1} does not exist.")]
    NoSigningKeyWithId(String, String),
    /// Invalid document for attestation.
    #[error("Document with DID {0} has invalid parameters.")]
    InvalidDocumentParameters(String),
    /// Failed to sign DID document.
    #[error("Signing error for Document with DID {0}: {1}.")]
    SigningError(String, String),
    /// Wrapped error for SSI error.
    #[error("A wrapped variant for an SSI error.")]
    SSI(ssi::error::Error),
    /// Wrapped error for key manager error.
    #[error("A wrapped variant for a key manager error.")]
    KeyManager(KeyManagerError),
}

impl From<ssi::error::Error> for AttestorError {
    fn from(err: ssi::error::Error) -> Self {
        AttestorError::SSI(err)
    }
}

impl From<KeyManagerError> for AttestorError {
    fn from(err: KeyManagerError) -> Self {
        AttestorError::KeyManager(err)
    }
}

/// An upstream entity that attests to a downstream DID.
pub trait Attestor: Subject {
    /// Attests to a DID Document. Subject attests to a DID document by signing the document with (one of) its private signing key(s).
    /// It doesn't matter which signing key you use, there's the option to pick one using the key index.
    /// Typically, the signer will be a controller, but not necessarily. However, every signer is the subject of its own DID.
    fn attest(&self, doc: &Document, key_id: Option<&str>) -> Result<String, AttestorError>;
}

/// A credential attestor attests to a credential to generate a verifiable credential.
#[async_trait]
pub trait CredentialAttestor: Attestor {
    /// Attests to a Credential. Attestor attests to a credential by signing the credential with (one of) its private signing key(s).
    async fn attest_credential<T: DIDResolver>(
        &self,
        credential: &Credential,
        key_id: Option<&str>,
        resolver: &T,
    ) -> Result<Credential, AttestorError>;
}

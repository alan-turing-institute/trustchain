use crate::key_manager::{AttestorKeyManager, KeyManager, KeyManagerError};
use crate::resolver::Resolver;
use crate::Subject;
use async_trait::async_trait;
use ssi::did::Document;
use ssi::did_resolve::DIDResolver;
use ssi::jwk::JWK;
use ssi::one_or_many::OneOrMany;
use ssi::vc::Credential;
use std::convert::From;
use thiserror::Error;

/// An error relating to a Trustchain Attestor.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttestorError {
    /// No trustchain subject.
    #[error("DID: {0} as Trustchain subject does not exist.")]
    NoTrustchainSubject(String),
    /// No signing key of passed ID.
    #[error("No signing key available for DID {0}.")]
    NoSigningKey(String),
    /// No signing key of passed ID.
    #[error("DID: {0} with signing key idx {1} does not exist.")]
    NoSigningKeyWithId(String, String),
    /// Invalid document for attestation.
    #[error("Document with DID {0} has invalid parameters.")]
    InvalidDocumentParameters(String),
    /// Invalid document for attestation.
    #[error("Signing error for Document with DID {0}: {1}.")]
    SigningError(String, String),
}

/// An upstream entity that attests to a downstream DID.
pub trait Attestor: Subject {
    /// Attests to a DID Document. Subject attests to a did document by signing the document with (one of) its private signing key(s).
    /// It doesn't matter which signing key you use, there's the option to pick one using the key index.
    /// Typically, the signer will be a controller, but not necessarily. However, every signer is the subject of its own did.
    fn attest(
        &self,
        doc: &Document,
        key_id: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error>>;
    fn attest_str(
        &self,
        doc: &str,
        key_id: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error>>;
}

/// A credential attestor attests to a credential to generate a verifiable credential.
#[async_trait]
pub trait CredentialAttestor: Attestor {
    /// Attests to a Credential. Attestor attests to a credential by signing the credential with (one of) its private signing key(s).
    async fn attest_credential(
        &self,
        doc: &Credential,
        key_id: Option<&str>,
        resolver: &dyn DIDResolver,
    ) -> Result<Credential, Box<dyn std::error::Error>>;
}

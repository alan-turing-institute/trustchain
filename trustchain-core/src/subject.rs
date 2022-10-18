use crate::key_manager::{KeyManager, KeyManagerError, SubjectKeyManager};
use ssi::did::Document;
use ssi::jwk::JWK;
use ssi::one_or_many::OneOrMany;
use std::convert::From;
use thiserror::Error;

/// An error relating to Trustchain controllers.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SubjectError {
    /// No trustchain subject.
    #[error("DID: {0} as Trustchain subject does not exist.")]
    NoTrustchainSubject(String),
    /// No signing key of passed ID.
    #[error("DID: {0} with signing key idx {1} does not exist.")]
    NoSigningKey(String, String),
}

// use ssi::jwt::encode_sign();

/// Trait for common DID Subject functionality.
pub trait Subject {
    /// Returns the subject's DID.
    fn did(&self) -> &str;

    /// Attests to a DID Document. Subject attests to a did document by signing the document with (one of) its private signing key(s).
    /// It doesn't matter which signing key you use, there's the option to pick one using the key index.
    /// Typically, the signer will be a controller, but not necessarily. However, every signer is the subject of its own did.
    fn attest(&self, doc: &Document, key_id: Option<&str>) -> Result<String, SubjectError>;
}

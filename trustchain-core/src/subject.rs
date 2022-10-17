use ssi::one_or_many::OneOrMany;
use ssi::{did_resolve::DocumentMetadata, jwk::JWK};

use crate::key_manager::{read_signing_keys, KeyManagerError};
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
    fn did(&self) -> &str;
    fn load(&mut self, did: &str) -> Result<(), KeyManagerError>;
    fn save(&self) -> Result<(), SubjectError>;
    fn signing_keys(&self) -> OneOrMany<JWK>;
    // fn sign(&self, doc: &Document) -> &str;
    fn generate_signing_keys(&self) -> OneOrMany<JWK>;
    fn get_public_key(&self, key_id: Option<String>) -> Result<JWK, KeyManagerError>;
}

pub struct TrustchainSubject {
    did: String,
    signing_keys: Option<OneOrMany<JWK>>,
}

impl TrustchainSubject {
    /// Construct a new TrustchainSubject instance.
    pub fn new(did: &str) -> Result<Self, KeyManagerError> {
        let mut subject = Self {
            did: did.to_owned(),
            signing_keys: None,
        };
        subject.load(did)?;
        Ok(subject)
    }
}

impl Subject for TrustchainSubject {
    fn did(&self) -> &str {
        &self.did
    }

    /// Gets the public part of a signing key.
    fn get_public_key(&self, key_id: Option<String>) -> Result<JWK, KeyManagerError> {
        // let keys = read_keys(&self.did);
        // let keys = match keys {
        //     Ok(map) => map,
        //     Err(e) => return Err(e)
        // };
        // let signing = keys.get(&KeyType::SigningKey);
        todo!();
    }

    fn signing_keys(&self) -> OneOrMany<JWK> {
        todo!()
    }

    fn generate_signing_keys(&self) -> OneOrMany<JWK> {
        todo!()
    }

    fn load(&mut self, did: &str) -> Result<(), KeyManagerError> {
        if let Ok(signing_keys) = read_signing_keys(did) {
            self.signing_keys = Some(signing_keys);
            Ok(())
        } else {
            Err(KeyManagerError::FailedToLoadKey)
        }
    }

    fn save(&self) -> Result<(), SubjectError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_constructor() {}

    #[test]
    fn test_signing_keys() {}

    #[test]
    fn test_load() {}

    #[test]
    fn test_save() {}

    #[test]
    fn test_get_public_key() {}

    #[test]
    fn test_generate_signing_keys() {}
}

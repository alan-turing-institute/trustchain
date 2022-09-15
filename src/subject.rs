use ssi::one_or_many::OneOrMany;
use ssi::jwk::JWK;

use crate::key_manager::KeyManagerError;

/// Trait for common DID Subject functionality.
pub trait Subject {
    fn did(&self) -> &str;
    fn signing_keys(&self) -> OneOrMany<JWK>;
    fn generate_signing_keys(&self) -> OneOrMany<JWK>;
    fn get_public_key(key_id: Option<String>) -> Result<JWK, KeyManagerError>;
}

struct TrustchainSubject {
    did: String
}

impl TrustchainSubject {

    /// Construct a new TrustchainController instance.
    pub fn new(did: &str) -> Self {

        Self {
            did: did.to_owned()
        }
    }

    /// Gets the public part of a signing key.
    pub fn get_public_key(key_id: Option<String>) -> Result<JWK, KeyManagerError> {
        todo!()
    }
}

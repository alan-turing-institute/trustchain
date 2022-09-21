use ssi::one_or_many::OneOrMany;
use ssi::jwk::JWK;

use crate::key_manager::{KeyManagerError, KeyType, read_signing_keys};

/// Trait for common DID Subject functionality.
pub trait Subject {
    fn did(&self) -> &str;
    fn load(&self);
    fn signing_keys(&self) -> OneOrMany<JWK>;
    fn generate_signing_keys(&self) -> OneOrMany<JWK>;
    fn get_public_key(&self, key_id: Option<String>) -> Result<JWK, KeyManagerError>;
}

pub struct TrustchainSubject {
    did: String,
    signing_keys: Option<OneOrMany<JWK>>,
}

impl TrustchainSubject {

    /// Construct a new TrustchainSubject instance.
    pub fn new(did: &str) -> Self {

        let signing_keys = TrustchainSubject::load_keys(did);
        Self {
            did: did.to_owned(),
            signing_keys
        }
    }

    /// Loads signing keys for the given DID.
    fn load_keys(did: &str) -> Option<OneOrMany<JWK>> {

        // Read keys from disk.
        let read_result = read_signing_keys(did);
        // If the attempt to read keys failed, return None.
        let mut keys = match read_result {
            Ok(x) => x,
            Err(e) => return None
        };
        // If keys were read successfully, return the signing keys.
        Some(keys)
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

    fn load(&self) {
        todo!()
    }

}

#[cfg(test)]
mod tests {

    #[test]
    fn test_constructor() {

    }

    #[test]
    fn test_load_keys() {

    }


}
use ssi::jwk::JWK;
use ssi::one_or_many::OneOrMany;
use ssi::did::Document;

use crate::key_manager::{KeyManagerError, KeyManager};
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

/// Trait for common DID Subject functionality.
pub trait Subject {

    // Returns the subject's DID as a string slice.
    fn did(&self) -> &str;
    
    // fn load(&mut self, did: &str) -> Result<(), KeyManagerError>;
    // fn save(&self) -> Result<(), SubjectError>;
    // fn signing_keys(&self) -> OneOrMany<JWK>;
    // fn generate_signing_keys(&self) -> OneOrMany<JWK>;
    // fn get_public_key(&self, key_id: Option<String>) -> Result<JWK, KeyManagerError>;

    /// Attest to a DID Document.
    // Subject attests to a did document by signing the document with (one of) its private signing key(s).
    // It doesn't matter which signing key you use, there's the option to pick one using the key index.
    // Typically, the signer will be a controller, but not necessarily. However, every signer is the subject of its own did.
    fn attest(&self, doc: &Document, key_id: Option<&JWK>) -> Result<String, SubjectError> {
        // Ok(String::from("abc"))
        todo!()
        // let algorithm = ION::SIGNATURE_ALGORITHM;
        // let proof = (did_short.clone(), document_data_to_be_signed);
        // let proof_json = ION::json_canonicalization_scheme(&proof).unwrap();
        // let proof_json_bytes = ION::hash(proof_json.as_bytes());
        // let signed_data =
        //     ssi::jwt::encode_sign(algorithm, &proof_json_bytes, &verification_key).unwrap();
        // println!("Proof json (data to be signed): {}", proof_json);
        // println!("Signed hash of DID and patch: {}", signed_data);
    }
}

pub struct TrustchainSubject {
    did: String,
    key_manager: KeyManager,
    signing_keys: Option<OneOrMany<JWK>>,
}

impl TrustchainSubject {
    /// Construct a new TrustchainSubject instance.
    pub fn new(did: &str, key_manager: KeyManager) -> Self {
        Self {
            did: did.to_owned(),
            key_manager,
            signing_keys: None,
        }
    }

    fn load(&mut self, did: &str, key_manager: KeyManager) -> Result<(), KeyManagerError> {
        if let Ok(signing_keys) = key_manager.read_signing_keys(did) {
            self.signing_keys = Some(signing_keys);
            Ok(())
        } else {
            Err(KeyManagerError::FailedToLoadKey)
        }
    }
}

impl Subject for TrustchainSubject {
    
    fn did(&self) -> &str {
        &self.did
    }

    // /// Gets the public part of a signing key.
    // fn get_public_key(&self, key_id: Option<String>) -> Result<JWK, KeyManagerError> {
    //     // let keys = read_keys(&self.did);
    //     // let keys = match keys {
    //     //     Ok(map) => map,
    //     //     Err(e) => return Err(e)
    //     // };
    //     // let signing = keys.get(&KeyType::SigningKey);
    //     todo!();
    // }

    // fn signing_keys(&self) -> OneOrMany<JWK> {
    //     todo!()
    // }

    // fn generate_signing_keys(&self) -> OneOrMany<JWK> {
    //     todo!()
    // }

    // fn save(&self) -> Result<(), SubjectError> {
    //     todo!()
    // }
}

#[cfg(test)]
mod tests {
    use ssi::did::Document;

    use super::*;
    use crate::{data::TEST_TRUSTCHAIN_DOCUMENT, key_manager};

    #[test]
    fn test_attest() {
        let did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";

        // TODO: mock the KeyManager
        let key_manager = KeyManager;
        let target = TrustchainSubject::new(did, key_manager);

        let doc = Document::from_json(TEST_TRUSTCHAIN_DOCUMENT).expect("Document failed to load.");
        let result = target.attest(&doc, Option::None);

        assert!(result.is_ok());
        let proof_result = result.unwrap();

        // Test that the proof_result string is valid JSON.
        // TODO: figure out the correct result type here (guessed &str).
        let json_proof_result: Result<&str, serde_json::Error> = serde_json::from_str(&proof_result);
        
        // TODO: check for a key-value in the JSON.
    }

    // #[test]
    // fn test_signing_keys() {}

    // #[test]
    // fn test_load() {}

    // #[test]
    // fn test_save() {}

    // #[test]
    // fn test_get_public_key() {}

    // #[test]
    // fn test_generate_signing_keys() {}
}

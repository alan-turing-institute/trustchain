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

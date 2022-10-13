use serde_json::Value;
use ssi::did::Document;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use thiserror::Error;

use crate::key_manager::{read_recovery_key, read_update_key};
use crate::subject::{Subject, TrustchainSubject};

/// An error relating to Trustchain controllers.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ControllerError {
    /// No recovery key for DID.
    #[error("DID: {0} as Trustchain subject does not exist.")]
    NoTrustchainSubject(String),
    /// No recovery key for DID.
    #[error("DID: {0} recovery key does not exist.")]
    NoRecoveryKey(String),
    /// No update key for DID.
    #[error("DID: {0} recovery key does not exist.")]
    NoUpdateKey(String),
}

/// Trait for common DID Controller functionality.
pub trait Controller {
    fn to_subject(&self) -> &TrustchainSubject;
    fn load(&self, controlled_did: &str);
    fn update_key(&self) -> JWK; // Retrieve the update key for the loaded DID
    fn next_update_key(&self) -> JWK; // Retrieve the next update key for the loaded DID
    fn recovery_key(&self) -> JWK; // Retrieve the recovery key for the loaded DID
                                   // E.g JWT https://jwt.io/
    fn attest(&self, doc: &Document, key: &JWK) -> Result<String, ControllerError>;
    fn generate_next_update_key(&self);
    // fn generate_recovery_key(&self);
    // fn update_subject(&self);
    // fn recover_subject(&self);
}

/// Struct for common TrustchainController.
pub struct TrustchainController {
    subject: TrustchainSubject,
    controlled_did: String,
    update_key: Option<JWK>,
    recovery_key: Option<JWK>,
    next_update_key: Option<JWK>,
}

impl TrustchainController {
    /// Construct a new TrustchainController instance
    /// from existing Subject and Controller DIDs.
    pub fn new(did: &str, controlled_did: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Returns a result with propagating error
        let subject = TrustchainSubject::new(did)?;

        // Read update and recovery keys
        let update_key: Option<JWK> = match read_update_key(controlled_did) {
            Ok(x) => Some(x),
            Err(_) => {
                return Err(Box::new(ControllerError::NoUpdateKey(
                    controlled_did.to_string(),
                )))
            }
        };
        let recovery_key: Option<JWK> = match read_recovery_key(controlled_did) {
            Ok(x) => Some(x),
            Err(_) => {
                return Err(Box::new(ControllerError::NoRecoveryKey(
                    controlled_did.to_string(),
                )))
            }
        };

        Ok(Self {
            subject,
            controlled_did: controlled_did.to_owned(),
            update_key,
            recovery_key,
            next_update_key: None,
        })
    }

    /// Assume that the document to be made into a ION DID is agreed
    /// with subject (i.e. content is correct and subject has private key
    /// for public key in doc). The function then converts the document into
    /// a create operation that can be pushed to the ION server.
    fn create_subject(doc: Document) -> TrustchainController {
        todo!()
    }
}

impl Controller for TrustchainController {
    fn load(&self, controlled_did: &str) {
        todo!()
    }

    fn update_key(&self) -> JWK {
        todo!()
    }

    fn next_update_key(&self) -> JWK {
        todo!()
    }

    fn generate_next_update_key(&self) {
        todo!()
    }

    fn recovery_key(&self) -> JWK {
        todo!()
    }

    fn to_subject(&self) -> &TrustchainSubject {
        todo!()
    }

    fn attest(&self, doc: &Document, key: &JWK) -> Result<String, ControllerError> {
        // Implement using version in 'create_and_update' binary as basis
        // let proof = (did_short.clone(), document_data_to_be_signed);
        // let proof_json = ION::json_canonicalization_scheme(&proof).unwrap();
        // let proof_json_bytes = ION::hash(proof_json.as_bytes());
        // let signed_data =
        // ssi::jwt::encode_sign(algorithm, &proof_json_bytes, &verification_key).unwrap();
        todo!()
    }
}

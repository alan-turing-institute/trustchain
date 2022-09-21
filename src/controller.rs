use did_ion::sidetree::Sidetree;
use did_ion::ION;
use serde_json::Value;
use ssi::did::Document;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use thiserror::Error;

use crate::key_manager;
use crate::key_manager::{read_update_key, read_recovery_key};
use crate::subject::{TrustchainSubject, Subject};

/// Trait for common DID Controller functionality.
trait Controller {
    fn to_subject(&self) -> &TrustchainSubject;
    fn load(&self, controlled_did: &str);
    fn update_key(&self) -> JWK; // Retrieve the update key for the loaded DID
    fn recovery_key(&self) -> JWK; // Retrieve the recovery key for the loaded DID
    // fn generate_recovery_key(&self);
    // fn set_new_update_key();
    
    // fn update_subject(&self);
    // fn recover_subject(&self);
}

/// Struct for common TrustchainController.
pub struct TrustchainController {
    subject: TrustchainSubject,
    controlled_did: String,
    update_key: Option<JWK>,
    recovery_key: Option<JWK>,
}


impl TrustchainController {

    /// Construct a new TrustchainController instance 
    /// from existing Subject and Controller DIDs.
    pub fn new(did: &str, controlled_did: &str) -> Self {
        let subject = TrustchainSubject::new(did);

        // Read update and recovery keys
        let update_key: Option<JWK> = match read_update_key(controlled_did) {
            Ok(x) => Some(x),
            Err(e) => None,
        };
        let recovery_key: Option<JWK> = match read_recovery_key(controlled_did) {
            Ok(x) => Some(x),
            Err(e) => None,
        };
        
        Self {
            subject,
            controlled_did: controlled_did.to_owned(),
            update_key,
            recovery_key
        }
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

    fn recovery_key(&self) -> JWK {
        todo!()
    }

    fn to_subject(&self) -> &TrustchainSubject {
        todo!()
    }
}

use serde_json::Value;
use ssi::did::Document;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use thiserror::Error;

use crate::key_manager::KeyManager;
// use crate::key_manager::{read_recovery_key, read_update_key};
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
/// Controller extends Subject because every dDID 
/// controller is itself the subject of the uDID.
pub trait Controller : Subject {
    
    // fn to_subject(&self) -> &TrustchainSubject;
    fn load(&self, controlled_did: &str);
    fn update_key(&self) -> &JWK; // Retrieve the update key for the loaded DID
    fn next_update_key(&self) -> Option<&JWK>; // Retrieve the next update key for the loaded DID
    fn recovery_key(&self) -> &JWK; // Retrieve the recovery key for the loaded DID
                                    // E.g JWT https://jwt.io/
    fn generate_next_update_key(&self);
    // fn generate_recovery_key(&self);
    // fn update_subject(&self);
    // fn recover_subject(&self);
}

/// Struct for common TrustchainController.
pub struct TrustchainController {
    did: String,
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

        let key_manager = KeyManager;
        let subject = TrustchainSubject::new(did, key_manager);

        // subject.load(); // Do we need this?

        // Read update and recovery keys
        let key_manager = KeyManager;
        let update_key: Option<JWK> = match key_manager.read_update_key(controlled_did) {
            Ok(x) => Some(x),
            Err(_) => {
                return Err(Box::new(ControllerError::NoUpdateKey(
                    controlled_did.to_string(),
                )))
            }
        };
        let recovery_key: Option<JWK> = match key_manager.read_recovery_key(controlled_did) {
            Ok(x) => Some(x),
            Err(_) => {
                return Err(Box::new(ControllerError::NoRecoveryKey(
                    controlled_did.to_string(),
                )))
            }
        };

        Ok(Self {
            did: did.to_owned(),
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

impl Subject for TrustchainController { 

    fn did(&self) -> &str {
        &self.did
    }
}

impl Controller for TrustchainController {
    fn load(&self, controlled_did: &str) {
        todo!()
    }

    fn update_key(&self) -> &JWK {
        todo!()
    }

    fn next_update_key(&self) -> Option<&JWK> {
        todo!()
    }

    fn generate_next_update_key(&self) {
        todo!()
    }

    fn recovery_key(&self) -> &JWK {
        todo!()
    }

}

#[cfg(test)]
mod tests {
    use super::TrustchainController;
    use crate::controller::Controller;
    use crate::subject::Subject;

    // #[test]
    // fn test_to_subject() {

    //     let did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";
    //     let controlled_did = "did:ion:test:EiA8yZGuDKbcnmPRs9ywaCsoE2FT9HMuyD9WmOiQasxBBg";
    //     let target = TrustchainController::new(did, controlled_did);

    //     assert!(target.is_ok());
        
    //     let controller = target.unwrap();
    //     let subject = controller.to_subject();
    //     assert_eq!(subject.did(), did);
    // }
}

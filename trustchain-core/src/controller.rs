use serde_json::Value;
use ssi::did::Document;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use thiserror::Error;

use crate::key_manager::{ControllerKeyManager, KeyManager, KeyManagerError};

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

// DID, Update Key, Recovery Key
type ControllerData = (String, String, JWK, JWK);

impl From<ControllerData> for TrustchainController {
    fn from(data: ControllerData) -> Self {
        TrustchainController {
            did: data.0,
            controlled_did: data.1,
            update_key: Some(data.2),
            recovery_key: Some(data.3),
            next_update_key: None,
        }
    }
}

impl KeyManager for TrustchainController {}
impl ControllerKeyManager for TrustchainController {}

/// Struct for common TrustchainController.
pub struct TrustchainController {
    did: String,
    controlled_did: String,
    update_key: Option<JWK>,
    recovery_key: Option<JWK>,
    next_update_key: Option<JWK>,
}

/// Trait for common DID Controller functionality.
/// Controller extends Subject because every dDID
/// controller is itself the subject of the uDID.
pub trait Controller: Subject {
    // fn to_subject(&self) -> &TrustchainSubject;
    fn load(&self, controlled_did: &str);
    fn update_key(&mut self) -> Result<&JWK, KeyManagerError>; // Retrieve the update key for the loaded DID
    fn next_update_key(&mut self) -> Result<&Option<JWK>, KeyManagerError>; // Retrieve the next update key for the loaded DID
    fn recovery_key(&mut self) -> Result<&JWK, KeyManagerError>; // Retrieve the recovery key for the loaded DID
                                                                 // E.g JWT https://jwt.io/
    fn generate_next_update_key(&self);
    // fn generate_recovery_key(&self);
    // fn update_subject(&self);
    // fn recover_subject(&self);
}

impl TrustchainController {
    /// Construct a new TrustchainController instance
    /// from existing Subject and Controller DIDs.
    pub fn new(did: &str, controlled_did: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Returns a result with propagating error

        // Construct a KeyManager for the Subject.
        let subject = TrustchainSubject::new(did);

        // // Construct a KeyManager for the Controller.
        // let update_key: Option<JWK> = match self.read_update_key(controlled_did) {
        //     Ok(x) => Some(x),
        //     Err(_) => {
        //         return Err(Box::new(ControllerError::NoUpdateKey(
        //             controlled_did.to_string(),
        //         )))
        //     }
        // };
        // let recovery_key: Option<JWK> = match self.read_recovery_key(controlled_did) {
        //     Ok(x) => Some(x),
        //     Err(_) => {
        //         return Err(Box::new(ControllerError::NoRecoveryKey(
        //             controlled_did.to_string(),
        //         )))
        //     }
        // };

        Ok(Self {
            did: did.to_owned(),
            controlled_did: controlled_did.to_owned(),
            update_key: None,
            recovery_key: None,
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

    fn update_key(&mut self) -> Result<&JWK, KeyManagerError> {
        if self.update_key.is_none() {
            let read_key = self.read_update_key(self.did())?;
            self.update_key = Some(read_key);
        }
        Ok(&self.update_key.as_ref().unwrap())
    }

    fn next_update_key(&mut self) -> Result<&Option<JWK>, KeyManagerError> {
        if self.next_update_key.is_none() {
            let read_key = self.read_next_update_key(self.did())?;
            self.next_update_key = Some(read_key);
        }
        Ok(&self.next_update_key)
    }

    fn generate_next_update_key(&self) {
        todo!()
    }

    fn recovery_key(&mut self) -> Result<&JWK, KeyManagerError> {
        if self.recovery_key.is_none() {
            let read_key = self.read_recovery_key(self.did())?;
            self.recovery_key = Some(read_key);
        }
        Ok(&self.recovery_key.as_ref().unwrap())
    }
}

#[cfg(test)]
mod tests {
    // use super::TrustchainController;
    // use crate::controller::Controller;
    use super::*;
    use crate::key_manager::tests::{TEST_NEXT_UPDATE_KEY, TEST_RECOVERY_KEY, TEST_UPDATE_KEY};
    use crate::subject::Subject;

    #[test]
    fn test_from() -> Result<(), Box<dyn std::error::Error>> {
        let did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";
        let controlled_did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5AuAAA";
        let update_key: JWK = serde_json::from_str(TEST_UPDATE_KEY)?;
        let recovery_key: JWK = serde_json::from_str(TEST_RECOVERY_KEY)?;

        // Fn being tested
        let mut target = TrustchainController::from((
            did.to_string(),
            controlled_did.to_string(),
            update_key.clone(),
            recovery_key.clone(),
        ));

        assert_eq!(target.did(), did);
        let loaded_update_key = target.update_key()?;
        assert_eq!(loaded_update_key, &update_key);

        let loaded_recovery_key = target.recovery_key()?;
        assert_eq!(loaded_recovery_key, &recovery_key);

        // Getter tested elsewhere, should be None here.
        assert_eq!(target.next_update_key, None);
        Ok(())
    }

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

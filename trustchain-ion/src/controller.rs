use crate::subject::IONSubject;
use serde_json::Value;
use ssi::did::Document;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use std::convert::TryFrom;
use thiserror::Error;
use trustchain_core::controller::{Controller, ControllerError};
use trustchain_core::key_manager::{ControllerKeyManager, KeyManager, KeyManagerError, KeyType};
use trustchain_core::subject::{Subject, SubjectError};

impl KeyManager for IONController {}
impl ControllerKeyManager for IONController {}

/// Struct for common IONController.
pub struct IONController {
    did: String,
    controlled_did: String,
    // update_key: Option<JWK>,
    // recovery_key: Option<JWK>,
    // next_update_key: Option<JWK>,
}

impl IONController {
    /// Construct a new IONController instance
    /// from existing Subject and Controller DIDs.
    pub fn new(did: &str, controlled_did: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Returns a result with propagating error

        // Construct a KeyManager for the Subject.
        let subject = IONSubject::new(did);

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
        })
    }

    /// Assume that the document to be made into a ION DID is agreed
    /// with subject (i.e. content is correct and subject has private key
    /// for public key in doc). The function then converts the document into
    /// a create operation that can be pushed to the ION server.
    fn create_subject(doc: Document) -> IONController {
        todo!()
    }
}

impl Subject for IONController {
    fn did(&self) -> &str {
        &self.did
    }
    fn attest(&self, doc: &Document, signing_key: &JWK) -> Result<String, SubjectError> {
        todo!()
    }
}

impl Controller for IONController {
    fn update_key(&self) -> Result<JWK, KeyManagerError> {
        let update_key = self.read_update_key(self.did())?;
        Ok(update_key)
    }

    fn next_update_key(&self) -> Result<Option<JWK>, KeyManagerError> {
        let next_update_key = self.read_next_update_key(self.did())?;
        Ok(Some(next_update_key))
    }

    fn generate_next_update_key(&self) {
        todo!()
    }

    fn recovery_key(&self) -> Result<JWK, KeyManagerError> {
        let recovery_key = self.read_recovery_key(self.did())?;
        Ok(recovery_key)
    }

    fn into_subject(&self) -> Box<dyn Subject> {
        Box::new(IONSubject::new(&self.did))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trustchain_core::data::{
        TEST_NEXT_UPDATE_KEY, TEST_RECOVERY_KEY, TEST_SIGNING_KEYS, TEST_UPDATE_KEY,
    };

    use trustchain_core::init;

    // DID, Update Key, Recovery Key
    type ControllerData = (String, String, JWK, JWK);

    impl TryFrom<ControllerData> for IONController {
        type Error = Box<dyn std::error::Error>;
        fn try_from(data: ControllerData) -> Result<Self, Self::Error> {
            let controller = IONController {
                did: data.0,
                controlled_did: data.1,
            };

            controller.save_key(&controller.controlled_did, KeyType::UpdateKey, &data.2)?;
            controller.save_key(&controller.controlled_did, KeyType::RecoveryKey, &data.3)?;
            Ok(controller)
        }
    }

    const DID: &str = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";
    const CONTROLLED_DID: &str = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5AuAAA";

    // TODO: move the update_key and recovery_key loads out as lazy_static!()

    // fn test_controller() -> Result<IONController, Box<dyn std::error::Error>> {
    fn test_controller(
        did: &str,
        controlled_did: &str,
    ) -> Result<IONController, Box<dyn std::error::Error>> {
        // init();
        let update_key: JWK = serde_json::from_str(TEST_UPDATE_KEY)?;
        let recovery_key: JWK = serde_json::from_str(TEST_RECOVERY_KEY)?;
        IONController::try_from((
            did.to_string(),
            controlled_did.to_string(),
            update_key.clone(),
            recovery_key.clone(),
        ))
    }

    #[test]
    fn test_try_from() -> Result<(), Box<dyn std::error::Error>> {
        init();
        assert_eq!(0, 0);
        let update_key: JWK = serde_json::from_str(TEST_UPDATE_KEY)?;
        let recovery_key: JWK = serde_json::from_str(TEST_RECOVERY_KEY)?;
        let did = "did_try_from";
        let controlled_did = "controlled_did_try_from";

        let target = IONController::try_from((
            did.to_string(),
            controlled_did.to_string(),
            update_key.clone(),
            recovery_key.clone(),
        ))?;

        // println!("{:?}", target.update_key);

        assert_eq!(target.did(), did);

        // let loaded_update_key = target.update_key()?;
        // assert_eq!(loaded_update_key, update_key);

        let loaded_recovery_key = target.recovery_key()?;
        assert_eq!(loaded_recovery_key, recovery_key);

        Ok(())
    }

    #[test]
    fn test_into_subject() -> Result<(), Box<dyn std::error::Error>> {
        init();
        let did = "did_into_subject";
        let controlled_did = "controlled_did_into_subject";
        let target = test_controller(did, controlled_did)?;
        assert_eq!(target.did(), did);
        assert_ne!(target.did(), controlled_did);

        let result = target.into_subject();
        assert_eq!(result.did(), did);
        assert_ne!(result.did(), controlled_did);
        Ok(())
    }
}

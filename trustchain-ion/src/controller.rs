use crate::attestor::IONAttestor;
use serde_json::Value;
use ssi::did::Document;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use std::convert::TryFrom;
use thiserror::Error;
use trustchain_core::attestor::{Attestor, AttestorError};
use trustchain_core::controller::{Controller, ControllerError};
use trustchain_core::key_manager::{ControllerKeyManager, KeyManager, KeyManagerError, KeyType};
use trustchain_core::Subject;
impl KeyManager for IONController {}
impl ControllerKeyManager for IONController {}

/// Type for holding controller data.
struct ControllerData {
    did: String,
    controlled_did: String,
    update_key: JWK,
    recovery_key: JWK,
}

impl ControllerData {
    fn new(did: String, controlled_did: String, update_key: JWK, recovery_key: JWK) -> Self {
        ControllerData {
            did,
            controlled_did,
            update_key,
            recovery_key,
        }
    }
}

impl TryFrom<ControllerData> for IONController {
    type Error = Box<dyn std::error::Error>;
    fn try_from(data: ControllerData) -> Result<Self, Self::Error> {
        let controller = IONController {
            did: data.did,
            controlled_did: data.controlled_did,
        };
        // Attempt to save the update key, but do not overwrite existing key data.
        controller.save_key(
            &controller.controlled_did,
            KeyType::UpdateKey,
            &data.update_key,
            false,
        )?;
        // Attempt to save the recovery key, but do not overwrite existing key data.
        controller.save_key(
            &controller.controlled_did,
            KeyType::RecoveryKey,
            &data.recovery_key,
            false,
        )?;
        Ok(controller)
    }
}

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
}

impl Controller for IONController {
    fn controlled_did(&self) -> &str {
        &self.controlled_did
    }

    fn update_key(&self) -> Result<JWK, KeyManagerError> {
        let update_key = self.read_update_key(self.controlled_did())?;
        Ok(update_key)
    }

    fn next_update_key(&self) -> Result<Option<JWK>, KeyManagerError> {
        let next_update_key = self.read_next_update_key(self.controlled_did())?;
        Ok(Some(next_update_key))
    }

    fn generate_next_update_key(&self) -> Result<(), KeyManagerError> {
        let key = self.generate_key();
        self.save_key(&self.did, KeyType::NextUpdateKey, &key, false)?;
        Ok(())
    }

    fn recovery_key(&self) -> Result<JWK, KeyManagerError> {
        let recovery_key = self.read_recovery_key(self.controlled_did())?;
        Ok(recovery_key)
    }

    fn to_attestor(&self) -> Box<dyn Attestor> {
        Box::new(IONAttestor::new(&self.did))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trustchain_core::data::{
        TEST_NEXT_UPDATE_KEY, TEST_RECOVERY_KEY, TEST_SIGNING_KEYS, TEST_UPDATE_KEY,
    };

    use trustchain_core::init;

    // TODO: move the update_key and recovery_key loads out as lazy_static!()

    // Make a IONController using this test function
    fn test_controller(
        did: &str,
        controlled_did: &str,
    ) -> Result<IONController, Box<dyn std::error::Error>> {
        let update_key: JWK = serde_json::from_str(TEST_UPDATE_KEY)?;
        let recovery_key: JWK = serde_json::from_str(TEST_RECOVERY_KEY)?;
        IONController::try_from(ControllerData::new(
            did.to_string(),
            controlled_did.to_string(),
            update_key,
            recovery_key,
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

        // Make controller using try_from()
        let target = test_controller(did, controlled_did)?;

        assert_eq!(target.controlled_did(), controlled_did);

        let loaded_update_key = target.update_key()?;
        assert_eq!(loaded_update_key, update_key);

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

        let result = target.to_attestor();
        assert_eq!(result.did(), did);
        assert_ne!(result.did(), controlled_did);
        Ok(())
    }
}

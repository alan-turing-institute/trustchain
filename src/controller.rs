use did_ion::sidetree::Sidetree;
use did_ion::ION;
use serde_json::Value;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use thiserror::Error;

use crate::key_holder;

/// Trait for common DID Controller functionality.
trait Controller {
    fn load(&self, controlled_did: &str);
    fn update_key(&self) -> JWK; // Retrieve the update key for the loaded DID
    fn recovery_key(&self) -> JWK; // Retrieve the recovery key for the loaded DID
    // fn generate_recovery_key(&self);
    // fn set_new_update_key();
}

/// Struct for common TrustchainController.
pub struct TrustchainController {
    controlled_did: String
}

impl TrustchainController {

    /// Construct a new TrustchainController instance.
    pub fn new(controlled_did: &str) -> Self {

        Self {
            controlled_did: controlled_did.to_owned()
        }
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
}

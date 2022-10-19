use serde_json::Value;
use ssi::did::Document;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use thiserror::Error;

use crate::key_manager::{ControllerKeyManager, KeyManager, KeyManagerError};

// use crate::key_manager::{read_recovery_key, read_update_key};
use crate::attestor::Attestor;

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

/// A DID controller.
pub trait Controller {
    fn controlled_did(&self) -> &str;
    fn to_attestor(&self) -> Box<dyn Attestor>;
    fn update_key(&self) -> Result<JWK, KeyManagerError>; // Retrieve the update key for the loaded DID
    fn next_update_key(&self) -> Result<Option<JWK>, KeyManagerError>; // Retrieve the next update key for the loaded DID
    fn recovery_key(&self) -> Result<JWK, KeyManagerError>; // Retrieve the recovery key for the loaded DID
                                                            // E.g JWT https://jwt.io/
    fn generate_next_update_key(&self) -> Result<(), KeyManagerError>;
    // fn generate_recovery_key(&self);
    // fn update_subject(&self);
    // fn recover_subject(&self);
}

#[cfg(test)]
mod tests {
    // use super::TrustchainController;
    // use crate::controller::Controller;
    // use super::*;
    // use crate::key_manager::tests::{TEST_NEXT_UPDATE_KEY, TEST_RECOVERY_KEY, TEST_UPDATE_KEY};
}

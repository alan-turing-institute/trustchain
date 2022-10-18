use serde_json::Value;
use ssi::did::Document;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use thiserror::Error;

use crate::key_manager::{ControllerKeyManager, KeyManager, KeyManagerError};

// use crate::key_manager::{read_recovery_key, read_update_key};
use crate::subject::Subject;

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

#[cfg(test)]
mod tests {
    // use super::TrustchainController;
    // use crate::controller::Controller;
    // use super::*;
    // use crate::key_manager::tests::{TEST_NEXT_UPDATE_KEY, TEST_RECOVERY_KEY, TEST_UPDATE_KEY};
}

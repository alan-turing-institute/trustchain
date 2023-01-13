use crate::attestor::Attestor;
use crate::key_manager::KeyManagerError;
use crate::utils::get_did_suffix;
use ssi::jwk::JWK;
use thiserror::Error;

/// An error relating to Trustchain controllers.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ControllerError {
    /// Subject does not exist.
    #[error("DID: {0} as Trustchain subject does not exist.")]
    NoTrustchainSubject(String),
    /// No recovery key.
    #[error("DID: {0} recovery key does not exist.")]
    NoRecoveryKey(String),
    /// No update key.
    #[error("DID: {0} update key does not exist.")]
    NoUpdateKey(String),
}

/// A DID controller.
pub trait Controller {
    /// Returns the DID controlled by this controller.
    fn controlled_did(&self) -> &str;
    /// Returns the suffix of the DID controlled by this controller.
    fn controlled_did_suffix(&self) -> &str {
        get_did_suffix(self.controlled_did())
    }
    /// Converts this controller into an attestor.
    fn to_attestor(&self) -> Box<dyn Attestor>;
    /// Retrieves the update key.
    fn update_key(&self) -> Result<JWK, KeyManagerError>;
    /// Retrieves the next update key.
    fn next_update_key(&self) -> Result<Option<JWK>, KeyManagerError>;
    /// Retrieves the recovery key.
    fn recovery_key(&self) -> Result<JWK, KeyManagerError>;
    /// Generates a new update key.
    fn generate_next_update_key(&self) -> Result<(), KeyManagerError>;
}

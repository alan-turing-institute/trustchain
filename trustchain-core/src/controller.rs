use crate::attestor::Attestor;
use crate::key_manager::KeyManagerError;
use ssi::jwk::JWK;
use thiserror::Error;

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
    fn controlled_did_suffix(&self) -> &str;
    fn to_attestor(&self) -> Box<dyn Attestor>;
    /// Retrieves the update key.
    fn update_key(&self) -> Result<JWK, KeyManagerError>;
    /// Retrieves the next update key.
    fn next_update_key(&self) -> Result<Option<JWK>, KeyManagerError>;
    /// Retrieves the recovery key.
    fn recovery_key(&self) -> Result<JWK, KeyManagerError>;
    fn generate_next_update_key(&self) -> Result<(), KeyManagerError>;
    // fn generate_recovery_key(&self);
    // fn update_subject(&self);
    // fn recover_subject(&self);
}

#[cfg(test)]
mod tests {}

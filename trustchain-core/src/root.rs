use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::verifier::VerifiableTimestamp;

/// An error relating to the root DID.
#[derive(Error, Debug)]
pub enum RootError {
    /// Invalid confirmation code.
    #[error("Invalid confirmation code: {0}")]
    InvalidConfirmationCode(String),
    /// Failed to identify unique root DID.
    #[error("No unique root DID on date: {0}")]
    NoUniqueRootDid(NaiveDate),
    /// Failed to fetch root identification material.
    #[error("Failed to fetch root identification material: {0}")]
    FailureToFetchRootIdentificationMaterial(String),
}

pub const MIN_CONFIRMATION_CODE_LENGTH: usize = 3;

/// A confirmation code for uniquely identifying a root DID on a particular date.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ConfirmationCode {
    confirmation_code: String,
}

impl ConfirmationCode {
    pub fn new(code: &str) -> Result<Self, RootError> {
        if code.len() < MIN_CONFIRMATION_CODE_LENGTH {
            return Err(RootError::InvalidConfirmationCode(code.to_string()));
        }
        Ok(ConfirmationCode {
            confirmation_code: code.to_string(),
        })
    }

    /// Gets the confirmation code.
    pub fn code(&self) -> &str {
        &self.confirmation_code
    }
}

/// Root DID configuration parameters.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct RootConfig {
    date: NaiveDate,
    confirmation_code: ConfirmationCode,
}

impl RootConfig {
    pub fn new(date: NaiveDate, confirmation_code: &str) -> Result<Self, RootError> {
        let confirmation_code = ConfirmationCode::new(confirmation_code)?;
        Ok(RootConfig {
            date: date,
            confirmation_code: confirmation_code,
        })
    }

    // Immutable access:
    pub fn date(&self) -> &NaiveDate {
        &self.date
    }
    pub fn confirmation_code(&self) -> &str {
        &self.confirmation_code.confirmation_code
    }
}

// A configured root DID.
pub trait Root: Sync {
    // Gets the root DID configuration parameters.
    fn config(&self) -> &RootConfig;
    // Gets the root DID.
    fn did(&self) -> &str;
    // Gets a verifiable timestamp for the root DID.
    fn timestamp(&self) -> &dyn VerifiableTimestamp;
}

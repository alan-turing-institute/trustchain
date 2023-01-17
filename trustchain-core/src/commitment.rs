use thiserror::Error;

use crate::utils::json_contains;

/// An error relating to Commitment verification.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommitmentError {
    /// Invalid IteratedCommitment.
    #[error("Invalid IteratedCommitment")]
    InvalidIteratedCommitment,
    /// Data decoding error.
    #[error("Data decoding error.")]
    DataDecodingError,
    /// Failed to compute hash.
    #[error("Failed to compute hash.")]
    FailedToComputeHash,
    /// Failed hash verification.
    #[error("Failed hash verification. Computed hash not equal to target.")]
    FailedHashVerification,
    /// Failed content verification.
    #[error("Failed content verification. Expected data not found in candidate.")]
    FailedContentVerification,
}

/// Represents a verifiable commitment between two datasets.
pub trait Commitment {
    /// Gets the commitment target.
    fn target(&self) -> &str;
    /// Gets the hasher (function).
    fn hasher(&self) -> Box<dyn Fn(&[u8]) -> Result<String, CommitmentError>>;
    /// Gets the candidate data.
    fn candidate_data(&self) -> &[u8];
    // TODO: change the return type here to Box<dyn Fn(&[u8]) -> Result<serde_json::Value, CommitmentError>>
    /// Decodes the candidate data.
    fn decode_candidate_data(&self) -> Result<serde_json::Value, CommitmentError>;
    /// Gets the expected data.
    fn expected_data(&self) -> &serde_json::Value;

    /// Verifies that the hash of the candidate data matches the target.
    fn verify_target(&self) -> Result<(), CommitmentError> {
        // Call the hasher (closure) on the candidate data.
        let hash = self.hasher()(self.candidate_data())?;
        // Compare the computed hash to the target.
        if hash.ne(self.target()) {
            return Err(CommitmentError::FailedHashVerification);
        }
        Ok(())
    }

    /// Verifies that the expected data is found in the candidate data.
    fn verify_content(&self) -> Result<(), CommitmentError> {
        let candidate_data = match self.decode_candidate_data() {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Failed to verify content. Data decoding error: {}", e);
                return Err(CommitmentError::DataDecodingError);
            }
        };
        if !json_contains(&candidate_data, &self.expected_data()) {
            return Err(CommitmentError::FailedContentVerification);
        }
        Ok(())
    }

    /// Verifies the commitment.
    fn verify(&self) -> Result<(), CommitmentError> {
        let _ = &self.verify_content()?;
        let _ = &self.verify_target()?;
        Ok(())
    }
}

pub trait IteratedCommitment: Commitment {
    /// Gets the sequence of commitments.
    fn commitments(&self) -> Vec<Box<dyn Commitment>>;

    /// Checks that the seqence of commitments is valid.
    fn validate_sequence(&self) -> Result<(), CommitmentError> {
        // Check that the  target in the n'th commitment is identical to
        // the expected data in the (n+1)'th commitment.
        let mut target = Vec::<u8>::new();
        for commitment in self.commitments() {
            if target.len() == 0 {
                continue;
            }

            if let serde_json::Value::String(expected) = commitment.expected_data() {
                if !expected.as_bytes().eq(&target) {
                    eprintln!("Invalid target/expected data sequence.");
                    return Err(CommitmentError::InvalidIteratedCommitment);
                }
            } else {
                eprintln!("Unhandled serde_json::Value variant. Expected String.");
                return Err(CommitmentError::InvalidIteratedCommitment);
            }
            target = commitment.target().into();
        }
        Ok(())
    }

    /// Runs the verification process over the sequence of commitments.
    fn verify(&self) -> Result<(), CommitmentError> {
        let _ = self.validate_sequence();
        for commitment in self.commitments() {
            commitment.verify()?;
        }
        Ok(())
    }
}

use thiserror::Error;

use crate::utils::json_contains;

/// An error relating to Commitment verification.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommitmentError {
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

/// A cryptographic commitment with no expected data content.
pub trait TrivialCommitment {
    /// Gets the hasher (as a function pointer).
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError>;
    /// Gets the candidate data.
    fn candidate_data(&self) -> &[u8];
    /// Candidate data decoder (function).
    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError>;
    /// Computes the hash (commitment).
    fn hash(&self) -> Result<String, CommitmentError> {
        // Call the hasher on the candidate data.
        self.hasher()(self.candidate_data())
    }
}

/// A cryptographic commitment with expected data content.
pub trait Commitment: TrivialCommitment {
    /// Gets the expected data.
    fn expected_data(&self) -> &serde_json::Value;

    /// Verifies that the expected data is found in the candidate data.
    fn verify_content(&self) -> Result<(), CommitmentError> {
        // Get the decoded candidate data.
        let candidate_data = match self.decode_candidate_data()(self.candidate_data()) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Failed to verify content. Data decoding error: {}", e);
                return Err(CommitmentError::DataDecodingError);
            }
        };
        // Verify the content.
        if !json_contains(&candidate_data, &self.expected_data()) {
            return Err(CommitmentError::FailedContentVerification);
        }
        Ok(())
    }

    /// Verifies the commitment.
    fn verify(&self, target: &str) -> Result<(), CommitmentError> {
        // Verify the content.
        let _ = &self.verify_content()?;
        // Verify the target by comparing with the computed hash.
        let hash = self.hash()?;
        if hash.ne(target) {
            return Err(CommitmentError::FailedHashVerification);
        }
        Ok(())
    }
}

/// A sequence of commitments in which the target in the n'th commitment
/// is identical to the expected data in the (n+1)'th commitment
pub trait IterableCommitment {
    /// Gets the sequence of commitments.
    fn commitments(&self) -> Vec<Box<dyn Commitment>>;
    /// Appends a TrivialCommitment to extend this IterableCommitment.
    fn append(
        &self,
        trivial_commitment: Box<dyn TrivialCommitment>,
    ) -> Result<Box<dyn IterableCommitment>, CommitmentError>;

    // /// Checks that the seqence of commitments is valid.
    // fn validate_sequence(&self) -> Result<(), CommitmentError> {
    //     // Check that the  target in the n'th commitment is identical to
    //     // the expected data in the (n+1)'th commitment.
    //     let mut target = Vec::<u8>::new();
    //     for commitment in self.commitments() {
    //         if target.len() == 0 {
    //             continue;
    //         }

    //         if let serde_json::Value::String(expected) = commitment.expected_data() {
    //             if !expected.as_bytes().eq(&target) {
    //                 eprintln!("Invalid target/expected data sequence.");
    //                 return Err(CommitmentError::InvalidIteratedCommitment);
    //             }
    //         } else {
    //             eprintln!("Unhandled serde_json::Value variant. Expected String.");
    //             return Err(CommitmentError::InvalidIteratedCommitment);
    //         }
    //         // OLD (TODO...)
    //         // target = commitment.target().into();

    //     }
    //     Ok(())
    // }

    /// Runs the verification process over the sequence of commitments.
    fn verify(&self, target: &str) -> Result<(), CommitmentError> {
        // let _ = self.validate_sequence(); OLD
        let mut current_target = target;
        for commitment in self.commitments() {
            commitment.verify(current_target)?;
        }
        Ok(())
    }
}

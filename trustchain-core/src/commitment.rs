use serde_json::json;
use thiserror::Error;

use crate::utils::{json_contains, type_of};

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
    FailedHashVerification(String),
    /// Failed content verification.
    #[error("Failed content verification. Expected data not found in candidate.")]
    FailedContentVerification(String),
    /// Empty iterated commitment.
    #[error("Failed verification. Empty iterated commitment.")]
    EmptyIteratedCommitment,
}

/// A cryptographic commitment with no expected data content.
pub trait TrivialCommitment {
    /// Gets the hasher (as a function pointer).
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError>;
    /// Gets the candidate data.
    fn candidate_data(&self) -> &[u8];
    /// Gets the candidate data decoder (function).
    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError>;
    /// Computes the hash (commitment).
    fn hash(&self) -> Result<String, CommitmentError> {
        // Call the hasher on the candidate data.
        self.hasher()(self.candidate_data())
    }
    /// Gets the data content that the hash verifiably commits to.
    fn commitment_content(&self) -> Result<serde_json::Value, CommitmentError> {
        self.decode_candidate_data()(self.candidate_data())
    }
    // See https://users.rust-lang.org/t/is-there-a-way-to-move-a-trait-object/707 for Box<Self> hint.
    /// Converts this TrivialCommitment to a Commitment.
    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment>;
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
            return Err(CommitmentError::FailedContentVerification(type_of(&self)));
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
            return Err(CommitmentError::FailedHashVerification(type_of(&self)));
        }
        Ok(())
    }
}

/// A chain of commitments in which the target in the n'th commitment
/// is identical to the expected data in the (n+1)'th commitment
pub trait CommitmentChain: Commitment {
    /// Gets the sequence of commitments.
    fn commitments(&self) -> &Vec<Box<dyn Commitment>>;

    /// Gets the sequence of commitments as a mutable reference.
    fn mut_commitments(&mut self) -> &mut Vec<Box<dyn Commitment>>;

    /// Appends a TrivialCommitment to extend this IterableCommitment.
    ///
    /// The appended commitment must be endowed with expected data identical
    /// to the hash of this commitment, so the resulting iterable
    /// commitment is itself a commitment to the same expected data.
    fn append(
        &mut self,
        trivial_commitment: Box<dyn TrivialCommitment>,
    ) -> Result<(), CommitmentError>;
}

/// An iterated commitment in which the hash of the n'th commitment
/// is identical to the expected data in the (n+1)'th commitment.
pub struct ChainedCommitment {
    commitments: Vec<Box<dyn Commitment>>,
}

impl ChainedCommitment {
    pub fn new(commitment: Box<dyn Commitment>) -> Self {
        let mut commitments = Vec::new();
        commitments.push(commitment);
        Self { commitments }
    }
}

impl TrivialCommitment for ChainedCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        // TODO: Compose the hasher functions in the sequence of commitments.
        // Unclear how to compose the function pointers (some approaches only work on closures).
        // If this were implemented there might be no need to implement verify for IteratedCommitment.
        |_| {
            eprintln!("Composed hasher not implemented. Call verify directly.");
            Err(CommitmentError::FailedToComputeHash)
        }
    }

    fn candidate_data(&self) -> &[u8] {
        // Use as_ref to avoid consuming the Some() value from first().
        &self.commitments.first().as_ref().unwrap().candidate_data()
    }

    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
        self.commitments().first().unwrap().decode_candidate_data()
    }

    fn hash(&self) -> Result<String, CommitmentError> {
        // The hash of the iterated commitment is that of the last in the sequence.
        self.commitments().last().as_ref().unwrap().hash()
    }

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        self
    }
}

impl Commitment for ChainedCommitment {
    fn expected_data(&self) -> &serde_json::Value {
        // The chained commitment commits to the expected data in the first of the
        // sequence of commitments. Must cast here to avoid infinite recursion.
        let first_commitment: &Box<dyn Commitment> =
            **&self.commitments().first().as_ref().unwrap();
        &first_commitment.expected_data()
    }

    /// Verifies an IteratedCommitment by verifying each of its constituent commitments.
    fn verify(&self, target: &str) -> Result<(), CommitmentError> {
        // Verify the content.
        let _ = &self.verify_content()?;
        // Verify each commitment in the sequence.
        let commitments = self.commitments();
        if commitments.len() == 0 {
            return Err(CommitmentError::EmptyIteratedCommitment);
        }
        let mut it = self.commitments().iter();
        let mut commitment = it.next().unwrap();
        let mut this_target = "";

        while let Some(&next) = it.next().as_ref() {
            // The target for the current commitment is the expected data of the next one.
            this_target = match next.expected_data() {
                serde_json::Value::String(x) => x,
                _ => {
                    eprintln!("Unhandled JSON Value variant. Expected String.");
                    return Err(CommitmentError::DataDecodingError);
                }
            };
            commitment.verify(this_target)?;
            commitment = next;
        }
        // Verify the last commitment in the sequence against the given target.
        commitment.verify(target)?;
        Ok(())
    }
}

impl CommitmentChain for ChainedCommitment {
    fn commitments(&self) -> &Vec<Box<dyn Commitment>> {
        &self.commitments
    }

    fn mut_commitments(&mut self) -> &mut Vec<Box<dyn Commitment>> {
        &mut self.commitments
    }

    fn append(
        &mut self,
        trivial_commitment: Box<dyn TrivialCommitment>,
    ) -> Result<(), CommitmentError> {
        // Set the expected data in the appended commitment to be the hash of this commitment.
        // This ensures that the composition still commits to the expected data.
        let expected_data = json!(self.hash()?);
        let new_commitment = trivial_commitment.to_commitment(expected_data);
        // let commitments: &mut Vec<Box<dyn Commitment>> = self.commitments.as_mut();
        let commitments: &mut Vec<Box<dyn Commitment>> = self.mut_commitments();
        commitments.push(new_commitment);
        Ok(())
    }
}

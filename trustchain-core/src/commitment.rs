//! Commitment scheme API with default implementation.
use crate::utils::{json_contains, type_of, HasEndpoints, HasKeys};
use crate::verifier::Timestamp;
use serde_json::{json, Value};
use ssi::{
    did::{Document, ServiceEndpoint},
    jwk::JWK,
};
use std::convert::TryInto;
use thiserror::Error;

/// Type for commitment result.
pub type CommitmentResult<T> = Result<T, CommitmentError>;

/// An error relating to Commitment verification.
#[derive(Error, Debug)]
pub enum CommitmentError {
    /// Data decoding failure.
    #[error("Data decoding failed.")]
    DataDecodingFailure,
    /// Data decoding error.
    #[error("Data decoding error: {0}")]
    DataDecodingError(String),
    /// Failed to compute hash.
    #[error("Failed to compute hash: {0}")]
    FailedToComputeHash(String),
    /// Failed hash verification.
    #[error("Failed hash verification. Computed hash not equal to target.")]
    FailedHashVerification(String),
    /// Failed content verification.
    #[error("Failed content verification. Expected data {0} not found in candidate: {1}.")]
    FailedContentVerification(String, String),
    /// Empty iterated commitment.
    #[error("Failed verification. Empty iterated commitment.")]
    EmptyChainedCommitment,
    /// No expected data present.
    #[error("Failed retrieval of expected data. Empty expected data.")]
    EmptyExpectedData,
    /// Wrapped serde JSON deserialization error.
    #[error("Failed to deserialize.")]
    FailedToDeserialize(serde_json::Error),
}

impl From<serde_json::Error> for CommitmentError {
    fn from(err: serde_json::Error) -> Self {
        CommitmentError::FailedToDeserialize(err)
    }
}

/// A cryptographic commitment with no expected data content.
pub trait TrivialCommitment {
    /// Gets the hasher (as a function pointer).
    fn hasher(&self) -> fn(&[u8]) -> CommitmentResult<String>;
    /// Gets the candidate data.
    fn candidate_data(&self) -> &[u8];
    /// Gets the candidate data decoder (function).
    fn decode_candidate_data(&self) -> fn(&[u8]) -> CommitmentResult<Value>;
    /// A closure for filtering candidate data. By default there is no filtering.
    fn filter(&self) -> Option<Box<dyn Fn(&serde_json::Value) -> CommitmentResult<Value>>> {
        None
    }
    /// Computes the hash (commitment). This method should not be overridden by implementors.
    fn hash(&self) -> CommitmentResult<String> {
        // Call the hasher on the candidate data.
        self.hasher()(self.candidate_data())
    }
    /// Gets the data content that the hash verifiably commits to. This method should not be overridden by implementors.
    fn commitment_content(&self) -> CommitmentResult<Value> {
        let unfiltered_candidate_data = self.decode_candidate_data()(self.candidate_data())?;
        // Optionally filter the candidate data.
        let candidate_data = match self.filter() {
            Some(filter) => filter(&unfiltered_candidate_data).map_err(|e| {
                CommitmentError::DataDecodingError(format!(
                    "Error filtering commitment content: {}",
                    e
                ))
            }),
            None => Ok(unfiltered_candidate_data.clone()),
        }?;

        // Check that the unfiltered candidate data contains the filtered data
        // (to ensure no pollution from the filter closure).
        if self.filter().is_some() && !json_contains(&unfiltered_candidate_data, &candidate_data) {
            return Err(CommitmentError::DataDecodingError(
                "Filtering of candidate data injects pollution.".to_string(),
            ));
        }
        Ok(candidate_data)
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
    fn verify_content(&self) -> CommitmentResult<()> {
        // Get the decoded candidate data.
        let candidate_data = self.commitment_content()?;

        // Verify the content.
        if !json_contains(&candidate_data, self.expected_data()) {
            return Err(CommitmentError::FailedContentVerification(
                self.expected_data().to_string(),
                candidate_data.to_string(),
            ));
        }
        Ok(())
    }

    /// Verifies the commitment.
    fn verify(&self, target: &str) -> CommitmentResult<()> {
        // Verify the content.
        self.verify_content()?;
        // Verify the target by comparing with the computed hash.
        if self.hash()?.ne(target) {
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
    fn append(&mut self, trivial_commitment: Box<dyn TrivialCommitment>) -> CommitmentResult<()>;
}

/// A chain of commitments in which the hash of the n'th commitment
/// is identical to the expected data in the (n+1)'th commitment.
pub struct ChainedCommitment {
    commitments: Vec<Box<dyn Commitment>>,
}

impl ChainedCommitment {
    pub fn new(commitment: Box<dyn Commitment>) -> Self {
        let commitments: Vec<Box<dyn Commitment>> = vec![commitment];
        Self { commitments }
    }
}

impl TrivialCommitment for ChainedCommitment {
    fn hasher(&self) -> fn(&[u8]) -> CommitmentResult<String> {
        // The hasher of a chained commitment is that of the last in the sequence.
        self.commitments()
            .last()
            .expect("Unexpected empty commitment chain.")
            .hasher()
    }

    fn candidate_data(&self) -> &[u8] {
        // Use as_ref to avoid consuming the Some() value from first().
        self.commitments
            .first()
            .as_ref()
            .expect("Unexpected empty commitment chain.")
            .candidate_data()
    }

    fn decode_candidate_data(&self) -> fn(&[u8]) -> CommitmentResult<Value> {
        self.commitments()
            .first()
            .expect("Unexpected empty commitment chain.")
            .decode_candidate_data()
    }

    fn hash(&self) -> CommitmentResult<String> {
        // The hash of a chained commitment is that of the last in the sequence.
        self.commitments()
            .last()
            .ok_or(CommitmentError::EmptyChainedCommitment)?
            .hash()
    }

    fn to_commitment(self: Box<Self>, _expected_data: serde_json::Value) -> Box<dyn Commitment> {
        self
    }
}

impl Commitment for ChainedCommitment {
    fn expected_data(&self) -> &serde_json::Value {
        // The chained commitment commits to the expected data in the first of the
        // sequence of commitments. Must cast here to avoid infinite recursion.
        self.commitments().first().unwrap().expected_data()
    }

    /// Verifies an IteratedCommitment by verifying each of its constituent commitments.
    fn verify(&self, target: &str) -> CommitmentResult<()> {
        // Verify the content.
        self.verify_content()?;

        // Verify each commitment in the sequence.
        let commitments = self.commitments();
        if commitments.is_empty() {
            return Err(CommitmentError::EmptyChainedCommitment);
        }
        let mut it = self.commitments().iter();
        let mut commitment = it.next().unwrap();

        while let Some(&next) = it.next().as_ref() {
            // The target for the current commitment is the expected data of the next one.
            let this_target = match next.expected_data() {
                serde_json::Value::String(x) => x,
                _ => {
                    return Err(CommitmentError::DataDecodingError(
                        "Unhandled JSON Value variant. Expected String.".to_string(),
                    ));
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

    fn append(&mut self, trivial_commitment: Box<dyn TrivialCommitment>) -> CommitmentResult<()> {
        // Set the expected data in the appended commitment to be the hash of this commitment.
        // This ensures that the composition still commits to the expected data.
        let expected_data = json!(self.hash()?);
        let new_commitment = trivial_commitment.to_commitment(expected_data);

        self.mut_commitments().push(new_commitment);
        Ok(())
    }
}

pub trait DIDCommitment: Commitment {
    /// Gets the DID.
    fn did(&self) -> &str;
    /// Gets the DID Document.
    fn did_document(&self) -> &Document;
    /// Gets the keys in the candidate data.
    fn candidate_keys(&self) -> Option<Vec<JWK>> {
        self.did_document().get_keys()
    }
    /// Gets the endpoints in the candidate data.
    fn candidate_endpoints(&self) -> Option<Vec<ServiceEndpoint>> {
        self.did_document().get_endpoints()
    }
    /// Get the candidate data in which we expect to find a timestamp.
    fn timestamp_candidate_data(&self) -> CommitmentResult<&[u8]>;
    /// Gets the decoder (function) for the timestamp candidate data.
    fn decode_timestamp_candidate_data(
        &self,
    ) -> CommitmentResult<fn(&[u8]) -> CommitmentResult<Value>>;
}

/// A Commitment whose expected data is a Unix time and hasher
/// and candidate data are obtained from a given DIDCommitment.
pub struct TimestampCommitment {
    expected_data: serde_json::Value,
    hasher: fn(&[u8]) -> CommitmentResult<String>,
    candidate_data: Vec<u8>,
    decode_candidate_data: fn(&[u8]) -> CommitmentResult<Value>,
}

impl TimestampCommitment {
    /// Constructs a TimestampCommitment from a given DIDCommitment, with a Unix
    /// timestamp as expected data.
    pub fn new(
        did_commitment: &dyn DIDCommitment,
        expected_data: Timestamp,
    ) -> CommitmentResult<Self> {
        // Note the expected data in the TimestampCommitment is the timestamp, but the
        // hasher & candidate data are identical to those in the DIDCommitment. Therefore,
        // by verifying both the DIDCommitment and the TimestampCommitment we confirm
        // that the *same* hash commits to *both* the DID Document data and the timestamp.
        //
        // The decoded candidate data must contain the timestamp such that it is found
        // by the json_contains function, otherwise the content verification will fail.
        Ok(Self {
            expected_data: json!(expected_data),
            hasher: did_commitment.hasher(),
            candidate_data: did_commitment.timestamp_candidate_data()?.to_vec(),
            decode_candidate_data: did_commitment.decode_timestamp_candidate_data()?,
        })
    }

    /// Gets the timestamp as a Unix time.
    pub fn timestamp(&self) -> Timestamp {
        self.expected_data
            .as_u64()
            .unwrap()
            .try_into()
            .expect("Construction guarantees u32.")
    }
}

impl TrivialCommitment for TimestampCommitment {
    fn hasher(&self) -> fn(&[u8]) -> CommitmentResult<String> {
        self.hasher
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    fn decode_candidate_data(&self) -> fn(&[u8]) -> CommitmentResult<Value> {
        self.decode_candidate_data
    }

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        if !expected_data.eq(self.expected_data()) {
            panic!("Attempted modification of expected timestamp data not permitted.");
        }
        self
    }
}

impl Commitment for TimestampCommitment {
    fn expected_data(&self) -> &serde_json::Value {
        // Safe to unwrap as a complete commitment must have expected data
        &self.expected_data
    }
}

use serde_json::json;
use ssi::{
    did::{Document, ServiceEndpoint},
    jwk::JWK,
};
use thiserror::Error;

use crate::utils::{json_contains, type_of, HasEndpoints, HasKeys};
use crate::verifier::Timestamp;

/// An error relating to Commitment verification.
#[derive(Error, Debug)]
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
    #[error("Failed content verification. Expected data {0} not found in candidate: {1}.")]
    FailedContentVerification(String, String),
    /// Empty iterated commitment.
    #[error("Failed verification. Empty iterated commitment.")]
    EmptyIteratedCommitment,
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
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError>;
    /// Gets the candidate data.
    fn candidate_data(&self) -> &[u8];
    /// Gets the candidate data decoder (function).
    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError>;
    /// A closure for filtering candidate data. By default there is no filtering.
    fn filter(
        &self,
    ) -> Option<Box<dyn Fn(serde_json::Value) -> Result<serde_json::Value, CommitmentError>>> {
        None
    }
    // TODO: consider all replacements hash() and commitment_content()
    // For both of these two functions, get rid of these "helper" methods and
    // instead make the "inner" calls directly on the commitment object, e.g.
    // instead of:
    // commitment.hash()
    // we should use:
    // commitment.hasher()(commitment.candidate_data())
    //
    // and instead of:
    // commitment.commitment_content()
    // we should use:
    // commitment.decode_candidate_data()(commitment.candidate_data())

    /// Computes the hash (commitment). This method should not be overridden by implementors.
    fn hash(&self) -> Result<String, CommitmentError> {
        // Call the hasher on the candidate data.
        self.hasher()(self.candidate_data())
    }
    /// Gets the data content that the hash verifiably commits to. This method should not be overridden by implementors.
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
    fn expected_data(&self) -> Result<&serde_json::Value, CommitmentError>;

    /// Verifies that the expected data is found in the candidate data.
    fn verify_content(&self) -> Result<(), CommitmentError> {
        // Get the decoded candidate data.
        let unfiltered_candidate_data = match self.commitment_content() {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Failed to verify content. Data decoding error: {}", e);
                return Err(CommitmentError::DataDecodingError);
            }
        };

        // Optionally filter the candidate data.
        let optional_filter = self.filter();
        let candidate_data: serde_json::Value = match &optional_filter {
            Some(filter) => match filter(unfiltered_candidate_data.clone()) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("Failed to verify content. Data decoding error: {}", e);
                    return Err(CommitmentError::DataDecodingError);
                }
            },
            None => unfiltered_candidate_data.clone(),
        };

        // Check that the unfiltered candidate data contains the filtered data
        // (to ensure no pollution from the filter closture).
        if optional_filter.is_some() && !json_contains(&unfiltered_candidate_data, &candidate_data)
        {
            return Err(CommitmentError::FailedContentVerification(
                self.expected_data()?.to_string(),
                candidate_data.to_string(),
            ));
        }

        // Verify the content.
        if !json_contains(&candidate_data, self.expected_data()?) {
            return Err(CommitmentError::FailedContentVerification(
                self.expected_data()?.to_string(),
                candidate_data.to_string(),
            ));
        }
        Ok(())
    }

    /// Verifies the commitment.
    fn verify(&self, target: &str) -> Result<(), CommitmentError> {
        // Verify the content.
        self.verify_content()?;
        // Verify the target by comparing with the computed hash.
        // TODO: consider replacing `self.hash()` with `self.hasher()(self.candidate_data())` to
        // prevent invalid verification if method overridden.
        // if self.hasher()(self.candidate_data())?.ne(target) {
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
    fn append(
        &mut self,
        trivial_commitment: Box<dyn TrivialCommitment>,
    ) -> Result<(), CommitmentError>;
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
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        // The hasher of a chained commitment is that of the last in the sequence.
        self.commitments().last().unwrap().hasher()
    }

    fn candidate_data(&self) -> &[u8] {
        // Use as_ref to avoid consuming the Some() value from first().
        self.commitments.first().as_ref().unwrap().candidate_data()
    }

    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
        self.commitments().first().unwrap().decode_candidate_data()
    }

    fn hash(&self) -> Result<String, CommitmentError> {
        // The hash of a chained commitment is that of the last in the sequence.
        self.commitments().last().as_ref().unwrap().hash()
    }

    fn to_commitment(self: Box<Self>, _expected_data: serde_json::Value) -> Box<dyn Commitment> {
        self
    }
}

impl Commitment for ChainedCommitment {
    fn expected_data(&self) -> Result<&serde_json::Value, CommitmentError> {
        // The chained commitment commits to the expected data in the first of the
        // sequence of commitments. Must cast here to avoid infinite recursion.
        self.commitments().first().as_ref().unwrap().expected_data()
    }

    /// Verifies an IteratedCommitment by verifying each of its constituent commitments.
    fn verify(&self, target: &str) -> Result<(), CommitmentError> {
        // Verify the content.
        self.verify_content()?;

        // Verify each commitment in the sequence.
        let commitments = self.commitments();
        if commitments.is_empty() {
            return Err(CommitmentError::EmptyIteratedCommitment);
        }
        let mut it = self.commitments().iter();
        let mut commitment = it.next().unwrap();

        while let Some(&next) = it.next().as_ref() {
            // The target for the current commitment is the expected data of the next one.
            let this_target = match next.expected_data()? {
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

        self.mut_commitments().push(new_commitment);
        Ok(())
    }
}

pub trait DIDCommitment: Commitment {
    /// Gets the DID.
    fn did(&self) -> &str;
    /// Gets the DID Document.
    fn did_document(&self) -> &Document;
    // /// Gets the DID Document Metadata.
    // fn did_document_metadata(&self) -> DocumentMetadata;
    /// Gets the keys in the candidate data.
    fn candidate_keys(&self) -> Option<Vec<JWK>> {
        self.did_document().get_keys()
    }
    /// Gets the endpoints in the candidate data.
    fn candidate_endpoints(&self) -> Option<Vec<ServiceEndpoint>> {
        self.did_document().get_endpoints()
    }
    /// Get the candidate data in which we expect to find a timestamp.
    fn timestamp_candidate_data(&self) -> Result<&[u8], CommitmentError>;
    /// Gets the decoder (function) for the timestamp candidate data.
    fn decode_timestamp_candidate_data(
        &self,
    ) -> Result<fn(&[u8]) -> Result<serde_json::Value, CommitmentError>, CommitmentError>;
}

/// A Commitment whose expected data is a Unix time and hasher
/// and candidate data are obtained from a given DIDCommitment.
pub struct TimestampCommitment {
    timestamp: Timestamp,
    expected_data: Option<serde_json::Value>,
    hasher: fn(&[u8]) -> Result<String, CommitmentError>,
    candidate_data: Vec<u8>,
    decode_candidate_data: fn(&[u8]) -> Result<serde_json::Value, CommitmentError>,
}

impl TimestampCommitment {
    /// Constructs a TimestampCommitment from a given DIDCommitment, with a Unix
    /// timestamp as expected data.
    pub fn new(
        did_commitment: &dyn DIDCommitment,
        expected_data: Timestamp,
    ) -> Result<Self, CommitmentError> {
        // Note the expected data in the TimestampCommitment is the timestamp, but the
        // hasher & candidate data are identical to those in the DIDCommitment. Therefore,
        // by verifying both the DIDCommitment and the TimestampCommitment we confirm
        // that the *same* hash commits to *both* the DID Document data and the timestamp.

        // The decoded candidate data must contain the timestamp such that it is found
        // by the json_contains function, otherwise the content verification will fail.

        // TODO: the hasher, candidate_data and decoder (function) need to come from the *last*
        // commitment in the DIDCommitment chain. But in general DIDCommitment is a Commitment,
        // but not necessarily a CommitmentChain, so we need to implement the "last commitment" code
        // in trustchain-ion.
        // Therefore, DIDCommitment must have overridden methods for hasher(), candidate_data() and
        // decode_candidate_data(). Just do this in trustchain-ion commitment.rs and we're done.
        // BUT that won't work because DIDCommitment is implemented (in trustchain-ion) for
        // IONCommitment, which is *both* a CommitmentChain *and* a DIDCommitment.
        // So it needs to be a CommitmentChain for verifying the pub keys & endpoints
        // and at the same time a TimestampCommitment.
        Ok(Self {
            timestamp: expected_data,
            expected_data: Some(json!(expected_data)),
            hasher: did_commitment.hasher(),
            candidate_data: did_commitment.timestamp_candidate_data()?.to_vec(),
            decode_candidate_data: did_commitment.decode_timestamp_candidate_data()?,
        })
    }

    /// Gets the timestamp as a Unix time.
    fn timestamp(&self) -> Timestamp {
        self.timestamp
    }
}

impl TrivialCommitment for TimestampCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        self.hasher
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
        self.decode_candidate_data
    }

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        if !expected_data.eq(self.expected_data().expect("No expected data present.")) {
            eprintln!("Attempted modification of expected timestamp data not permitted. Ignored.");
        }
        panic!("A TimestampCommitment is not convertible to a Commitment.");
    }
}

impl Commitment for TimestampCommitment {
    fn expected_data(&self) -> Result<&serde_json::Value, CommitmentError> {
        self.expected_data
            .as_ref()
            .ok_or(CommitmentError::EmptyExpectedData)
    }
}

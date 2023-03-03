use crate::chain::{Chain, ChainError, DIDChain};
use crate::commitment::{Commitment, CommitmentError, DIDCommitment, TimestampCommitment};
use crate::resolver::Resolver;
use crate::utils::{json_contains, HasEndpoints, HasKeys};
use serde_json::json;
use ssi::did_resolve::DIDResolver;
use thiserror::Error;

/// An error relating to Trustchain verification.
#[derive(Error, Debug)]
pub enum VerifierError {
    /// Invalid payload in proof compared to resolved document.
    #[error("Invalid payload provided in proof for dDID: {0}.")]
    InvalidPayload(String),
    /// Invalid payload in proof compared to resolved document.
    #[error("Invalid signature for proof in dDID: {0}.")]
    InvalidSignature(String),
    /// Invalid root DID after self-controller reached in path.
    #[error("Invalid root DID: {0}.")]
    InvalidRoot(String),
    // /// DID not resolvable.
    // #[error("DID: {0} is not resolvable.")]
    // UnresolvableDID(String),
    /// Failed to build DID chain.
    #[error("Failed to build chain: {0}.")]
    ChainBuildFailure(String),
    /// Chain verification failed.
    #[error("Chain verification failed: {0}.")]
    InvalidChain(String),
    /// Invalid proof-of-work hash.
    #[error("Invalid proof-of-work hash: {0}.")]
    InvalidProofOfWorkHash(String),
    /// Failed to get DID operation.
    #[error("Error getting {0} DID operation.")]
    FailureToGetDIDOperation(String),
    /// Failed to get DID content.
    #[error("Error getting {0} DID content.")]
    FailureToGetDIDContent(String),
    /// Failed to recognise/handle DID content.
    #[error("Unrecognised DID content found at: {0}")]
    UnrecognisedDIDContent(String),
    /// Failed to read DID content.
    #[error("Error reading DID content found at: {0}")]
    FailureToReadDIDContent(String),
    /// Failed to parse DID content.
    #[error("Error parsing DID content.")]
    FailureToParseDIDContent(),
    /// Failed to verify DID content.
    #[error("Error verifying DID content.")]
    FailureToVerifyDIDContent,
    /// Failed to parse timestamp.
    #[error("Error parsing timestamp data.")]
    FailureToParseTimestamp,
    /// Invalid block hash.
    #[error("Invalid block hash: {0}")]
    InvalidBlockHash(String),
    /// Invalid block height.
    #[error("Invalid block height: {0}")]
    InvalidBlockHeight(i32),
    /// Invalid transaction index.
    #[error("Invalid transaction index: {0}")]
    InvalidTransactionIndex(i32),
    /// Failed to get the block hash for DID.
    #[error("Failed to get block hash for DID: {0}")]
    FailureToGetBlockHash(String),
    /// Failed to get the block height for DID.
    #[error("Failed to get block height for DID: {0}")]
    FailureToGetBlockHeight(String),
    /// Failure of API call to PoW ledger client.
    #[error("Failed API call to PoW ledger client: {0}")]
    LedgerClientError(String),
    /// Detected multiple DID content identifiers.
    #[error("Detected multiple DID content identifiers in tx: {0}")]
    MultipleDIDContentIdentifiers(String),
    /// No DID content identifier was found.
    #[error("No DID content identifier was found in tx: {0}")]
    NoDIDContentIdentifier(String),
    /// Failed verification of DID-related content hash.
    #[error("Content hash {0} does not match expected: {1}")]
    FailedContentHashVerification(String, String),
    /// Unhandled DID content.
    #[error("Unhandled DID content: {0}")]
    UnhandledDIDContent(String),
    /// Failed to resolve DID for verification.
    #[error("Failed to resolve DID: {0}")]
    DIDResolutionError(String),
    /// Failed to parse DID Document metadata.
    #[error("Failed to parse DID Document metadata.")]
    DIDMetadataError,
    /// Failed to find expected key in verified DID content.
    #[error("Key not found in verified content for DID: {0}")]
    KeyNotFoundInVerifiedContent(String),
    /// Failed to find expected service endpoint in verified DID content.
    #[error("Endpoint not found in verified content for DID: {0}")]
    EndpointNotFoundInVerifiedContent(String),
    /// Found duplicate update commitments in different DID operations.
    #[error("Duplicate update commitments: {0}")]
    DuplicateDIDUpdateCommitments(String),
    /// Failed to verify Proof of Work hashes.
    #[error("Proof of Work hashes do not match: {0}, {1}")]
    FailedProofOfWorkHashVerification(String, String),
    /// Failed to verify transaction timestamp.
    #[error("Timestamp verification failed for transaction: {0}")]
    FailedTransactionTimestampVerification(String),
    /// Failed block hash verification.
    #[error("Block hash verification failed for DID: {0}.")]
    FailedBlockHashVerification(String),
    /// Failed DID timestamp verification.
    #[error("Timestamp verification failed for DID: {0}.")]
    TimestampVerificationError(String),
    /// Failed to fetch verification material.
    #[error("Failed to fetch verification material.")]
    FailureToFetchVerificationMaterial,
    /// Attempt to access verification material before it has been fetched.
    #[error("Verification material not yet fetched for DID: {0}.")]
    VerificationMaterialNotYetFetched(String),
    /// Wrapped commitment error.
    #[error("A commitment error during verification.")]
    CommitmentFailure(crate::commitment::CommitmentError),
    /// Wrapped resolver error.
    #[error("A resolver error during verification.")]
    ResolverFailure(crate::resolver::ResolverError),
    /// Wrapped chain error.
    #[error("A chain error during verification.")]
    ChainFailure(crate::chain::ChainError),
}

impl From<crate::commitment::CommitmentError> for VerifierError {
    fn from(err: CommitmentError) -> Self {
        VerifierError::CommitmentFailure(err)
    }
}

impl From<crate::resolver::ResolverError> for VerifierError {
    fn from(err: crate::resolver::ResolverError) -> Self {
        VerifierError::ResolverFailure(err)
    }
}

impl From<ChainError> for VerifierError {
    fn from(err: ChainError) -> Self {
        VerifierError::ChainFailure(err)
    }
}

/// A Unix timestamp.
pub type Timestamp = u32;

/// A verifiably timestamped DID Document.
pub struct VerifiableTimestamp {
    did_commitment: Box<dyn DIDCommitment>,
    timestamp: Timestamp,
}

impl VerifiableTimestamp {
    fn new(did_commitment: Box<dyn DIDCommitment>, expected_timestamp: Timestamp) -> Self {
        Self {
            did_commitment,
            timestamp: expected_timestamp,
        }
    }

    /// Gets the DID Commitment.
    fn did_commitment(&self) -> &dyn DIDCommitment {
        self.did_commitment.as_ref()
    }

    /// Gets a Timestamp Commitment with hash, hasher and candidate data identical to the
    /// owned DID Commitment, and with the expected timestamp as expected data.
    pub fn timestamp_commitment(&self) -> Result<TimestampCommitment, VerifierError> {
        Ok(TimestampCommitment::new(
            &*self.did_commitment,
            self.timestamp,
        )?)
    }

    /// Gets the hash (proof-of-work) commitment.
    pub fn hash(&self) -> Result<String, VerifierError> {
        Ok(self.did_commitment.hash()?)
    }

    /// Gets the timestamp as a Unix time.
    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    /// Verifies that the DID Document data (public keys & endpoints)
    /// are contained as expected data in the DID Commitment.
    fn verify_content(&self) -> Result<(), VerifierError> {
        // Check each expected key is found in the vector of verified keys.
        if let Some(expected_keys) = self.did_commitment().did_document().get_keys() {
            if let Some(candidate_keys) = self.did_commitment().candidate_keys() {
                if !expected_keys.iter().all(|key| candidate_keys.contains(key)) {
                    eprintln!("Expected key not found in DID Commitment data.");
                    return Err(VerifierError::FailureToVerifyDIDContent);
                }
            } else {
                eprintln!("No candidate keys found in DID Commitment data.");
                return Err(VerifierError::FailureToVerifyDIDContent);
            }
        }
        // Check each expected endpoint is found in the vector of verified endpoints.
        if let Some(expected_endpoints) = self.did_commitment().did_document().get_endpoints() {
            if let Some(candidate_endpoints) = self.did_commitment().candidate_endpoints() {
                if !expected_endpoints
                    .iter()
                    .all(|uri| candidate_endpoints.contains(uri))
                {
                    eprintln!("Expected endpoint not found in DID Commitment data.");
                    return Err(VerifierError::FailureToVerifyDIDContent);
                }
            } else {
                eprintln!("No candidate endpoints found in DID Commitment data.");
                return Err(VerifierError::FailureToVerifyDIDContent);
            }
        }
        Ok(())
    }
}

/// A verifier of root and downstream DIDs.
pub trait Verifier<T: Sync + Send + DIDResolver> {
    /// Verifies a downstream DID by tracing its chain back to the root.
    fn verify(&mut self, did: &str, root_timestamp: Timestamp) -> Result<DIDChain, VerifierError> {
        // Build a chain from the given DID to the root.
        let chain = DIDChain::new(did, self.resolver())?;

        // Verify the proofs in the chain.
        chain.verify_proofs()?;

        // Verify the root timestamp.
        let root = chain.root();
        let verifiable_timestamp = self.verifiable_timestamp(root)?;
        self.verify_timestamp(&verifiable_timestamp)?;

        // At this point we know that the same proof of work commits to both the timestamp
        // in verifiable_timestamp and the data (keys & endpoints) in the root DID Document.
        // It only remains to check that the verified timestamp matches the expected root timestamp.
        if !verifiable_timestamp.timestamp().eq(&root_timestamp) {
            Err(VerifierError::InvalidRoot(root.to_string()))
        } else {
            Ok(chain)
        }
    }

    /// Constructs a verifiable timestamp for the given DID, including an expected
    /// value for the timestamp retreived from a local proof-of-work network node.
    fn verifiable_timestamp(&mut self, did: &str) -> Result<VerifiableTimestamp, VerifierError> {
        // Get the DID Commitment.
        let did_commitment = self.did_commitment(did)?;
        // Hash the DID commitment
        let hash = did_commitment.hash()?;
        // Get the expected timestamp for the proof-of-work hash by querying a *local* node.
        let expected_timestamp = self.expected_timestamp(&hash)?;
        Ok(VerifiableTimestamp::new(did_commitment, expected_timestamp))
    }

    /// TODO: docstring, and mention the to_string() conversion from u32 unix time.
    fn verify_timestamp(
        &self,
        verifiable_timestamp: &VerifiableTimestamp,
    ) -> Result<(), VerifierError> {
        // Verify that the DID Commitment commits to the DID Document data.
        verifiable_timestamp.verify_content()?;

        let did_commitment = verifiable_timestamp.did_commitment();
        let timestamp_commitment = verifiable_timestamp.timestamp_commitment()?;

        // Verify that the expected data in the Timestamp Commitment matches the timestamp itself.
        if !json_contains(
            timestamp_commitment.expected_data()?,
            &json!(verifiable_timestamp.timestamp()),
        ) {
            return Err(VerifierError::TimestampVerificationError(
                did_commitment.did().to_string(),
            ));
        }

        // Verify both the commitments with the *same* target hash, thereby confirming
        // that the same proof-of-work commits to both the DID Document data & the timestamp.
        let hash = verifiable_timestamp.hash()?;
        did_commitment.verify(&hash)?;
        timestamp_commitment.verify(&hash)?;

        Ok(())
    }

    /// Queries a local proof-of-work node to get the expected timestamp for a given proof-of-work hash.
    fn expected_timestamp(&self, hash: &str) -> Result<Timestamp, VerifierError>;

    /// Gets a block hash (proof-of-work) Commitment for the given DID.
    /// The mutable reference to self enables a newly-fetched Commitment
    /// to be stored locally for faster subsequent retrieval.
    fn did_commitment(&mut self, did: &str) -> Result<Box<dyn DIDCommitment>, VerifierError>;

    /// Gets the resolver used for DID verification.
    fn resolver(&self) -> &Resolver<T>;
}

#[cfg(test)]
mod tests {}

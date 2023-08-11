//! DID verifier API and default implementation.
use std::error::Error;

use crate::chain::{Chain, ChainError, DIDChain};
use crate::commitment::{CommitmentError, DIDCommitment, TimestampCommitment};
use crate::resolver::{Resolver, ResolverError};
use async_trait::async_trait;
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
    /// Failed to build DID chain.
    #[error("Failed to build chain: {0}.")]
    ChainBuildFailure(String),
    /// Chain verification failed.
    #[error("Chain verification failed: {0}.")]
    InvalidChain(String),
    /// Invalid PoW hash.
    #[error("Invalid PoW hash: {0}.")]
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
    #[error("Error parsing DID content: {0}")]
    FailureToParseDIDContent(String),
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
    InvalidBlockHeight(i64),
    /// Invalid transaction index.
    #[error("Invalid transaction index: {0}")]
    InvalidTransactionIndex(i32),
    /// Failed to get the block hash for DID.
    #[error("Failed to get block hash for DID: {0}")]
    FailureToGetBlockHash(String),
    /// Failed to get the block height for DID.
    #[error("Failed to get block height for DID: {0}")]
    FailureToGetBlockHeight(String),
    /// Failed to get the block header for block hash.
    #[error("Failed to get block header for block hash: {0}")]
    FailureToGetBlockHeader(String),
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
    #[error("Failed to resolve DID: {0} with associated resolution metadata: {1}")]
    // Note: ResolverError boxed to remove large Err-variant lint: <https://rust-lang.github.io/rust-clippy/master/index.html#result_large_err>
    DIDResolutionError(String, Box<ResolverError>),
    /// Failed to parse DID Document metadata.
    #[error("Failed to parse DID Document metadata.")]
    DIDMetadataError,
    /// Failed to find expected key in verified DID content.
    #[error("Key not found in verified content for DID: {0}")]
    KeyNotFoundInVerifiedContent(String),
    /// Failed to find expected key in verified DID content.
    #[error("No keys found in verified content for DID: {0}")]
    NoKeysFoundInVerifiedContent(String),
    /// Failed to find expected service endpoint in verified DID content.
    #[error("Endpoint not found in verified content for DID: {0}")]
    EndpointNotFoundInVerifiedContent(String),
    /// No endpoints found in verified DID content.
    #[error("No endpoints found in verified content for DID: {0}")]
    NoEndpointsFoundInVerifiedContent(String),
    /// Found duplicate update commitments in different DID operations.
    #[error("Duplicate update commitments: {0}")]
    DuplicateDIDUpdateCommitments(String),
    /// Failed to verify PoW hashes.
    #[error("PoW hashes do not match: {0}, {1}")]
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
    /// Error fetching verification material.
    #[error("Error fetching verification material: {0}. Error: {1}")]
    ErrorFetchingVerificationMaterial(String, Box<dyn Error>),
    /// Failed to fetch verification material.
    #[error("Failed to fetch verification material: {0}")]
    FailureToFetchVerificationMaterial(String),
    /// Attempt to access verification material before it has been fetched.
    #[error("Verification material not yet fetched for DID: {0}.")]
    VerificationMaterialNotYetFetched(String),
    /// Wrapped commitment error.
    #[error("A commitment error during verification: {0}")]
    CommitmentFailure(CommitmentError),
    /// Wrapped resolver error.
    #[error("A resolver error during verification.")]
    ResolverFailure(ResolverError),
    /// Wrapped chain error.
    #[error("A chain error during verification.")]
    ChainFailure(ChainError),
    /// Wrapped serde JSON deserialization error.
    #[error("Failed to deserialize.")]
    FailedToDeserialize(serde_json::Error),
}

impl From<CommitmentError> for VerifierError {
    fn from(err: CommitmentError) -> Self {
        VerifierError::CommitmentFailure(err)
    }
}

impl From<ResolverError> for VerifierError {
    fn from(err: ResolverError) -> Self {
        VerifierError::ResolverFailure(err)
    }
}

impl From<ChainError> for VerifierError {
    fn from(err: ChainError) -> Self {
        VerifierError::ChainFailure(err)
    }
}

impl From<serde_json::Error> for VerifierError {
    fn from(err: serde_json::Error) -> Self {
        VerifierError::FailedToDeserialize(err)
    }
}

/// A Unix timestamp.
pub type Timestamp = u32;

/// A verifiably-timestamped DID.
pub trait VerifiableTimestamp {
    /// Gets the wrapped DIDCommitment.
    fn did_commitment(&self) -> &dyn DIDCommitment;
    /// Gets the wrapped TimestampCommitment.
    fn timestamp_commitment(&self) -> &dyn TimestampCommitment;
    /// Gets the Timestamp.
    fn timestamp(&self) -> Timestamp {
        self.timestamp_commitment().timestamp()
    }
    /// Verifies both the DIDCommitment and the TimestampCommitment against the same target.
    fn verify(&self, target: &str) -> Result<(), CommitmentError> {
        // The expected data in the TimestampCommitment is the timestamp, while in the
        // DIDCommitment the expected data are the public keys & service endpoints.
        // By verifying both commitments using the same target, we confirm that the *same*
        // hash commits to *both* the DID Document data and the timestamp.
        self.did_commitment().verify(target)?;
        self.timestamp_commitment().verify(target)?;
        Ok(())
    }
}

/// A verifier of root and downstream DIDs.
#[async_trait]
pub trait Verifier<T: Sync + Send + DIDResolver> {
    /// Verifies a downstream DID by tracing its chain back to the root.
    async fn verify(
        &self,
        did: &str,
        root_timestamp: Timestamp,
    ) -> Result<DIDChain, VerifierError> {
        // Build a chain from the given DID to the root.
        let resolver = self.resolver();
        let chain = DIDChain::new(did, resolver).await?;

        // Verify the proofs in the chain.
        chain.verify_proofs()?;

        // Verify the root timestamp.
        let root = chain.root();

        let verifiable_timestamp = self.verifiable_timestamp(root, root_timestamp).await?;

        // Verify that the root DID content (keys & endpoints) and the timestamp share a common
        // commitment target.
        verifiable_timestamp.verify(&verifiable_timestamp.timestamp_commitment().hash()?)?;

        // Validate the PoW on the common target hash.
        self.validate_pow_hash(&verifiable_timestamp.timestamp_commitment().hash()?)?;

        // Verify explicitly that the return value from the timestamp method equals the expected
        // root timestamp (in case the default timestamp method implementation has been overridden).
        if !verifiable_timestamp.timestamp().eq(&root_timestamp) {
            Err(VerifierError::InvalidRoot(root.to_string()))
        } else {
            Ok(chain)
        }
    }

    /// Constructs a verifiable timestamp for the given DID, including an expected
    /// value for the timestamp retrieved from a local PoW network node.
    async fn verifiable_timestamp(
        &self,
        did: &str,
        expected_timestamp: Timestamp,
    ) -> Result<Box<dyn VerifiableTimestamp>, VerifierError>;

    /// Gets a block hash (PoW) Commitment for the given DID.
    async fn did_commitment(&self, did: &str) -> Result<Box<dyn DIDCommitment>, VerifierError>;

    /// Queries a local PoW node to get the expected timestamp for a given PoW hash.
    fn validate_pow_hash(&self, hash: &str) -> Result<(), VerifierError>;

    /// Gets the resolver used for DID verification.
    fn resolver(&self) -> &Resolver<T>;
}

#[cfg(test)]
mod tests {}

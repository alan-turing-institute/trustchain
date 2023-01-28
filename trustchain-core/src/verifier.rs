use crate::chain::{Chain, DIDChain};
use crate::commitment::{self, Commitment};
use crate::resolver::Resolver;
use ssi::did_resolve::DIDResolver;
use std::io::ErrorKind;
use thiserror::Error;

/// An error relating to Trustchain verification.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
}

/// Verifier of root and downstream DIDs.
pub trait Verifier<T: Sync + Send + DIDResolver> {
    /// Verifies a downstream DID by tracing its chain back to the root.
    fn verify(&mut self, did: &str, root_timestamp: u32) -> Result<DIDChain, VerifierError> {
        // Build a chain from the given DID to the root.
        let chain = match DIDChain::new(did, self.resolver()) {
            Ok(x) => x,
            Err(e) => return Err(VerifierError::ChainBuildFailure(e.to_string())),
        };

        // Verify the proofs in the chain.
        match chain.verify_proofs() {
            Ok(_) => (),
            Err(e) => return Err(VerifierError::InvalidChain(e.to_string())),
        };

        // Verify the root timestamp.
        let root = chain.root();
        match self.verified_timestamp(root) {
            Ok(timestamp) => {
                if timestamp == root_timestamp {
                    Ok(chain)
                } else {
                    Err(VerifierError::InvalidRoot(root.to_string()))
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Gets the verified block hash for a DID.
    /// This is the hash of the PoW block (header) that has been verified
    /// to contain the most recent DID operation for the given DID.
    fn verified_block_hash(&mut self, did: &str) -> Result<String, VerifierError> {
        let _ = self.fetch_commitment(did)?;
        let commitment = self.commitment(did)?;
        let candidate_hash = self.block_hash(did);
        match commitment.verify(candidate_hash) {
            Ok(_) => Ok(candidate_hash.to_string()),
            Err(e) => {
                eprintln!(
                    "Hash {} verification failed for DID: {}. With error: {}",
                    candidate_hash, did, e
                );
                Err(VerifierError::FailedBlockHashVerification(did.to_string()))
            }
        }
    }

    /// Gets the verified timestamp for a DID as a Unix time.
    fn verified_timestamp(&mut self, did: &str) -> Result<u32, VerifierError> {
        match self.verified_block_hash(did) {
            Ok(block_hash) => self.block_hash_to_unix_time(&block_hash),
            Err(e) => Err(e),
        }
    }

    /// Maps a block hash to a Unix time.
    fn block_hash_to_unix_time(&self, block_hash: &str) -> Result<u32, VerifierError>;

    /// Gets a proof-of-work Commitment for the given DID.
    fn commitment(&mut self, did: &str) -> Result<Box<dyn Commitment>, VerifierError>;

    /// Fetches data for a proof-of-work Commitment for the given DID and
    /// stores it locally for later retrieval via the `commitment` method.
    fn fetch_commitment(&mut self, did: &str) -> Result<(), VerifierError>;

    /// Gets the *unverified* block hash for a given DID.
    fn block_hash(&self, did: &str) -> &str;

    /// Gets the resolver used for DID verification.
    fn resolver(&self) -> &Resolver<T>;
}

#[cfg(test)]
mod tests {}

use crate::chain::{Chain, DIDChain};
use crate::resolver::Resolver;
use ssi::did_resolve::DIDResolver;
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

    /// Refactorign from here.
    /// Invalid IteratedCommitment.
    #[error("Invalid IteratedCommitment")]
    InvalidIteratedCommitment,
    /// Data decoding error.
    #[error("Data decoding error.")]
    DataDecodingError,
    /// Failed hash verification
    #[error("Failed hash verification. Computed hash not equal to target.")]
    FailedHashVerification,
}

/// Verifier of root and downstream DIDs.
pub trait Verifier<T: Sync + Send + DIDResolver> {
    /// Verifies a downstream DID by tracing its chain back to the root.
    fn verify(&self, did: &str, root_timestamp: u32) -> Result<DIDChain, VerifierError> {
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
    fn verified_block_hash(&self, did: &str) -> Result<String, VerifierError>;

    /// Get the verified timestamp for a DID as a Unix time.
    fn verified_timestamp(&self, did: &str) -> Result<u32, VerifierError> {
        match self.verified_block_hash(did) {
            Ok(block_hash) => self.block_hash_to_unix_time(&block_hash),
            Err(e) => Err(e),
        }
    }

    /// Maps a block hash to a Unix time.
    fn block_hash_to_unix_time(&self, block_hash: &str) -> Result<u32, VerifierError>;

    /// Gets the resolver used for DID verification.
    fn resolver(&self) -> &Resolver<T>;
}

pub trait Commitment {
    /// Gets the commitment target.
    fn target(&self) -> &str;
    /// Gets the hasher (function).
    fn hasher(&self) -> Box<dyn Fn(&[u8]) -> String>;
    /// Gets the candidate data.
    fn candidate_data(&self) -> &[u8];
    // Decodes the candidate data.
    fn decode_candidate_data(&self) -> Result<serde_json::Value, VerifierError>;
    /// Gets the expected data.
    fn expected_data(&self) -> &serde_json::Value;

    /// Verifies that the hash of the candidate data matches the target.
    fn verify_target(&self) -> Result<(), VerifierError> {
        // Call the hasher (closure) on the candidate data.
        let hash = self.hasher()(self.candidate_data());
        // Compare the computed hash to the target.
        if hash.ne(self.target()) {
            return Err(VerifierError::FailedHashVerification);
        }
        Ok(())
    }

    /// Verifies that the expected data is found in the candidate data.
    fn verify_content(&self) -> Result<(), VerifierError> {
        todo!();
    }

    /// Verifies the commitment.
    fn verify(&self) -> Result<(), VerifierError> {
        let _ = &self.verify_content()?;
        let _ = &self.verify_target()?;
        Ok(())
    }
}

pub trait IteratedCommitment {
    /// Gets the sequence of commitments.
    fn commitments(&self) -> Vec<Box<dyn Commitment>>;

    /// Verifies that the seqence of commitments is valid.
    fn verify_sequence(&self) -> Result<(), VerifierError> {
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
                    return Err(VerifierError::InvalidIteratedCommitment);
                }
            } else {
                eprintln!("Unhandled serde_json::Value variant. Expected String.");
                return Err(VerifierError::InvalidIteratedCommitment);
            }
            let target = commitment.target();
        }
        Ok(())
    }

    /// Runs the verification process over the sequence of commitments.
    fn verify(&self) -> Result<(), VerifierError> {
        for commitment in self.commitments() {
            commitment.verify();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {}

use crate::chain::{Chain, DIDChain};
use crate::resolver::{Resolver, ResolverError};
use crate::utils::canonicalize;
use crate::{controller, ROOT_EVENT_TIME};
use serde_json::to_string_pretty as to_json;
use ssi::did::{VerificationMethod, VerificationMethodMap};
use ssi::did_resolve::Metadata;
use ssi::did_resolve::ResolutionMetadata;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use ssi::one_or_many::OneOrMany;
use ssi::{
    did::Document,
    did_resolve::{DIDResolver, DocumentMetadata},
    ldp::JsonWebSignature2020,
};
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
    /// DID not resolvable.
    #[error("DID: {0} is not resolvable.")]
    UnresolvableDID(String),
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
    UnrecognisedDidContent(String),
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
}

/// Verifier of root and downstream DIDs.
pub trait Verifier<T: Sync + Send + DIDResolver> {
    /// Verify a downstream DID by tracing its chain back to the root.
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

    /// Get the verified block hash for a DID.
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

    /// Map a block hash to a Unix time.
    fn block_hash_to_unix_time(&self, block_hash: &str) -> Result<u32, VerifierError>;

    /// Get the resolver used for DID verification.
    fn resolver(&self) -> &Resolver<T>;
}

#[cfg(test)]
mod tests {}

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
    /// Failure to get DID operation.
    #[error("Error getting {0} DID operation: {1}")]
    FailureToGetDIDOperation(String, String),
    /// Invalid block height.
    #[error("Invalid block height: {0}")]
    InvalidBlockHeight(i32),
    /// Invalid transaction index.
    #[error("Invalid transaction index: {0}")]
    InvalidTransactionIndex(i32),
    /// Failed to get the block height for DID.
    #[error("Failed to get block height for DID: {0}")]
    FailureToGetBlockHeight(String),
}

/// Verifier of root and downstream DIDs.
pub trait Verifier<T: Sync + Send + DIDResolver> {
    /// Verify a downstream DID by tracing its chain back to the root.
    fn verify(&self, did: &str, root_timestamp: u32) -> Result<(), VerifierError> {
        // Build a chain from the given DID to the root.
        let chain = match DIDChain::new(did, &self.resolver()) {
            Ok(x) => x,
            Err(e) => return Err(VerifierError::ChainBuildFailure(e.to_string())),
        };

        // Verify the proofs in the chain.
        match chain.verify_proofs() {
            Ok(_) => (),
            Err(e) => return Err(VerifierError::InvalidChain(e.to_string())),
        };

        // Verify the root timestamp.
        // TODO: use the Unix timestamp rather than the block height.
        let root = chain.root();
        if let Ok(block_height) = self.verified_block_height(root) {
            if block_height != root_timestamp {
                return Err(VerifierError::InvalidRoot(root.to_string()));
            }
        } else {
            return Err(VerifierError::FailureToGetBlockHeight(root.to_owned()));
        }
        Ok(())
    }

    /// Get the verified block height for a DID.
    fn verified_block_height(&self, did: &str) -> Result<u32, VerifierError>;
    /// Get the verified timestamp for a DID as a Unix time.
    fn verified_timestamp(&self, did: &str) -> Result<u32, VerifierError>;
    // /// Get the resolver used for DID verification.
    fn resolver(&self) -> &Resolver<T>;
}

#[cfg(test)]
mod tests {}

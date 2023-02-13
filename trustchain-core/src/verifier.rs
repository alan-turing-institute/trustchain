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
    /// Invalid signature in DID proof.
    #[error("Invalid signature for proof in dDID: {0}.")]
    InvalidSignature(String),
    /// Invalid root DID after self-controller reached in path.
    #[error("Invalid root DID: {0}.")]
    InvalidRoot(String),
    /// DID not resolvable.
    #[error("DID: {0} is not resolvable.")]
    UnresolvableDID(String),
    /// Failed to build DID chain.
    #[error("Failed to build chain for DID: {0}.")]
    ChainBuildFailure(String),
    /// Chain verification failed.
    #[error("Chain verification failed for chain: {0}.")]
    InvalidChain(String),
    /// Failure to get a DID operation.
    #[error("Error getting '{0}' operation for DID: {1}")]
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
    /// Failed to get Unix time from block height.
    #[error("Failed to get Unix time from block height: {0}")]
    FailureToGetUnixTime(u32),
}

/// Verifier of root and downstream DIDs.
pub trait Verifier<T: Sync + Send + DIDResolver> {
    /// Converts block height to Unix time.
    fn block_height_to_unixtime(&self, block_height: u32) -> Result<u32, VerifierError>;

    /// Verify a downstream DID by tracing its chain back to the root.
    fn verify(&self, did: &str, root_timestamp: u32) -> Result<DIDChain, VerifierError> {
        // Build a chain from the given DID to the root.
        let chain = match DIDChain::new(did, self.resolver()) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("{e}");
                return Err(VerifierError::ChainBuildFailure(did.to_string()));
            }
        };

        // Verify the proofs in the chain.
        match chain.verify_proofs() {
            Ok(_) => (),
            Err(e) => {
                eprintln!("{e}");
                return Err(VerifierError::InvalidChain(chain.to_string()));
            }
        };

        // Verify the root timestamp.
        let root = chain.root();
        if let Ok(block_height) = self.verified_block_height(root) {
            if let Ok(unixtime) = self.block_height_to_unixtime(block_height) {
                if unixtime != root_timestamp {
                    return Err(VerifierError::InvalidRoot(root.to_string()));
                }
            } else {
                return Err(VerifierError::FailureToGetUnixTime(block_height));
            }
        } else {
            return Err(VerifierError::FailureToGetBlockHeight(root.to_owned()));
        }

        // TODO: consider whether to set a root event time here for the chain.

        Ok(chain)
    }

    /// Gets the verified block height for a DID.
    fn verified_block_height(&self, did: &str) -> Result<u32, VerifierError>;
    /// Gets the verified timestamp for a DID as a Unix time.
    fn verified_timestamp(&self, did: &str) -> Result<u32, VerifierError>;
    /// Gets the resolver used for DID verification.
    fn resolver(&self) -> &Resolver<T>;
}

#[cfg(test)]
mod tests {}

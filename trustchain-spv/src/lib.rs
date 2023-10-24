use std::path::PathBuf;

use nakamoto::chain::BlockHeader;
use thiserror::Error;

/// An error relating to the Trustchain-spv crate.
#[derive(Error, Debug)]
pub enum TrustchainSPVError {
    /// Block hash not found.
    #[error("Block hash not found: {0}")]
    BlockHashNotFound(String),
}

/// Initializes a local Bitcoin SPV client with a directory path for
/// writing block headers data.
pub fn initialize(path: &PathBuf, testnet: bool) -> Result<(), TrustchainSPVError> {
    todo!()
}

/// Gets a block header from the local Bitcoin SPV client by reading
/// data from the given path.
pub fn get_block_header(
    hash: &str,
    path: &PathBuf,
    testnet: bool,
) -> Result<BlockHeader, TrustchainSPVError> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize() {
        // todo!()
    }
}

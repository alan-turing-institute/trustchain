pub mod logger;

use std::{
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    str::FromStr,
    thread,
};

use nakamoto::{
    chain::{
        cache::BlockCache,
        store::{File, Genesis},
        BlockHash, BlockHeader, BlockReader,
    },
    client::{Client, Config},
    common::{
        bitcoin::consensus::Params,
        block::{checkpoints, Height},
    },
};
use thiserror::Error;

/// An error relating to the Trustchain-spv crate.
#[derive(Error, Debug)]
pub enum TrustchainSPVError {
    /// Bitcoin client error.
    #[error("Bitcoin client error: {0}")]
    NakamotoClientError(nakamoto::client::Error),
    /// Bitcoin client chain error.
    #[error("Bitcoin client chain error: {0}")]
    NakamotoChainError(nakamoto::chain::Error),
    /// Block hash not found.
    #[error("Block hash not found: {0}")]
    BlockHashNotFound(String),
}

impl From<nakamoto::client::Error> for TrustchainSPVError {
    fn from(err: nakamoto::client::Error) -> Self {
        TrustchainSPVError::NakamotoClientError(err)
    }
}

impl From<nakamoto::chain::Error> for TrustchainSPVError {
    fn from(err: nakamoto::chain::Error) -> Self {
        TrustchainSPVError::NakamotoChainError(err)
    }
}

type Reactor = nakamoto::net::poll::Reactor<std::net::TcpStream>;

fn bitcoin_network(testnet: bool) -> nakamoto::common::bitcoin::Network {
    match testnet {
        true => nakamoto::common::bitcoin::Network::Testnet,
        false => nakamoto::common::bitcoin::Network::Bitcoin,
    }
}

fn client_network(testnet: bool) -> nakamoto::client::Network {
    match testnet {
        true => nakamoto::client::Network::Testnet,
        false => nakamoto::client::Network::Mainnet,
    }
}

/// Initializes a local Bitcoin SPV client with a directory path for
/// writing block headers data.
pub fn initialize(path: PathBuf, testnet: bool) -> Result<(), TrustchainSPVError> {
    logger::init(log::Level::Info).expect("initializing logger for the first time");

    let client: Client<Reactor> = Client::new()?;
    let mut config = Config::new(client_network(testnet));
    config.root = path;

    // The `run` method is meant to be run in its own thread.
    thread::spawn(|| {
        let _ = client.run(config);
    });
    Ok(())
}

/// Gets a block header from the local Bitcoin SPV client by reading
/// data from the given path.
pub fn get_block_header(
    hash: &str,
    path: PathBuf,
    testnet: bool,
) -> Result<BlockHeader, TrustchainSPVError> {
    let genesis = BlockHeader::genesis(client_network(testnet));

    // Construct the path to the block headers database file.
    let path = path.join(Path::new("headers.db"));
    let store: File<BlockHeader> = File::open(path, genesis).unwrap();

    let params = Params::new(bitcoin_network(testnet));

    // TODO: work out how to add checkpoints.
    // The nakamoto::client::Network enum has a checkpoints method, but it
    // returns an Iterator. Here we need an array slice.
    let checkpoints: &[(Height, BlockHash)] = &[];

    let block_cache = BlockCache::new(store, params, &checkpoints)?;
    let block_cache = block_cache.load()?;

    let block_hash = BlockHash::from_str(hash).unwrap();

    if let Some((_, block_header)) = block_cache.get_block(&block_hash) {
        return Ok(block_header.clone());
    }
    Err(TrustchainSPVError::BlockHashNotFound(hash.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn test_initialize() {
        // Create a temp directory for the block store.
        // Its location is printed in the log.
        let path = TempDir::new("nakamoto").unwrap().into_path();
        let testnet = true;

        initialize(path.clone(), testnet).unwrap();
    }
}

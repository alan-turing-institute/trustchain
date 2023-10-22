pub mod logger;
pub mod spv;

use std::{
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
    common::{bitcoin::consensus::Params, block::Height},
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

pub fn get_block(
    path: PathBuf,
    testnet: bool,
    hash: &str,
) -> Result<(Height, BlockHeader), TrustchainSPVError> {
    // TODO: work out how to set default heights (for testnet & mainnet).
    let genesis = BlockHeader::genesis(client_network(testnet));

    // Construct the path to the block headers database file.
    let path = path.join(Path::new("headers.db"));
    let store: File<BlockHeader> = File::open(path, genesis).unwrap();

    let params = Params::new(bitcoin_network(testnet));

    // TODO: work out how to add a checkpoint.
    let checkpoints: &[(Height, BlockHash)] = &[];

    let block_cache = BlockCache::new(store, params, checkpoints)?;
    let block_cache = block_cache.load()?;

    let block_hash = BlockHash::from_str(hash).unwrap();

    if let Some((height, block_header)) = block_cache.get_block(&block_hash) {
        return Ok((height, block_header.clone()));
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
        // To find the temp directory, redirect the test output to a log file
        // and search the beginning of the log for the following line:
        // INFO client Initializing new block store "/var/folders/..."
        let path = TempDir::new("nakamoto").unwrap().into_path();
        let testnet = true;

        initialize(path, testnet).unwrap();
    }
}

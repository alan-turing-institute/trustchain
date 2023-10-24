pub mod logger;

use std::{path::PathBuf, thread};

use nakamoto::{
    chain::BlockHeader,
    client::{Client, Config},
};
use thiserror::Error;

/// An error relating to the Trustchain-spv crate.
#[derive(Error, Debug)]
pub enum TrustchainSPVError {
    /// Bitcoin client error.
    #[error("Bitcoin client error: {0}")]
    NakamotoClientError(nakamoto::client::Error),
    /// Block hash not found.
    #[error("Block hash not found: {0}")]
    BlockHashNotFound(String),
}

impl From<nakamoto::client::Error> for TrustchainSPVError {
    fn from(err: nakamoto::client::Error) -> Self {
        TrustchainSPVError::NakamotoClientError(err)
    }
}

type Reactor = nakamoto::net::poll::Reactor<std::net::TcpStream>;

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
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn test_initialize() {
        // Create a temp directory for the block store.
        let path = TempDir::new("nakamoto").unwrap().into_path();
        let testnet = true;

        initialize(path.clone(), testnet).unwrap();
    }
}

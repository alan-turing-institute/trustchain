pub mod logger;

use fs2::FileExt;

use std::{
    panic::catch_unwind,
    path::{Path, PathBuf},
    str::FromStr,
    thread::{self},
    time::Duration,
};

use nakamoto::{
    chain::{
        cache::BlockCache,
        store::{File, Genesis},
        BlockHash, BlockHeader, BlockReader,
    },
    client::{traits::Handle, Client, Config},
    common::{bitcoin::consensus::Params, block::Height},
    net::poll::Waker,
};
use thiserror::Error;

// Default timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MILLIS: u32 = 2000;
pub const DEFAULT_LOG_LEVEL: log::Level = log::Level::Info;

/// An error relating to the Trustchain-spv crate.
#[derive(Error, Debug)]
pub enum TrustchainSPVError {
    /// Bitcoin client error.
    #[error("Bitcoin client error: {0}")]
    NakamotoClientError(nakamoto::client::Error),
    /// Bitcoin client handle error.
    #[error("Bitcoin client handle error: {0}")]
    NakamotoClientHandleError(nakamoto::client::handle::Error),
    /// Client handle failed to get current tip.
    #[error("Client handle failed to get current tip: {0}")]
    GetCurrentTipError(nakamoto::client::handle::Error),
    /// Client handle error while listening.
    #[error("Client handle error while listening: {0}")]
    ClientHandleListeningError(nakamoto::client::handle::Error),
    /// Error while waiting for response from peer.
    #[error("Error while waiting for response from peer: {0}")]
    WaitingForPeerError(nakamoto::client::handle::Error),
    /// Node not ready.
    #[error("Node not ready error: {0}")]
    NodeNotReadyError(nakamoto::client::handle::Error),
    /// Bitcoin client chain error.
    #[error("Bitcoin client chain error: {0}")]
    NakamotoChainError(nakamoto::chain::Error),
    /// Reconnection failure: headers.db file not found.
    #[error("Reconnection failure: headers.db file not found.")]
    ReconnectionFailureHeadersFileNotFound,
    /// Reconnection failure: file lock attempt failed.
    #[error("Reconnection failure: file lock attempt failed.")]
    ReconnectionFailureFileLockError,
    /// Reconnection failure: file already locked.
    #[error("Reconnection failure: file already locked.")]
    ReconnectionFailureFileAlreadyLocked,
    /// Reconnection failure: file unlock attempt failed.
    #[error("Reconnection failure: file unlock attempt failed.")]
    ReconnectionFailureFileUnlockError,
    /// Reconnection failure: attempt timed out.
    #[error("Reconnection failure: attempt timed out.")]
    ReconnectionFailureTimeout,
    /// Shutdown attempt failed.
    #[error("Client shutdown attempt failed.")]
    ClientShutdownAttemptFailed,
    /// Failed to parse block hash.
    #[error("Failed to parse block hash: {0}")]
    InvalidBlockHash(String),
    /// Block hash not found.
    #[error("Block hash not found: {0}")]
    BlockHashNotFound(String),
    /// Failure to open BlockCache file.
    #[error("Failure to open BlockCache file.")]
    BlockCacheFileOpenError,
    /// BlockCache load panicked.
    #[error("BlockCache load panicked.")]
    BlockCacheLoadPanicked,
}

impl From<nakamoto::client::Error> for TrustchainSPVError {
    fn from(err: nakamoto::client::Error) -> Self {
        TrustchainSPVError::NakamotoClientError(err)
    }
}

impl From<nakamoto::client::handle::Error> for TrustchainSPVError {
    fn from(err: nakamoto::client::handle::Error) -> Self {
        TrustchainSPVError::NakamotoClientHandleError(err)
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

fn headers_db_path(path: PathBuf, testnet: bool) -> PathBuf {
    path.join(Path::new(".nakamoto"))
        .join(Path::new(&bitcoin_network(testnet).to_string()))
        .join(Path::new("headers.db"))
}

fn set_timeout(handle: &mut nakamoto::client::Handle<Waker>, timeout_millis: Option<u32>) {
    let duration = Duration::from_millis(timeout_millis.unwrap_or(DEFAULT_TIMEOUT_MILLIS).into());
    handle.set_timeout(duration);
}

/// Initializes a local Bitcoin SPV client with a directory path for
/// writing block headers data.
pub fn initialize(
    path: PathBuf,
    testnet: bool,
    log_level: Option<String>,
) -> Result<nakamoto::client::Handle<Waker>, TrustchainSPVError> {
    let log_level = match log_level {
        Some(level) => match log::Level::from_str(&level) {
            Ok(x) => x,
            Err(_) => DEFAULT_LOG_LEVEL,
        },
        None => DEFAULT_LOG_LEVEL,
    };
    if logger::init(log_level).is_err() {
        log::info!("Logger already initialized.");
    }

    let client: Client<Reactor> = Client::new()?;
    let mut config = Config::new(client_network(testnet));
    config.root = path.clone();
    let handle = client.handle();

    // The `run` method is meant to be run in its own thread.
    thread::spawn(move || {
        let _ = client.run(config);
    });

    Ok(handle)
}

/// Reconnects to a local Bitcoin SPV client whose block headers data
/// is stored under the given path.
fn reconnect(
    path: PathBuf,
    testnet: bool,
) -> Result<nakamoto::client::Handle<Waker>, TrustchainSPVError> {
    let client: Client<Reactor> = Client::new()?;
    let mut config = Config::new(client_network(testnet));
    config.root = path.clone();
    let handle = client.handle();

    let path = headers_db_path(path.clone(), testnet);
    if !path.exists() {
        return Err(TrustchainSPVError::ReconnectionFailureHeadersFileNotFound);
    }

    // Lock the headers.db file.
    log::info!("Preparing to lock file: {:?}", path.clone());
    let file = std::fs::File::open(path.clone());
    if file.is_err() {
        return Err(TrustchainSPVError::ReconnectionFailureFileLockError);
    }
    let file = file.unwrap();
    let try_lock = file.try_lock_shared();
    if try_lock.is_err() {
        return Err(TrustchainSPVError::ReconnectionFailureFileAlreadyLocked);
    }
    log::info!("Locked file: {:?}", path.clone());

    // Wait till the client has received any event, then unlock the file.
    let unlock_wait = handle.wait(|_| {
        let try_unlock = file.unlock();
        if try_unlock.is_err() {
            return None;
        }
        log::info!("Unlocked file: {:?}", path.clone());
        Some(())
    });

    // If the wait times out, unlock the file and return an error.
    if unlock_wait.is_err() {
        let try_unlock = file.unlock();
        if try_unlock.is_err() {
            return Err(TrustchainSPVError::ReconnectionFailureFileUnlockError);
        }
        return Err(TrustchainSPVError::ReconnectionFailureTimeout);
    }
    return Ok(handle);
}

/// Shuts down the local Bitcoin SPV client
pub fn shutdown(path: PathBuf, testnet: bool) -> Result<(), TrustchainSPVError> {
    let handle = reconnect(path, testnet)?;
    log::info!("Shutting down.");
    let try_shutdown = handle.shutdown();
    if try_shutdown.is_err() {
        return Err(TrustchainSPVError::ClientShutdownAttemptFailed);
    };
    Ok(())
}

/// Gets the current synchronised block height of the local Bitcoin SPV node.
pub fn get_tip(
    path: PathBuf,
    testnet: bool,
    timeout_millis: Option<u32>,
) -> Result<Height, TrustchainSPVError> {
    let mut handle = reconnect(path, testnet)?;
    set_timeout(&mut handle, timeout_millis);

    let (height, _) = handle.get_tip()?;
    Ok(height)
}

// Loads the block header cache file.
fn load_block_cache(
    path: PathBuf,
    testnet: bool,
) -> Result<BlockCache<File<BlockHeader>>, TrustchainSPVError> {
    let genesis = BlockHeader::genesis(client_network(testnet));

    let path = headers_db_path(path, testnet);

    // TODO: add checkpoints.
    // The nakamoto::client::Network enum has a checkpoints method, but it
    // returns an Iterator. Here we need an array slice.
    let checkpoints: &[(Height, BlockHash)] = &[];
    let store = nakamoto::chain::store::File::open(path, genesis);
    if store.is_err() {
        return Err(TrustchainSPVError::BlockCacheFileOpenError);
    }
    let store = store.unwrap();

    // Loading of the BlockCache can result in panic during chain syncing.
    // (Absence of panic does *not* imply that the chain is fully synced.)
    let params = Params::new(bitcoin_network(testnet));
    let block_cache = match catch_unwind(|| BlockCache::from(store, params, &checkpoints)) {
        Ok(x) => x,
        Err(_) => return Err(TrustchainSPVError::BlockCacheLoadPanicked),
    }?;

    Ok(block_cache)
}

/// Gets a block header from the local Bitcoin SPV client by reading
/// data from the given path.
pub fn get_block_header(
    hash: &str,
    path: PathBuf,
    testnet: bool,
) -> Result<BlockHeader, TrustchainSPVError> {
    let block_cache = load_block_cache(path, testnet)?;
    let block_hash = match BlockHash::from_str(hash) {
        Ok(x) => x,
        Err(e) => return Err(TrustchainSPVError::InvalidBlockHash(e.to_string())),
    };

    if let Some((_, block_header)) = block_cache.get_block(&block_hash) {
        return Ok(block_header.clone());
    }
    Err(TrustchainSPVError::BlockHashNotFound(hash.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nakamoto::client::traits::Handle;
    use tempdir::TempDir;

    #[test]
    fn test_initialize_shutdown() {
        // Create a temp directory for the block store.
        // Its location is printed in the log.
        let path = TempDir::new("nakamoto").unwrap().into_path();
        let testnet = true;

        let handle = initialize(path.clone(), testnet, None).unwrap();
        handle.shutdown().unwrap();
    }
}

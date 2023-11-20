//! Trustchain library for ION DID method.
pub mod attest;
pub mod attestor;
pub mod commitment;
pub mod config;
pub mod controller;
pub mod create;
pub mod data;
pub mod ion;
pub mod mnemonic;
pub mod resolver;
pub mod root;
pub mod sidetree;
pub mod utils;
pub mod verifier;

use crate::ion::IONTest as ION;
use crate::resolver::HTTPTrustchainResolver;
use did_ion::sidetree::HTTPSidetreeDIDResolver;
use serde::{Deserialize, Serialize};
use std::string::FromUtf8Error;
use std::{io, num::ParseIntError};
use thiserror::Error;

/// Type alias for URL
// TODO [#126]: remove in favour of new type pattern (e.g. URL(String)) or use https://crates.io/crates/url
// for better handling of URLs.
pub type URL = String;

/// Full client zero sized type for marker in `IONVerifier`.
pub struct FullClient;
/// Light client zero sized type for marker in `IONVerifier`.
pub struct LightClient;

/// Type for representing an endpoint as a base URL and port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn new(url: String, port: u16) -> Self {
        Self { host: url, port }
    }
    // TODO: add more flexible address handling
    pub fn to_address(&self) -> String {
        match self.host.starts_with("http") {
            true => format!("{}:{}/", self.host, self.port),
            false => format!("http://{}:{}/", self.host, self.port),
        }
    }
}

/// ION DID resolver.
pub fn http_resolver(endpoint: &str) -> HTTPSidetreeDIDResolver<ION> {
    HTTPSidetreeDIDResolver::new(endpoint)
}

/// Trustchain ION DID resolver for full client.
pub fn trustchain_resolver(
    ion_endpoint: &str,
) -> HTTPTrustchainResolver<HTTPSidetreeDIDResolver<ION>> {
    HTTPTrustchainResolver::<_, FullClient>::new(http_resolver(ion_endpoint))
}

/// Trustchain ION DID resolver for light client.
pub fn trustchain_resolver_light_client(
    trustchain_endpoint: &str,
) -> HTTPTrustchainResolver<HTTPSidetreeDIDResolver<ION>, LightClient> {
    HTTPTrustchainResolver::<_, LightClient>::new(http_resolver(trustchain_endpoint))
}

/// An error relating for Trustchain-ion crate.
#[derive(Error, Debug)]
pub enum TrustchainIONError {
    /// Key cannot be converted to commmitment value.
    #[error("Key cannot be converted to commmitment value.")]
    FailedToConvertToCommitment,
    /// Commitment value could not be extracted from document metadata.
    #[error("Commitment value could not be extracted from document metadata.")]
    FailedToExtractCommitment,
    /// Incorrect key type provided.
    #[error("Incorrect key type provided.")]
    IncorrectKeyType,
}

/// An error relating to a MongoDB query.
#[derive(Error, Debug)]
pub enum TrustchainMongodbError {
    /// Query returned `None`.
    #[error("Query returned None.")]
    QueryReturnedNone,
    /// Query returned an `Error`.
    #[error("Query returned Error: {0}")]
    QueryReturnedError(mongodb::error::Error),
    /// `Error` creating client.
    #[error("Error creating client: {0}")]
    ErrorCreatingClient(mongodb::error::Error),
}

impl From<mongodb::error::Error> for TrustchainMongodbError {
    fn from(err: mongodb::error::Error) -> Self {
        TrustchainMongodbError::QueryReturnedError(err)
    }
}

impl From<io::Error> for TrustchainIpfsError {
    fn from(err: io::Error) -> Self {
        TrustchainIpfsError::DataDecodingError(err)
    }
}

impl From<serde_json::Error> for TrustchainIpfsError {
    fn from(err: serde_json::Error) -> Self {
        TrustchainIpfsError::DeserializeError(err)
    }
}

/// An error relating to an IPFS query.
#[derive(Error, Debug)]
pub enum TrustchainIpfsError {
    /// Failed to decode IPFS data.
    #[error("Failed to decode IPFS data.")]
    DataDecodingError(io::Error),
    /// Failed to decode IPFS data.
    #[error("Failed to decode UTF-8 string.")]
    Utf8DecodingError(FromUtf8Error),
    /// Failed to decode IPFS data.
    #[error("Failed to deserialize IPFS content to JSON")]
    DeserializeError(serde_json::Error),
}

impl From<bitcoincore_rpc::Error> for TrustchainBitcoinError {
    fn from(err: bitcoincore_rpc::Error) -> Self {
        TrustchainBitcoinError::BitcoinCoreRPCError(err)
    }
}

impl From<ParseIntError> for TrustchainBitcoinError {
    fn from(err: ParseIntError) -> Self {
        TrustchainBitcoinError::BlockHeaderConversionError(err)
    }
}

/// An error relating to a Bitcoin RPC API call.
#[derive(Error, Debug)]
pub enum TrustchainBitcoinError {
    /// Failed to convert block header timestamp hex.
    #[error("Failed to convert block header timestamp hex: {0}")]
    BlockHeaderConversionError(ParseIntError),
    /// Failed to decode block header data.
    #[error("Failed to decode block header data.")]
    BlockHeaderDecodingError,
    /// Wrapped bitcoincore_rpc error
    #[error("Bitcoin core RPC error: {0}")]
    BitcoinCoreRPCError(bitcoincore_rpc::Error),
    /// Failed to get block time at height.
    #[error("Block time was None at height: {0}")]
    BlockTimeAtHeightError(u64),
    /// Target date precedes start block timestamp or succeeds end block timestamp.
    #[error("Target date out of range of block timestamps.")]
    TargetDateOutOfRange,
}

// DID
pub const CONTROLLER_KEY: &str = "controller";

// ION
pub const ION_METHOD: &str = "ion";
pub const ION_TEST_METHOD: &str = "ion:test";

// MongoDB
pub const MONGO_COLLECTION_OPERATIONS: &str = "operations";
pub const MONGO_FILTER_TYPE: &str = "type";
pub const MONGO_CREATE_OPERATION: &str = "create";
pub const MONGO_FILTER_DID_SUFFIX: &str = "didSuffix";
pub const MONGO_FILTER_TXN_TIME: &str = "txnTime";
pub const MONGO_FILTER_TXN_NUMBER: &str = "txnNumber";
pub const MONGO_FILTER_OP_INDEX: &str = "opIndex";

// Bitcoin
// TODO: consider structs for deserialization similar to trustchain_ion::sidetree module
pub const TXID_KEY: &str = "txid";
pub const MERKLE_ROOT_KEY: &str = "merkle_root";
pub const VERSION_KEY: &str = "version";
pub const HASH_PREV_BLOCK_KEY: &str = "hash_prev_block";
pub const TIMESTAMP_KEY: &str = "timestamp";
pub const BITS_KEY: &str = "bits";
pub const NONCE_KEY: &str = "nonce";

// Minimum number of zeros for PoW block hash of root
// TODO: set differently for mainnet and testnet with features
pub const MIN_POW_ZEROS: usize = 14;

// BIP32
pub const SIGNING_KEY_DERIVATION_PATH: &str = "m/0h";
pub const UPDATE_KEY_DERIVATION_PATH: &str = "m/1h";
pub const RECOVERY_KEY_DERIVATION_PATH: &str = "m/2h";

// IPFS KEY
pub const SERVICE_TYPE_IPFS_KEY: &str = "IPFSKey";

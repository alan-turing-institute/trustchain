pub mod attest;
pub mod attestor;
pub mod commitment;
pub mod controller;
pub mod create;
pub mod data;
pub mod resolve;
pub mod sidetree;
pub mod utils;
pub mod verifier;
use std::num::ParseIntError;

use did_ion::{sidetree::SidetreeClient, ION};
use std::io;
use thiserror::Error;
use trustchain_core::resolver::{DIDMethodWrapper, Resolver};

/// Type alias
pub type IONResolver = Resolver<DIDMethodWrapper<SidetreeClient<ION>>>;

/// Type alias for URL
pub type URL = String;

/// Test resolver
pub fn get_ion_resolver(endpoint: &str) -> IONResolver {
    IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(endpoint))))
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
}

// DID
pub const DID_DELIMITER: &str = ":";

// ION
pub const ION_METHOD: &str = "ion";
pub const ION_METHOD_WITH_DELIMITER: &str = "ion:";
pub const ION_OPERATION_COUNT_DELIMITER: &str = ".";
pub const PROVISIONAL_INDEX_FILE_URI_KEY: &str = "provisionalIndexFileUri";
pub const CHUNK_FILE_URI_KEY: &str = "chunkFileUri";
pub const CHUNKS_KEY: &str = "chunks";
pub const DELTAS_KEY: &str = "deltas";
pub const UPDATE_COMMITMENT_KEY: &str = "updateCommitment";
pub const METHOD_KEY: &str = "method";
pub const VERIFICATION_METHOD_KEY: &str = "verificationMethod";
pub const SERVICE_KEY: &str = "service";

// IPFS
pub const CID_KEY: &str = "cid";

// MongoDB
pub const MONGO_CONNECTION_STRING: &str = "mongodb://localhost:27017/";
pub const MONGO_DATABASE_ION_TESTNET_CORE: &str = "ion-testnet-core";
pub const MONGO_COLLECTION_OPERATIONS: &str = "operations";
pub const MONGO_FILTER_TYPE: &str = "type";
pub const MONGO_CREATE_OPERATION: &str = "create";
pub const MONGO_FILTER_DID_SUFFIX: &str = "didSuffix";

// Bitcoin (TESTNET PORT: 18332!)
pub const TXID_KEY: &str = "txid";
pub const MERKLE_ROOT_KEY: &str = "merkle_root";
pub const VERSION_KEY: &str = "version";
pub const HASH_PREV_BLOCK_KEY: &str = "hash_prev_block";
pub const TIMESTAMP_KEY: &str = "timestamp";
pub const BITS_KEY: &str = "bits";
pub const NONCE_KEY: &str = "nonce";

pub const BITCOIN_CONNECTION_STRING: &str = "http://localhost:18332";
pub const BITCOIN_RPC_USERNAME: &str = "admin";
pub const BITCOIN_RPC_PASSWORD: &str = "lWrkJlpj8SbnNRUJfO6qwIFEWkD+I9kL4REsFyMBlow=";

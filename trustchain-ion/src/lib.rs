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
use did_ion::{sidetree::SidetreeClient, ION};
use thiserror::Error;
use trustchain_core::resolver::{DIDMethodWrapper, Resolver};

/// Type alias
pub type IONResolver = Resolver<DIDMethodWrapper<SidetreeClient<ION>>>;

/// Test resolver
pub fn get_ion_resolver(endpoint: &str) -> IONResolver {
    IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(endpoint))))
}

/// An error relating for Trustchain-ion crate.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustchainIONError {
    #[error("Key cannot be converted to commmitment value.")]
    FailedToConvertToCommitment,
    #[error("Commitment value could not be extracted from document metadata.")]
    FailedToExtractCommitment,
    #[error("Incorrect key type is provided.")]
    IncorrectKeyType,
}

/// An error relating to a MongoDB query.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustchainMongodbError {
    #[error("Query returned None.")]
    QueryReturnedNone,
    #[error("Query returned Error.")]
    QueryReturnedError(String),
}

/// An error relating to an IPFS query.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustchainIpfsError {
    /// Failed to decode IPFS data.
    #[error("Failed to decode IPFS data.")]
    DataDecodingError,
}

/// An error relating to a Bitcoin RPC API call.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustchainBitcoinError {
    /// Failed to decode Bitcoin RPC data.
    #[error("Failed to decode Bitcoin RPC data.")]
    DataDecodingError,
}

// DID
pub const DID_DELIMITER: &str = ":";

// ION
pub const ION_METHOD: &str = "ion";
pub const ION_OPERATION_COUNT_DELIMITER: &str = ".";
pub const PROVISIONAL_INDEX_FILE_URI_KEY: &str = "provisionalIndexFileUri";
pub const CHUNK_FILE_URI_KEY: &str = "chunkFileUri";
pub const CHUNKS_KEY: &str = "chunks";
pub const DELTAS_KEY: &str = "deltas";
pub const UPDATE_COMMITMENT_KEY: &str = "updateCommitment";
pub const METHOD_KEY: &str = "method";
pub const VERIFICATION_METHOD_KEY: &str = "verificationMethod";
pub const SERVICE_KEY: &str = "service";
pub const OPERATIONS_KEY: &str = "operations";
pub const CREATE_KEY: &str = "create";
pub const SUFFIX_DATA_KEY: &str = "suffixData";
pub const DELTA_HASH_KEY: &str = "deltaHash";
pub const RECOVERY_COMMITMENT_KEY: &str = "recoveryCommitment";

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

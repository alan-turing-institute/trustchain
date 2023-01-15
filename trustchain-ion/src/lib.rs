pub mod attest;
pub mod attestor;
pub mod commitment;
pub mod controller;
pub mod create;
pub mod data;
pub mod resolve;
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

/// An error relating for rustchain-ion crate.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustchainIONError {
    #[error("Key cannot be converted to commmitment value.")]
    FailedToConvertToCommitment,
    #[error("Commitment value could not be extracted from document metadata.")]
    FailedToExtractCommitment,
    #[error("Incorrect key type is provided.")]
    IncorrectKeyType,
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
pub const BITCOIN_CONNECTION_STRING: &str = "http://localhost:18332";
pub const BITCOIN_RPC_USERNAME: &str = "admin";
pub const BITCOIN_RPC_PASSWORD: &str = "lWrkJlpj8SbnNRUJfO6qwIFEWkD+I9kL4REsFyMBlow=";

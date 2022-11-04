pub mod attestor;
pub mod controller;
pub mod verifier;

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

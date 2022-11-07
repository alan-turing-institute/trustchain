#![allow(dead_code)]
pub mod attest;
pub mod attestor;
pub mod controller;
pub mod create;
pub mod resolve;
use did_ion::{sidetree::SidetreeClient, ION};
use thiserror::Error;
use trustchain_core::key_manager::KeyManager;
use trustchain_core::resolver::{DIDMethodWrapper, Resolver};

/// Key utility struct and const instance
pub struct KeyUtils;
impl KeyManager for KeyUtils {}
pub const KEY_UTILS: KeyUtils = KeyUtils;

/// Type alias
pub type IONResolver = Resolver<DIDMethodWrapper<SidetreeClient<ION>>>;

/// Test resolver
pub fn test_resolver(endpoint: &str) -> IONResolver {
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

// TODO: move to fixtures for trustchain-ion
const TEST_DOC_STATE: &str = r##"{
    "publicKeys": [
       {
          "id": "Mz94EfSCueClM5qv62SXxtLWRj4Ti7rR2wLWmW37aCs",
          "type": "JsonWebSignature2020",
          "publicKeyJwk": {
          "crv": "secp256k1",
          "kty": "EC",
          "x": "7VKmPezI_VEnMjOPfAeUnpQxhS1sLjAKfd0s7xrmx9A",
          "y": "gWZ5Bo197eZuMh3Se-3rqWCQjZWbuDpOYAaw8yC-yaQ"
          },
          "purposes": [
          "assertionMethod",
          "authentication",
          "keyAgreement",
          "capabilityInvocation",
          "capabilityDelegation"
          ]
       }
    ],
    "services": [
       {
          "id": "trustchain-controller-proof",
          "type": "TrustchainProofService",
          "serviceEndpoint": {
          "controller": "did:ion:test:EiA8yZGuDKbcnmPRs9ywaCsoE2FT9HMuyD9WmOiQasxBBg",
          "proofValue": "dummy_string"
          }
       }
    ]
 }"##;
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

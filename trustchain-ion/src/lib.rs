pub mod attest;
pub mod attestor;
pub mod controller;
pub mod verifier;

// MongoDB
pub const MONGO_COLLECTION_OPERATIONS: &str = "operations";
pub const MONGO_FILTER_TYPE: &str = "type";
pub const MONGO_CREATE_OPERATION: &str = "create";
pub const MONGO_FILTER_DID_SUFFIX: &str = "didSuffix";

pub mod create;
pub mod resolve;
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

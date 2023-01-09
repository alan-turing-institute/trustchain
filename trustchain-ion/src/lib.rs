pub mod attest;
pub mod attestor;
pub mod controller;
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

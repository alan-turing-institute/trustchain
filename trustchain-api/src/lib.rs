use std::error::Error;

use did_ion::sidetree::DocumentState;
use trustchain_ion::{attest::attest_operation, create::create_operation, resolve::main_resolve};

pub trait TrustchainDIDCLI {
    /// Creates a controlled DID from a passed document state, writing the associated create operation to file in the operations path.
    fn create(document_state: Option<DocumentState>, verbose: bool) -> Result<(), Box<dyn Error>> {
        create_operation(document_state, verbose)
    }
    /// An uDID attests to a dDID, writing the associated update operation to file in the operations path.
    fn attest(did: &str, controlled_did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
        attest_operation(did, controlled_did, verbose)
    }
    /// Resolves a given DID using a resolver available at localhost:3000
    fn resolve(did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
        main_resolve(did, verbose)
    }
    /// TODO: the below have no CLI implementation currently but are planned
    fn update(did: &str, controlled_did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;
    fn recover(did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;
    fn deactivate(did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;
    fn publish(did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;
}
pub trait TrustchainVCCLI {}

pub trait TrustchainFFI {}
pub trait TrustchainHTTP {}

#[cfg(test)]
mod tests {
    use super::*;
}

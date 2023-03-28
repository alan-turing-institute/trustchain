use did_ion::sidetree::DocumentState;
use ssi::{did_resolve::ResolutionResult, jwk::JWK, vc::Credential, vc::Presentation};
use std::error::Error;
use trustchain_core::{chain::DIDChain, verifier::VerifierError};

/// API for Trustchain CLI DID functionality.
pub trait TrustchainDIDCLI {
    /// Creates a controlled DID from a passed document state, writing the associated create operation to file in the operations path.
    fn create(document_state: Option<DocumentState>, verbose: bool) -> Result<(), Box<dyn Error>>;
    /// An uDID attests to a dDID, writing the associated update operation to file in the operations path.
    fn attest(did: &str, controlled_did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;
    /// Resolves a given DID using a resolver available at localhost:3000
    fn resolve(did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;

    /// TODO: the below have no CLI implementation currently but are planned
    /// Verifies a given DID using a resolver available at localhost:3000, returning a result.
    fn verify(did: &str, verbose: bool) -> Result<DIDChain, VerifierError>;
    /// Generates an update operation and writes to operations path.
    fn update(did: &str, controlled_did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;
    /// Generates a recover operation and writes to operations path.
    fn recover(did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;
    /// Generates a deactivate operation and writes to operations path.
    fn deactivate(did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;
    /// Publishes operations within the operations path (queue).
    fn publish(did: &str, verbose: bool) -> Result<(), Box<dyn Error>>;
}

struct TrustchainDID;

impl TrustchainDIDCLI for TrustchainDID {
    fn create(document_state: Option<DocumentState>, verbose: bool) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    fn attest(did: &str, controlled_did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    fn resolve(did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    fn verify(did: &str, verbose: bool) -> Result<DIDChain, VerifierError> {
        todo!()
    }

    fn update(did: &str, controlled_did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    fn recover(did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    fn deactivate(did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    fn publish(did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
        todo!()
    }
}

/// API for Trustchain CLI VC functionality.
pub trait TrustchainVCCLI {
    /// Signs a credential
    fn sign(credential: &Credential, did: &str, key: &JWK) -> Credential;
    /// Verifies a credential
    fn verify(credential: &Credential, did: &str, key: &JWK) -> Result<(), Box<dyn Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
}

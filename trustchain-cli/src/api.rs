use did_ion::sidetree::DocumentState;
use ssi::{
    did_resolve::ResolutionResult,
    jwk::JWK,
    vc::Presentation,
    vc::{Credential, URI},
};
use std::error::Error;
use trustchain_core::{chain::DIDChain, issuer::Issuer, verifier::VerifierError};
use trustchain_ion::{
    attest::attest_operation, attestor::IONAttestor, create::create_operation, get_ion_resolver,
    resolve::main_resolve,
};

/// API for Trustchain CLI DID functionality.
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
    /// Verifies a given DID using a resolver available at localhost:3000, returning a result.
    fn verify(did: &str, verbose: bool) -> Result<DIDChain, VerifierError> {
        todo!()
    }
    /// Generates an update operation and writes to operations path.
    fn update(did: &str, controlled_did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
        todo!()
    }
    /// Generates a recover operation and writes to operations path.
    fn recover(did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
        todo!()
    }
    /// Generates a deactivate operation and writes to operations path.
    fn deactivate(did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
        todo!()
    }
    /// Publishes operations within the operations path (queue).
    fn publish(did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
        todo!()
    }
}

/// API for Trustchain CLI VC functionality.
pub trait TrustchainVCCLI {
    /// Signs a credential
    fn sign(mut credential: Credential, did: &str, key_id: Option<&str>) -> Credential {
        let resolver = get_ion_resolver("http://localhost:3000/");
        credential.issuer = Some(ssi::vc::Issuer::URI(URI::String(did.to_string())));
        let attestor = IONAttestor::new(did);
        resolver.runtime.block_on(async {
            credential = attestor.sign(&credential, key_id, &resolver).await.unwrap();
        });
        credential
    }
    /// Verifies a credential
    fn verify(credential: &Credential, did: &str, key: &JWK) -> Result<(), Box<dyn Error>> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}

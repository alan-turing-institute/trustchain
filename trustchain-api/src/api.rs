use async_trait::async_trait;
use did_ion::sidetree::DocumentState;
use ssi::{
    vc::VerificationResult,
    vc::{Credential, URI},
};
use std::error::Error;
use trustchain_core::{
    chain::DIDChain,
    issuer::Issuer,
    resolver::ResolverResult,
    verifier::{Timestamp, Verifier, VerifierError},
};
use trustchain_ion::{
    attest::attest_operation, attestor::IONAttestor, create::create_operation, get_ion_resolver,
    verifier::IONVerifier,
};

/// API for Trustchain CLI DID functionality.
#[async_trait]
pub trait TrustchainDIDAPI {
    /// Creates a controlled DID from a passed document state, writing the associated create operation
    /// to file in the operations path returning the file name including the created DID suffix.
    fn create(
        document_state: Option<DocumentState>,
        verbose: bool,
    ) -> Result<String, Box<dyn Error>> {
        create_operation(document_state, verbose)
    }
    /// An uDID attests to a dDID, writing the associated update operation to file in the operations
    /// path.
    async fn attest(did: &str, controlled_did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
        attest_operation(did, controlled_did, verbose).await
    }
    /// Resolves a given DID using given endpoint.
    async fn resolve(did: &str, endpoint: &str) -> ResolverResult {
        // main_resolve(did, verbose)
        let resolver = get_ion_resolver(endpoint);

        // Result metadata, Document, Document metadata
        resolver.resolve_as_result(did).await
    }

    /// Verifies a given DID using a resolver available at given endpoint, returning a result.
    async fn verify(
        did: &str,
        root_event_time: Timestamp,
        endpoint: &str,
    ) -> Result<DIDChain, VerifierError> {
        IONVerifier::new(get_ion_resolver(endpoint))
            .verify(did, root_event_time)
            .await
    }

    // // TODO: the below have no CLI implementation currently but are planned
    // /// Generates an update operation and writes to operations path.
    // fn update(did: &str, controlled_did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
    //     todo!()
    // }
    // /// Generates a recover operation and writes to operations path.
    // fn recover(did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
    //     todo!()
    // }
    // /// Generates a deactivate operation and writes to operations path.
    // fn deactivate(did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
    //     todo!()
    // }
    // /// Publishes operations within the operations path (queue).
    // fn publish(did: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
    //     todo!()
    // }
}

/// API for Trustchain CLI VC functionality.
#[async_trait]
pub trait TrustchainVCAPI {
    /// Signs a credential.
    async fn sign(
        mut credential: Credential,
        did: &str,
        key_id: Option<&str>,
        endpoint: &str,
    ) -> Credential {
        let resolver = get_ion_resolver(endpoint);
        credential.issuer = Some(ssi::vc::Issuer::URI(URI::String(did.to_string())));
        let attestor = IONAttestor::new(did);
        attestor.sign(&credential, key_id, &resolver).await.unwrap()
    }
    /// Verifies a credential.
    async fn verify_credential(
        credential: &Credential,
        signature_only: bool,
        root_event_time: u32,
        endpoint: &str,
    ) -> (VerificationResult, Option<Result<DIDChain, VerifierError>>) {
        let resolver = get_ion_resolver(endpoint);
        let verification_result = credential.verify(None, &resolver).await;
        if signature_only {
            (verification_result, None)
        } else {
            let verifier = IONVerifier::new(get_ion_resolver(endpoint));
            let issuer = match credential.issuer.as_ref() {
                Some(ssi::vc::Issuer::URI(URI::String(did))) => did,
                _ => panic!("No issuer present in credential."),
            };
            (
                verification_result,
                Some(verifier.verify(issuer, root_event_time).await),
            )
        }
    }
}

#[cfg(test)]
mod tests {}

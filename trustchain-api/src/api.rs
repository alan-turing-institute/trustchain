use async_trait::async_trait;
use did_ion::sidetree::DocumentState;
use futures::{stream, StreamExt, TryStreamExt};
use ssi::{
    did_resolve::DIDResolver,
    ldp::LinkedDataDocument,
    vc::{Credential, CredentialOrJWT, URI},
    vc::{LinkedDataProofOptions, Presentation},
};
use std::error::Error;
use trustchain_core::{
    chain::DIDChain,
    holder::Holder,
    issuer::{Issuer, IssuerError},
    resolver::ResolverResult,
    vc::CredentialError,
    verifier::{Timestamp, Verifier, VerifierError},
    vp::PresentationError,
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
    // TODO: make specific error?
    fn create(
        document_state: Option<DocumentState>,
        verbose: bool,
    ) -> Result<String, Box<dyn Error>> {
        create_operation(document_state, verbose)
    }
    /// An uDID attests to a dDID, writing the associated update operation to file in the operations
    /// path.
    // TODO: make pecific error?
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
    ) -> Result<Credential, IssuerError> {
        let resolver = get_ion_resolver(endpoint);
        credential.issuer = Some(ssi::vc::Issuer::URI(URI::String(did.to_string())));
        let attestor = IONAttestor::new(did);
        attestor.sign(&credential, key_id, &resolver).await
    }

    /// Verifies a credential and returns a `DIDChain` if valid.
    async fn verify_credential<T: DIDResolver + Send + Sync>(
        credential: &Credential,
        ldp_options: Option<LinkedDataProofOptions>,
        root_event_time: Timestamp,
        verifier: &IONVerifier<T>,
    ) -> Result<DIDChain, CredentialError> {
        // Verify signature
        let result = credential.verify(ldp_options, verifier.resolver()).await;
        if !result.errors.is_empty() {
            return Err(CredentialError::VerificationResultError(result));
        }
        // Verify issuer
        let issuer = credential
            .get_issuer()
            .ok_or(CredentialError::NoIssuerPresent)?;
        Ok(verifier.verify(issuer, root_event_time).await?)
    }
}
#[async_trait]
pub trait TrustchainVPAPI {
    /// As a holder issue a verifiable presentation.
    async fn sign_presentation(
        mut presentation: Presentation,
        did: &str,
        key_id: Option<&str>,
        endpoint: &str,
    ) -> Result<Presentation, PresentationError> {
        let resolver = get_ion_resolver(endpoint);
        let attestor = IONAttestor::new(did);
        Ok(attestor
            .sign_presentation(&presentation, key_id, &resolver)
            .await?)
    }
    /// Verifies a verifiable presentation. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_verify_presentation.html).
    async fn verify_presentation<T: DIDResolver + Send + Sync>(
        presentation: &Presentation,
        ldp_options: Option<LinkedDataProofOptions>,
        root_event_time: Timestamp,
        verifier: &IONVerifier<T>,
    ) -> Result<(), PresentationError> {
        let credentials = presentation
            .verifiable_credential
            .as_ref()
            .ok_or(PresentationError::NoCredentialsPresent)?;

        // Attempt 2:
        // stream.map(Ok).try_for_each_concurrent().await
        // https://docs.rs/futures-util/latest/futures_util/stream/trait.TryStreamExt.html#method.try_for_each_concurrent
        // TODO consider concurrency limit (as rate limiting for verifier requests)
        // let limit = None;
        // stream::iter(credentials.into_iter())
        //     .map(Ok)
        //     .try_for_each_concurrent(limit, |credential_or_jwt| async {
        //         match credential_or_jwt {
        //             CredentialOrJWT::Credential(credential) => TrustchainVCAPI::verify_credential(
        //                 credential,
        //                 ldp_options,
        //                 root_event_time,
        //                 verifier,
        //             )
        //             .await
        //             .map(|_| ())
        //             .map_err(|err| err.into()),
        //             CredentialOrJWT::JWT(jwt) => {
        //                 let result =
        //                     Credential::verify_jwt(jwt, ldp_options, verifier.resolver()).await;
        //                 if !result.errors.is_empty() {
        //                     Err(PresentationError::CredentialError(
        //                         CredentialError::VerificationResultError(result),
        //                     ))
        //                 } else {
        //                     Ok(())
        //                 }
        //             }
        //         }
        //     })
        //     .await
        Ok(())

        // // Attempt 1:
        // // let valid = stream.then().all().await

        // // .then() returns an iterator over future<bool>, each of which is awaited in turn
        // // [stream::].all() returns a future
        // // disadvantages:
        // // - all credentials are checked before returning
        // // - difficult/not possible? to propagate errors out of closures to know which credential
        // //   failed
        // let valid = stream::iter(credentials.into_iter())
        //     .then(|credential_or_jwt| async {
        //         match credential_or_jwt {
        //             CredentialOrJWT::Credential(credential) => {
        //                 TrustchainVCAPI::verify_credential::<T>(
        //                     credential,
        //                     ldp_options,
        //                     root_event_time,
        //                     verifier,
        //                 )
        //                 .await
        //                 .map(|_| true)?
        //             }
        //             CredentialOrJWT::JWT(jwt) => {
        //                 let result =
        //                     Credential::verify_jwt(jwt, ldp_options, verifier.resolver()).await;
        //                 if !result.errors.is_empty() {
        //                     return Err(PresentationError::VerificationResultError(result));
        //                 }
        //             }
        //         }
        //     })
        //     .all(|validity| async { validity == true })
        //     .await;

        // if valid {
        //     Ok(())
        // } else {
        //     Err(PresentationError::NoCredentialsPresent)
        // }
    }
}

#[cfg(test)]
mod tests {}

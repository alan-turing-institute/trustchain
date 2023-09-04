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
    resolver::{Resolver, ResolverResult},
    vc::CredentialError,
    verifier::{Timestamp, Verifier, VerifierError},
    vp::PresentationError,
};
use trustchain_ion::{
    attest::attest_operation, attestor::IONAttestor, create::create_operation, get_ion_resolver,
    verifier::IONVerifier,
};

use crate::TrustchainAPI;

/// API for Trustchain CLI DID functionality.
#[async_trait]
pub trait TrustchainDIDAPI {
    /// Creates a controlled DID from a passed document state, writing the associated create
    /// operation to file in the operations path returning the file name including the created DID
    /// suffix.
    // TODO: consider replacing error variant with specific IONError/DIDError in future version.
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
    async fn resolve<T>(did: &str, resolver: &Resolver<T>) -> ResolverResult
    where
        T: DIDResolver + Send + Sync,
    {
        // Result metadata, Document, Document metadata
        resolver.resolve_as_result(did).await
    }

    /// Verifies a given DID using a resolver available at given endpoint, returning a result.
    async fn verify<T, U>(
        did: &str,
        root_event_time: Timestamp,
        verifier: &U,
    ) -> Result<DIDChain, VerifierError>
    where
        T: DIDResolver + Send,
        U: Verifier<T> + Send + Sync,
    {
        verifier.verify(did, root_event_time).await
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
    async fn sign<T: DIDResolver>(
        mut credential: Credential,
        did: &str,
        linked_data_proof_options: Option<LinkedDataProofOptions>,
        key_id: Option<&str>,
        resolver: &T,
    ) -> Result<Credential, IssuerError> {
        credential.issuer = Some(ssi::vc::Issuer::URI(URI::String(did.to_string())));
        let attestor = IONAttestor::new(did);
        attestor
            .sign(&credential, linked_data_proof_options, key_id, resolver)
            .await
    }

    /// Verifies a credential
    async fn verify_credential<T, U>(
        credential: &Credential,
        linked_data_proof_options: Option<LinkedDataProofOptions>,
        root_event_time: Timestamp,
        verifier: &U,
    ) -> Result<DIDChain, CredentialError>
    where
        T: DIDResolver + Send,
        U: Verifier<T> + Send + Sync,
    {
        // Verify signature
        let result = credential
            .verify(linked_data_proof_options, verifier.resolver())
            .await;
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
    /// Signs a presentation constructing a verifiable presentation.
    async fn sign_presentation(
        presentation: Presentation,
        did: &str,
        key_id: Option<&str>,
        endpoint: &str,
        ldp_options: Option<LinkedDataProofOptions>,
    ) -> Result<Presentation, PresentationError> {
        let resolver = get_ion_resolver(endpoint);
        let attestor = IONAttestor::new(did);
        Ok(attestor
            .sign_presentation(&presentation, key_id, &resolver, ldp_options)
            .await?)
    }
    /// Verifies a verifiable presentation.
    async fn verify_presentation<T: DIDResolver + Send + Sync>(
        presentation: &Presentation,
        ldp_options: Option<LinkedDataProofOptions>,
        root_event_time: Timestamp,
        verifier: &IONVerifier<T>,
    ) -> Result<(), PresentationError> {
        // Check credentials are present in presentation
        let credentials = presentation
            .verifiable_credential
            .as_ref()
            .ok_or(PresentationError::NoCredentialsPresent)?;

        // TODO: consider concurrency limit (as rate limiting for verifier requests)
        let limit = Some(5);
        let ldp_options_vec: Vec<Option<LinkedDataProofOptions>> = (0..credentials.len())
            .map(|_| ldp_options.clone())
            .collect();

        // Verify signatures and issuers for each credential included in the presentation
        stream::iter(credentials.into_iter().zip(ldp_options_vec))
            .map(Ok)
            .try_for_each_concurrent(limit, |(credential_or_jwt, ldp_options)| async move {
                match credential_or_jwt {
                    CredentialOrJWT::Credential(credential) => TrustchainAPI::verify_credential(
                        credential,
                        ldp_options,
                        root_event_time,
                        verifier,
                    )
                    .await
                    .map(|_| ())
                    .map_err(|err| err.into()),
                    CredentialOrJWT::JWT(jwt) => {
                        // TODO: add chain verification for JWT credentials.
                        let result =
                            Credential::verify_jwt(jwt, ldp_options, verifier.resolver()).await;
                        if !result.errors.is_empty() {
                            Err(PresentationError::CredentialError(
                                CredentialError::VerificationResultError(result),
                            ))
                        } else {
                            Ok(())
                        }
                    }
                }
            })
            .await?;

        // Verify signature by holder to authenticate
        let result = presentation
            .verify(ldp_options.clone(), verifier.resolver())
            .await;
        if !result.errors.is_empty() {
            return Err(PresentationError::VerifiedHolderUnauthenticated(result));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::api::{TrustchainVCAPI, TrustchainVPAPI};
    use crate::TrustchainAPI;
    use ssi::ldp::now_ms;
    use ssi::one_or_many::OneOrMany;
    use ssi::vc::{Credential, CredentialOrJWT, Presentation, VCDateTime};
    use trustchain_core::vc::CredentialError;
    use trustchain_core::vp::PresentationError;
    use trustchain_core::{holder::Holder, issuer::Issuer};
    use trustchain_ion::attestor::IONAttestor;
    use trustchain_ion::get_ion_resolver;
    use trustchain_ion::verifier::IONVerifier;

    // The root event time of DID documents in `trustchain-ion/src/data.rs` used for unit tests and the test below.
    const ROOT_EVENT_TIME_1: u32 = 1666265405;

    const TEST_UNSIGNED_VC: &str = r##"{
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1",
          "https://w3id.org/citizenship/v1"
        ],
        "credentialSchema": {
          "id": "did:example:cdf:35LB7w9ueWbagPL94T9bMLtyXDj9pX5o",
          "type": "did:example:schema:22KpkXgecryx9k7N6XN1QoN3gXwBkSU8SfyyYQG"
        },
        "type": ["VerifiableCredential"],
        "issuer": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
        "image": "some_base64_representation",
        "credentialSubject": {
          "givenName": "Jane",
          "familyName": "Doe",
          "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science and Arts",
            "college": "College of Engineering"
          }
        }
      }
      "##;

    #[ignore = "requires a running Sidetree node listening on http://localhost:3000"]
    #[tokio::test]
    async fn test_verify_credential() {
        let issuer_did = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A";
        let issuer = IONAttestor::new(issuer_did);
        let mut vc_with_proof = signed_credential(issuer).await;
        let resolver = get_ion_resolver("http://localhost:3000/");
        let res = TrustchainAPI::verify_credential(
            &vc_with_proof,
            None,
            ROOT_EVENT_TIME_1,
            &IONVerifier::new(resolver),
        )
        .await;
        assert!(res.is_ok());

        // Change credential to make signature invalid
        vc_with_proof.expiration_date = Some(VCDateTime::try_from(now_ms()).unwrap());

        // Verify: expect no warnings and a signature error as VC has changed
        let resolver = get_ion_resolver("http://localhost:3000/");
        let res = TrustchainAPI::verify_credential(
            &vc_with_proof,
            None,
            ROOT_EVENT_TIME_1,
            &IONVerifier::new(resolver),
        )
        .await;
        if let CredentialError::VerificationResultError(ver_res) = res.err().unwrap() {
            assert_eq!(ver_res.errors, vec!["signature error"]);
        } else {
            panic!("should error with VerificationResultError varient of CredentialError")
        }
    }

    #[ignore = "requires a running Sidetree node listening on http://localhost:3000"]
    #[tokio::test]
    async fn test_verify_presentation() {
        // root+1
        let issuer_did = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A";
        // root+2
        let holder_did = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q";

        let issuer = IONAttestor::new(issuer_did);
        let holder = IONAttestor::new(holder_did);

        let vc_with_proof = signed_credential(issuer).await;
        let resolver = get_ion_resolver("http://localhost:3000/");
        let mut presentation = Presentation {
            verifiable_credential: Some(OneOrMany::Many(vec![
                CredentialOrJWT::Credential(vc_with_proof.clone()),
                CredentialOrJWT::Credential(vc_with_proof.clone()),
                CredentialOrJWT::Credential(vc_with_proof.clone()),
                CredentialOrJWT::Credential(vc_with_proof.clone()),
                CredentialOrJWT::Credential(vc_with_proof.clone()),
                CredentialOrJWT::Credential(vc_with_proof.clone()),
                CredentialOrJWT::Credential(vc_with_proof.clone()),
                CredentialOrJWT::Credential(vc_with_proof.clone()),
                CredentialOrJWT::Credential(vc_with_proof.clone()),
                CredentialOrJWT::Credential(vc_with_proof),
            ])),
            // NB. Holder must be specified in order to retrieve verification method to verify
            // presentation. Otherwise must be specified in LinkedDataProofOptions.
            // If the holder field is left unpopulated here, it is automatically populated during
            // signing (with the did of the presentation signer) in `holder.sign_presentation()`
            ..Default::default()
        };

        presentation = holder
            .sign_presentation(&presentation, None, &resolver, None)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&presentation).unwrap());
        assert!(TrustchainAPI::verify_presentation(
            &presentation,
            None,
            ROOT_EVENT_TIME_1,
            &IONVerifier::new(resolver),
        )
        .await
        .is_ok());
    }

    #[ignore = "requires a running Sidetree node listening on http://localhost:3000"]
    #[tokio::test]
    // No signature from holder in presentation (unauthenticated)
    async fn test_verify_presentation_unauthenticated() {
        // root+1
        let issuer_did = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A";
        let issuer = IONAttestor::new(issuer_did);

        let vc_with_proof = signed_credential(issuer).await;
        let resolver = get_ion_resolver("http://localhost:3000/");
        let presentation = Presentation {
            verifiable_credential: Some(OneOrMany::Many(vec![CredentialOrJWT::Credential(
                vc_with_proof,
            )])),
            ..Default::default()
        };

        println!("{}", serde_json::to_string_pretty(&presentation).unwrap());
        assert!(matches!(
            TrustchainAPI::verify_presentation(
                &presentation,
                None,
                ROOT_EVENT_TIME_1,
                &IONVerifier::new(resolver),
            )
            .await,
            Err(PresentationError::VerifiedHolderUnauthenticated(..))
        ));
    }

    // Helper function to create a signed credential given an attesor.
    async fn signed_credential(attestor: IONAttestor) -> Credential {
        let resolver = get_ion_resolver("http://localhost:3000/");
        let vc: Credential = serde_json::from_str(TEST_UNSIGNED_VC).unwrap();
        attestor.sign(&vc, None, None, &resolver).await.unwrap()
    }
}

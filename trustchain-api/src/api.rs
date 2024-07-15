use crate::TrustchainAPI;
use async_trait::async_trait;
use did_ion::sidetree::DocumentState;
use futures::{stream, StreamExt, TryStreamExt};
use ssi::{
    did_resolve::DIDResolver,
    jsonld::ContextLoader,
    ldp::LinkedDataDocument,
    vc::{Credential, CredentialOrJWT, URI},
    vc::{LinkedDataProofOptions, Presentation},
};
use std::error::Error;
use trustchain_core::{
    chain::DIDChain,
    holder::Holder,
    issuer::{Issuer, IssuerError},
    resolver::{ResolverResult, TrustchainResolver},
    vc::CredentialError,
    verifier::{Timestamp, Verifier, VerifierError},
    vp::PresentationError,
};
use trustchain_ion::{
    attest::attest_operation, attestor::IONAttestor, create::create_operation, trustchain_resolver,
};

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
    async fn resolve(did: &str, resolver: &dyn TrustchainResolver) -> ResolverResult {
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
    async fn sign(
        mut credential: Credential,
        did: &str,
        linked_data_proof_options: Option<LinkedDataProofOptions>,
        key_id: Option<&str>,
        resolver: &dyn TrustchainResolver,
        context_loader: &mut ContextLoader,
    ) -> Result<Credential, IssuerError> {
        credential.issuer = Some(ssi::vc::Issuer::URI(URI::String(did.to_string())));
        let attestor = IONAttestor::new(did);
        attestor
            .sign(
                &credential,
                linked_data_proof_options,
                key_id,
                resolver,
                context_loader,
            )
            .await
    }

    /// Verifies a credential
    async fn verify_credential<T, U>(
        credential: &Credential,
        linked_data_proof_options: Option<LinkedDataProofOptions>,
        root_event_time: Timestamp,
        verifier: &U,
        context_loader: &mut ContextLoader,
    ) -> Result<DIDChain, CredentialError>
    where
        T: DIDResolver + Send,
        U: Verifier<T> + Send + Sync,
    {
        // Verify signature
        let result = credential
            .verify(
                linked_data_proof_options,
                verifier.resolver().as_did_resolver(),
                context_loader,
            )
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
        linked_data_proof_options: Option<LinkedDataProofOptions>,
        context_loader: &mut ContextLoader,
    ) -> Result<Presentation, PresentationError> {
        let resolver = trustchain_resolver(endpoint);
        let attestor = IONAttestor::new(did);
        Ok(attestor
            .sign_presentation(
                &presentation,
                linked_data_proof_options,
                key_id,
                &resolver,
                context_loader,
            )
            .await?)
    }
    /// Verifies a verifiable presentation.
    async fn verify_presentation<T, U>(
        presentation: &Presentation,
        ldp_options: Option<LinkedDataProofOptions>,
        root_event_time: Timestamp,
        verifier: &U,
        context_loader: &mut ContextLoader,
    ) -> Result<(), PresentationError>
    where
        T: DIDResolver + Send,
        U: Verifier<T> + Send + Sync,
    {
        // Check credentials are present in presentation
        let credentials = presentation
            .verifiable_credential
            .as_ref()
            .ok_or(PresentationError::NoCredentialsPresent)?;

        // Verify signatures and issuers for each credential included in the presentation
        // TODO: consider concurrency limit (as rate limiting for verifier requests)
        let limit = Some(5);
        let ldp_opts_and_context_loader: Vec<(Option<LinkedDataProofOptions>, ContextLoader)> = (0
            ..credentials.len())
            .map(|_| (ldp_options.clone(), context_loader.clone()))
            .collect();
        stream::iter(credentials.into_iter().zip(ldp_opts_and_context_loader))
            .map(Ok)
            .try_for_each_concurrent(
                limit,
                |(credential_or_jwt, (ldp_opts, mut context_loader))| async move {
                    match credential_or_jwt {
                        CredentialOrJWT::Credential(credential) => {
                            TrustchainAPI::verify_credential(
                                credential,
                                ldp_opts,
                                root_event_time,
                                verifier,
                                &mut context_loader,
                            )
                            .await
                            .map(|_| ())
                        }
                        CredentialOrJWT::JWT(jwt) => {
                            // decode and verify for credential jwts
                            match Credential::decode_verify_jwt(
                                jwt,
                                ldp_opts.clone(),
                                verifier.resolver().as_did_resolver(),
                                &mut context_loader,
                            )
                            .await
                            .0
                            .ok_or(CredentialError::FailedToDecodeJWT)
                            {
                                Ok(credential) => TrustchainAPI::verify_credential(
                                    &credential,
                                    ldp_opts,
                                    root_event_time,
                                    verifier,
                                    &mut context_loader,
                                )
                                .await
                                .map(|_| ()),
                                Err(e) => Err(e),
                            }
                        }
                    }
                },
            )
            .await?;

        // Verify signature by holder to authenticate
        let result = presentation
            .verify(
                ldp_options.clone(),
                verifier.resolver().as_did_resolver(),
                context_loader,
            )
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
    use did_ion::sidetree::PublicKeyEntry;
    use ssi::jsonld::ContextLoader;
    use ssi::ldp::now_ns;
    use ssi::one_or_many::OneOrMany;
    use ssi::vc::{Credential, CredentialOrJWT, CredentialSubject, Presentation, VCDateTime};
    use trustchain_core::utils::init;
    use trustchain_core::vc::CredentialError;
    use trustchain_core::vp::PresentationError;
    use trustchain_core::{holder::Holder, issuer::Issuer};
    use trustchain_ion::attestor::IONAttestor;
    use trustchain_ion::trustchain_resolver;
    use trustchain_ion::verifier::TrustchainVerifier;

    // The root event time of DID documents in `trustchain-ion/src/data.rs` used for unit tests and the test below.
    const ROOT_EVENT_TIME_1: u64 = 1666265405;

    const TEST_UNSIGNED_VC: &str = r#"{
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1",
          "https://w3id.org/citizenship/v1"
        ],
        "type": ["VerifiableCredential"],
        "issuer": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
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
      "#;

    const UNSIGNED_DRIVERS_LICENCE_VC: &str = r###"{
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://w3id.org/vdl/v1"
        ],
        "type": [
          "VerifiableCredential",
          "Iso18013DriversLicense"
        ],
        "issuer": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
        "issuanceDate": "2023-11-23T11:43:26.806224Z",
        "credentialSubject": {
          "id": "did:example:12347abcd",
          "Iso18013DriversLicense": {
            "height": 1.8,
            "weight": 70,
            "nationality": "France",
            "given_name": "Test",
            "family_name": "A",
            "issuing_country": "US",
            "birth_date": "1958-07-17",
            "age_in_years": 30,
            "age_birth_year": 1958
          }
        }
      }"###;

    #[ignore = "requires a running Sidetree node listening on http://localhost:3000"]
    #[tokio::test]
    async fn test_verify_credential() {
        init();
        let issuer_did = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A"; // root+1
        let issuer = IONAttestor::new(issuer_did);
        let mut vc_with_proof = signed_credential(issuer).await;
        let resolver = trustchain_resolver("http://localhost:3000/");
        let mut context_loader = ContextLoader::default();
        let res = TrustchainAPI::verify_credential(
            &vc_with_proof,
            None,
            ROOT_EVENT_TIME_1,
            &TrustchainVerifier::new(resolver),
            &mut context_loader,
        )
        .await;
        assert!(res.is_ok());

        // Change credential to make signature invalid
        vc_with_proof.expiration_date = Some(VCDateTime::from(now_ns()));

        // Verify: expect no warnings and a signature error as VC has changed
        let resolver = trustchain_resolver("http://localhost:3000/");
        let res = TrustchainAPI::verify_credential(
            &vc_with_proof,
            None,
            ROOT_EVENT_TIME_1,
            &TrustchainVerifier::new(resolver),
            &mut context_loader,
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
    async fn test_verify_rss_credential() {
        init();

        // DID with RSS verification method
        let issuer_did_suffix = "EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q";
        let resolver = trustchain_resolver("http://localhost:3000/");
        let vc: Credential = serde_json::from_str(UNSIGNED_DRIVERS_LICENCE_VC).unwrap();
        let attestor = IONAttestor::new(issuer_did_suffix);

        let signed_vc = attestor
            .sign(
                &vc,
                None,
                Some("QDsGIX_7NfNEaXdEeV7PJ5e_CwoH5LlF3srsCp5dcHA"),
                &resolver,
                &mut ContextLoader::default(),
            )
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&signed_vc).unwrap());
        let mut context_loader = ContextLoader::default();
        let verifier = TrustchainVerifier::new(resolver);
        let res = TrustchainAPI::verify_credential(
            &signed_vc,
            None,
            ROOT_EVENT_TIME_1,
            &verifier,
            &mut context_loader,
        )
        .await;
        // println!("{:?}", &res);
        assert!(res.is_ok());
    }

    #[ignore = "requires a running Sidetree node listening on http://localhost:3000"]
    #[tokio::test]
    async fn test_redact_verify_rss_credential() {
        init();

        // DID with RSS verification method
        let issuer_did_suffix = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q";
        let resolver = trustchain_resolver("http://localhost:3000/");
        let vc: Credential = serde_json::from_str(UNSIGNED_DRIVERS_LICENCE_VC).unwrap();
        let attestor = IONAttestor::new(issuer_did_suffix);

        let mut signed_vc = attestor
            .sign(
                &vc,
                None,
                Some("QDsGIX_7NfNEaXdEeV7PJ5e_CwoH5LlF3srsCp5dcHA"),
                &resolver,
                &mut ContextLoader::default(),
            )
            .await
            .unwrap();
        // println!("{}", serde_json::to_string_pretty(&signed_vc).unwrap());
        // derive redacted RSignature
        let masked_cred_sub: CredentialSubject = serde_json::from_str(
            r###"{
              "id": "did:example:12347abcd",
              "Iso18013DriversLicense": {
                "height": null,
                "weight": null,
                "nationality": null,
                "given_name": null,
                "family_name": null,
                "issuing_country": "US",
                "birth_date": null,
                "age_in_years": 30,
                "age_birth_year": null
              }
            }"###,
        )
        .unwrap();
        let mut masked_copy = signed_vc.clone();
        masked_copy.credential_subject = OneOrMany::One(masked_cred_sub);

        // produce redacted vc from redacted json
        let mut context_loader = ContextLoader::default();
        let verifier = TrustchainVerifier::new(resolver);
        signed_vc
            .rss_redact(
                masked_copy,
                &trustchain_resolver("http://localhost:3000/"),
                &mut context_loader,
            )
            .await
            .unwrap();
        // println!("{}", serde_json::to_string_pretty(&signed_vc).unwrap());

        let res = TrustchainAPI::verify_credential(
            &signed_vc,
            None,
            ROOT_EVENT_TIME_1,
            &verifier,
            &mut context_loader,
        )
        .await;

        assert!(res.is_ok());
    }

    #[ignore = "requires a running Sidetree node listening on http://localhost:3000"]
    #[tokio::test]
    async fn test_verify_presentation() {
        init();
        let issuer_did = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A"; // root+1
        let holder_did = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"; // root+2

        let issuer = IONAttestor::new(issuer_did);
        let holder = IONAttestor::new(holder_did);

        let vc_with_proof = signed_credential(issuer).await;
        let resolver = trustchain_resolver("http://localhost:3000/");
        let mut context_loader = ContextLoader::default();

        // let vc: Credential = serde_json::from_str(TEST_UNSIGNED_VC).unwrap();
        // let root_plus_1_signing_key: &str = r#"{"kty":"EC","crv":"secp256k1","x":"aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU","y":"dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0","d":"HbjLQf4tnwJR6861-91oGpERu8vmxDpW8ZroDCkmFvY"}"#;
        // let jwk: JWK = serde_json::from_str(root_plus_1_signing_key).unwrap();
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
                CredentialOrJWT::Credential(vc_with_proof.clone()),
                // Currently cannot generate a valid jwt that passes verification
                // Open issue to implement jwt generation for Issuer
                // https://github.com/alan-turing-institute/trustchain/issues/118
                // CredentialOrJWT::JWT(
                //     vc.generate_jwt(
                //         Some(&jwk),
                //         &LinkedDataProofOptions {
                //             checks: None,
                //             created: None,
                //             ..Default::default() // created: None,
                //                                  // challenge: None,
                //                                  // domain: None,
                //                                  // type_: None,
                //                                  // eip712_domain: None,
                //                                  // proof_purpose: None,
                //                                  // verification_method: None,
                //         },
                //         &resolver,
                //     )
                //     .await
                //     .unwrap(),
                // ),
            ])),
            // NB. Holder must be specified in order to retrieve verification method to verify
            // presentation. Otherwise must be specified in LinkedDataProofOptions.
            // If the holder field is left unpopulated here, it is automatically populated during
            // signing (with the did of the presentation signer) in `holder.sign_presentation()`
            ..Default::default()
        };

        presentation = holder
            .sign_presentation(&presentation, None, None, &resolver, &mut context_loader)
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&presentation).unwrap());
        let res = TrustchainAPI::verify_presentation(
            &presentation,
            None,
            ROOT_EVENT_TIME_1,
            &TrustchainVerifier::new(resolver),
            &mut context_loader,
        )
        .await;
        println!("{:?}", res);
        assert!(res.is_ok());
    }

    #[ignore = "requires a running Sidetree node listening on http://localhost:3000"]
    #[tokio::test]
    // No signature from holder in presentation (unauthenticated)
    async fn test_verify_presentation_unauthenticated() {
        init();
        let issuer_did = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A"; // root+1
        let issuer = IONAttestor::new(issuer_did);

        let vc_with_proof = signed_credential(issuer).await;
        let resolver = trustchain_resolver("http://localhost:3000/");
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
                &TrustchainVerifier::new(resolver),
                &mut ContextLoader::default()
            )
            .await,
            Err(PresentationError::VerifiedHolderUnauthenticated(..))
        ));
    }

    // Helper function to create a signed credential given an attesor.
    async fn signed_credential(attestor: IONAttestor) -> Credential {
        let resolver = trustchain_resolver("http://localhost:3000/");
        let vc: Credential = serde_json::from_str(TEST_UNSIGNED_VC).unwrap();
        attestor
            .sign(&vc, None, None, &resolver, &mut ContextLoader::default())
            .await
            .unwrap()
    }

    #[test]
    fn get_key_entry() {
        use ps_sig::keys::Params;
        use ssi::jwk::rss::generate_keys_jwk;
        use ssi::jwk::JWK;

        let key: JWK = generate_keys_jwk(64, &Params::new("test".to_string().as_bytes())).unwrap();
        println!("{}", serde_json::to_string_pretty(&key).unwrap());
        let entry: PublicKeyEntry = key.try_into().unwrap();
        println!("{}", serde_json::to_string_pretty(&entry).unwrap());
    }
}

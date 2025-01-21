use crate::{TrustchainAPI, DATA_ATTRIBUTE, DATA_CREDENTIAL_TEMPLATE};
use async_trait::async_trait;
use did_ion::sidetree::DocumentState;
use futures::{stream, StreamExt, TryStreamExt};
use sha2::{Digest, Sha256};
use ssi::{
    did_resolve::DIDResolver,
    jsonld::ContextLoader,
    ldp::LinkedDataDocument,
    vc::{Credential, CredentialOrJWT, LinkedDataProofOptions, Presentation, URI},
};
use std::error::Error;
use trustchain_core::{
    chain::DIDChain,
    holder::Holder,
    issuer::{Issuer, IssuerError},
    resolver::{ResolverResult, TrustchainResolver},
    vc::{CredentialError, DataCredentialError},
    verifier::{Timestamp, Verifier, VerifierError},
    vp::PresentationError,
};
use trustchain_ion::{
    attest::attest_operation, attestor::IONAttestor, create::create_operation, trustchain_resolver,
};

/// API for Trustchain DID functionality.
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

/// API for Trustchain VC functionality.
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

/// API for Trustchain VP functionality.
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

/// API for Trustchain DATA functionality.
#[async_trait]
pub trait TrustchainDataAPI {
    /// Signs data in the form of bytes.
    async fn sign_data(
        bytes: &[u8],
        did: &str,
        linked_data_proof_options: Option<LinkedDataProofOptions>,
        key_id: Option<&str>,
        resolver: &dyn TrustchainResolver,
        context_loader: &mut ContextLoader,
    ) -> Result<Credential, IssuerError> {
        // Read the data credential template.
        let mut credential = Credential::from_json_unsigned(DATA_CREDENTIAL_TEMPLATE).unwrap();
        // Add the issuer & issuanceDate attributes.
        credential.issuer = Some(ssi::vc::Issuer::URI(URI::String(did.to_string())));
        credential.issuance_date = Some(chrono::offset::Local::now().into());

        // Compute the SHA256 hash of the data.
        let data_hash = Sha256::digest(bytes);

        // Insert the data hash into the credential.
        let data_element = credential
            .credential_subject
            .to_single_mut()
            .expect("Template credential has a single credentialSubject.")
            .property_set
            .as_mut()
            .expect("Template credential has a property set.")
            .get_mut(DATA_ATTRIBUTE)
            .expect("Template credential has a dataset property.");
        *data_element = hex::encode(data_hash).to_string().into();

        // Sign the credential
        let attestor = IONAttestor::new(did);
        Ok(attestor
            .sign(
                &credential,
                linked_data_proof_options,
                key_id,
                resolver,
                context_loader,
            )
            .await?)
    }

    /// Verifies a data credential by hashing the data bytes.
    async fn verify_data<T, U>(
        bytes: &[u8],
        credential: &Credential,
        linked_data_proof_options: Option<LinkedDataProofOptions>,
        root_event_time: Timestamp,
        verifier: &U,
        context_loader: &mut ContextLoader,
    ) -> Result<DIDChain, DataCredentialError>
    where
        T: DIDResolver + Send,
        U: Verifier<T> + Send + Sync,
    {
        // Compute the SHA256 hash of the data.
        let actual_hash = hex::encode(Sha256::digest(bytes));

        // Check that the hash matches the dataset attribute value in the credential.
        let expected_hash = credential
            .credential_subject
            .to_single()
            .ok_or(DataCredentialError::ManyCredentialSubject(
                credential.credential_subject.clone(),
            ))?
            .property_set
            .as_ref()
            .ok_or(DataCredentialError::MissingAttribute(
                "property_set".to_string(),
            ))?
            .get(DATA_ATTRIBUTE)
            .ok_or(DataCredentialError::MissingAttribute(
                DATA_ATTRIBUTE.to_string(),
            ))?
            .as_str()
            .expect("dataset attribute is a str");

        if actual_hash != expected_hash {
            return Err(DataCredentialError::MismatchedHashDigests(
                expected_hash.to_string(),
                actual_hash,
            ));
        };
        // Verify the data credential.
        TrustchainAPI::verify_credential(
            credential,
            linked_data_proof_options,
            root_event_time,
            verifier,
            context_loader,
        )
        .await
        .map_err(DataCredentialError::CredentialError)
    }
}

#[cfg(test)]
mod tests {
    use crate::api::{
        TrustchainDataAPI, TrustchainVCAPI, TrustchainVPAPI, DATA_CREDENTIAL_TEMPLATE,
    };
    use crate::TrustchainAPI;
    use sha2::{Digest, Sha256};
    use ssi::jsonld::ContextLoader;
    use ssi::ldp::now_ns;
    use ssi::one_or_many::OneOrMany;
    use ssi::vc::{Credential, CredentialOrJWT, Presentation, VCDateTime, URI};
    use trustchain_core::utils::init;
    use trustchain_core::vc::{CredentialError, DataCredentialError};
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

    // Helper function to create a signed data credential given an attesor & data hash.
    async fn signed_data_credential(issuer_did: &str, bytes: &[u8]) -> Credential {
        let attestor = IONAttestor::new(issuer_did);
        let resolver = trustchain_resolver("http://localhost:3000/");
        let mut vc: Credential = serde_json::from_str(DATA_CREDENTIAL_TEMPLATE).unwrap();
        vc.issuer = Some(ssi::vc::Issuer::URI(URI::String(issuer_did.to_string())));
        // Insert the data hash into the credential.
        let data_element = vc
            .credential_subject
            .to_single_mut()
            .expect("Template credential has a single credentialSubject.")
            .property_set
            .as_mut()
            .expect("Template credential has a property set.")
            .get_mut(crate::DATA_ATTRIBUTE)
            .expect("Template credential has a dataset property.");
        *data_element = hex::encode(Sha256::digest(bytes)).to_string().into();
        attestor
            .sign(&vc, None, None, &resolver, &mut ContextLoader::default())
            .await
            .unwrap()
    }

    #[test]
    fn test_data_credential_template() {
        // Read the data credential template.
        let credential = Credential::from_json_unsigned(DATA_CREDENTIAL_TEMPLATE).unwrap();
        assert_eq!(credential.issuer.unwrap().get_id(), "did:ion:test:XYZ");
    }

    #[ignore = "requires a running Sidetree node listening on http://localhost:3000"]
    #[tokio::test]
    async fn test_verify_data() {
        init();
        let issuer_did = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A"; // root+1

        let bytes = "test-data-content".as_bytes();
        let expected_hash = hex::encode(Sha256::digest(bytes));

        let vc_with_proof = signed_data_credential(issuer_did, bytes).await;

        let resolver = trustchain_resolver("http://localhost:3000/");
        let mut context_loader = ContextLoader::default();

        let res = TrustchainAPI::verify_data(
            bytes,
            &vc_with_proof,
            None,
            ROOT_EVENT_TIME_1,
            &TrustchainVerifier::new(resolver),
            &mut context_loader,
        )
        .await;
        assert!(res.is_ok());

        // Change the data to make the hash digest invalid.
        let bytes = "different-data-content".as_bytes();

        // Verify: expect no warnings and a MismatchedHashDigests error as the data has changed.
        let resolver = trustchain_resolver("http://localhost:3000/");
        let res = TrustchainAPI::verify_data(
            bytes,
            &vc_with_proof,
            None,
            ROOT_EVENT_TIME_1,
            &TrustchainVerifier::new(resolver),
            &mut context_loader,
        )
        .await;
        assert!(res.is_err());

        if let DataCredentialError::MismatchedHashDigests(expected, actual) = res.err().unwrap() {
            assert_eq!(expected, expected_hash);
            assert_ne!(actual, expected_hash);
        } else {
            panic!("Unexpected CredentialError variant.")
        }
    }
}

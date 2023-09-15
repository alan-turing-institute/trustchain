use async_trait::async_trait;
use did_ion::sidetree::DocumentState;
use futures::{stream, StreamExt, TryStreamExt};
use ps_sig::rsssig::RSignature;
use ssi::ldp::now_ms;
use ssi::vc::VerificationResult;
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
use trustchain_core::vc::ProofVerify;

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
        // linked_data_proof_options: Option<LinkedDataProofOptions>,
        root_event_time: Timestamp,
        verifier: &U,
    ) -> Result<DIDChain, CredentialError>
    where
        T: DIDResolver + Send,
        U: Verifier<T> + Send + Sync,
    {
        let mut results = VerificationResult::new();
        if let Some(proofs) = &credential.proof {
            // Try verifying each proof until one succeeds
            for proof in proofs {
                // TODO(?): filter proofs based on verification_method found in
                // linked_data_proof_options.unwrap_or_default(), matching the behaviour of the
                // credential.verify() method
                let mut verification_result = if &proof.type_ == "RSSSignature" {
                    // TODO(?): implement ProofSuite for RSignature (will need a workaround for the
                    // orphan rule)
                    // more generally, some interface will be required to impl proof verification
                    // behaviour for RSignature - eg. ProofVerify trait with ::verify_proof()
                    //      this could return VerificationResult to have a return type the same as
                    //      proof.verify()
                    match RSignature::verify_proof(proof, credential) {
                        Ok(_) => VerificationResult::new(),
                        Err(e) => e.into(),
                    }
                    .into()
                } else {
                    // Proof.verify() calls LinkedDataProofs::verify() which matches on proof.type_
                    // and verifies for all proof types supported by ssi
                    // &Credential is passed as the LinkedDataDocument, as it is in
                    // ssi::vc::Credential.verify()
                    // There are two steps excluded from the workflow used in Credential.verify():
                    //      - "checks" are not parsed from ldp options passed into .verify().
                    //      - The proofs are not filtered based on the verification_method in ldp
                    //        options.
                    proof.verify(credential, verifier.resolver()).await
                };
                results.append(&mut verification_result);
            }
        } else {
            return Err(CredentialError::NoProofPresent);
        }

        // Deviation from the ssi Credential verification algorithm:
        // ssi return the results after the *first* proof passes verification (including any failed
        // verification results in the returned results).
        // This algorithm checks all proofs, and only proceeds to the Trustchain issuer verification
        // if all proofs verified without error.
        if results.errors.is_empty() {
            // Verify issuer
            let issuer = credential
                .get_issuer()
                .ok_or(CredentialError::NoIssuerPresent)?;
            return Ok(verifier.verify(issuer, root_event_time).await?);
        } else {
            Err(CredentialError::VerificationResultError(results))
        }
    }
}

#[async_trait]
pub trait TrustchainVPAPI {
    /// As a holder issue a verifiable presentation.
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
    /// Verifies a verifiable presentation. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_verify_presentation.html).
    async fn verify_presentation<T: DIDResolver + Send + Sync>(
        presentation: &Presentation,
        ldp_options: Option<LinkedDataProofOptions>,
        root_event_time: Timestamp,
        verifier: &IONVerifier<T>,
    ) -> Result<(), PresentationError> {
        // Verify contained credentials
        let credentials = presentation
            .verifiable_credential
            .as_ref()
            .ok_or(PresentationError::NoCredentialsPresent)?;

        // https://gendignoux.com/blog/2021/04/01/rust-async-streams-futures-part1.html#unordered-buffering-1
        // https://docs.rs/futures-util/latest/futures_util/stream/trait.TryStreamExt.html#method.try_for_each_concurrent
        // TODO consider concurrency limit (as rate limiting for verifier requests)
        let limit = Some(5);
        let ldp_options_vec: Vec<Option<LinkedDataProofOptions>> = (0..credentials.len())
            .map(|_| ldp_options.clone())
            .collect();
        let start = now_ms();
        stream::iter(credentials.into_iter().zip(ldp_options_vec))
            .enumerate()
            .map(Ok)
            .try_for_each_concurrent(
                limit,
                |(idx, (credential_or_jwt, ldp_options))| async move {
                    match credential_or_jwt {
                        CredentialOrJWT::Credential(credential) => {
                            println!("start {}: {}", idx, now_ms());
                            let v = TrustchainAPI::verify_credential(
                                credential,
                                root_event_time,
                                verifier,
                            )
                            .await
                            .map(|_| ())
                            .map_err(|err| err.into());
                            println!("done {}:  {}", idx, now_ms());
                            v
                        }

                        CredentialOrJWT::JWT(jwt) => {
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
                },
            )
            .await?;
        let end = now_ms();
        println!("Full time: {}", end - start);

        // Only verify signature by holder to authenticate
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
    use ps_sig::keys::{rsskeygen, PKrss, Params};
    use ps_sig::message_structure::message_encode::EncodedMessages;
    use ps_sig::rsssig::RSignature;
    use ssi::one_or_many::OneOrMany;
    use ssi::vc::{Credential, CredentialOrJWT, Presentation, Proof};
    use trustchain_core::vc_encoding::CanonicalFlatten;
    use trustchain_core::vc_encoding::RedactValues;
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
      "##;

    #[tokio::test]
    async fn test_verify_credential() {
        let issuer_did = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A";
        let issuer = IONAttestor::new(issuer_did);
        let vc_with_proof = signed_credential(issuer).await;
        let resolver = get_ion_resolver("http://localhost:3000/");
        let res = TrustchainAPI::verify_credential(
            &vc_with_proof,
            ROOT_EVENT_TIME_1,
            &IONVerifier::new(resolver),
        )
        .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_verify_rss_credential() {
        // chose indicies to disclose
        let idxs = vec![2, 3, 6];

        // obtain a vc with an RSS proof
        let signed_vc = issue_rss_vc();
        println!("{}", serde_json::to_string_pretty(&signed_vc).unwrap());

        // produce a Vec<String> representation of the VC with only the selected fields disclosed
        let mut redacted_seq = signed_vc.flatten();
        redacted_seq.redact(&idxs).unwrap();
        println!("{}", serde_json::to_string_pretty(&redacted_seq).unwrap());

        // encode redacted sequence into FieldElements
        let messages = EncodedMessages::from(redacted_seq);

        // parse issuers PK from the proof on the signed vc
        let issuers_proofs = signed_vc.proof.as_ref().unwrap();
        let issuers_pk = PKrss::from_hex(
            &issuers_proofs
                .first()
                .unwrap()
                .verification_method
                .as_ref()
                .unwrap(),
        )
        .unwrap();

        // derive redacted RSignature
        let r_rsig = RSignature::from_hex(
            &issuers_proofs
                .first()
                .unwrap()
                .proof_value
                .as_ref()
                .unwrap(),
        )
        .derive_signature(
            &issuers_pk,
            EncodedMessages::from(signed_vc.flatten()).as_slice(),
            &messages.infered_idxs,
        );

        // generate proof from derived RSS signature
        let mut proof = Proof::new("RSSSignature");
        proof.proof_value = Some(r_rsig.to_hex());
        proof.verification_method = Some(issuers_pk.to_hex());

        // produce an unsigned, redacted vc
        let mut redacted_vc = signed_vc;
        redacted_vc.proof = None;
        redacted_vc.redact(&idxs).unwrap();

        // add the derived RSS proof
        redacted_vc.add_proof(proof);

        // verify redacted vc
        let resolver = get_ion_resolver("http://localhost:3000/");
        let res = TrustchainAPI::verify_credential(
            &redacted_vc,
            ROOT_EVENT_TIME_1,
            &IONVerifier::new(resolver),
        )
        .await;
        println!("{:?}", &res);
        assert!(res.is_ok());
    }

    fn issue_rss_vc() -> Credential {
        // create rss keypair
        let (sk, pk) = rsskeygen(10, &Params::new("test".as_bytes()));
        // load complete (unredacted) vc
        let mut vc: Credential = serde_json::from_str(TEST_UNSIGNED_VC).unwrap();
        let rsig = RSignature::new(EncodedMessages::from(vc.flatten()).as_slice(), &sk);
        let mut proof = Proof::new("RSSSignature");
        proof.proof_value = Some(rsig.to_hex());
        proof.verification_method = Some(pk.to_hex());
        vc.add_proof(proof);
        vc
    }

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

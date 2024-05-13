//! Mobile FFI.
use crate::config::FFIConfig;
use anyhow::Result;
use chrono::{DateTime, Utc};
use did_ion::sidetree::Operation;
use serde::{Deserialize, Serialize};
use ssi::{
    jsonld::ContextLoader,
    jwk::JWK,
    ldp::{now_ns, Proof},
    one_or_many::OneOrMany,
    vc::{Credential, LinkedDataProofOptions, Presentation},
};
use thiserror::Error;
use tokio::runtime::Runtime;
use trustchain_api::{
    api::{TrustchainDIDAPI, TrustchainVCAPI, TrustchainVPAPI},
    TrustchainAPI,
};
use trustchain_core::{
    resolver::ResolverError, vc::CredentialError, verifier::VerifierError, vp::PresentationError,
};
use trustchain_ion::{
    create::{mnemonic_to_create_and_keys, OperationDID},
    trustchain_resolver_light_client,
    verifier::TrustchainVerifier,
};

/// A speicfic error for FFI mobile making handling easier.
#[derive(Error, Debug)]
pub enum FFIMobileError {
    /// Failed to deserialize JSON.
    #[error("JSON Deserialization Error: {0}.")]
    FailedToDeserialize(serde_json::Error),
    /// Failed to serialize.
    #[error("JSON Serialization Error: {0}.")]
    FailedToSerialize(serde_json::Error),
    #[error("Missing config error: {0}")]
    NoConfig(anyhow::Error),
    #[error("DID Resolve Error: {0}.")]
    FailedToResolveDID(ResolverError),
    #[error("DID Verify Error: {0}.")]
    FailedToVerifyDID(VerifierError),
    #[error("Failed to verify credential error: {0}.")]
    FailedToVerifyCredential(CredentialError),
    #[error("Credential proof created time ({0}) is in the future relative to now ({1}).")]
    FutureProofCreatedTime(DateTime<Utc>, DateTime<Utc>),
    #[error("Failed to issue presentation error: {0}.")]
    FailedToIssuePresentation(PresentationError),
    #[error("Failed to verify presentation error: {0}.")]
    FailedToVerifyPresentation(PresentationError),
    #[error("Failed to make create operation from mnemonic: {0}.")]
    FailedCreateOperation(String),
}

/// Checks time on proof is valid.
// When using android emulator, the time can be less than the created time in the proof if
// the clock is not correctly synchronised. This leads to a failure upon the proofs being
// checked:
//   https://docs.rs/ssi/0.4.0/src/ssi/vc.rs.html#1243 (filtered here)
//   https://docs.rs/ssi/0.4.0/src/ssi/vc.rs.html#1973-1975 (created time checked here)
//
// To recover, check that a time later than when the created time on the credential is used.
fn check_proof_time(created_time: &DateTime<Utc>) -> Result<(), FFIMobileError> {
    let now = now_ns();
    if &now < created_time {
        return Err(FFIMobileError::FutureProofCreatedTime(
            created_time.to_owned(),
            now,
        ));
    }
    Ok(())
}

/// Example greet function.
pub fn greet() -> String {
    format!("Hello from Rust at time: {}", now_ns())
}

/// Resolves a given DID document returning the serialized DID document as a JSON string.
pub fn did_resolve(did: String, opts: String) -> Result<String> {
    let mobile_opts: FFIConfig = opts.parse()?;
    let endpoint_opts = mobile_opts.endpoint()?;
    let resolver =
        trustchain_resolver_light_client(&endpoint_opts.trustchain_endpoint().to_address());
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        Ok(TrustchainAPI::resolve(&did, &resolver)
            .await
            .map_err(FFIMobileError::FailedToResolveDID)
            .and_then(|(_, doc, _)| {
                serde_json::to_string_pretty(&doc).map_err(FFIMobileError::FailedToSerialize)
            })?)
    })
}

/// Verifies a given DID returning the serialized DIDChain as a JSON string.
pub fn did_verify(did: String, opts: String) -> Result<String> {
    let mobile_opts: FFIConfig = opts.parse()?;
    let endpoint_opts = mobile_opts.endpoint()?;
    let trustchain_opts = mobile_opts.trustchain()?;
    let root_event_time = trustchain_opts.root_event_time;
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let verifier = TrustchainVerifier::with_endpoint(
            trustchain_resolver_light_client(&endpoint_opts.trustchain_endpoint().to_address()),
            endpoint_opts.trustchain_endpoint().to_address(),
        );
        Ok(TrustchainAPI::verify(&did, root_event_time, &verifier)
            .await
            .map_err(FFIMobileError::FailedToVerifyDID)
            .and_then(|did_chain| {
                serde_json::to_string_pretty(&did_chain).map_err(FFIMobileError::FailedToSerialize)
            })?)
    })
}

/// Verifies a verifiable credential returning the serialized DIDChain as a JSON string.
pub fn vc_verify_credential(credential: String, opts: String) -> Result<String> {
    let mobile_opts: FFIConfig = opts.parse()?;
    let endpoint_opts = mobile_opts.endpoint()?;
    let trustchain_opts = mobile_opts.trustchain()?;
    let ldp_opts = mobile_opts.linked_data_proof().cloned().ok();
    let credential: Credential = serde_json::from_str(&credential)?;
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let verifier = TrustchainVerifier::with_endpoint(
            trustchain_resolver_light_client(&endpoint_opts.trustchain_endpoint().to_address()),
            endpoint_opts.trustchain_endpoint().to_address(),
        );
        let root_event_time = trustchain_opts.root_event_time;

        // Check that time is later than the credential proof created time
        if let Some(OneOrMany::One(Proof {
            created: Some(created_time),
            ..
        })) = credential.proof.as_ref()
        {
            check_proof_time(created_time)?;
        }
        Ok(TrustchainAPI::verify_credential(
            &credential,
            ldp_opts,
            root_event_time,
            &verifier,
            &mut ContextLoader::default(),
        )
        .await
        .map_err(FFIMobileError::FailedToVerifyCredential)
        .and_then(|did_chain| {
            serde_json::to_string_pretty(&did_chain).map_err(FFIMobileError::FailedToSerialize)
        })?)
    })
}

/// Issues a verifiable presentation. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_issue_presentation.html).
pub fn vp_issue_presentation(
    presentation: String,
    opts: String,
    jwk_json: String,
) -> Result<String> {
    let mobile_opts: FFIConfig = opts.parse()?;
    let endpoint_opts = mobile_opts.endpoint()?;
    let ldp_opts =
        mobile_opts
            .linked_data_proof()
            .cloned()
            .ok()
            .unwrap_or(LinkedDataProofOptions {
                proof_purpose: Some(ssi::vc::ProofPurpose::Authentication),
                ..Default::default()
            });
    let mut presentation: Presentation =
        serde_json::from_str(&presentation).map_err(FFIMobileError::FailedToDeserialize)?;
    let jwk: JWK = serde_json::from_str(&jwk_json)?;
    let resolver =
        trustchain_resolver_light_client(&endpoint_opts.trustchain_endpoint().to_address());
    let rt = Runtime::new().unwrap();
    let proof = rt
        .block_on(async {
            presentation
                .generate_proof(&jwk, &ldp_opts, &resolver, &mut ContextLoader::default())
                .await
        })
        .map_err(|err| FFIMobileError::FailedToIssuePresentation(PresentationError::VC(err)))?;
    presentation.add_proof(proof);
    Ok(serde_json::to_string_pretty(&presentation).map_err(FFIMobileError::FailedToSerialize)?)
}

/// Verifies a verifiable presentation.
pub fn vp_verify_presentation(presentation: String, opts: String) -> Result<()> {
    let mobile_opts: FFIConfig = opts.parse()?;
    let endpoint_opts = mobile_opts.endpoint()?;
    let trustchain_opts = mobile_opts.trustchain()?;
    let presentation: Presentation =
        serde_json::from_str(&presentation).map_err(FFIMobileError::FailedToDeserialize)?;

    // Check that time is later than the authentication in the presentation.
    if let Some(OneOrMany::One(Proof {
        created: Some(created_time),
        ..
    })) = presentation.proof.as_ref()
    {
        check_proof_time(created_time)?;
    }

    // Verify presentation
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let verifier = TrustchainVerifier::with_endpoint(
            trustchain_resolver_light_client(&endpoint_opts.trustchain_endpoint().to_address()),
            endpoint_opts.trustchain_endpoint().to_address(),
        );
        let root_event_time = trustchain_opts.root_event_time;
        Ok(TrustchainAPI::verify_presentation(
            &presentation,
            None,
            root_event_time,
            &verifier,
            &mut ContextLoader::default(),
        )
        .await
        .map_err(FFIMobileError::FailedToVerifyPresentation)?)
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateOperationAndDID {
    create_operation: Operation,
    did: String,
}

/// Makes a new ION DID from a mnemonic.
// TODO: consider optional index in API
pub fn create_operation_mnemonic(mnemonic: String) -> Result<String> {
    // Generate create operation from mnemonic
    let (create_operation, _) = mnemonic_to_create_and_keys(&mnemonic, None)
        .map_err(|err| FFIMobileError::FailedCreateOperation(err.to_string()))?;

    // Return DID and create operation as JSON
    Ok(serde_json::to_string_pretty(&CreateOperationAndDID {
        did: create_operation.to_did(),
        create_operation: Operation::Create(create_operation),
    })?)
}

#[cfg(test)]
mod tests {
    use ssi::vc::CredentialOrJWT;
    use trustchain_core::utils::canonicalize_str;

    use crate::config::parse_toml;

    use super::*;
    const TEST_FFI_CONFIG: &str = r#"
    [ffi.trustchainOptions]
    rootEventTime = 1666265405
    signatureOnly = false

    [ffi.endpointOptions]
    trustchainEndpoint.host = "127.0.0.1"
    trustchainEndpoint.port = 8081
    "#;

    const TEST_CREDENTIAL: &str = r#"
    {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "type": [
          "VerifiableCredential"
        ],
        "credentialSubject": {
          "familyName": "Bloggs",
          "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Arts",
            "college": "University of Oxbridge"
          },
          "givenName": "Jane"
        },
        "issuer": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
        "proof": {
          "type": "EcdsaSecp256k1Signature2019",
          "proofPurpose": "assertionMethod",
          "verificationMethod": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI",
          "created": "2023-07-28T12:53:28.645Z",
          "jws": "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..a3bK-CKwhX0jIKNAv_aBjHxBNe3qf_Szc6aUTFagYa8ipWV2a13wipHNxfP3Nq5bM10P3khgdH4hR0d45s1qDA"
        }
    }
    "#;

    const TEST_PRESENTATION: &str = r#"
    {
        "@context": [
          "https://www.w3.org/2018/credentials/v1"
        ],
        "type": "VerifiablePresentation",
        "verifiableCredential": {
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
          ],
          "type": [
            "VerifiableCredential"
          ],
          "credentialSubject": {
            "givenName": "Jane",
            "familyName": "Bloggs",
            "degree": {
              "type": "BachelorDegree",
              "name": "Bachelor of Arts",
              "college": "University of Oxbridge"
            }
          },
          "issuer": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
          "proof": {
            "type": "EcdsaSecp256k1Signature2019",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI",
            "created": "2023-07-28T12:53:28.645Z",
            "jws": "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..a3bK-CKwhX0jIKNAv_aBjHxBNe3qf_Szc6aUTFagYa8ipWV2a13wipHNxfP3Nq5bM10P3khgdH4hR0d45s1qDA"
          }
        },
        "proof": {
          "type": "Ed25519Signature2018",
          "proofPurpose": "authentication",
          "verificationMethod": "did:key:z6MkhG98a8j2d3jqia13vrWqzHwHAgKTv9NjYEgdV3ndbEdD#z6MkhG98a8j2d3jqia13vrWqzHwHAgKTv9NjYEgdV3ndbEdD",
          "created": "2023-11-01T11:30:04.894683Z",
          "jws": "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..jyj1g5XvRFVU1ucxXvha20PJmAWGJo4VMkf54wzOvfU4UP7OeolloojsdNlMxeWPLw4ArRB-ENdtuizLbhNyDQ"
        },
        "holder": "did:key:z6MkhG98a8j2d3jqia13vrWqzHwHAgKTv9NjYEgdV3ndbEdD"
    }
    "#;

    const TEST_ION_CREATE_OPERATION: &str = r#"
    {
        "createOperation": {
          "delta": {
            "patches": [
              {
                "action": "replace",
                "document": {
                  "publicKeys": [
                    {
                      "id": "CIMzmuW8XaQoc2DyccLwMZ35GyLhPj4yG2k38JNw5P4",
                      "publicKeyJwk": {
                        "crv": "Ed25519",
                        "kty": "OKP",
                        "x": "jil0ZZqW_cldlxq2a0Ezw59IgEIULSj9E3NOD6YQCHo"
                      },
                      "purposes": [
                        "assertionMethod",
                        "authentication",
                        "keyAgreement",
                        "capabilityInvocation",
                        "capabilityDelegation"
                      ],
                      "type": "JsonWebSignature2020"
                    }
                  ]
                }
              }
            ],
            "updateCommitment": "EiA2gSveT83s4DD4kJp6tLJuPfy_M3m_m6NtRJzjwtrlDg"
          },
          "suffixData": {
            "deltaHash": "EiBtaFhQ3mbpKXwOXD2wr7so32FvbZDGvRyGJ-yOfforGQ",
            "recoveryCommitment": "EiDKEn4lG5ETCoQpQxAsMVahzuerhlk0rtqtuoHPYKEEog"
          },
          "type": "create"
        },
        "did": "did:ion:test:EiA1dZD7jVkS5ZP7JJO01t6HgTU3eeLpbKEV1voOFWJV0g"
    }"#;

    #[test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    fn test_did_resolve() {
        let did = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string();
        let ffi_opts = serde_json::to_string(&parse_toml(TEST_FFI_CONFIG)).unwrap();
        did_resolve(did, ffi_opts).unwrap();
    }

    #[test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    fn test_did_verify() {
        let did = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string();
        let ffi_opts = serde_json::to_string(&parse_toml(TEST_FFI_CONFIG)).unwrap();
        did_verify(did, ffi_opts).unwrap();
    }

    #[test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    fn test_vc_verify_credential() {
        let ffi_opts = serde_json::to_string(&parse_toml(TEST_FFI_CONFIG)).unwrap();
        let credential: Credential = serde_json::from_str(TEST_CREDENTIAL).unwrap();
        vc_verify_credential(serde_json::to_string(&credential).unwrap(), ffi_opts).unwrap();
    }

    #[test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    fn test_vp_issue_presentation() {
        let ffi_opts = serde_json::to_string(&parse_toml(TEST_FFI_CONFIG)).unwrap();
        let credential: Credential = serde_json::from_str(TEST_CREDENTIAL).unwrap();
        let root_plus_1_did: &str = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A";
        let presentation: Presentation = Presentation {
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(credential))),
            holder: Some(ssi::vc::URI::String(root_plus_1_did.to_string())),
            ..Default::default()
        };
        let root_plus_1_signing_key: &str = r#"{"kty":"EC","crv":"secp256k1","x":"aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU","y":"dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0","d":"HbjLQf4tnwJR6861-91oGpERu8vmxDpW8ZroDCkmFvY"}"#;
        let presentation = vp_issue_presentation(
            serde_json::to_string(&presentation).unwrap(),
            ffi_opts,
            root_plus_1_signing_key.to_string(),
        );
        println!("{}", presentation.unwrap());
    }

    #[test]
    fn test_vp_issue_presentation_ed25519() {
        let ffi_opts = serde_json::to_string(&parse_toml(TEST_FFI_CONFIG)).unwrap();
        let credential: Credential = serde_json::from_str(TEST_CREDENTIAL).unwrap();
        let did: &str = "did:key:z6MkhG98a8j2d3jqia13vrWqzHwHAgKTv9NjYEgdV3ndbEdD";
        let key: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"Kbnao1EkojaLeZ135PuIf28opnQybD0lB-_CQxuvSDg","d":"vwJwnuhHd4J0UUvjfYr8YxYwvNLU_GVkdqEbC3sUtAY"}"#;
        let presentation: Presentation = Presentation {
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(credential))),
            holder: Some(ssi::vc::URI::String(did.to_string())),
            ..Default::default()
        };

        let presentation = vp_issue_presentation(
            serde_json::to_string(&presentation).unwrap(),
            ffi_opts,
            key.to_string(),
        );
        println!("{}", presentation.unwrap());
    }

    #[test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    fn test_vp_verify_presentation() {
        let ffi_opts = serde_json::to_string(&parse_toml(TEST_FFI_CONFIG)).unwrap();
        vp_verify_presentation(TEST_PRESENTATION.to_string(), ffi_opts).unwrap();
    }

    #[test]
    fn test_ion_create_operation() {
        let mnemonic =
            "state draft moral repeat knife trend animal pretty delay collect fall adjust";
        let create_op_and_did = create_operation_mnemonic(mnemonic.to_string()).unwrap();
        assert_eq!(
            canonicalize_str::<CreateOperationAndDID>(&create_op_and_did).unwrap(),
            canonicalize_str::<CreateOperationAndDID>(TEST_ION_CREATE_OPERATION).unwrap()
        );
    }
}

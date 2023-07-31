use crate::config::FFIConfig;
use anyhow::{anyhow, Result};
use ssi::{
    one_or_many::OneOrMany,
    vc::{Credential, LinkedDataProofOptions, Proof},
};
use tokio::runtime::Runtime;
use trustchain_api::{api::TrustchainDIDAPI, TrustchainAPI};
use trustchain_core::{
    chain::{Chain, DIDChain},
    verifier::Verifier,
};
use trustchain_ion::{get_ion_resolver, verifier::IONVerifier};

/// Example greet function.
pub fn greet() -> String {
    "Hello from Rust! 🦀".into()
}

/// Resolves a given DID document assuming trust in endpoint.
pub fn did_resolve(did: String, opts: String) -> Result<String> {
    let mobile_opts: FFIConfig = serde_json::from_str(&opts)?;
    let endpoint_opts = mobile_opts.endpoint()?;
    let resolver = get_ion_resolver(&endpoint_opts.ion_endpoint().to_address());
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        TrustchainAPI::resolve(&did, &resolver)
            .await
            .map_err(|e| anyhow!(e))
            .and_then(|(_, doc, _)| serde_json::to_string_pretty(&doc).map_err(|e| anyhow!(e)))
    })
}
/// Verifies a given DID assuming trust in endpoint.
pub fn did_verify(did: String, opts: String) -> Result<()> {
    let mobile_opts: FFIConfig = serde_json::from_str(&opts)?;
    let endpoint_opts = mobile_opts.endpoint()?;
    let trustchain_opts = mobile_opts.trustchain()?;
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let verifier = IONVerifier::with_endpoint(
            get_ion_resolver(&endpoint_opts.ion_endpoint().to_address()),
            endpoint_opts.trustchain_endpoint()?.to_address(),
        );
        verifier
            .verify(&did, trustchain_opts.root_event_time)
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
        Ok(())
    })
}

/// Verifies a verifiable credential. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_verify_credential.html).
pub fn vc_verify_credential(credential: String, opts: String) -> Result<String> {
    let mobile_opts: FFIConfig = serde_json::from_str(&opts)?;
    let endpoint_opts = mobile_opts.endpoint()?;
    let trustchain_opts = mobile_opts.trustchain()?;
    let ldp_opts = mobile_opts.linked_data_proof().cloned().unwrap_or_default();
    let credential: Credential = serde_json::from_str(&credential)?;
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let verifier = IONVerifier::with_endpoint(
            get_ion_resolver(&endpoint_opts.ion_endpoint().to_address()),
            endpoint_opts.trustchain_endpoint()?.to_address(),
        );
        let signature_only = trustchain_opts.signature_only;
        let root_event_time = trustchain_opts.root_event_time;

        // NB. When using android emulator, the time is less than the created time on
        // the credential. This leads to a failure upon the proofs being checked:
        // https://docs.rs/ssi/0.4.0/src/ssi/vc.rs.html#1243 (filtered here)
        // https://docs.rs/ssi/0.4.0/src/ssi/vc.rs.html#1973-1975 (created time checked here)
        //
        // TODO: remove once confirmed time passed from mobile is functional
        // A workaround is to set the "created" time from the credential directly with
        // LinkedDataProofOptions
        // let ldpo = match credential.proof {
        //     Some(OneOrMany::One(Proof {
        //         created: created_time,
        //         ..
        //     })) => LinkedDataProofOptions {
        //         created: created_time,
        //         ..Default::default()
        //     },
        //     _ => return Err(anyhow!("No proof or created time available in proof.")),
        // };

        // TODO: try setting time as now from emulator to check time used from now_ms() call

        // TODO: refactor below

        // Verify credential signature with LinkedDataProofOptions
        let verification_result = credential.verify(Some(ldp_opts), verifier.resolver()).await;

        // Get DID chain if not signature only
        let did_chain = if signature_only {
            None
        } else {
            let issuer = match credential.issuer {
                Some(issuer) => issuer.get_id(),
                _ => return Err(anyhow!("No issuer present in credential.")),
            };
            Some(verifier.verify(&issuer, root_event_time).await)
        };

        // Returns
        if !verification_result.errors.is_empty() {
            Err(anyhow!(
                "Invalid signature:\n{}",
                serde_json::to_string_pretty(&verification_result.errors).unwrap()
            ))
        } else if signature_only {
            Ok("OK: signature only".to_string())
        } else if let Some(did_chain) = did_chain {
            match did_chain {
                Ok(_) => Ok("OK".to_string()),
                Err(e) => Err(anyhow!(e.to_string())),
            }
        } else {
            Err(anyhow!("No DID chain returned, failed to verify issuer."))
        }
    })
}
/// Issues a verifiable presentation. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_issue_presentation.html).
pub fn vc_issue_presentation(presentation: String, opts: String, key_json: String) {
    todo!()
}
/// Verifies a verifiable presentation. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_verify_presentation.html).
pub fn vc_verify_presentation(presentation: String, opts: String) -> Result<String> {
    todo!()
}
#[cfg(test)]
mod tests {
    use crate::config::parse_toml;

    use super::*;
    const TEST_FFI_CONFIG: &str = r#"
    [ffi.trustchainOptions]
    rootEventTime = 1666265405
    signatureOnly = false

    [ffi.endpointOptions]
    ionEndpoint.host = "127.0.0.1"
    ionEndpoint.port = 3000
    trustchainEndpoint.host = "127.0.0.1"
    trustchainEndpoint.port = 8081
    "#;

    // TODO: add test credential issued by did:ion:testEiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q
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
    fn test_vc_issue_presentation() {}

    #[test]
    fn test_vc_verify_presentation() {}
}

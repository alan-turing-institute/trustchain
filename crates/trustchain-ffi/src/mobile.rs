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
    vc::{Credential, CredentialSubject, LinkedDataProofOptions, Presentation},
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
    #[error("Failed to redact credential fields with RSS selective disclosure: {0}.")]
    FailedToRedactCredential(ssi::ldp::Error),
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

/// Generate a selectivley disclosed Credential with a new RSS proof derived from the original
/// credential and a masked copy of the credential subject.
pub fn vc_redact(
    original_credential: String,
    credential_subject_mask: String,
    opts: String,
) -> Result<String> {
    let mobile_opts: FFIConfig = opts.parse()?;
    let endpoint_opts = mobile_opts.endpoint()?;
    let mut o_cred: Credential = serde_json::from_str(&original_credential)?;
    let cred_sub: CredentialSubject = serde_json::from_str(&credential_subject_mask)?;
    let mut masked_copy = o_cred.clone();
    masked_copy.credential_subject = OneOrMany::One(cred_sub);
    let resolver =
        trustchain_resolver_light_client(&endpoint_opts.trustchain_endpoint().to_address());

    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        o_cred
            .rss_redact(masked_copy, &resolver, &mut ContextLoader::default())
            .await
    })
    .map_err(FFIMobileError::FailedToRedactCredential)?;
    Ok(serde_json::to_string_pretty(&o_cred).map_err(FFIMobileError::FailedToSerialize)?)
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
    use bitcoin::Network;
    use ssi::vc::CredentialOrJWT;
    use trustchain_core::utils::canonicalize_str;
    use trustchain_http::config::HTTPConfig;
    use trustchain_ion::utils::init;
    use trustchain_ion::utils::BITCOIN_NETWORK;

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

    const TESTNET4_TEST_FFI_CONFIG: &str = r#"
    [ffi.trustchainOptions]
    rootEventTime = 1766953540
    signatureOnly = false

    [ffi.endpointOptions]
    trustchainEndpoint.host = "127.0.0.1"
    trustchainEndpoint.port = 8081
    "#;

    const TEST_FFI_CONFIG_RSS: &str = r#"
    [ffi.trustchainOptions]
    rootEventTime = 1697213008
    signatureOnly = false

    [ffi.endpointOptions]
    trustchainEndpoint.host = "127.0.0.1"
    trustchainEndpoint.port = 8081
    "#;

    const TESTNET4_TEST_FFI_CONFIG_RSS: &str = r#"
    [ffi.trustchainOptions]
    rootEventTime = 1766953540
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

    const TESTNET4_TEST_CREDENTIAL: &str = r#"
    {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1",
            "https://w3id.org/citizenship/v1"
        ],
        "type": [
            "VerifiableCredential"
        ],
        "credentialSubject": {
            "familyName": "Doe",
            "givenName": "Jane",
            "degree": {
            "type": "BachelorDegree",
            "name": "Bachelor of Science and Arts",
            "college": "College of Engineering"
            }
        },
        "issuer": "did:ion:test:EiBsaims7YMtoe3XYZ-7nQ-CGBGBsZQUIIfTRAh0Mrd8Sw",
        "proof": {
            "type": "EcdsaSecp256k1Signature2019",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:ion:test:EiBsaims7YMtoe3XYZ-7nQ-CGBGBsZQUIIfTRAh0Mrd8Sw#HpzXYjTYoo7WX4QTP_KhpGoeym29F8SUUi4yRS--714",
            "created": "2026-01-03T22:29:25.689347577Z",
            "jws": "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..bdgKOWzWQd_Zzq30ozmu_l7L5oBX81rGix9LR8AkWOUhTiL3_xN8Wq-PwMdRL5LsVZ5z8QAC1ceDV8EAn8pijA"
        }
    }
    "#;

    const TEST_CREDENTIAL_RSS: &str = r#"{"@context":["https://www.w3.org/2018/credentials/v1","https://w3id.org/vdl/v1"],"type":["VerifiableCredential","Iso18013DriversLicense"],"credentialSubject":{"id":"did:key:z6Mkt68mqTgiLQdeZhnyai61yvSkG5SbzUR768n9cPMxyq9i","Iso18013DriversLicense":{"nationality":"British","given_name":"Jane","family_name":"Bloggs","issuing_country":"UK","birth_date":"1958-07-17","age_in_years":65,"age_birth_year":1958,"birth_place":"London","document_number":123456789,"resident_city":"London","resident_address":"London, UK"}},"issuer":"did:ion:test:EiDSE2lEM65nYrEqVvQO5C3scYhkv1KmZzq0S0iZmNKf1Q","issuanceDate":"2023-11-23T14:37:04.349867Z","proof":{"type":"RSSSignature2023","proofPurpose":"assertionMethod","proofValue":"1 0FCABC8DA586913D57CA7C3D5A9083E2C63999F2B07ABE7A091468A8290137232D21178A3093B41A182EBD0CB0314D96 1 0192B26C65C48F88E21E29D5985DD7B41D8E052382E557DD0EAEF2E60C77251632217A1A1B4B3CB4C61399B7B22832F8 1 0BBC5C12C26C3BCD90AA0B95BF83C147E43A47F49E5BDAB5EF91618ED017829829D1BB3F7E8B48A9E67B6D2A007A9D2C 1 10F41FE24A63CB21342250325C5FAD5213599EFA0EBEA69C55E66DC56FB544850DE756354390107FD484B703BF52EA16 2 13317C30F3A0D636D56A23C34FDD80B891ECBDE7C2B7D6E16B0F4B0B7E6D26CB6147ACDE629C4A23C57400D203A9FB84 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:1 0055C44D1473432D778E23A1C141F645BDA5EAB305045E3B2630F82F2AEB6A29F8DC413889F55F30AD7AD7F53984FB22 1 0CCFEEBFE7B5BBB224E64003C1501E69A4141A29D5BDF0EAA011C1A71D533A33C435A61B22D674B9C36F27ED4EA81ED4 1 186888DD113D3570CEAE2305783B9857AAB7A51869CD1C1D0D4A57411DF14DADEF2528BCE2EBC257C7DDD9C6BDE79B62 1 0A8B390C4EE079DD728C093ED8E9D56BB4BB96B3EA7C047E9B19BA7A2F7F970AD6E2ACDC8C26AEF474BE18E4B9996061 2 13317C30F3A0D636D56A23C34FDD80B891ECBDE7C2B7D6E16B0F4B0B7E6D26CB6147ACDE629C4A23C57400D203A9FB84 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 2 13317C30F3A0D636D56A23C34FDD80B891ECBDE7C2B7D6E16B0F4B0B7E6D26CB6147ACDE629C4A23C57400D203A9FB84 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 2 13317C30F3A0D636D56A23C34FDD80B891ECBDE7C2B7D6E16B0F4B0B7E6D26CB6147ACDE629C4A23C57400D203A9FB84 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","verificationMethod":"did:ion:test:EiDSE2lEM65nYrEqVvQO5C3scYhkv1KmZzq0S0iZmNKf1Q#Un2E28ffH75_lvA59p7R0wUaGaACzbg8i2H9ksviS34","created":"2023-11-23T14:37:04.356221Z"}}"#;
    const TEST_CREDENTIAL_SUBJECT_MASK: &str = r#"{"id":"did:key:z6Mkt68mqTgiLQdeZhnyai61yvSkG5SbzUR768n9cPMxyq9i","Iso18013DriversLicense":{"nationality":null,"given_name":null,"family_name":null,"issuing_country":"UK","birth_date":"1958-07-17","age_in_years":65,"age_birth_year":1958,"birth_place":"London","document_number":123456789,"resident_city":"London","resident_address":"London, UK"}}"#;

    const TESTNET4_TEST_CREDENTIAL_RSS: &str = r#"{"@context":["https://www.w3.org/2018/credentials/v1","https://w3id.org/vdl/v1"],"type":["VerifiableCredential","Iso18013DriversLicense"],"credentialSubject":{"id":"did:example:12347abcd","Iso18013DriversLicense":{"height":1.8,"weight":70,"nationality":"France","given_name":"Test","family_name":"A","issuing_country":"US","birth_date":"1958-07-17","age_in_years":30,"age_birth_year":1958}},"issuer":"did:ion:test:EiBdezm5h0cCTfeoDjKoFrpc6cf2Np4RoMSbFyEel-u8og","issuanceDate":"2025-11-23T11:43:26.806224Z","proof":{"type":"RSSSignature2023","proofPurpose":"assertionMethod","proofValue":"1 07BB2E2FB721D74441AAC2A27B69B0CCCBA37B3C67AAE5B79A41655FF599594E158B00A0B8164F183462914C6CA69E0B 1 09D7A1BE437B234DBE2274590EAD4D5F53548DD34C27F3DE959A0F610A5FAD3126AD40141E52F12C52D1BA9D575FA154 1 18235BAAD9803C4BB375E3EF44953913E2ADE3F5C35A9216FB88EC44EA8D41F2965298DD6064F154B64621C3E7DD7974 1 138555E086820CE5B45755FA4511CCE16F6CFD03C589E36E706BE8BBD4EFE18E00961154F30BFBB4B6C812476FA3CE6D 2 13317C30F3A0D636D56A23C34FDD80B891ECBDE7C2B7D6E16B0F4B0B7E6D26CB6147ACDE629C4A23C57400D203A9FB84 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:1 0BC9768E8B4B877A14F4EC4705D88A60A0B4EB1B0714CD319EB15CCA983850E7FF6DD37D88EF88AD9F5B542A99F8E6B0 1 121BA9086B3FB4E10F8B3B538E2D66FF1AFA9C6FAEE2F4D821BF775BE1B73A4E10203690B440A52EE5D169E309C35380 1 002AB54639250E79780F0E7C30E184590CA0812E9758963CD4B86C2C12C95DEBF0B50BA3EE1244D82C31771207B6AFF0 1 026AE4C737D5FD16D3C89F5625A5AF513352C39D2F3600306046FC036EE930922D3689A058413F3CA81B14CAB1A253C1 2 13317C30F3A0D636D56A23C34FDD80B891ECBDE7C2B7D6E16B0F4B0B7E6D26CB6147ACDE629C4A23C57400D203A9FB84 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 2 13317C30F3A0D636D56A23C34FDD80B891ECBDE7C2B7D6E16B0F4B0B7E6D26CB6147ACDE629C4A23C57400D203A9FB84 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000:1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 2 13317C30F3A0D636D56A23C34FDD80B891ECBDE7C2B7D6E16B0F4B0B7E6D26CB6147ACDE629C4A23C57400D203A9FB84 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","verificationMethod":"did:ion:test:EiBdezm5h0cCTfeoDjKoFrpc6cf2Np4RoMSbFyEel-u8og#nNW6wsf4UdHKtjnEC7SerqCZI0CarVaxDwrxyhLJl0I","created":"2026-01-12T13:39:41.570305959Z"}}"#;
    const TESTNET4_TEST_CREDENTIAL_SUBJECT_MASK: &str = r#"{"id":"did:example:12347abcd","Iso18013DriversLicense":{"height":1.8,"weight":70,"nationality":null,"given_name":null,"family_name":null,"issuing_country":"US","birth_date":"1958-07-17","age_in_years":30,"age_birth_year":1958}}"#;

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

    const TESTNET4_TEST_PRESENTATION: &str = r#"
    {
        "@context": [
            "https://www.w3.org/2018/credentials/v1"
        ],
        "type": "VerifiablePresentation",
        "verifiableCredential": [
            {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
                "https://w3id.org/citizenship/v1"
            ],
            "type": [
                "VerifiableCredential"
            ],
            "credentialSubject": {
                "givenName": "Jane",
                "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science and Arts",
                "college": "College of Engineering"
                },
                "familyName": "Doe"
            },
            "issuer": "did:ion:test:EiBsaims7YMtoe3XYZ-7nQ-CGBGBsZQUIIfTRAh0Mrd8Sw",
            "proof": {
                "type": "EcdsaSecp256k1Signature2019",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:ion:test:EiA-CAfMgrNRa2Gv5D8ZF7AazX9nKxnSlYkYViuKeomymw#ZWXNr31cpZX62JBSR91Nc-rEYdoI4kDFsqf6IBtv6Dk",
                "created": "2026-01-03T18:45:55.485325961Z",
                "jws": "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..yOpr-wPOaZvnPC7dMxvFBjUCvqm_x3kh66Pvq54mvosFCy01S0phl-IW5QXCV7YfBoDqYY4iTxTi02UYvIhFig"
            }
            }
        ],
        "proof": {
            "type": "EcdsaSecp256k1Signature2019",
            "proofPurpose": "authentication",
            "verificationMethod": "did:ion:test:EiBsaims7YMtoe3XYZ-7nQ-CGBGBsZQUIIfTRAh0Mrd8Sw#HpzXYjTYoo7WX4QTP_KhpGoeym29F8SUUi4yRS--714",
            "created": "2026-01-03T18:45:55.894832754Z",
            "jws": "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..MOghyY8s8jL0q8w9frySb7WaXEc7sKUAaHeAEzNkj2dpnfqiZrQ13MLLAoEae1xcAOrcv5zRsxFvBOlkNDsRnQ"
        },
        "holder": "did:ion:test:EiBsaims7YMtoe3XYZ-7nQ-CGBGBsZQUIIfTRAh0Mrd8Sw"
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

    fn init_http_ephemeral() -> u16 {
        init();
        // Create channel to receive port number from the thread with the server
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let http_config = HTTPConfig {
                host: "127.0.0.1".parse().unwrap(),
                port: 0,
                server_did: Some(
                    "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A".to_owned(),
                ),
                root_event_time: Some(1666265405),
                ..Default::default()
            };
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let server = trustchain_http::server::http_server(http_config);
                // Send assigned ephemeral port number to receiver
                tx.send(server.local_addr().port()).unwrap();
                server.await.unwrap();
            });
        });
        // Receive port number to return for client
        rx.recv().unwrap()
    }

    fn ffi_opts_with_port(ffi_config: &str, port: u16) -> String {
        let mut ffi_config = parse_toml(ffi_config);
        ffi_config
            .endpoint_options
            .as_mut()
            .unwrap()
            .trustchain_endpoint
            .port = port;
        serde_json::to_string(&ffi_config).unwrap()
    }

    #[test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    fn test_did_resolve() {
        let ffi_opts = ffi_opts_with_port(TEST_FFI_CONFIG, init_http_ephemeral());
        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                let did = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string();
                did_resolve(did, ffi_opts).unwrap();
            }
            Network::Testnet4 => {
                let did = "did:ion:test:EiBdezm5h0cCTfeoDjKoFrpc6cf2Np4RoMSbFyEel-u8og".to_string();
                did_resolve(did, ffi_opts).unwrap();
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }
    }

    #[test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    fn test_did_verify() {
        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                let ffi_opts = ffi_opts_with_port(TEST_FFI_CONFIG, init_http_ephemeral());
                let did = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string();
                did_verify(did, ffi_opts).unwrap();
            }
            Network::Testnet4 => {
                let ffi_opts = ffi_opts_with_port(TESTNET4_TEST_FFI_CONFIG, init_http_ephemeral());
                let did = "did:ion:test:EiBsaims7YMtoe3XYZ-7nQ-CGBGBsZQUIIfTRAh0Mrd8Sw".to_string();
                did_verify(did, ffi_opts).unwrap();
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }
    }

    #[test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    fn test_vc_verify_credential() {
        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                let ffi_opts = ffi_opts_with_port(TEST_FFI_CONFIG, init_http_ephemeral());
                let credential: Credential = serde_json::from_str(TEST_CREDENTIAL).unwrap();
                vc_verify_credential(serde_json::to_string(&credential).unwrap(), ffi_opts)
                    .unwrap();
            }
            Network::Testnet4 => {
                let ffi_opts = ffi_opts_with_port(TESTNET4_TEST_FFI_CONFIG, init_http_ephemeral());
                let credential: Credential =
                    serde_json::from_str(TESTNET4_TEST_CREDENTIAL).unwrap();
                vc_verify_credential(serde_json::to_string(&credential).unwrap(), ffi_opts)
                    .unwrap();
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }
    }

    #[test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    fn test_vc_verify_rss_credential() {
        let ffi_opts = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => ffi_opts_with_port(TEST_FFI_CONFIG_RSS, init_http_ephemeral()),
            Network::Testnet4 => {
                ffi_opts_with_port(TESTNET4_TEST_FFI_CONFIG_RSS, init_http_ephemeral())
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };
        let credential: Credential = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => serde_json::from_str(TEST_CREDENTIAL_RSS).unwrap(),
            Network::Testnet4 => serde_json::from_str(TESTNET4_TEST_CREDENTIAL_RSS).unwrap(),
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };
        vc_verify_credential(serde_json::to_string(&credential).unwrap(), ffi_opts).unwrap();
    }

    #[test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    fn test_vc_redact_rss_credential() {
        let ffi_opts = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => ffi_opts_with_port(TEST_FFI_CONFIG_RSS, init_http_ephemeral()),
            Network::Testnet4 => {
                ffi_opts_with_port(TESTNET4_TEST_FFI_CONFIG_RSS, init_http_ephemeral())
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };
        let credential: Credential = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => serde_json::from_str(TEST_CREDENTIAL_RSS).unwrap(),
            Network::Testnet4 => serde_json::from_str(TESTNET4_TEST_CREDENTIAL_RSS).unwrap(),
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };
        let credential_subject_mask: CredentialSubject = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => serde_json::from_str(TEST_CREDENTIAL_SUBJECT_MASK).unwrap(),
            Network::Testnet4 => {
                serde_json::from_str(TESTNET4_TEST_CREDENTIAL_SUBJECT_MASK).unwrap()
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };
        let derived_vc = vc_redact(
            serde_json::to_string(&credential).unwrap(),
            serde_json::to_string(&credential_subject_mask).unwrap(),
            ffi_opts.clone(),
        )
        .unwrap();
        vc_verify_credential(derived_vc, ffi_opts).unwrap();
    }

    #[test]
    #[ignore = "integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    fn test_vp_issue_presentation() {
        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                let ffi_opts = ffi_opts_with_port(TEST_FFI_CONFIG_RSS, init_http_ephemeral());
                let credential: Credential = serde_json::from_str(TEST_CREDENTIAL).unwrap();
                let root_plus_1_did: &str =
                    "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A";
                let presentation: Presentation = Presentation {
                    verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(
                        credential,
                    ))),
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
            Network::Testnet4 => {
                let ffi_opts = ffi_opts_with_port(TESTNET4_TEST_FFI_CONFIG, init_http_ephemeral());
                let credential: Credential =
                    serde_json::from_str(TESTNET4_TEST_CREDENTIAL).unwrap();
                let root_plus_1_did: &str =
                    "did:ion:test:EiA-CAfMgrNRa2Gv5D8ZF7AazX9nKxnSlYkYViuKeomymw";
                let presentation: Presentation = Presentation {
                    verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(
                        credential,
                    ))),
                    holder: Some(ssi::vc::URI::String(root_plus_1_did.to_string())),
                    ..Default::default()
                };
                let root_plus_1_signing_key: &str = r#"{"kty":"EC","crv":"secp256k1","x":"LHdUjoN7l4TEPrpyumQnDim36faTAbcSKyK7_L8QYpc","y":"kjg9wS4s9W1WQWTl1zDCucqGi-Ho5r8Ne-Hca7TIWuc","d":"h0nN-wziAiuDd5IM6aAkBSCTrQxVAfubMxBplqCmxSU"}"#;
                let presentation = vp_issue_presentation(
                    serde_json::to_string(&presentation).unwrap(),
                    ffi_opts,
                    root_plus_1_signing_key.to_string(),
                );
                println!("{}", presentation.unwrap());
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }
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
        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                let ffi_opts = ffi_opts_with_port(TEST_FFI_CONFIG, init_http_ephemeral());
                vp_verify_presentation(TEST_PRESENTATION.to_string(), ffi_opts).unwrap();
            }
            Network::Testnet4 => {
                let ffi_opts = ffi_opts_with_port(TESTNET4_TEST_FFI_CONFIG, init_http_ephemeral());
                vp_verify_presentation(TESTNET4_TEST_PRESENTATION.to_string(), ffi_opts).unwrap();
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }
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

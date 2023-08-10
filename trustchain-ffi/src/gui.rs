use anyhow::anyhow;
use did_ion::sidetree::DocumentState;
use ssi::did_resolve::ResolutionResult;
use ssi::vc::Credential;
use thiserror::Error;
use tokio::runtime::Runtime;
use trustchain_api::{api::TrustchainDIDAPI, api::TrustchainVCAPI, TrustchainAPI};
use trustchain_core::verifier::VerifierError;
use trustchain_core::{resolver::ResolverError, vc::CredentialError};
use trustchain_ion::{get_ion_resolver, verifier::IONVerifier};

use crate::config::{ffi_config, EndpointOptions};
// TODO: implement the below functions that will be used as FFI on desktop GUI. Aim to implement the
// functions to that they each call a TrustchainCLI method.
//
// NOTE: There is currently an [open pull request](https://github.com/fzyzcjy/flutter_rust_bridge/pull/582)
// for support of the rust Result type which will add the functionality of returning custom error
// types rather than only a custom error message (&str).
#[derive(Error, Debug)]
enum FFIGUIError {
    #[error("JSON Deserialisation Error: {0}.")]
    FailedToDeserialise(serde_json::Error),
    #[error("JSON Deserialisation Error: {1} \n Info: {0}")]
    FailedToDeserialiseVerbose(String, serde_json::Error),
    #[error("DID Create Error: {0}.")]
    FailedToCreateDID(Box<dyn std::error::Error>),
    #[error("dDID Attest Error: {0}.")]
    FailedToAttestdDID(Box<dyn std::error::Error>),
    #[error("DID Resolve Error: {0}.")]
    FailedToResolveDID(ResolverError),
    #[error("DID Verify Error: {0}.")]
    FailedToVerifyDID(VerifierError),
    #[error("DID Verify Credential: {0}.")]
    FailedToVerifyCredential(CredentialError),
}

impl From<CredentialError> for FFIGUIError {
    fn from(err: CredentialError) -> Self {
        Self::FailedToVerifyCredential(err)
    }
}
/// Creates a controlled DID from a passed document state, writing the associated create operation to file in the operations path.
pub fn create(doc_state: Option<String>, verbose: bool) -> anyhow::Result<String> {
    let mut document_state: Option<DocumentState> = None;
    if let Some(doc_string) = doc_state {
        match serde_json::from_str(&doc_string) {
            Ok(doc) => document_state = Some(doc),
            Err(err) => return Err(anyhow!("{}", FFIGUIError::FailedToDeserialise(err))),
        }
    }
    match TrustchainAPI::create(document_state, verbose) {
        Ok(filename) => Ok(filename),
        Err(err) => Err(anyhow!("{}", FFIGUIError::FailedToCreateDID(err))),
    }
}

/// An uDID attests to a dDID, writing the associated update operation to file in the operations path.
pub fn attest(did: String, controlled_did: String, verbose: bool) -> anyhow::Result<()> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        match TrustchainAPI::attest(&did, &controlled_did, verbose).await {
            Ok(_) => Ok(()),
            Err(err) => Err(anyhow!("{}", FFIGUIError::FailedToAttestdDID(err))),
        }
    })
}

/// Resolves a given DID using a resolver available at "ion_endpoint"
pub fn resolve(did: String) -> anyhow::Result<String> {
    let resolver_address = if let Some(ion_endpoint) = &ffi_config().endpoint_options {
        ion_endpoint.ion_endpoint().to_address()
    } else {
        EndpointOptions::default().ion_endpoint().to_address()
    };
    let resolver = get_ion_resolver(&resolver_address);
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        match TrustchainAPI::resolve(&did, &resolver).await {
            Ok((res_meta, doc, doc_meta)) => Ok(serde_json::to_string_pretty(
                // TODO: refactor conversion into trustchain-core resolve module
                &ResolutionResult {
                    context: Some(serde_json::Value::String(
                        "https://w3id.org/did-resolution/v1".to_string(),
                    )),
                    did_document: doc,
                    did_resolution_metadata: Some(res_meta),
                    did_document_metadata: doc_meta,
                    property_set: None,
                },
            )
            .expect("Serialise implimented for ResolutionResult struct")),
            Err(err) => Err(anyhow!("{}", FFIGUIError::FailedToResolveDID(err))),
        }
    })
}

/// TODO: the below have no CLI implementation currently but are planned
/// Verifies a given DID using a resolver available at "ion_endpoint", returning a result.
pub fn verify(did: String) -> anyhow::Result<String> {
    let resolver_address = if let Some(ion_endpoint) = &ffi_config().endpoint_options {
        ion_endpoint.ion_endpoint().to_address()
    } else {
        EndpointOptions::default().ion_endpoint().to_address()
    };
    let resolver = get_ion_resolver(&resolver_address);
    let verifier = IONVerifier::new(resolver);
    let root_event_time = &ffi_config().trustchain().unwrap().root_event_time;
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        match TrustchainAPI::verify(&did, *root_event_time, &verifier).await {
            Ok(did_chain) => Ok(serde_json::to_string_pretty(&did_chain)
                .expect("Serialise implimented for DIDChain struct")),
            Err(err) => Err(anyhow!("{}", FFIGUIError::FailedToVerifyDID(err))),
        }
    })
}
/// Generates an update operation and writes to operations path.
fn update(did: String, controlled_did: String, verbose: bool) -> anyhow::Result<()> {
    todo!()
}
/// Generates a recover operation and writes to operations path.
fn recover(did: String, verbose: bool) -> anyhow::Result<()> {
    todo!()
}
/// Generates a deactivate operation and writes to operations path.
fn deactivate(did: String, verbose: bool) -> anyhow::Result<()> {
    todo!()
}
/// Publishes operations within the operations path (queue).
fn publish(did: String, verbose: bool) -> anyhow::Result<()> {
    todo!()
}

pub fn vc_sign(
    serial_credential: String,
    did: String,
    key_id: Option<String>,
    // TODO handle optional LinkedDataProofOptions either from gui input, or using existing config
) -> anyhow::Result<String> {
    let resolver_address = if let Some(ion_endpoint) = &ffi_config().endpoint_options {
        ion_endpoint.ion_endpoint().to_address()
    } else {
        EndpointOptions::default().ion_endpoint().to_address()
    };
    let resolver = get_ion_resolver(&resolver_address);
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let mut credential: Credential;
        match serde_json::from_str(&serial_credential) {
            Ok(cred) => credential = cred,
            Err(err) => return Err(anyhow!("{}", FFIGUIError::FailedToDeserialise(err))),
        }
        credential = TrustchainAPI::sign(
            credential,
            &did,
            // TODO accept Some LinkedDataProofOptions
            None,
            key_id.as_ref().map(|x| &**x),
            &resolver,
        )
        .await?;
        Ok(serde_json::to_string_pretty(&credential)
            .expect("Serialise implimented for Credential struct"))
    })
}

pub fn vc_verify(serial_credential: String) -> anyhow::Result<String> {
    let resolver_address = if let Some(ion_endpoint) = &ffi_config().endpoint_options {
        ion_endpoint.ion_endpoint().to_address()
    } else {
        EndpointOptions::default().ion_endpoint().to_address()
    };
    let resolver = get_ion_resolver(&resolver_address);
    let root_event_time = &ffi_config().trustchain().unwrap().root_event_time;
    let rt = Runtime::new().unwrap();
    let credential: Credential;
    match serde_json::from_str(&serial_credential) {
        Ok(cred) => credential = cred,
        Err(err) => return Err(anyhow!("{}", FFIGUIError::FailedToDeserialise(err))),
    }
    rt.block_on(async {
        match TrustchainAPI::verify_credential(
            &credential,
            None,
            *root_event_time,
            &IONVerifier::new(resolver),
        )
        .await
        {
            Ok(did_chain) => Ok(serde_json::to_string_pretty(&did_chain)
                .expect("Serialise implimented for DIDChain struct")),
            Err(err) => Err(anyhow!("{}", FFIGUIError::FailedToVerifyCredential(err))),
        }
        // let did_chain = TrustchainAPI::verify_credential(
        //     &credential,
        //     None,
        //     *root_event_time,
        //     &IONVerifier::new(resolver),
        // )
        // .await?;
        // Ok(serde_json::to_string_pretty(&did_chain).unwrap())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use trustchain_core::TRUSTCHAIN_DATA;

    const TEST_CREDENTIAL: &str = r##"
    {
    "@context" : [
       "https://www.w3.org/2018/credentials/v1",
       "https://schema.org/"
    ],
    "credentialSubject" : {
       "address" : {
          "addressCountry" : "UK",
          "addressLocality" : "London",
          "postalCode" : "SE1 3WY",
          "streetAddress" : "10 Main Street"
       },
       "birthDate" : "1989-03-15",
       "name" : "J. Doe"
    },
    "id" : "http://example.edu/credentials/332",
    "issuanceDate" : "2020-08-19T21:41:50Z",
    "issuer" : "did:key:z6MkpbgE27YYYpSF8hd7ipazeJxiUGMEzQFT5EgN46TDwAeU",
    "type" : [
       "VerifiableCredential",
       "IdentityCredential"
    ]
 }"##;

    #[test]
    fn test_resolve() {
        assert!(
            resolve("did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string())
                .is_ok()
        );
    }

    #[test]
    fn test_create() {
        let did = create(None, false).unwrap();
        assert!(fs::read_to_string(
            std::env::var(TRUSTCHAIN_DATA).unwrap() + &format!("/operations/{did}")
        )
        .is_ok());
    }

    #[test]
    fn test_verify() {
        assert!(
            verify("did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string())
                .is_ok()
        );
    }

    #[test]
    fn test_sign_vc() {
        let cred = String::from(TEST_CREDENTIAL);
        assert!(vc_sign(
            cred,
            String::from("did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"),
            None
        )
        .is_ok())
    }

    #[test]
    fn test_verify_credential() {
        let vc_string = vc_sign(
            String::from(TEST_CREDENTIAL),
            String::from("did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"),
            None,
        )
        .unwrap();
        let verification = vc_verify(vc_string);
        assert!(verification.is_ok());
    }
}

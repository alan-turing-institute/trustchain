use anyhow::anyhow;
use did_ion::sidetree::DocumentState;
use ssi::did_resolve::ResolutionResult;
use ssi::vc::Credential;
use thiserror::Error;
use tokio::runtime::Runtime;
use trustchain_api::{api::TrustchainDIDAPI, api::TrustchainVCAPI, TrustchainAPI};
use trustchain_core::resolver::ResolverError;
use trustchain_core::verifier::VerifierError;
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

/// Resolves a given DID using a resolver available at localhost:3000
pub fn resolve(did: String) -> anyhow::Result<String> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        // let (res_meta, doc, doc_meta) = TrustchainAPI::resolve(&did, "http://localhost:3000/".into())?;
        match TrustchainAPI::resolve(&did, "http://localhost:3000/".into()).await {
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
/// Verifies a given DID using a resolver available at localhost:3000, returning a result.
pub fn verify(did: String) -> anyhow::Result<String> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        match TrustchainAPI::verify(&did).await {
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
) -> anyhow::Result<String> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        // TODO: handle optional key_id
        let mut credential: Credential;
        match serde_json::from_str(&serial_credential) {
            Ok(cred) => credential = cred,
            Err(err) => return Err(anyhow!("{}", FFIGUIError::FailedToDeserialise(err))),
        }
        credential = TrustchainAPI::sign(credential, &did, None).await;
        Ok(serde_json::to_string_pretty(&credential)
            .expect("Serialise implimented for Credential struct"))
    })
}

// pub fn vc_verify(serial_credential: String, signature_only: bool, root_event_time: u32) -> anyhow::Result<String> {

// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolution() {
        println!(
            "{}",
            resolve("did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string())
                .unwrap()
        );
    }
}

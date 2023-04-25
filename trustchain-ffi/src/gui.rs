use anyhow::anyhow;
use did_ion::sidetree::DocumentState;
use serde_json::to_string_pretty;
use ssi::did_resolve::ResolutionResult;
use thiserror::Error;
use trustchain_api::{api::TrustchainDIDAPI, TrustchainAPI};
use trustchain_core::chain::DIDChain;
use trustchain_core::verifier::Verifier;
use trustchain_ion::{get_ion_resolver, verifier::IONVerifier};

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
    #[error("Failed to deserialise: {1} \n Info: {0}")]
    FailedToDeserialiseVerbose(String, serde_json::Error),
}
/// Creates a controlled DID from a passed document state, writing the associated create operation to file in the operations path.
pub fn create(doc_state: Option<String>, verbose: bool) -> anyhow::Result<()> {
    let mut document_state: Option<DocumentState> = None;
    if let Some(doc_string) = doc_state {
        match serde_json::from_str(&doc_string) {
            Ok(doc) => document_state = Some(doc),
            // Err(err) => return Err(FFIGUIError::FailedToDeserialise(err).into()),
            Err(err) => {
                return Err(anyhow!(
                    "{}",
                    FFIGUIError::FailedToDeserialise(err).to_string()
                ))
            }
        }
        // document_state = Some(serde_json::from_str(&doc_string).unwrap())
    }
    match TrustchainAPI::create(document_state, verbose) {
        Ok(_) => Ok(()),
        Err(err) => Err(anyhow!("{err}")),
    }
}

/// An uDID attests to a dDID, writing the associated update operation to file in the operations path.
pub fn attest(did: String, controlled_did: String, verbose: bool) -> anyhow::Result<()> {
    match TrustchainAPI::attest(&did, &controlled_did, verbose) {
        Ok(_) => Ok(()),
        Err(err) => Err(anyhow!("{err}")),
    }
}
/// Resolves a given DID using a resolver available at localhost:3000
pub fn resolve(did: String) -> anyhow::Result<String> {
    let (res_meta, doc, doc_meta) = TrustchainAPI::resolve(&did, "http://localhost:3000/".into())?;
    // TODO: refactor conversion into trustchain-core resolve module
    Ok(serde_json::to_string_pretty(&ResolutionResult {
        context: Some(serde_json::Value::String(
            "https://w3id.org/did-resolution/v1".to_string(),
        )),
        did_document: doc,
        did_resolution_metadata: Some(res_meta),
        did_document_metadata: doc_meta,
        property_set: None,
    })?)
}

/// TODO: the below have no CLI implementation currently but are planned
/// Verifies a given DID using a resolver available at localhost:3000, returning a result.
pub fn verify(did: String, verbose: bool) -> anyhow::Result<String> {
    match TrustchainAPI::verify(&did) {
        Ok(did_chain) => Ok(serde_json::to_string_pretty(&did_chain)
            .expect("Serialize implimented for DIDChain struct")),
        Err(err) => Err(anyhow!("{err}")),
    }
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

use serde_json::to_string_pretty;
use ssi::did_resolve::ResolutionResult;
use tokio::runtime::Runtime;
use trustchain_api::{api::TrustchainDIDAPI, TrustchainAPI};
use trustchain_core::chain::DIDChain;
use trustchain_core::verifier::Verifier;
use trustchain_ion::{get_ion_resolver, verifier::IONVerifier};

/// Example greet function.
pub fn greet() -> String {
    "Hello from Rust! 🦀".into()
}

/// Example resolve interface.
pub fn resolve_prototype(did: String) -> String {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        // Trustchain Resolver with android localhost
        let resolver = get_ion_resolver("http://127.0.0.1:3000/");
        // Result metadata, Document, Document metadata
        let (_, doc, _) = resolver.resolve_as_result(&did).await.unwrap();
        to_string_pretty(&doc.unwrap()).expect("Cannot convert to JSON.")
    })
}

//"did:ion:test:EiCzekHARUPkqf0NRsQ6kfpcnEbwtpdTIgadTYWaggx8Rg"
// ROOT_EVENT_TIME_2378493
pub fn verify_prototype(did: String, root_timestamp: u32) -> DIDChain {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
        let resolver = get_ion_resolver("http://localhost:3000/");
        let verifier = IONVerifier::new(resolver);

        verifier.verify(&did, root_timestamp).await.unwrap()
    })
}

// TODO: implement the below functions that will be used as FFI on desktop GUI. Aim to implement the
// functions to that they each call a TrustchainCLI method.
//
// NOTE: There is currently an [open pull request](https://github.com/fzyzcjy/flutter_rust_bridge/pull/582)
// for support of the rust Result type which will add the functionality of returning custom error
// types rather than only a custom error message (&str).

/// Creates a controlled DID from a passed document state, writing the associated create operation to file in the operations path.
fn create(document_state: Option<String>, verbose: bool) -> anyhow::Result<()> {
    todo!()
}

/// An uDID attests to a dDID, writing the associated update operation to file in the operations path.
fn attest(did: String, controlled_did: String, verbose: bool) -> anyhow::Result<()> {
    todo!()
}
/// Resolves a given DID using a resolver available at localhost:3000
fn resolve(did: String, verbose: bool) -> anyhow::Result<String> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let (res_meta, doc, doc_meta) =
            TrustchainAPI::resolve(&did, "http://localhost:3000/".into()).await?;
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
    })
}

/// TODO: the below have no CLI implementation currently but are planned
/// Verifies a given DID using a resolver available at localhost:3000, returning a result.
fn verify(did: String, verbose: bool) -> anyhow::Result<DIDChain> {
    todo!()
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

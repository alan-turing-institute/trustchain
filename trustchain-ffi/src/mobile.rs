use std::path::PathBuf;

use anyhow::{anyhow, Result};
use serde_json::to_string_pretty;
use tokio::runtime::Runtime;
use trustchain_api::{api::TrustchainDIDAPI, TrustchainAPI};
use trustchain_ion::get_ion_resolver;
use trustchain_spv::{get_block, initialize};

/// Android localhost endpoint.
const ANDROID_ENDPOINT: &str = "http://10.0.2.2:3000/";

/// Example greet function.
pub fn greet() -> String {
    "Hello from Rust! 🦀".into()
}

// TODO: update to use TrustchainCLI once endpoint can be passed
/// Example resolve interface.
pub fn resolve(did: String) -> Result<String> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        // Trustchain Resolver with android localhost
        let resolver = get_ion_resolver(ANDROID_ENDPOINT);
        // Result metadata, Document, Document metadata
        let (_, doc, _) = resolver.resolve_as_result(&did).await.unwrap();
        Ok(to_string_pretty(&doc.unwrap())?)
    })
}

/// Resolves a given DID document assuming trust in endpoint.
pub fn did_resolve(did: String) -> Result<String> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        // Trustchain Resolver with android localhost
        TrustchainAPI::resolve(&did, ANDROID_ENDPOINT.into())
            .await
            .map_err(|e| anyhow!(e))
            .and_then(|(_, doc, _)| serde_json::to_string_pretty(&doc).map_err(|e| anyhow!(e)))
    })
}
/// Verifies a given DID assuming trust in endpoint.
pub fn did_verify(did: String) -> Result<String> {
    todo!()
}
/// Verifies a given DID bundle providing complete verification without trust in endpoint.
pub fn did_verify_bundle(bundle_json: String) -> Result<String> {
    todo!()
}
/// Verifies a verifiable credential. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_verify_credential.html).
pub fn vc_verify_credential(credential_json: String, proof_options_json: String) -> Result<String> {
    todo!()
}
/// Issues a verifiable presentation. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_issue_presentation.html).
pub fn vc_issue_presentation(
    presentation_json: String,
    proof_options_json: String,
    key_json: String,
) {
    todo!()
}
/// Verifies a verifiable presentation. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_verify_presentation.html).
pub fn vc_verify_presentation(
    presentation_json: String,
    proof_options_json: String,
) -> Result<String> {
    todo!()
}

/// Initializes the light Bitcoin node.
pub fn spv_initialize(path: String, testnet: bool) -> Result<()> {
    initialize(PathBuf::from(path), testnet)?;
    Ok(())
}

/// Gets a block header and height from the Bitcoin light client running locally.
pub fn spv_get_block(hash: String, path: String, testnet: bool) -> Result<String> {
    let (height, header) = get_block(PathBuf::from(path), testnet, &hash)?;
    Ok(to_string_pretty(&(height, header))?)
}

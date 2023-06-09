use anyhow::{anyhow, Result};
use serde_json::to_string_pretty;
use ssi::vc::Credential;
use tokio::runtime::Runtime;
use trustchain_api::{
    api::{TrustchainDIDAPI, TrustchainVCAPI},
    TrustchainAPI,
};
use trustchain_core::{config::core_config, verifier::Verifier};
use trustchain_ion::{get_ion_resolver, verifier::IONVerifier};

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
pub fn did_verify(did: String, endpoint: String) -> Result<()> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        // Trustchain Resolver with android localhost
        let mut verifier = IONVerifier::new(get_ion_resolver(ANDROID_ENDPOINT));
        verifier.fetch_bundle(&did, Some(endpoint));
        verifier
            .verify(&did, core_config().root_event_time)
            .await
            .map_err(|err| anyhow!(err.to_string()));
        Ok(())
    })
}
/// Verifies a given DID bundle providing complete verification without trust in endpoint.
pub fn did_verify_bundle(bundle_json: String) -> Result<String> {
    todo!()
}
/// Verifies a verifiable credential. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_verify_credential.html).
pub fn vc_verify_credential(credential_json: String, proof_options_json: String) -> Result<String> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let credential: Credential = serde_json::from_str(&credential_json).unwrap();
        let (verify_result, did_chain) =
            TrustchainAPI::verify_credential(&credential, false, core_config().root_event_time)
                .await;
        if verify_result.errors.is_empty() {
        } else {
            return Err(anyhow!("Invalid signature"));
        }
        if let Some(did_chain) = did_chain {
            if did_chain.is_ok() {
                Ok("OK".to_string())
            } else {
                Err(anyhow!("Invalid DID chain of issuer."))
            }
        } else {
            Err(anyhow!("No DID chain returned, failed to verify issuer."))
        }
    })
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

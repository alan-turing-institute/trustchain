use serde_json::to_string_pretty;
use trustchain_ion::get_ion_resolver;

/// Example greet function.
pub fn greet() -> String {
    "Hello from Rust! 🦀".into()
}

// TODO: update to use TrustchainCLI once endpoint can be passed
/// Example resolve interface.
pub fn resolve(did: String) -> String {
    // Trustchain Resolver with android localhost
    let resolver = get_ion_resolver("http://10.0.2.2:3000/");
    // Result metadata, Document, Document metadata
    let (_, doc, _) = resolver.resolve_as_result(&did).unwrap();
    to_string_pretty(&doc.unwrap()).expect("Cannot convert to JSON.")
}

/// Resolves a given DID assuming trust in endpoint.
fn did_resolve(did: String) -> String {
    todo!()
}
/// Verifies a given DID assuming trust in endpoint.
fn did_verify(did: String) -> String {
    todo!()
}
/// Verifies a given DID bundle providing complete verification without trust in endpoint.
fn did_verify_bundle(bundle_json: String) -> String {
    todo!()
}
/// Verifies a verifiable credential. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_verify_credential.html).
fn vc_verify_credential(credential_json: String, proof_options_json: String) -> String {
    todo!()
}
/// Issues a verifiable presentation. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_issue_presentation.html).
fn vc_issue_presentation(presentation_json: String, proof_options_json: String, key_json: String) {
    todo!()
}
/// Verifies a verifiable presentation. Analogous with [didkit](https://docs.rs/didkit/latest/didkit/c/fn.didkit_vc_verify_presentation.html).
fn vc_verify_presentation(presentation_json: String, proof_options_json: String) -> String {
    todo!()
}

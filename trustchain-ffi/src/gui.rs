use serde_json::to_string_pretty;
use trustchain_core::chain::DIDChain;
use trustchain_core::verifier::Verifier;
use trustchain_ion::{get_ion_resolver, verifier::IONVerifier};
// use trustchain_core::{ROOT_EVENT_TIME, ROOT_EVENT_TIME_2378493};

/// Example greet function.
pub fn greet() -> String {
    "Hello from Rust! 🦀".into()
}

/// Example resolve interface.
pub fn resolve(did: String) -> String {
    // Trustchain Resolver with android localhost
    let resolver = get_ion_resolver("http://127.0.0.1:3000/");
    // Result metadata, Document, Document metadata
    let (_, doc, _) = resolver.resolve_as_result(&did).unwrap();
    to_string_pretty(&doc.unwrap()).expect("Cannot convert to JSON.")
}

//"did:ion:test:EiCzekHARUPkqf0NRsQ6kfpcnEbwtpdTIgadTYWaggx8Rg"
// ROOT_EVENT_TIME_2378493
pub fn verify(did: String, root_timestamp: u32) -> DIDChain {
    // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
    let resolver = get_ion_resolver("http://localhost:3000/");
    let verifier = IONVerifier::new(resolver);

    verifier.verify(&did, root_timestamp).unwrap()
}

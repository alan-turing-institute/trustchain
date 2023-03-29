use serde_json::to_string_pretty;
use trustchain_ion::get_ion_resolver;

/// Example greet function.
pub fn greet() -> String {
    "Hello from Rust! 🦀".into()
}

/// Example resolve interface.
pub fn resolve(did: String) -> String {
    // Trustchain Resolver with android localhost
    let resolver = get_ion_resolver("http://10.0.2.2:3000/");
    // Result metadata, Document, Document metadata
    let (_, doc, _) = resolver.resolve_as_result(&did).unwrap();
    to_string_pretty(&doc.unwrap()).expect("Cannot convert to JSON.")
}

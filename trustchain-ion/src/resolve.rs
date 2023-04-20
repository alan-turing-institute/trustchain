use did_ion::{sidetree::SidetreeClient, ION};
use serde_json::to_string_pretty as to_json;

use crate::IONResolver;

// Binary to resolve a passed DID from the command line.
pub async fn main_resolve(did: &str, _verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
    let resolver = IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(
        "http://localhost:3000/",
    ))));

    // Result metadata, Document, Document metadata
    let result = resolver.resolve_as_result(did).await;
    let (res_meta, doc, doc_meta) = match result {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return Err(Box::new(e));
        }
    };

    // Print results
    println!("---");
    println!("Trustchain resolved document, document metadata and resolution metadata");
    println!("---");
    println!("Document:");
    let doc_json = &doc.as_ref().unwrap();
    println!("{}", to_json(&doc_json).expect("Cannot convert to JSON."));
    println!("---");
    println!("Document metadata:");
    let doc_meta_json = &doc_meta.unwrap();
    println!(
        "{}",
        to_json(&doc_meta_json).expect("Cannot convert to JSON.")
    );
    println!("---");
    println!("Result metadata (canonicalized):");
    let result_meta_json = &res_meta;
    println!(
        "{}",
        to_json(&result_meta_json).expect("Cannot convert to JSON.")
    );
    Ok(())
}

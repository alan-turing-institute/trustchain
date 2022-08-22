use did_ion::sidetree::Sidetree;
use did_ion::ION;
// use serde_json::{to_string_pretty as to_json, Map, Value};

use trustchain::resolver::Resolver;

fn main() {
    // Make Trsutchain resolver
    let resolver: Resolver = Resolver::new();

    // DID to resolve
    let example_did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ";

    // Result metadata, Document, Document metadata
    let (res_meta, doc, doc_meta) = resolver.resolve(example_did);

    // Print results
    println!("---");
    println!("Document (canonicalized):");
    let doc_json =
        ION::json_canonicalization_scheme(&doc.as_ref().unwrap()).expect("Canonicalized Doc JSON");
    println!("{}", doc_json);
    println!("---");
    println!("Document (Trustchain canonicalized):");
    let trustchain_doc = resolver.convert_to_trustchain(doc.clone().unwrap());
    let trustchain_doc_json =
        ION::json_canonicalization_scheme(&trustchain_doc).expect("Canonicalized Doc JSON");
    println!("{}", trustchain_doc_json);
    println!("---");
    println!("Document metadata (canonicalized):");
    let doc_meta_json = ION::json_canonicalization_scheme(&doc_meta.unwrap())
        .expect("Canonicalized Doc Metadata JSON");
    println!("{}", doc_meta_json);
    println!("---");
    println!("Result metadata (canonicalized):");
    let result_meta_json =
        ION::json_canonicalization_scheme(&res_meta).expect("Canonicalized Result Metadata JSON");
    println!("{}", result_meta_json);
}

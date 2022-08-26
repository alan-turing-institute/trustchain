use did_ion::sidetree::Sidetree;
use did_ion::ION;
// use serde_json::{to_string_pretty as to_json, Map, Value};
use clap::{arg, command, value_parser, Arg, ArgAction};
use trustchain::resolver::Resolver;

fn main() {
    let matches = command!()
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!(-i --input <INPUT>)
                .default_value("did:ion:test:EiA8yZGuDKbcnmPRs9ywaCsoE2FT9HMuyD9WmOiQasxBBg")
                .required(false),
        )
        .get_matches();

    // Make Trsutchain resolver
    let resolver: Resolver = Resolver::new();

    // Get DID from clap
    let did_to_resolve = matches.get_one::<String>("input").unwrap();
    // Previous
    // let did_to_resolve = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ";

    // Result metadata, Document, Document metadata
    let (res_meta, doc, doc_meta) = resolver.resolve(did_to_resolve);

    // Print results
    println!("---");
    println!("Document (canonicalized):");
    let doc_json =
        ION::json_canonicalization_scheme(&doc.as_ref().unwrap()).expect("Canonicalized Doc JSON");
    println!("{}", doc_json);
    println!("---");
    println!("Document (Trustchain canonicalized):");
    let trustchain_doc = resolver.ion_to_trustchain_doc(&doc.clone().unwrap(), did_to_resolve);
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

use clap::{arg, command, Arg, ArgAction};
use did_ion::{sidetree::SidetreeClient, ION};
use serde_json::to_string_pretty as to_json;
use trustchain_core::resolver::{DIDMethodWrapper, Resolver};

// Type aliases
pub type IONResolver = Resolver<DIDMethodWrapper<SidetreeClient<ION>>>;

// Binary to resolve a passed DID from the command line.
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

    // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
    let resolver = IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(
        "http://localhost:3000/",
    ))));

    // Get DID from clap
    let did_to_resolve = matches.get_one::<String>("input").unwrap();

    // Result metadata, Document, Document metadata
    let result = resolver.resolve_as_result(did_to_resolve);
    let (res_meta, doc, doc_meta) = match result {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return;
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
}

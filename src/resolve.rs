use clap::{arg, command, Arg, ArgAction};
use did_ion::ION;
use serde_json::to_string_pretty as to_json;
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
    let resolver: Resolver<ION> = Resolver::<ION>::new();

    // Get DID from clap
    let did_to_resolve = matches.get_one::<String>("input").unwrap();
    // Previous
    // let did_to_resolve = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ";

    // Result metadata, Document, Document metadata
    let result = resolver.resolve(did_to_resolve);
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
    // let doc_json = json!(&ION::json_canonicalization_scheme(&doc.as_ref().unwrap()).expect("Canonicalized Doc JSON"));
    let doc_json = &doc.as_ref().unwrap();
    println!("{}", to_json(&doc_json).expect("Cannot convert to JSON."));
    println!("---");
    println!("Document metadata:");
    // let doc_meta_json = ION::json_canonicalization_scheme(&doc_meta.unwrap())
    let doc_meta_json = &doc_meta.unwrap();
    println!(
        "{}",
        to_json(&doc_meta_json).expect("Cannot convert to JSON.")
    );
    println!("---");
    println!("Result metadata (canonicalized):");
    // let result_meta_json =
    // ION::json_canonicalization_scheme(&res_meta).expect("Canonicalized Result Metadata JSON");
    let result_meta_json = &res_meta;
    println!(
        "{}",
        to_json(&result_meta_json).expect("Cannot convert to JSON.")
    );
}

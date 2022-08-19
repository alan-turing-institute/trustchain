use did_ion::sidetree::{
    DIDStatePatch, DIDSuffix, DocumentState, Operation, PublicKeyEntry, PublicKeyJwk,
    ServiceEndpointEntry, Sidetree, SidetreeClient, SidetreeDID, SidetreeOperation,
};
use did_ion::ION;

use futures::executor::block_on;
use serde_json::{to_string_pretty as to_json, Map, Value};
use ssi::did::{self, Document, ServiceEndpoint};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
};
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use std::convert::TryFrom;
use std::fmt::format;
use std::fs::{read, write};
use std::thread::sleep;
use std::time::Duration;
use tokio::runtime::Runtime;

async fn http_resolve(
    did_short: &String,
    ion_client: &SidetreeClient<ION>,
) -> (
    ResolutionMetadata,
    Option<Document>,
    Option<DocumentMetadata>,
) {
    // let resolver = ion_client.resolver.unwrap();
    let resolver = ion_client.resolver.as_ref().unwrap();
    let (res_meta, doc, doc_meta) = resolver
        .resolve(&did_short[..], &ResolutionInputMetadata::default())
        .await;

    return (res_meta, doc, doc_meta);
}

// struct Resolver {
//     runtime: Runtime,
//     ion_server_uri: String,
//     ion_client: SidetreeClient::<ION>
// }

// impl Resolver {
//     pub fn new () -> Self {
//          // Make runtime
//         let rt = tokio::runtime::Builder::new_multi_thread()
//         .enable_all()
//         .build()
//         .unwrap();

//     }
// }

fn main() {
    // Make runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        // Set-up ION server URI at localhost given port forwarding from ION server
        let ion_server_uri: &str = "http://localhost:3000/";
        let ion_client = SidetreeClient::<ION>::new(Some(ion_server_uri.to_string()));

        // Example DID to resolve
        let did_short = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ";

        let (res_meta, doc, doc_meta) = loop {
            // Do resolve and extract data from future

            let tup = block_on(http_resolve(&did_short.to_string(), &ion_client));
            if tup.1.is_some() {
                break tup;
            }
            sleep(Duration::new(1, 0));
            println!("Trying again...");
        };

        // Print results
        println!("Document (canonicalized):");
        let doc_json =
            ION::json_canonicalization_scheme(&doc.unwrap()).expect("Canonicalized Doc JSON");
        println!("{}", doc_json);
        println!("Document metadat (canonicalized):");
        let doc_meta_json = ION::json_canonicalization_scheme(&doc_meta.unwrap())
            .expect("Canonicalized Doc Metadata JSON");
        println!("{}", doc_meta_json);
        println!("Result metadata (canonicalized):");
        let result_meta_json = ION::json_canonicalization_scheme(&res_meta)
            .expect("Canonicalized Result Metadata JSON");
        println!("{}", result_meta_json);
    });
}

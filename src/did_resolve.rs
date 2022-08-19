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

use trustchain::resolver::Resolver;

fn get_proof_idx(doc: &Document) -> Option<usize> {
    // Get index of proof
    let fragment = "controller-proof";

    // let service = doc.select_service(fragment).clone();
    // println!("{:?}", service);
    // println!("{:#?}", doc);

    for (idx, service) in doc.service.iter().flatten().enumerate() {
        if let [service_fragment, _] = service.id.rsplitn(2, '#').collect::<Vec<&str>>().as_slice()
        {
            if service_fragment == &fragment {
                return Some(idx);
            }
        }
    }
    None
}

fn convert_to_trustchain(mut doc: Document) -> Document {
    // Check if the Trustchain proof service exists in document
    // https://docs.rs/ssi/latest/ssi/did/struct.Document.html#method.select_service
    // https://docs.rs/ssi/latest/src/ssi/did.rs.html#1251-1262

    if doc.service.is_some() {
        if let Some(idx) = get_proof_idx(&doc) {
            let services = doc.service.as_mut().unwrap();
            services.remove(idx);
            if services.len() == 0 {
                doc.service = None;
            }
        }
    }
    doc
}

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
    let trustchain_doc = convert_to_trustchain(doc.clone().unwrap());
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

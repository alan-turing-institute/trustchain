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

fn main() {
    // Make Trsutchain resolver
    let resolver: Resolver = Resolver::new();

    let example_did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ";
    let (res_meta, doc, doc_meta) = resolver.resolve(example_did);

    //   Print results
    println!("Document (canonicalized):");
    let doc_json =
        ION::json_canonicalization_scheme(&doc.unwrap()).expect("Canonicalized Doc JSON");
    println!("{}", doc_json);
    println!("Document metadat (canonicalized):");
    let doc_meta_json = ION::json_canonicalization_scheme(&doc_meta.unwrap())
        .expect("Canonicalized Doc Metadata JSON");
    println!("{}", doc_meta_json);
    println!("Result metadata (canonicalized):");
    let result_meta_json =
        ION::json_canonicalization_scheme(&res_meta).expect("Canonicalized Result Metadata JSON");
    println!("{}", result_meta_json);
}

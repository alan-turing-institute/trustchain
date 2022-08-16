use did_ion::sidetree::{
    DIDStatePatch, DIDSuffix, DocumentState, Operation, PublicKeyEntry, PublicKeyJwk,
    ServiceEndpointEntry, Sidetree, SidetreeClient, SidetreeDID, SidetreeOperation,
};
use did_ion::ION;

use futures::executor;
use serde_json::{to_string_pretty as to_json, Map, Value};
use ssi::did::{self, Document, ServiceEndpoint};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
};
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use std::convert::TryFrom;
use std::fmt::format;
use std::fs::{read, write};

async fn http_resolve(
    did_short: &String,
    ion_client: SidetreeClient<ION>,
) -> (
    ResolutionMetadata,
    Option<Document>,
    Option<DocumentMetadata>,
) {
    let resolver = ion_client.resolver.unwrap();
    let (res_meta, doc, doc_meta) = resolver
        .resolve(&did_short[..], &ResolutionInputMetadata::default())
        .await;

    return (res_meta, doc, doc_meta);
}

#[tokio::main]
async fn main() {
    // Set-up ION server URI at localhost given port forwarding from ION server
    let ion_server_uri: &str = "http://localhost:3000/";
    let ion_client = SidetreeClient::<ION>::new(Some(ion_server_uri.to_string()));

    // Example DID to resolve
    let did_short = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ";

    // Do resolve and extract data from future
    let (res_meta, doc, doc_meta) =
        executor::block_on(http_resolve(&did_short.to_string(), ion_client));

    println!("Document:");
    println!("{:?}", doc.unwrap());
    println!("Document metadata:");
    println!("{:?}", doc_meta.unwrap());
    println!("Result metadata:");
    println!("{:?}", res_meta);
}

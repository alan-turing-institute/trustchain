use core::panic;

use ssi::did_resolve::Metadata;
use ssi::one_or_many::OneOrMany;

use did_ion::{sidetree::SidetreeClient, ION};
use trustchain_core::resolver::{DIDMethodWrapper, Resolver};

// Type aliases
pub type IONResolver = Resolver<DIDMethodWrapper<SidetreeClient<ION>>>;

pub fn test_resolver(endpoint: &str) -> IONResolver {
    IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(endpoint))))
}

#[test]
#[ignore] // Requires a running Sidetree node listening on http://localhost:3000.
fn trustchain_resolution() {
    // Integration test of the Trustchain resolution pipeline.

    let did = "did:ion:test:EiA8yZGuDKbcnmPRs9ywaCsoE2FT9HMuyD9WmOiQasxBBg";

    // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
    let resolver = test_resolver("http://localhost:3000/");

    // Resolve DID Document & Metadata.
    let result = resolver.resolve_as_result(did);

    // Check the result is not an error.
    // If this fails, make sure the Sidetree server is up and listening on the above URL endpoint.
    assert!(result.is_ok());

    let (_res_meta, doc, doc_meta) = result.unwrap();

    // Check the DID Document and Metadata were successfully resolved.
    assert!(doc.is_some());
    assert!(doc_meta.is_some());

    let doc = doc.unwrap();
    let doc_meta = doc_meta.unwrap();

    // Check the subject's DID is in the DID Document (id propery).
    assert_eq!(doc.id, did);
    // Check the controller's DID is in the DID Document (controller property).
    // TODO: update the DID Document used for this test to contain distinct DIDs for subject & controller.
    // TODO: update the controller property value in the DID document to contain the whole DID including prefix "did:ion:test:"
    assert_eq!(
        doc.controller,
        Some(OneOrMany::One(String::from(&did[13..])))
    );
    // Check the proof service is *not* found in the DID Document.
    assert!(doc.service.is_none());

    // Check the proof is in the DID Document Metadata.
    assert!(doc_meta.property_set.is_some());
    let doc_meta_properties = doc_meta.property_set.unwrap();
    assert!(doc_meta_properties.contains_key("proof"));

    // Get the properties inside the proof.
    let proof_properties = match doc_meta_properties.get("proof").unwrap() {
        Metadata::Map(m) => m,
        _ => panic!(),
    };

    // Check the proof property contains id, type and proofValue properties.
    assert!(proof_properties.contains_key("id"));
    assert!(proof_properties.contains_key("type"));
    assert!(proof_properties.contains_key("proofValue"));

    // Check the value of the type property.
    let actual_type = match proof_properties.get("type").unwrap() {
        Metadata::String(s) => s,
        _ => panic!(),
    };
    assert_eq!(actual_type, &String::from("JsonWebSignature2020"));

    // Check the value of the id property (inside the proof) matches the controller's DID.
    let actual_proof_id = match proof_properties.get("id").unwrap() {
        Metadata::String(s) => s,
        _ => panic!(),
    };
    // TODO: update the DID Document used for this test to contain distinct DIDs for subject & controller.
    // TODO: update the controller property value in the DID document to contain the whole DID including prefix "did:ion:test:"
    assert_eq!(actual_proof_id, &did[13..]);
}

use core::panic;
use did_method_key::DIDKey;
use ssi::did::{DIDMethod, Source};
use ssi::did_resolve::Metadata;
use ssi::jwk::JWK;
use ssi::one_or_many::OneOrMany;
use trustchain_ion::did_methods::{build_methods_resolver, DID_METHODS};
use trustchain_ion::get_ion_resolver;

#[tokio::test]
async fn resolve_did_key_method_ed25519() {
    // DID resolution for the "key" method is inlcuded in the DIDMethodsResult implementation.
    // Offline resolution using an algorithm that maps between the DID and the DID document
    let key = JWK::generate_ed25519().unwrap();
    let did = DIDKey.generate(&Source::Key(&key)).unwrap();
    let resolver = &DID_METHODS;
    let (res_meta, _doc, _doc_meta) = resolver.resolve_as_result(&did).await.unwrap();
    assert_eq!(res_meta.error, None);
    println!("{}", serde_json::to_string_pretty(&_doc.unwrap()).unwrap());
}

#[tokio::test]
#[ignore] // Requires a running Sidetree node listening on http://localhost:3000.
async fn trustchain_resolution_with_prebuilt_resolver() {
    let resolver = &DID_METHODS;
    let did = "did:ion:test:EiA8yZGuDKbcnmPRs9ywaCsoE2FT9HMuyD9WmOiQasxBBg";
    let result = resolver.resolve_as_result(did).await;
    assert!(result.is_ok());
}

#[tokio::test]
#[ignore] // Requires a running Sidetree node listening on http://localhost:3000.
async fn trustchain_resolution() {
    // Integration test of the Trustchain resolution pipeline.
    let did = "did:ion:test:EiA8yZGuDKbcnmPRs9ywaCsoE2FT9HMuyD9WmOiQasxBBg";

    // Construct a set of Resolvers to handle a number of DIDMethods.
    let ion_resolver = get_ion_resolver("http://localhost:3000/");
    let resolvers: &[&dyn DIDMethod] = &[&ion_resolver];
    let resolver = build_methods_resolver(resolvers);

    // Resolve DID Document & Metadata.
    let result = resolver.resolve_as_result(did).await;

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

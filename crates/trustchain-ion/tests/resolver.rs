use core::panic;

use bitcoin::Network;
use ssi::did_resolve::Metadata;
use ssi::one_or_many::OneOrMany;
use trustchain_core::resolver::TrustchainResolver;
use trustchain_ion::trustchain_resolver;
use trustchain_ion::utils::BITCOIN_NETWORK;

#[tokio::test]
#[ignore] // Requires a running Sidetree node listening on http://localhost:3000.
async fn trustchain_resolution() {
    // Integration test of the Trustchain resolution pipeline.

    let did = match BITCOIN_NETWORK
        .as_ref()
        .expect("Integration test requires Bitcoin")
    {
        Network::Testnet => "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
        Network::Testnet4 => "did:ion:test:EiA-CAfMgrNRa2Gv5D8ZF7AazX9nKxnSlYkYViuKeomymw",
        network @ _ => {
            panic!("No test fixtures for network: {:?}", network);
        }
    };

    let controller_did = match BITCOIN_NETWORK
        .as_ref()
        .expect("Integration test requires Bitcoin")
    {
        Network::Testnet => "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
        Network::Testnet4 => "did:ion:test:EiDnaq8k5I4xGy1NjKZkNgcFwNt1Jm6mLm0TVVes7riyMA",
        network @ _ => {
            panic!("No test fixtures for network: {:?}", network);
        }
    };

    // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
    let resolver = trustchain_resolver("http://localhost:3000/");

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
    assert_eq!(
        doc.controller,
        Some(OneOrMany::One(String::from(controller_did)))
    );

    // Check the Trustchain proof service is *not* found in the DID Document.
    // It should instead be in the DID Document Metadata.
    if let Some(services) = doc.service {
        assert!(!services.iter().any(|s| s.id.contains(&String::from(
            trustchain_core::TRUSTCHAIN_PROOF_SERVICE_ID_VALUE
        ))));
    }

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
    assert_eq!(actual_proof_id, &controller_did);
}

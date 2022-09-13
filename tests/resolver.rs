use did_ion::{sidetree::SidetreeClient, ION};
use trustchain::resolver::{Resolver, DIDMethodWrapper};

type IONClient = SidetreeClient::<ION>;
type IONResolver = Resolver::<DIDMethodWrapper<IONClient>>;

#[test] #[ignore] // Requires a running Sidetree node listening on http://localhost:3000.
fn trustchain_resolution() {
    // Integration test of the Trustchain resolution pipeline.

    let did = "did:ion:test:EiA8yZGuDKbcnmPRs9ywaCsoE2FT9HMuyD9WmOiQasxBBg";

    // Construct a Trustchain Resolver from a Sidetree DIDMethod.
    let sidetree_client = IONClient::new(Some(String::from("http://localhost:3000/")));
    let resolver = IONResolver::from(sidetree_client);
    
    // Resolve DID Document & Metadata.
    let result = resolver.resolve(did);

    // Check the result is not an error. 
    // If this fails, make sure the Sidetree server is up and listening on the above URL endpoint.
    assert!(result.is_ok());

    let (_res_meta, doc, doc_meta) = result.unwrap();

    // Check the DID Document and Metadata were successfully resolved.
    assert!(doc.is_some());
    assert!(doc_meta.is_some());

    // Check the subject's DID is in the DID Document.
    todo!();
    // Check the controller's DID is in the DID Document.
    todo!();
    // Check the proof service is *not* found in the DID Document.
    todo!();

    // Check the proof is in the DID Document Metadata.
    todo!();
    // Check the proof property contains id, type and proofValue properties.
    todo!();
    // Check the id inside the proof matches the controller's DID.
    todo!();

}
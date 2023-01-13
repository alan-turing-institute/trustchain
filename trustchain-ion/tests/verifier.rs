use core::panic;

use ssi::did_resolve::Metadata;
use ssi::one_or_many::OneOrMany;

use did_ion::{sidetree::SidetreeClient, ION};
use trustchain_core::chain::{Chain, DIDChain};
use trustchain_core::resolver::{DIDMethodWrapper, Resolver};

// Type aliases
pub type IONResolver = Resolver<DIDMethodWrapper<SidetreeClient<ION>>>;

pub fn test_resolver(endpoint: &str) -> IONResolver {
    IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(endpoint))))
}

use trustchain_core::verifier::Verifier;
use trustchain_core::ROOT_EVENT_TIME;
use trustchain_ion::verifier::IONVerifier;

#[test]
#[ignore] // Requires a running Sidetree node listening on http://localhost:3000.
fn trustchain_verification() {
    // Integration test of the Trustchain resolution pipeline.
    // root - root-plus-1 - root-plus-2
    let dids = vec![
        "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
        "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
        "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
    ];

    // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
    let resolver = test_resolver("http://localhost:3000/");
    let verifier = IONVerifier::new(resolver);
    for did in dids {
        // TODO.
        // let result = verifier.verify(did, ROOT_EVENT_TIME);
        // println!(
        //     "DID: {:?},  VERIFIED!!!\n{:?}",
        //     did,
        //     result.as_ref().unwrap()
        // );
        // assert!(result.is_ok());
    }
}

#[test]
#[ignore = "Integration test requires ION, Bitcoin RPC & IPFS"]
fn test_verified_block_hash() {
    let resolver = test_resolver("http://localhost:3000/");
    let target = IONVerifier::new(resolver);

    let did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
    let result = target.verified_block_hash(did);

    assert!(result.is_ok());
    assert_eq!(
        result.unwrap(),
        "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f"
    );
}

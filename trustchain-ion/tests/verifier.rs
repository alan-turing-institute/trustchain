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

use trustchain_core::verifier::Verifier;
use trustchain_core::ROOT_EVENT_TIME;
use trustchain_ion::verifier::IONVerifier;

#[test]
#[ignore] // Requires a running Sidetree node listening on http://localhost:3000.
fn trustchain_verification() {
    // Integration test of the Trustchain resolution pipeline.

    // root-plus-2
    let did = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q";

    // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
    let resolver = test_resolver("http://localhost:3000/");

    let verifier = IONVerifier::new(resolver);

    let result = verifier.verify(did, ROOT_EVENT_TIME);

    assert!(result.is_ok());
}

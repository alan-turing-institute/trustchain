use trustchain_core::verifier::Verifier;
use trustchain_core::{ROOT_EVENT_TIME, ROOT_EVENT_TIME_2378493};
use trustchain_ion::get_ion_resolver;
use trustchain_ion::verifier::IONVerifier;

#[test]
#[ignore = "Requires a running Sidetree node listening on http://localhost:3000."]
fn trustchain_verification() {
    // Integration test of the Trustchain resolution pipeline.
    // root - root-plus-1 - root-plus-2
    let dids = vec![
        "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
        "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
        "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
    ];

    // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
    let resolver = get_ion_resolver("http://localhost:3000/");

    let verifier = IONVerifier::new(resolver);

    // Verify initial DIDs
    for did in dids {
        let result = verifier.verify(did, ROOT_EVENT_TIME);
        // println!("{}", result.as_ref().unwrap());
        assert!(result.is_ok());
    }

    // Example DIDs for ROOT_EVENT_TIME_2378493
    let new_dids = vec![
        "did:ion:test:EiC9KEQyCzGFs_dJ2Iy1lgah3nTuy0ns8ZxXa9ZPZILBpQ",
        "did:ion:test:EiBwr2eTfupemVBq28VyIb8po0r_jpuHMUMFzw25Flnmrg",
        "did:ion:test:EiBa0sTcKeJa4jZSrRsZ648qu1cyQyvnmWCpj7J_ApHMGQ",
        "did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA",
        "did:ion:test:EiDMe2SFfJ_7eXVW7RF1ZHOkeu2M-Bre0ak2cXNBH0P-TQ",
        "did:ion:test:EiCgM_1sQtff-iAFmOR0h3jDmYI_sMAoXduOeCdRFGBIjQ",
        "did:ion:test:EiD488CJha35r-aRa_HvB__exWx4mV5G7XchOHypJvP_ig",
        "did:ion:test:EiBujcSXT9rpq9FUrk-qgDuKNIaegzmSi0Ix_XXqD3woLQ",
        "did:ion:test:EiCzekHARUPkqf0NRsQ6kfpcnEbwtpdTIgadTYWaggx8Rg",
    ];
    for did in new_dids {
        let result = verifier.verify(did, ROOT_EVENT_TIME_2378493);
        // println!("{}", result.as_ref().unwrap());
        assert!(result.is_ok());
    }
}

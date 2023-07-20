use serde_json::json;
use trustchain_core::commitment::Commitment;
use trustchain_core::verifier::{Timestamp, Verifier};
use trustchain_ion::get_ion_resolver;
use trustchain_ion::verifier::IONVerifier;

// The root event time of DID documents in `data.rs` used for unit tests and the test below.
const ROOT_EVENT_TIME_1: u32 = 1666265405;

#[tokio::test]
#[ignore = "requires a running Sidetree node listening on http://localhost:3000."]
async fn trustchain_verification() {
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
    for did in dids {
        let result = verifier.verify(did, ROOT_EVENT_TIME_1).await;
        assert!(result.is_ok());
    }
}

#[tokio::test]
#[ignore = "Integration test requires ION, Bitcoin RPC & IPFS"]
async fn test_verifiable_timestamp() {
    let resolver = get_ion_resolver("http://localhost:3000/");
    let target = IONVerifier::new(resolver);
    let timestamp: Timestamp = 1666265405;

    let did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
    let result = target.verifiable_timestamp(did, timestamp).await;

    assert!(result.is_ok());

    let verifiable_timestamp = result.unwrap();

    // Check that the DID commitment is the expected PoW hash.
    // See https://blockstream.info/testnet/block/000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f
    let expected_hash = "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f";
    assert_eq!(
        verifiable_timestamp.did_commitment().hash().unwrap(),
        expected_hash
    );

    // Check that the DID timestamp is correct by comparing to the known header.
    assert_eq!(verifiable_timestamp.timestamp(), timestamp);

    // Confirm that the same timestamp is the expected data in the TimestampCommitment.
    assert_eq!(
        verifiable_timestamp.timestamp_commitment().expected_data(),
        &json!(timestamp)
    );

    // Verify the timestamp.
    let _ = target.verify_timestamp(verifiable_timestamp.as_ref());
    // Verify a second time to check data is not consumed
    let actual = target.verify_timestamp(verifiable_timestamp.as_ref());
    assert!(actual.is_ok());
}

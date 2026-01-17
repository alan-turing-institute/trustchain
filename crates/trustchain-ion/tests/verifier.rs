use bitcoin::Network;
use trustchain_core::utils::type_of;
use trustchain_core::verifier::{Timestamp, Verifier};
use trustchain_ion::trustchain_resolver;
use trustchain_ion::utils::BITCOIN_NETWORK;
use trustchain_ion::verifier::TrustchainVerifier;

#[tokio::test]
#[ignore = "requires a running Sidetree node listening on http://localhost:3000."]
async fn trustchain_verification() {
    // Integration test of the Trustchain resolution pipeline.
    // root - root-plus-1 - root-plus-2
    let dids = match BITCOIN_NETWORK
        .as_ref()
        .expect("Integration test requires Bitcoin")
    {
        Network::Testnet => vec![
            "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
            "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
            "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
        ],
        Network::Testnet4 => vec![
            "did:ion:test:EiDnaq8k5I4xGy1NjKZkNgcFwNt1Jm6mLm0TVVes7riyMA",
            "did:ion:test:EiA-CAfMgrNRa2Gv5D8ZF7AazX9nKxnSlYkYViuKeomymw",
            "did:ion:test:EiBsaims7YMtoe3XYZ-7nQ-CGBGBsZQUIIfTRAh0Mrd8Sw",
        ],
        network @ _ => {
            panic!("No test fixtures for network: {:?}", network);
        }
    };

    let root_event_time = match BITCOIN_NETWORK
        .as_ref()
        .expect("Integration test requires Bitcoin")
    {
        Network::Testnet => 1666265405,
        Network::Testnet4 => 1766953540,
        network @ _ => {
            panic!("No test fixtures for network: {:?}", network);
        }
    };

    // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
    let resolver = trustchain_resolver("http://localhost:3000/");
    let verifier = TrustchainVerifier::new(resolver);
    for did in dids {
        let result = verifier.verify(did, root_event_time).await;
        assert!(result.is_ok());
    }
}

#[tokio::test]
#[ignore = "Integration test requires ION, Bitcoin RPC & IPFS"]
async fn test_verifiable_timestamp() {
    let resolver = trustchain_resolver("http://localhost:3000/");
    let target = TrustchainVerifier::new(resolver);

    let (did, timestamp, expected_hash) = match BITCOIN_NETWORK
        .as_ref()
        .expect("Integration test requires Bitcoin")
    {
        Network::Testnet => {
            let did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
            let timestamp: Timestamp = 1666265405;
            // See https://blockstream.info/testnet/block/000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f
            let expected_hash = "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f";
            (did, timestamp, expected_hash)
        }
        Network::Testnet4 => {
            let did = "did:ion:test:EiDnaq8k5I4xGy1NjKZkNgcFwNt1Jm6mLm0TVVes7riyMA";
            let timestamp: Timestamp = 1766953540;
            // See https://mempool.space/testnet4/block/00000000eae3c2b2e336d66e390f622bfe817ab524cfe08eff03189640ded9ec
            let expected_hash = "00000000eae3c2b2e336d66e390f622bfe817ab524cfe08eff03189640ded9ec";
            (did, timestamp, expected_hash)
        }
        network @ _ => {
            panic!("No test fixtures for network: {:?}", network);
        }
    };

    let result = target.verifiable_timestamp(did, timestamp).await;
    assert!(result.is_ok());

    let verifiable_timestamp = result.unwrap();

    // Check that the DID commitment is the expected PoW hash.
    assert_eq!(
        verifiable_timestamp.did_commitment().hash().unwrap(),
        expected_hash
    );
    assert_eq!(
        verifiable_timestamp.timestamp_commitment().hash().unwrap(),
        expected_hash
    );

    // Check that the DID timestamp is correct by comparing to the known header.
    assert_eq!(verifiable_timestamp.timestamp(), timestamp);

    // Confirm that the same timestamp is the expected data in the TimestampCommitment.
    assert_eq!(
        verifiable_timestamp.timestamp_commitment().expected_data(),
        &timestamp
    );
    assert_eq!(
        type_of(verifiable_timestamp.timestamp_commitment().expected_data()),
        type_of(&timestamp)
    );

    // Verify the timestamp.
    verifiable_timestamp
        .verify(&verifiable_timestamp.timestamp_commitment().hash().unwrap())
        .unwrap();
    // Verify a second time to check data is not consumed
    verifiable_timestamp
        .verify(&verifiable_timestamp.timestamp_commitment().hash().unwrap())
        .unwrap();
}

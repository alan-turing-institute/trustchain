use bitcoin::Network;
use trustchain_core::chain::{Chain, DIDChain};
use trustchain_core::graph::TrustchainGraph;
use trustchain_ion::trustchain_resolver;
use trustchain_ion::utils::BITCOIN_NETWORK;

#[tokio::test]
#[ignore] // Requires a running Sidetree node listening on http://localhost:3000.
async fn trustchain_graph() {
    // Example DIDs for ROOT_EVENT_TIME_2378493
    let resolver = trustchain_resolver("http://localhost:3000/");

    let new_dids = match BITCOIN_NETWORK
        .as_ref()
        .expect("Integration test requires Bitcoin")
    {
        Network::Testnet => vec![
            "did:ion:test:EiC9KEQyCzGFs_dJ2Iy1lgah3nTuy0ns8ZxXa9ZPZILBpQ",
            "did:ion:test:EiBwr2eTfupemVBq28VyIb8po0r_jpuHMUMFzw25Flnmrg",
            "did:ion:test:EiBa0sTcKeJa4jZSrRsZ648qu1cyQyvnmWCpj7J_ApHMGQ",
            "did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA",
            "did:ion:test:EiDMe2SFfJ_7eXVW7RF1ZHOkeu2M-Bre0ak2cXNBH0P-TQ",
            "did:ion:test:EiCgM_1sQtff-iAFmOR0h3jDmYI_sMAoXduOeCdRFGBIjQ",
            "did:ion:test:EiD488CJha35r-aRa_HvB__exWx4mV5G7XchOHypJvP_ig",
            "did:ion:test:EiBujcSXT9rpq9FUrk-qgDuKNIaegzmSi0Ix_XXqD3woLQ",
            "did:ion:test:EiCzekHARUPkqf0NRsQ6kfpcnEbwtpdTIgadTYWaggx8Rg",
            "did:ion:test:EiDtNQrvGxaXF51U9SMOvPjzLQDtkYRdKb7q7UDfpSIzlQ",
            "did:ion:test:EiDtNQrvGxaXF51U9SMOvPjzLQDtkYRdKb7q7UDfpSIzlQ",
        ],
        Network::Testnet4 => vec![
            "did:ion:test:EiDnaq8k5I4xGy1NjKZkNgcFwNt1Jm6mLm0TVVes7riyMA",
            "did:ion:test:EiA-CAfMgrNRa2Gv5D8ZF7AazX9nKxnSlYkYViuKeomymw",
            "did:ion:test:EiCMPaKNeI1AMj_tdPXRtV2PmAA3FemrqsTexloHKyTybg",
        ],
        network @ _ => {
            panic!("No test fixtures for network: {:?}", network);
        }
    };
    let mut chains = vec![];
    for did in new_dids {
        let chain = DIDChain::new(did, &resolver).await.unwrap();
        chain.verify_proofs().unwrap();
        chains.push(chain);
    }

    let graph = TrustchainGraph::new(&chains, 50).unwrap();
    println!("{}", graph);
}

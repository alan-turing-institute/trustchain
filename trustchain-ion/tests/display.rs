use trustchain_core::chain::{Chain, DIDChain};
use trustchain_core::graph::TrustchainGraph;
use trustchain_ion::get_ion_resolver;

#[tokio::test]
#[ignore] // Requires a running Sidetree node listening on http://localhost:3000.
async fn trustchain_graph() {
    // Example DIDs for ROOT_EVENT_TIME_2378493
    let resolver = get_ion_resolver("http://localhost:3000/");
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
        "did:ion:test:EiDtNQrvGxaXF51U9SMOvPjzLQDtkYRdKb7q7UDfpSIzlQ",
        "did:ion:test:EiDtNQrvGxaXF51U9SMOvPjzLQDtkYRdKb7q7UDfpSIzlQ",
    ];
    let mut chains = vec![];
    for did in new_dids {
        let chain = DIDChain::new(did, &resolver).await.unwrap();
        chain.verify_proofs().unwrap();
        chains.push(chain);
    }

    let graph = TrustchainGraph::new(&chains, 50).unwrap();
    println!("{}", graph);
}

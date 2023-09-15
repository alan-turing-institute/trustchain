use std::{path::Path, str::FromStr};

use home::home_dir;
use nakamoto::{
    chain::{
        block::cache::BlockCache,
        store::{File, Genesis, Store},
        BlockHash, BlockHeader, BlockReader,
    },
    common::{bitcoin::consensus::Params, block::Height, nonempty::NonEmpty},
};

pub fn get_block(hash: &str) -> Option<(u64, BlockHeader)> {
    // TODO: work out how to set default heights (for testnet & mainnet).
    let genesis = BlockHeader::genesis(nakamoto::client::Network::Testnet);

    // Open a BlockHeader File Store pointing to the local testnet headers.db file.
    // This will be available provided the nakamoto daemon has already been run locally with:
    // cargo run --release -p nakamoto-node -- --testnet
    let path = home_dir()
        .unwrap()
        .join(Path::new(".nakamoto/testnet/headers.db"));
    let mut store: File<BlockHeader> = File::open(path, genesis).unwrap();

    // Alternative approach with Memory (as opposed to File) Store:
    // let mut store = Memory::new(NonEmpty::new(block_header));

    println!("{}", store.len().unwrap());
    store.sync().unwrap();
    println!("{}", store.len().unwrap());

    // TODO: needs to be configurable for mainnet/testnet.
    let params = Params::new(nakamoto::common::bitcoin::Network::Testnet);

    // TODO: work out how to add a checkpoint.
    let checkpoints: &[(Height, BlockHash)] = &[];

    let block_cache = BlockCache::new(store, params, checkpoints).unwrap();
    let block_cache = block_cache.load().unwrap();

    let block_hash = BlockHash::from_str(hash).unwrap();

    println!("{:?}", block_hash);
    println!("{:?}", block_cache.get_block(&block_hash));

    if let Some((height, block_header)) = block_cache.get_block(&block_hash) {
        return Some((height, block_header.clone()));
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::spv::get_block;

    #[test]
    fn test_get_block() {
        let hash = "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f";
        let result = get_block(hash);
        assert!(result.is_some());

        let (height, header) = result.unwrap();

        // Confirm the known block height, Merkle root and timestamp of the corresponding testnet block.
        assert_eq!(height, 2377445);
        assert_eq!(
            header.merkle_root.to_string(),
            "7dce795209d4b5051da3f5f5293ac97c2ec677687098062044654111529cad69"
        );
        assert_eq!(header.time, 1666265405);
    }
}

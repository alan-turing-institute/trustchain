use chrono::NaiveDate;
use futures::{StreamExt, future};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use trustchain_core::utils::get_did_from_suffix;

use crate::{
    ION_TEST_METHOD, MONGO_FILTER_DID_SUFFIX, MONGO_FILTER_TXN_TIME, TrustchainBitcoinError,
    TrustchainMongodbError,
    utils::{
        block_height_range_on_date, locate_transaction, query_mongodb_on_interval, transaction,
    },
};

/// An error relating to the root DID.
#[derive(Error, Debug)]
pub enum TrustchainRootError {
    /// Bitcoin RPC interface error while processing root event date.
    #[error("Bitcoin RPC error while processing root event date.")]
    BitcoinRpcError(TrustchainBitcoinError),
    /// Mongo DB error while processing root event date.
    #[error("Mongo DB error while processing root event date.")]
    MongoDbError(TrustchainMongodbError),
    /// Failed to identify unique root DID.
    #[error("No unique root DID on date: {0}")]
    NoUniqueRootEvent(NaiveDate),
    /// Invalid date.
    #[error("Invalid date: {0}-{1}-{2}")]
    InvalidDate(i32, u32, u32),
    /// Failed to parse block height.
    #[error("Failed to parse block height: {0}")]
    FailedToParseBlockHeight(String),
}

impl From<TrustchainBitcoinError> for TrustchainRootError {
    fn from(err: TrustchainBitcoinError) -> Self {
        TrustchainRootError::BitcoinRpcError(err)
    }
}

impl From<TrustchainMongodbError> for TrustchainRootError {
    fn from(err: TrustchainMongodbError) -> Self {
        TrustchainRootError::MongoDbError(err)
    }
}

/// Struct representing a root DID candidate.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, PartialOrd, Eq, Ord)]
#[serde(rename_all = "camelCase")]
pub struct RootCandidate {
    pub did: String,
    pub txid: String,
    pub block_height: u64,
}

/// Identifies potential root DIDs whose (UTC) timestamp matches a given date.
/// Root DID candidates are those that are found in ION create operations with
/// operation index zero (opIndex = 0). As such, root DIDs must be created in
/// the first DID operation associated with a particular Bitcoin transaction.
pub async fn root_did_candidates(
    date: NaiveDate,
) -> Result<Vec<RootCandidate>, TrustchainRootError> {
    let block_height_range = block_height_range_on_date(date, None, None)?;
    let cursor =
        query_mongodb_on_interval(block_height_range.0 as u32, block_height_range.1 as u32).await?;

    // The mongodb Cursor instance streams all bson documents that:
    // - represent ION DID create operations, and
    // - whose timestamp falls within the given date, and
    // - whose ION operation index is zero.

    // This Cursor is then filtered by:
    // - discarding any errors when extracting the opIndex or didSuffix fields, and
    // - discarding any operations for which the corresponding Bitcoin transaction cannot be located & retrieved.

    // TODO:
    // Additional filtering should be added to discard any downstream DIDs by resolving and inspecting the DID metadata.
    // For this the steps are:
    //  - get the DID suffix from the bson document
    //  - resolve the DID (using an IONResolver passed in to this function)
    //  - inspect the document metadata...

    let rpc_client = &crate::utils::rpc_client();
    let vec = cursor
        .filter(|x| future::ready(x.is_ok()))
        .map(|x| x.unwrap())
        .filter_map(|doc| async move {
            if doc.get_str(MONGO_FILTER_DID_SUFFIX).is_err() {
                return None;
            }
            let did_suffix = doc.get_str(MONGO_FILTER_DID_SUFFIX).unwrap();
            // TODO: test vs mainnet needs handling here:
            let did = get_did_from_suffix(did_suffix, ION_TEST_METHOD);
            let tx_locator = locate_transaction(&did, rpc_client).await;
            if tx_locator.is_err() {
                return None;
            }
            let (block_hash, tx_index) = tx_locator.unwrap();
            let tx = transaction(&block_hash, tx_index, Some(rpc_client));
            if tx.is_err() {
                return None;
            }
            let txid = tx.unwrap().compute_txid().to_string();

            let block_height = doc
                .get_i32(MONGO_FILTER_TXN_TIME)
                .unwrap()
                .try_into()
                .unwrap();
            Some(RootCandidate {
                did,
                txid,
                block_height,
            })
        })
        .collect::<Vec<RootCandidate>>()
        .await;
    Ok(vec)
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use itertools::Itertools;

    use crate::utils::BITCOIN_NETWORK;

    use super::*;

    #[tokio::test]
    #[ignore = "Integration test requires Bitcoin & MongoDB"]
    async fn test_root_did_candidates() {
        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                let date = NaiveDate::from_ymd_opt(2022, 10, 20).unwrap();
                let result = root_did_candidates(date)
                    .await
                    .unwrap()
                    .into_iter()
                    .sorted()
                    .collect_vec();

                // There were 38 testnet ION operations with opIndex 0 on 20th Oct 2022.
                // The block height range on that date is (2377360, 2377519).
                // The relevant mongosh query is:
                // db.operations.find({type: 'create', opIndex: 0, txnTime: { $gt: 2377359, $lt: 2377520}}).count()
                assert_eq!(result.len(), 38);

                assert_eq!(
                    result[0].did,
                    "did:ion:test:EiA6m4-V4fW_l1xEu3jH9xvXt1JyynmO7I_rkBpFulEAuQ"
                );
                assert_eq!(
                    result[0].txid,
                    "b698c0919a91a161bc141cd395788296edb85d19415a6d29a13a220a8f2249e0"
                );
                assert_eq!(result[0].block_height, 2377410);

                // This is the root DID used in testing:
                assert_eq!(
                    result[26].did,
                    "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
                );
                assert_eq!(
                    result[26].txid,
                    "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c"
                );
                assert_eq!(result[26].block_height, 2377445);

                assert_eq!(
                    result[37].did,
                    "did:ion:test:EiDz_zvUa2FUIgLUvBia9wUJakhrrW889nDdGlr1-RTAWw"
                );
                assert_eq!(
                    result[37].txid,
                    "c369dd566a0dd5c2f381c1ab9c8e96b4f6b4fd323f5c1ed68dbb2a1bfb9cb48f"
                );
                assert_eq!(result[37].block_height, 2377416);
            }
            Network::Testnet4 => {
                let date = NaiveDate::from_ymd_opt(2025, 12, 28).unwrap();
                let result = root_did_candidates(date)
                    .await
                    .unwrap()
                    .into_iter()
                    .sorted()
                    .collect_vec();

                // There were 3 testnet ION operations with opIndex 0 on 28th Dec 2025.
                // The block height range on that date is (115580, 115729).
                // The relevant mongosh query is:
                // db.operations.find({type: 'create', opIndex: 0, txnTime: { $gt: 115580, $lt: 115729}}).count()
                assert_eq!(result.len(), 3);

                assert_eq!(
                    result[0].did,
                    "did:ion:test:EiCKLQjzVNl0R7UCUW74JH_FN5VyfxWpL1IX1FUYTJ4uIA"
                );
                assert_eq!(
                    result[0].txid,
                    "e6ab4e7eb0dfd266fff8cd2cc679fad128d31f4bce37aa088a033bec1ee3505c"
                );
                assert_eq!(result[0].block_height, 115688);

                // This is the root DID used in testing:
                assert_eq!(
                    result[2].did,
                    "did:ion:test:EiDnaq8k5I4xGy1NjKZkNgcFwNt1Jm6mLm0TVVes7riyMA"
                );
                assert_eq!(
                    result[2].txid,
                    "45fd2acb89da0c5c79e59df90c0e3580a515e66bc71b8194e5ee764640e52e57"
                );
                assert_eq!(result[2].block_height, 115709);
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }
    }
}

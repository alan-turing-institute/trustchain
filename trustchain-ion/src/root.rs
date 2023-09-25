use chrono::NaiveDate;
use futures::{future, StreamExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use trustchain_core::utils::get_did_from_suffix;

use crate::{
    utils::{
        block_height_range_on_date, locate_transaction, query_mongodb_on_interval, transaction,
    },
    TrustchainBitcoinError, TrustchainMongodbError, ION_TEST_METHOD, MONGO_FILTER_DID_SUFFIX,
    MONGO_FILTER_OP_INDEX,
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
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootCandidate {
    pub did: String,
    pub tx_id: String,
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
            if !doc.get_str(MONGO_FILTER_DID_SUFFIX).is_ok() {
                return None;
            }
            let did_suffix = doc.get_str(MONGO_FILTER_DID_SUFFIX).unwrap();
            // TODO: test vs mainnet needs handling here:
            let did = get_did_from_suffix(&did_suffix, ION_TEST_METHOD);
            let tx_locator = locate_transaction(&did, rpc_client).await;
            if tx_locator.is_err() {
                return None;
            }
            let (block_hash, tx_index) = tx_locator.unwrap();
            let tx = transaction(&block_hash, tx_index, Some(rpc_client));
            if tx.is_err() {
                return None;
            }
            let tx_id = tx.unwrap().txid().to_string();
            Some(RootCandidate { did, tx_id })
        })
        .collect::<Vec<RootCandidate>>()
        .await;
    Ok(vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "Integration test requires Bitcoin & MongoDB"]
    async fn test_root_did_candidates() {
        let date = NaiveDate::from_ymd_opt(2022, 10, 20).unwrap();
        let result = root_did_candidates(date).await.unwrap();

        // There were 38 testnet ION operations with opIndex 0 on 20th Oct 2022.
        // The block height range on that date is (2377360, 2377519).
        // The relevant mongosh query is:
        // db.operations.find({type: 'create', opIndex: 0, txnTime: { $gt: 2377359, $lt: 2377520}}).count()
        assert_eq!(result.len(), 38);

        assert_eq!(
            result[0].did,
            "did:ion:test:EiAcmytgsm-AUWtmJ9cioW-MWq-DnjIUfGYdIVUnrpg6kw"
        );
        assert_eq!(
            result[0].tx_id,
            "1fae017f2c9f14cec0487a04b3f1d1b7336bd38547f755748beb635296de3ee8"
        );

        // This is the root DID used in testing:
        assert_eq!(
            result[16].did,
            "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
        );
        assert_eq!(
            result[16].tx_id,
            "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c"
        );

        assert_eq!(
            result[37].did,
            "did:ion:test:EiBbes2IRKhGauhQc5r4T30i06S6dEWgzCKx-WCKT3x0Lw"
        );
        assert_eq!(
            result[37].tx_id,
            "502f1a418eff99e50b91aea33e43e4c270af05eb0381d57ca4f48f16d7efe9e1"
        );
    }
}

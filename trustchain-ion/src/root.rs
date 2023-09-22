use chrono::NaiveDate;
use futures::{future, StreamExt};
use thiserror::Error;
use trustchain_core::utils::get_did_from_suffix;

use crate::{
    utils::{
        block_height_range_on_date, locate_transaction, query_mongodb_on_interval, transaction,
    },
    TrustchainBitcoinError, TrustchainMongodbError, ION_TEST_METHOD, MONGO_FILTER_DID_SUFFIX,
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
pub struct RootCandidate {
    did: String,
    tx_id: String,
}

/// Identifies potential root DIDs whose (UTC) timestamp matches a given date.
pub async fn root_did_candidates(
    date: NaiveDate,
) -> Result<Vec<RootCandidate>, TrustchainRootError> {
    let block_height_range = block_height_range_on_date(date, None, None)?;
    let cursor =
        query_mongodb_on_interval(block_height_range.0 as u32, block_height_range.1 as u32).await?;

    // TODO:
    // Filter out any dDIDs by resolving and inspecting the DID metadata. For this the steps are:
    //  - get the DID suffix from the bson document
    //  - resolve the DID (using an IONResolver passed in to this function)
    //  - if the document metadata contains...

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

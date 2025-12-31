//! ION-related utilities.
use crate::data::{ROOT_PLUS_1_SIGNING_KEY, ROOT_PLUS_2_SIGNING_KEYS, TESTNET4_ROOT_PLUS_1_SIGNING_KEY, TESTNET4_ROOT_PLUS_2_SIGNING_KEYS};
use crate::{
    config::ion_config, MONGO_FILTER_OP_INDEX, MONGO_FILTER_TXN_NUMBER, MONGO_FILTER_TXN_TIME,
};
use bitcoin::Network;
use bitcoin::{block::Header, blockdata::block::BlockHash, Transaction};
use bitcoincore_rpc::{bitcoincore_rpc_json::BlockStatsFields, RpcApi};
use chrono::NaiveDate;
use flate2::read::GzDecoder;
use futures::TryStreamExt;
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient};
use lazy_static::lazy_static;
use mongodb::{bson::doc, options::ClientOptions, Cursor};
use serde_json::{json, Value};
use ssi::jwk::JWK;
use ssi::one_or_many::OneOrMany;
use std::io::Read;
use std::path::Path;
use std::sync::Once;
use std::{cmp::Ordering, collections::HashMap};
use trustchain_core::key_manager::{KeyManager, KeyType};
use trustchain_core::TRUSTCHAIN_DATA;
use trustchain_core::{utils::get_did_suffix, verifier::VerifierError};

use crate::{
    TrustchainBitcoinError, TrustchainIpfsError, TrustchainMongodbError, BITS_KEY,
    HASH_PREV_BLOCK_KEY, MERKLE_ROOT_KEY, MONGO_COLLECTION_OPERATIONS, MONGO_CREATE_OPERATION,
    MONGO_FILTER_DID_SUFFIX, MONGO_FILTER_TYPE, NONCE_KEY, TIMESTAMP_KEY, VERSION_KEY,
};

const ION_METHOD_WITH_DELIMITER: &str = "ion:";
const ION_OPERATION_COUNT_DELIMITER: &str = ".";
const DID_DELIMITER: &str = ":";

lazy_static! {
    /// Lazy static reference to the Bitcoin blockchain network.
    pub static ref BITCOIN_NETWORK: Result<Network, TrustchainBitcoinError> = bitcoin_network(None);
}

/// Locator for a transaction on the PoW ledger, given by the pair:
/// (block_hash, tx_index_within_block).
pub type TransactionLocator = (BlockHash, u32);

/// Utility key manager.
struct UtilsKeyManager;

impl KeyManager for UtilsKeyManager {}

/// Set-up tempdir and use as env var for `TRUSTCHAIN_DATA`.
// https://stackoverflow.com/questions/58006033/how-to-run-setup-code-before-any-tests-run-in-rust
static INIT: Once = Once::new();
pub fn init() {
    INIT.call_once(|| {
        let utils_key_manager = UtilsKeyManager;
        // initialization code here
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var(TRUSTCHAIN_DATA, Path::new(tempdir.as_ref().as_os_str()));
        // Manually drop here so additional writes in the init call are not removed
        drop(tempdir);
        // Include test signing keys for two resolvable DIDs
        let (root_plus_1_did_suffix, root_plus_2_did_suffix) = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => (
                "EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
                "EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
            ),
            Network::Testnet4 => (
                "EiA-CAfMgrNRa2Gv5D8ZF7AazX9nKxnSlYkYViuKeomymw",
                "EiCMPaKNeI1AMj_tdPXRtV2PmAA3FemrqsTexloHKyTybg",
            ),
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };

        let (root_plus_1_did_signing_key, root_plus_2_did_signing_keys) = match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => (
                ROOT_PLUS_1_SIGNING_KEY,
                ROOT_PLUS_2_SIGNING_KEYS,
            ),
            Network::Testnet4 => (
                TESTNET4_ROOT_PLUS_1_SIGNING_KEY,
                TESTNET4_ROOT_PLUS_2_SIGNING_KEYS,
            ),
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        };
        // Dummy DID suffix and signing key as candidate for testing.
        let root_plus_2_candidate_did_suffix = "EiCDmY0qxsde9AdIwMf2tUKOiMo4aHnoWaPBRCeGt7iMHA";
        let root_plus_2_candidate_signing_key: &str = r#"{"kty":"EC","crv":"secp256k1","x":"WzbWcgvvq21xKDTsvANakBSI3nJKDSmNa99usFmYJ0E","y":"vAFo1gkFqgEE3QsX1xlmHcoKxs5AuDqc18kkYEGVwDk","d":"LHt66ri5ykeVqEZwbzboJevbh5UEZkT8r8etsjg3KeE"}"#;
        let root_plus_1_signing_jwk: JWK = serde_json::from_str(root_plus_1_did_signing_key).unwrap();
        let root_plus_2_signing_jwks: Vec<JWK> =
            serde_json::from_str(root_plus_2_did_signing_keys).unwrap();
        utils_key_manager
            .save_keys(
                root_plus_1_did_suffix,
                KeyType::SigningKey,
                &OneOrMany::One(root_plus_1_signing_jwk),
                false,
            )
            .unwrap();
        utils_key_manager
            .save_keys(
                root_plus_2_did_suffix,
                KeyType::SigningKey,
                &OneOrMany::Many(root_plus_2_signing_jwks),
                false,
            )
            .unwrap();
        let root_plus_2_candidate_signing_jwk: JWK = serde_json::from_str(root_plus_2_candidate_signing_key).unwrap();
        utils_key_manager
            .save_keys(
                root_plus_2_candidate_did_suffix, 
                KeyType::SigningKey, 
                &OneOrMany::One(root_plus_2_candidate_signing_jwk), 
                false,
            ).unwrap();
    });
}

/// Queries IPFS for the given content identifier (CID) to retrieve the content
/// (as bytes), hashes the content and checks that the hash matches the CID,
/// decompresses the content, converts it to a UTF-8 string and then to JSON.
///
/// By checking that the hash of the content is identical to the CID, this method
/// verifies that the content itself must have been used to originally construct the CID.
pub async fn query_ipfs(
    cid: &str,
    client: &IpfsClient,
) -> Result<Vec<u8>, ipfs_api_backend_hyper::Error> {
    client
        .cat(cid)
        .map_ok(|chunk| chunk.to_vec())
        .try_concat()
        .await
}

/// Extracts the ION OP_RETURN data from a Bitcoin transaction. Gets the output scripts that contain
/// an OP_RETURN and extracts any that contain the substring 'ion:' and returns an error unless
/// precisely one such script exists.
fn tx_to_op_return_data(tx: &Transaction) -> Result<String, VerifierError> {
    let extracted: Vec<String> = tx
        .output
        .iter()
        .filter_map(|x| match x.script_pubkey.is_op_return() {
            true => Some(&x.script_pubkey),
            false => None,
        })
        .filter_map(|script| {
            std::str::from_utf8(script.as_ref())
                .ok()
                .and_then(|op_return_str| op_return_str.split_once(ION_METHOD_WITH_DELIMITER))
                .map(|(_, r)| format!("{}{}", ION_METHOD_WITH_DELIMITER, r))
        })
        .collect();

    match extracted.len() {
        0 => Err(VerifierError::NoDIDContentIdentifier(
            tx.compute_txid().to_string(),
        )),
        1 => Ok(extracted.first().unwrap().to_string()),
        _ => Err(VerifierError::MultipleDIDContentIdentifiers(
            tx.compute_txid().to_string(),
        )),
    }
}
/// Extracts the IPFS content identifier from the ION OP_RETURN data inside a Bitcoin transaction.
pub fn tx_to_op_return_cid(tx: &Transaction) -> Result<String, VerifierError> {
    let op_return_data = tx_to_op_return_data(tx)?;
    let (_, operation_count_plus_cid) = op_return_data.rsplit_once(DID_DELIMITER).unwrap();
    let (_, cid) = operation_count_plus_cid
        .rsplit_once(ION_OPERATION_COUNT_DELIMITER)
        .unwrap();
    Ok(cid.to_string())
}

/// Decodes an IPFS file.
pub fn decode_ipfs_content(ipfs_file: &[u8], gunzip: bool) -> Result<Value, TrustchainIpfsError> {
    let mut ipfs_content_str;
    if gunzip {
        // Decompress the content and deserialize to JSON.
        let mut decoder = GzDecoder::new(ipfs_file);
        ipfs_content_str = String::new();
        decoder.read_to_string(&mut ipfs_content_str)?;
    } else {
        ipfs_content_str = String::from_utf8(ipfs_file.to_vec())
            .map_err(TrustchainIpfsError::Utf8DecodingError)?;
    }
    Ok(serde_json::from_str(&ipfs_content_str)?)
}

/// Gets a MongoDB client instance.
pub async fn mongodb_client() -> Result<mongodb::Client, TrustchainMongodbError> {
    let client_options = ClientOptions::parse(&ion_config().mongo_connection_string)
        .await
        .map_err(TrustchainMongodbError::ErrorCreatingClient)?;
    mongodb::Client::with_options(client_options)
        .map_err(TrustchainMongodbError::ErrorCreatingClient)
}

/// Queries the ION MongoDB for a DID create operation.
pub async fn query_mongodb(did: &str) -> Result<mongodb::bson::Document, TrustchainMongodbError> {
    // Construct a MongoDB client.
    let client = mongodb_client().await?;

    // TODO: when extending to other operations aside from "create" consider other queries
    // (different to .find_one()) to see whether a fuller collection of DID operations can be obtained
    // (e.g. both create and updates).
    let query_result: Result<Option<mongodb::bson::Document>, mongodb::error::Error> = client
        .database(&ion_config().mongo_database_ion_core)
        .collection(MONGO_COLLECTION_OPERATIONS)
        .find_one(
            doc! {
                MONGO_FILTER_TYPE : MONGO_CREATE_OPERATION,
                MONGO_FILTER_DID_SUFFIX : did
            },
            None,
        )
        .await;
    match query_result {
        Ok(Some(doc)) => Ok(doc),
        Ok(None) => Err(TrustchainMongodbError::QueryReturnedNone),
        Err(e) => Err(TrustchainMongodbError::QueryReturnedError(e)),
    }
}

/// Queries the ION MongoDB for DID create operations with opIndex = 0 over a block height interval.
pub async fn query_mongodb_on_interval(
    from: u32,
    to: u32,
) -> Result<Cursor<mongodb::bson::Document>, TrustchainMongodbError> {
    let client = mongodb_client().await?;
    let cursor: Result<Cursor<mongodb::bson::Document>, mongodb::error::Error> = client
        .database(&ion_config().mongo_database_ion_core)
        .collection(MONGO_COLLECTION_OPERATIONS)
        .find(
            doc! {
                MONGO_FILTER_TYPE : MONGO_CREATE_OPERATION,
                MONGO_FILTER_OP_INDEX : 0,
                MONGO_FILTER_TXN_TIME : {
                    "$gte" : from,
                    "$lte" : to
                }
            },
            None,
        )
        .await;
    Ok(cursor?)
}

/// Gets a Bitcoin RPC client instance.
pub fn rpc_client() -> bitcoincore_rpc::Client {
    bitcoincore_rpc::Client::new(
        &ion_config().bitcoin_connection_string,
        bitcoincore_rpc::Auth::UserPass(
            ion_config().bitcoin_rpc_username.clone(),
            ion_config().bitcoin_rpc_password.clone(),
        ),
    )
    // Safe to use unwrap() here, as Client::new can only return Err when using cookie authentication.
    .unwrap()
}

/// Gets the Bitcoin chain via the RPC API.
pub fn bitcoin_network(
    client: Option<&bitcoincore_rpc::Client>,
) -> Result<Network, TrustchainBitcoinError> {
    // If necessary, construct a Bitcoin RPC client to communicate with the ION Bitcoin node.
    if client.is_none() {
        let rpc_client = rpc_client();
        return bitcoin_network(Some(&rpc_client));
    };
    Ok(client.unwrap().get_blockchain_info()?.chain)
}

/// Gets a Bitcoin block header via the RPC API.
pub fn block_header(
    block_hash: &BlockHash,
    client: Option<&bitcoincore_rpc::Client>,
) -> Result<Header, TrustchainBitcoinError> {
    // If necessary, construct a Bitcoin RPC client to communicate with the ION Bitcoin node.
    if client.is_none() {
        let rpc_client = rpc_client();
        return block_header(block_hash, Some(&rpc_client));
    };
    Ok(client.unwrap().get_block_header(block_hash)?)
}

/// Decodes a Bitcoin block from 80 bytes of data into a JSON object.
/// Format is explained [here](https://en.bitcoin.it/wiki/Block_hashing_algorithm).
pub fn decode_block_header(bytes: &[u8; 80]) -> Result<Value, TrustchainBitcoinError> {
    // Deconstruct the header bytes into big-endian hex. Safe to unwrap as we begin with bytes.
    let version = reverse_endianness(&hex::encode(&bytes[0..4])).unwrap();
    let hash_prev_block = reverse_endianness(&hex::encode(&bytes[4..36])).unwrap();
    let merkle_root = reverse_endianness(&hex::encode(&bytes[36..68])).unwrap();
    let timestamp_hex = reverse_endianness(&hex::encode(&bytes[68..72])).unwrap();
    let bits = reverse_endianness(&hex::encode(&bytes[72..76])).unwrap();
    let nonce = reverse_endianness(&hex::encode(&bytes[76..])).unwrap();

    // Convert the timestamp to a u32 Unix time.
    let timestamp = i32::from_str_radix(&timestamp_hex, 16)?;

    // Construct a HashMap for the block header (minus the timestamp).
    let mut map = HashMap::new();
    map.insert(VERSION_KEY, version);
    map.insert(HASH_PREV_BLOCK_KEY, hash_prev_block);
    map.insert(MERKLE_ROOT_KEY, merkle_root);
    map.insert(BITS_KEY, bits);
    map.insert(NONCE_KEY, nonce);

    let mut json_obj = json!(map);
    let json_map = json_obj
        .as_object_mut()
        .ok_or(TrustchainBitcoinError::BlockHeaderDecodingError)?;

    // Insert the timestamp as a serde_json::Value of type Number.
    json_map.insert(TIMESTAMP_KEY.to_string(), json!(timestamp));
    Ok(json!(json_map))
}

/// Gets the Bitcoin transaction at the given location via the RPC API.
pub fn transaction(
    block_hash: &BlockHash,
    tx_index: u32,
    client: Option<&bitcoincore_rpc::Client>,
) -> Result<Transaction, TrustchainBitcoinError> {
    // If necessary, construct a Bitcoin RPC client to communicate with the ION Bitcoin node.
    if client.is_none() {
        let rpc_client = rpc_client();
        return transaction(block_hash, tx_index, Some(&rpc_client));
    }
    Ok(client
        .unwrap()
        .get_block(block_hash)
        .map(|block| block.txdata[tx_index as usize].to_owned())?)
}

/// Returns the location on the ledger of the transaction embedding
/// the most recent ION operation for the given DID.
pub async fn locate_transaction(
    did: &str,
    client: &bitcoincore_rpc::Client,
) -> Result<TransactionLocator, VerifierError> {
    let suffix = get_did_suffix(did);

    // Query the database for a bson::Document.
    let doc = query_mongodb(suffix).await.map_err(|e| {
        VerifierError::ErrorFetchingVerificationMaterial(
            "Error querying MongoDB".to_string(),
            e.into(),
        )
    })?;

    // Extract the block height.
    let block_height: i64 = doc
        .get_i32(MONGO_FILTER_TXN_TIME)
        .map_err(|_| VerifierError::FailureToGetDIDOperation(suffix.to_owned()))?
        .into();

    // Convert to block height u32
    let block_height: u32 = block_height
        .try_into()
        .map_err(|_| VerifierError::InvalidBlockHeight(block_height))?;

    // Extract the index of the transaction inside the block.
    let tx_index = doc
        .get_i64(MONGO_FILTER_TXN_NUMBER)
        .map_err(|_| VerifierError::FailureToGetDIDOperation(suffix.to_owned()))?
        .to_string()
        .strip_prefix(&block_height.to_string())
        .ok_or(VerifierError::FailureToGetDIDOperation(did.to_owned()))?
        .parse::<u32>()
        .map_err(|_| VerifierError::FailureToGetDIDOperation(suffix.to_owned()))?;

    // If call to get_network_info fails, return error.
    client
        .get_network_info()
        .map_err(|_| VerifierError::LedgerClientError("getnetworkinfo".to_string()))?;

    // Convert the block height to a block hash.
    let block_hash = client
        .get_block_hash(u64::from(block_height))
        .map_err(|_| VerifierError::LedgerClientError("getblockhash".to_string()))?;

    Ok((block_hash, tx_index))
}

/// Gets a Merkle proof for the given Bitcoin transaction via the RPC API.
pub fn merkle_proof(
    tx: &Transaction,
    block_hash: &BlockHash,
    client: Option<&bitcoincore_rpc::Client>,
) -> Result<Vec<u8>, TrustchainBitcoinError> {
    // If necessary, construct a Bitcoin RPC client to communicate with the ION Bitcoin node.
    if client.is_none() {
        let rpc_client = rpc_client();
        return merkle_proof(tx, block_hash, Some(&rpc_client));
    }
    Ok(client
        .unwrap()
        .get_tx_out_proof(&[tx.compute_txid()], Some(block_hash))?)
}

pub fn reverse_endianness(hex: &str) -> Result<String, hex::FromHexError> {
    let mut bytes = hex::decode(hex)?;
    bytes.reverse();
    Ok(hex::encode(bytes))
}

pub fn int_to_little_endian_hex(int: &u32) -> String {
    let hex = format!("{:x}", int);
    reverse_endianness(&hex).unwrap()
}

/// Gets the block time at a particular height, as a Unix time.
pub fn time_at_block_height(
    block_height: u64,
    client: Option<&bitcoincore_rpc::Client>,
) -> Result<u64, TrustchainBitcoinError> {
    // If necessary, construct a Bitcoin RPC client to communicate with the ION Bitcoin node.
    if client.is_none() {
        let rpc_client = rpc_client();
        return time_at_block_height(block_height, Some(&rpc_client));
    };
    match client
        .unwrap()
        .get_block_stats_fields(block_height, &[BlockStatsFields::Time])?
        .time
    {
        Some(time) => Ok(time),
        None => Err(TrustchainBitcoinError::BlockTimeAtHeightError(block_height)),
    }
}

/// Returns the unix timestamp at 00h:00m:00s UTC on the given date.
fn first_unixtime_on(date: NaiveDate) -> i64 {
    let datetime = date.and_hms_opt(0, 0, 0).unwrap();
    datetime.and_utc().timestamp()
}

/// Returns the height of the last block mined before the given date.
pub fn last_block_height_before(
    date: NaiveDate,
    start_height: Option<u64>,
    client: Option<&bitcoincore_rpc::Client>,
) -> Result<u64, TrustchainBitcoinError> {
    // If necessary, construct a Bitcoin RPC client to communicate with the ION Bitcoin node.
    if client.is_none() {
        let rpc_client = rpc_client();
        return last_block_height_before(date, start_height, Some(&rpc_client));
    }
    let client = client.unwrap();

    // Following https://github.com/kristapsk/bitcoin-scripts/blob/master/blockheightat.sh

    let mut start_height = start_height.unwrap_or(1);
    let start_unixtime = time_at_block_height(start_height, Some(client))?;
    let target_unixtime = first_unixtime_on(date);

    if target_unixtime < start_unixtime as i64 {
        return Err(TrustchainBitcoinError::TargetDateOutOfRange);
    }

    let mut end_height = client.get_block_count()?; // Latest block height
    let end_unixtime = time_at_block_height(end_height, Some(client))?;

    if target_unixtime >= end_unixtime as i64 {
        return Err(TrustchainBitcoinError::TargetDateOutOfRange);
    }

    while end_height - start_height > 1 {
        let current_height = (start_height + end_height) / 2; // Rounds down.
        let current_unixtime = time_at_block_height(current_height, Some(client))?;

        match (current_unixtime as i64).cmp(&target_unixtime) {
            // TODO CHECK: original script has: current_height - 1
            Ordering::Greater => end_height = current_height,
            // TODO CHECK: original script has: current_height + 1;
            Ordering::Less => start_height = current_height,
            // TODO: WHAT IF current_unixtime == target_unixtime?
            // (does the loop exit and is start_height the right result in that case?)
            Ordering::Equal => unimplemented!(),
        }
    }
    Ok(start_height)
}

/// Returns the range of block heights mined on the given date.
pub fn block_height_range_on_date(
    date: NaiveDate,
    start_height: Option<u64>,
    client: Option<&bitcoincore_rpc::Client>,
) -> Result<(u64, u64), TrustchainBitcoinError> {
    let first_block = last_block_height_before(date, start_height, client)? + 1;
    let next_date = date.succ_opt().unwrap();
    let last_block = last_block_height_before(next_date, Some(first_block), client)?;
    Ok((first_block, last_block))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidetree::CoreIndexFile;
    use flate2::read::GzDecoder;
    use futures::StreamExt;
    use ssi::{
        did::{Document, ServiceEndpoint},
        jwk::Params,
    };
    use std::str::FromStr;
    use trustchain_core::{
        data::{
            TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS, TEST_SIDETREE_DOCUMENT_SERVICE_AND_PROOF,
            TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF,
        },
        utils::{HasEndpoints, HasKeys},
    };

    const TEST_TRANSACTION: &str = r#"{"version":2,"lock_time":0,"input":[{"previous_output":"5953f37dfeb8343d67cde66e752da195c38c07395d1ce03002e71a10bd04dd71:1","script_sig":"473044022021cc3feacddcdda52b0f8313d6e753c3fcd9f6aafb53e52f4e3aae5c5bdef3ba02204774e9ae6f36e9c58a635d64af99a5c2a665cb1ad992a983d0e6f7feab0c0502012103d28a65a6d49287eaf550380b3e9f71cf711069664b2c20826d77f19a0c035507","sequence":4294967295,"witness":[]}],"output":[{"value":0,"script_pubkey":"6a34696f6e3a332e516d5276675a6d344a334a5378666b3477526a453275324869325537566d6f62596e7071687148355150364a3937"},{"value":15617133,"script_pubkey":"76a914c7f6630ac4f5e2a92654163bce280931631418dd88ac"}]}"#;

    #[test]
    fn test_get_keys_from_document() {
        let doc: Document = serde_json::from_str(TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF).unwrap();

        let result = doc.get_keys();
        assert!(result.as_ref().is_some());
        assert_eq!(result.as_ref().unwrap().len(), 1);

        // Check the values of the key's x & y coordinates.
        if let Params::EC(ec_params) = &result.unwrap().first().unwrap().params {
            assert!(ec_params.x_coordinate.is_some());
            assert!(ec_params.y_coordinate.is_some());
            if let (Some(x), Some(y)) = (&ec_params.x_coordinate, &ec_params.y_coordinate) {
                assert_eq!(
                    serde_json::to_string(x).unwrap(),
                    "\"RbIj1Y4jeqkn0cizEfxHZidD-GQouFmAtE6YCpxFjpg\""
                );
                assert_eq!(
                    serde_json::to_string(y).unwrap(),
                    "\"ZcbgNp3hrfp3cujZFKqgFS0uFGOn2Rk16Y9nOv0h15s\""
                );
            };
        } else {
            panic!();
        }

        // Now test with a Document containing two keys.
        let doc: Document = serde_json::from_str(TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS).unwrap();

        let result = doc.get_keys();
        assert!(result.as_ref().is_some());
        assert_eq!(result.as_ref().unwrap().len(), 2);
    }

    // #[test]
    // fn test_get_keys_from_document_state() {
    //     let chunk_file_json: Value = serde_json::from_str(TEST_CHUNK_FILE_CONTENT).unwrap();
    //     let deltas = content_deltas(&chunk_file_json).unwrap();
    //     // Note: this is the update commitment for the *second* delta in TEST_CHUNK_FILE_CONTENT.
    //     let update_commitment = "EiC0EdwzQcqMYNX_3aqoZNUau4AKOL3gXQ5Pz3ATi1q_iA";
    //     let doc_state = extract_doc_state(deltas, update_commitment).unwrap();

    //     let result = doc_state.get_keys();
    //     assert!(result.as_ref().is_some());
    //     assert_eq!(result.as_ref().unwrap().len(), 1);

    //     // Check the values of the key's x & y coordinates.
    //     if let Params::EC(ec_params) = &result.unwrap().first().unwrap().params {
    //         assert!(ec_params.x_coordinate.is_some());
    //         assert!(ec_params.y_coordinate.is_some());
    //         if let (Some(x), Some(y)) = (&ec_params.x_coordinate, &ec_params.y_coordinate) {
    //             assert_eq!(
    //                 serde_json::to_string(x).unwrap(),
    //                 "\"aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU\""
    //             );
    //             assert_eq!(
    //                 serde_json::to_string(y).unwrap(),
    //                 "\"dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0\""
    //             );
    //         };
    //     } else {
    //         panic!();
    //     }

    //     // Now test with a DocumentState containing two keys.
    //     let chunk_file_json: Value =
    //         serde_json::from_str(TEST_CHUNK_FILE_CONTENT_MULTIPLE_KEYS).unwrap();
    //     let deltas = content_deltas(&chunk_file_json).unwrap();
    //     // Note: this is the update commitment for the *second* delta in TEST_CHUNK_FILE_CONTENT.
    //     let update_commitment = "EiC0EdwzQcqMYNX_3aqoZNUau4AKOL3gXQ5Pz3ATi1q_iA";
    //     let doc_state = extract_doc_state(deltas, update_commitment).unwrap();

    //     let result = doc_state.get_keys();
    //     assert!(result.as_ref().is_some());
    //     assert_eq!(result.as_ref().unwrap().len(), 2);
    // }

    #[test]
    fn test_get_endpoints_from_document() {
        let doc: Document = serde_json::from_str(TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF).unwrap();

        let result = doc.get_endpoints();
        assert!(&result.is_some());
        let result = result.unwrap();
        assert_eq!(&result.len(), &1);
        let uri = match result.first().unwrap() {
            ServiceEndpoint::URI(x) => x,
            _ => panic!(),
        };
        assert_eq!(uri, "https://bar.example.com");

        // Now test with a DID document containing two ServiceEndpoints:
        let doc: Document = serde_json::from_str(TEST_SIDETREE_DOCUMENT_SERVICE_AND_PROOF).unwrap();

        let result = doc.get_endpoints();
        assert!(&result.is_some());
        let result = result.unwrap();

        // Expect two ServiceEndpoints. The first a Map and the second a URI.
        assert_eq!(&result.len(), &2);
        assert!(matches!(&result[0], ServiceEndpoint::Map { .. }));
        assert!(matches!(&result[1], ServiceEndpoint::URI { .. }));
        let uri = match &result[1] {
            ServiceEndpoint::URI(x) => x,
            _ => panic!(),
        };
        assert_eq!(uri, "https://bar.example.com");
    }

    // #[test]
    // fn test_get_endpoints_from_document_state() {
    //     let chunk_file_json: Value = serde_json::from_str(TEST_CHUNK_FILE_CONTENT).unwrap();
    //     let deltas = content_deltas(&chunk_file_json).unwrap();
    //     let update_commitment = "EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg";
    //     let doc_state = extract_doc_state(deltas, update_commitment).unwrap();

    //     let result = doc_state.get_endpoints();
    //     assert!(&result.is_some());
    //     let result = result.unwrap();
    //     assert_eq!(&result.len(), &1);
    //     let uri = match result.first().unwrap() {
    //         ServiceEndpoint::URI(x) => x,
    //         _ => panic!(),
    //     };

    //     assert_eq!(uri, "https://identity.foundation/ion/trustchain-root");

    //     // Now test with DocumentState containing two service endpoints.
    //     let chunk_file_json: Value =
    //         serde_json::from_str(TEST_CHUNK_FILE_CONTENT_MULTIPLE_SERVICES).unwrap();
    //     let deltas = content_deltas(&chunk_file_json).unwrap();
    //     let update_commitment = "EiC0EdwzQcqMYNX_3aqoZNUau4AKOL3gXQ5Pz3ATi1q_iA";
    //     let doc_state = extract_doc_state(deltas, update_commitment).unwrap();

    //     let result = doc_state.get_endpoints();
    //     assert!(&result.is_some());
    //     let result = result.unwrap();
    //     assert_eq!(&result.len(), &2);
    // }

    #[tokio::test]
    #[ignore = "Integration test requires IPFS"]
    async fn test_query_ipfs() {
        let cid = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";

        let ipfs_client = IpfsClient::default();
        let result = query_ipfs(cid, &ipfs_client).await.unwrap();

        // Decompress the content and deserialize to JSON.
        let mut decoder = GzDecoder::new(&result[..]);
        let mut ipfs_content_str = String::new();
        decoder.read_to_string(&mut ipfs_content_str).unwrap();
        let core_index_file: CoreIndexFile = serde_json::from_str(&ipfs_content_str).unwrap();

        // The CID is the address of a core index file, so the JSON result
        // contains the key "provisionalIndexFileUri".
        assert!(core_index_file.provisional_index_file_uri.is_some());

        // Expect an invalid CID to fail.
        let cid = "PmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        assert!(query_ipfs(cid, &ipfs_client).await.is_err());
    }

    #[tokio::test]
    #[ignore = "Integration test requires MongoDB"]
    async fn test_query_mongodb() {
        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                let suffix = "EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
                let doc = query_mongodb(suffix).await.unwrap();
                let block_height: i32 = doc.get_i32("txnTime").unwrap();
                assert_eq!(block_height, 2377445);
            }
            Network::Testnet4 => {
                let suffix = "EiA6o-kI_QCKqwJ53WftfdWWhUH7W9QtK7PhyaF47BZBzg";
                let doc = query_mongodb(suffix).await.unwrap();
                let block_height: i32 = doc.get_i32("txnTime").unwrap();
                assert_eq!(block_height, 75432);
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }
    }

    #[tokio::test]
    #[ignore = "Integration test requires MongoDB"]
    async fn test_query_mongodb_on_interval_short() {
        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                let mut result = query_mongodb_on_interval(1902375, 1902377).await.unwrap();

                let mut dids: Vec<String> = Vec::new();
                assert_eq!(dids.len(), 0);
                while let Some(doc) = result.next().await {
                    dids.push(
                        doc.unwrap()
                            .get_str(MONGO_FILTER_DID_SUFFIX)
                            .unwrap()
                            .to_owned(),
                    );
                }

                // Two ION operations with opIndex = 0 exist on testnet during this interval.
                // db.operations.find({opIndex: 0, txnTime: { $gte: 1902375, $lte: 1902377}})
                assert_eq!(dids.len(), 2);
                assert!(dids.contains(&String::from(
                    "EiDlkji8etHKKZl58SQNx02_HHSJkotwYmDqF77AfVvPtA"
                )));
                assert!(dids.contains(&String::from(
                    "EiDYpQWYf_vkSm60EeNqWys6XTZYvg6UcWrRI9Mh12DuLQ"
                )));
            }
            Network::Testnet4 => {
                let mut result = query_mongodb_on_interval(75422, 75432).await.unwrap();

                let mut dids: Vec<String> = Vec::new();
                assert_eq!(dids.len(), 0);
                while let Some(doc) = result.next().await {
                    dids.push(
                        doc.unwrap()
                            .get_str(MONGO_FILTER_DID_SUFFIX)
                            .unwrap()
                            .to_owned(),
                    );
                }

                // Two ION operations with opIndex = 0 exist on testnet during this interval.
                // db.operations.find({opIndex: 0, txnTime: { $gte: 75422, $lte: 75432}})
                // Both operations relate to the same DID:
                assert_eq!(dids.len(), 2);
                assert!(dids.contains(&String::from(
                    "EiAsi4efXUijeTw7OTEeETzcBC5hZJJ8u9ybzjGeMcXdIA"
                )));
                assert_eq!(dids[0], dids[1]);
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }
    }

    #[tokio::test]
    #[ignore = "Integration test requires MongoDB"]
    async fn test_query_mongodb_on_interval_long() {
        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                let result = query_mongodb_on_interval(2377360, 2377519).await.unwrap();
                let docs = result
                    .try_collect::<Vec<mongodb::bson::Document>>()
                    .await
                    .unwrap();

                // There are 38 testnet ION create operations with opIndex = 0 testnet during this interval.
                // db.operations.find({type: 'create', opIndex: 0, txnTime: { $gte: 2377360, $lte: 2377519}})
                assert_eq!(docs.len(), 38);
            }
            Network::Testnet4 => {
                let result = query_mongodb_on_interval(75422, 92219).await.unwrap();
                let docs = result
                    .try_collect::<Vec<mongodb::bson::Document>>()
                    .await
                    .unwrap();

                // There are four Testnet4 ION create operations with opIndex = 0 testnet during this interval.
                // db.operations.find({type: 'create', opIndex: 0, txnTime: { $gte: 75422, $lte: 92219}})
                assert_eq!(docs.len(), 4);
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }
    }

    #[test]
    #[ignore = "Integration test requires Bitcoin"]
    fn test_transaction() {
        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                // The transaction can be found on-chain inside this block (indexed 3, starting from 0):
                // https://blockstream.info/testnet/block/000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f
                let block_hash = BlockHash::from_str(
                    "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f",
                )
                .unwrap();
                let tx_index = 3;
                let result = transaction(&block_hash, tx_index, None);

                assert!(result.is_ok());
                let tx = result.unwrap();

                // Expected transaction ID:
                let expected = "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
                assert_eq!(tx.compute_txid().to_string(), expected);

                // Expect a different transaction ID to fail.
                let not_expected =
                    "8dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
                assert_ne!(tx.compute_txid().to_string(), not_expected);
            }
            Network::Testnet4 => {
                // The transaction can be found on-chain inside this block (indexed 66, starting from 0):
                // https://mempool.space/testnet4/block/0000000000000000a2d13f2c71c739e9e61e576bb3a0759c71befae09a5a8f40
                let block_hash = BlockHash::from_str(
                    "0000000000000000a2d13f2c71c739e9e61e576bb3a0759c71befae09a5a8f40",
                )
                .unwrap();
                let tx_index = 66;
                let result = transaction(&block_hash, tx_index, None);

                assert!(result.is_ok());
                let tx = result.unwrap();

                // Expected transaction ID:
                let expected = "7d0413f646550b8ac6b4a82346b8f78df1f7d451f892bf2533893ba9558b082b";
                assert_eq!(tx.compute_txid().to_string(), expected);

                // Expect a different transaction ID to fail.
                let not_expected =
                    "7d4ef05d7e83c2731bebb6ce1fe739bb9c994bb6063bb87606b029462faec3a1";
                assert_ne!(tx.compute_txid().to_string(), not_expected);
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }
    }

    #[tokio::test]
    #[ignore = "Integration test requires MongoDB"]
    async fn test_locate_transaction() {
        let client = rpc_client();

        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                let did = "did:ion:test:EiDYpQWYf_vkSm60EeNqWys6XTZYvg6UcWrRI9Mh12DuLQ";
                let (block_hash, transaction_index) =
                    locate_transaction(did, &client).await.unwrap();
                // Block 1902377
                let expected_block_hash = BlockHash::from_str(
                    "00000000e89bddeae5ad5589dfa4a7ea76ad9c83b0d711b5e6d4ee515ace6447",
                )
                .unwrap();
                assert_eq!(block_hash, expected_block_hash);
                assert_eq!(transaction_index, 118);

                let did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
                let (block_hash, transaction_index) =
                    locate_transaction(did, &client).await.unwrap();
                // Block 2377445
                let expected_block_hash = BlockHash::from_str(
                    "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f",
                )
                .unwrap();
                assert_eq!(block_hash, expected_block_hash);
                assert_eq!(transaction_index, 3);

                let did = "did:ion:test:EiBP_RYTKG2trW1_SN-e26Uo94I70a8wB4ETdHy48mFfMQ";
                let (block_hash, transaction_index) =
                    locate_transaction(did, &client).await.unwrap();
                // Block 2377339
                let expected_block_hash = BlockHash::from_str(
                    "000000000000003fadd15bdd2b55994371b832c6251781aa733a2a9e8865162b",
                )
                .unwrap();
                assert_eq!(block_hash, expected_block_hash);
                assert_eq!(transaction_index, 10);

                // Invalid DID
                let invalid_did = "did:ion:test:EiCClfEdkTv_aM3UnBBh10V89L1GhpQAbfeZLFdFxVFkEg";
                let result = locate_transaction(invalid_did, &client).await;
                assert!(result.is_err());
            }
            Network::Testnet4 => {
                let did = "did:ion:test:EiA6o-kI_QCKqwJ53WftfdWWhUH7W9QtK7PhyaF47BZBzg";
                let (block_hash, transaction_index) =
                    locate_transaction(did, &client).await.unwrap();
                // Block 75432
                let expected_block_hash = BlockHash::from_str(
                    "0000000000000000a2d13f2c71c739e9e61e576bb3a0759c71befae09a5a8f40",
                )
                .unwrap();
                assert_eq!(block_hash, expected_block_hash);
                assert_eq!(transaction_index, 66);

                let did = "did:ion:test:EiBt8NTmSKf3jt_FMKf-r6JMSJIp7njcTTPe24USYu4B9w";
                let (block_hash, transaction_index) =
                    locate_transaction(did, &client).await.unwrap();
                // Block 75425
                let expected_block_hash = BlockHash::from_str(
                    "000000000b91285d8d7943ee85b9471e3e807571eba2ba6439fb0f7eab5f3b08",
                )
                .unwrap();
                assert_eq!(block_hash, expected_block_hash);
                assert_eq!(transaction_index, 120);

                let did = "did:ion:test:EiCKLQjzVNl0R7UCUW74JH_FN5VyfxWpL1IX1FUYTJ4uIA";
                let (block_hash, transaction_index) =
                    locate_transaction(did, &client).await.unwrap();
                // Block 92219
                let expected_block_hash = BlockHash::from_str(
                    "0000000000000003ba24b7ed918955105d4c488c0d7d0a2bcaface7f889b1993",
                )
                .unwrap();
                assert_eq!(block_hash, expected_block_hash);
                assert_eq!(transaction_index, 586);

                // Invalid DID
                let invalid_did = "did:ion:test:EiCClfEdkTv_aM3UnBBh10V89L1GhpQAbfeZLFdFxVFkEg";
                let result = locate_transaction(invalid_did, &client).await;
                assert!(result.is_err());
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }
    }

    #[test]
    fn test_tx_to_op_return_data() {
        // The transaction, including OP_RETURN data, can be found on-chain (on Testnet3) at:
        // https://blockstream.info/testnet/tx/9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c
        let expected = "ion:3.QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let tx: Transaction = serde_json::from_str(TEST_TRANSACTION).unwrap();
        let actual = tx_to_op_return_data(&tx).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_tx_to_op_return_cid() {
        // The transaction, including OP_RETURN data, can be found on-chain (on Testnet3) at:
        // https://blockstream.info/testnet/tx/9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c
        let expected = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let tx: Transaction = serde_json::from_str(TEST_TRANSACTION).unwrap();
        let actual = tx_to_op_return_cid(&tx).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    #[ignore = "Integration test requires Bitcoin"]
    fn test_time_at_block_height() {
        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                // The block can be found on-chain at:
                // https://blockstream.info/testnet/block/000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f
                let block_height = 2377445;
                let result = time_at_block_height(block_height, None);

                assert!(result.is_ok());
                let time = result.unwrap();
                let expected = 1666265405;
                assert_eq!(time, expected);
            }
            Network::Testnet4 => {
                // The block can be found on-chain at:
                // https://mempool.space/testnet4/block/0000000000000003ba24b7ed918955105d4c488c0d7d0a2bcaface7f889b1993
                let block_height = 92219;
                let result = time_at_block_height(block_height, None);

                assert!(result.is_ok());
                let time = result.unwrap();
                let expected = 1753028520;
                assert_eq!(time, expected);
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }
    }

    #[test]
    #[ignore = "Integration test requires Bitcoin"]
    fn test_last_block_height_before() {
        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                let date = NaiveDate::from_ymd_opt(2022, 10, 20).unwrap();
                let result = last_block_height_before(date, None, None).unwrap();

                // The first testnet block mined on 2022-10-20 (UTC) was at height 2377360.
                assert_eq!(result, 2377359);

                let date = NaiveDate::from_ymd_opt(2023, 9, 16).unwrap();
                let result = last_block_height_before(date, None, None).unwrap();

                // The first testnet block mined on 2023-09-16 (UTC) was at height 2501917.
                assert_eq!(result, 2501916);
            }
            Network::Testnet4 => {
                let date = NaiveDate::from_ymd_opt(2025, 10, 20).unwrap();
                let result = last_block_height_before(date, None, None).unwrap();

                // The first Testnet4 block mined on 2025-10-20 (UTC) was at height 107252.
                assert_eq!(result, 107251);

                let date = NaiveDate::from_ymd_opt(2024, 11, 16).unwrap();
                let result = last_block_height_before(date, None, None).unwrap();

                // The first Testnet4 block mined on 2023-11-16 (UTC) was at height 54540.
                assert_eq!(result, 54539);

                let date = NaiveDate::from_ymd_opt(2023, 9, 16).unwrap();
                let result = last_block_height_before(date, None, None);

                // Testnet4 did not exist on 2023-09-16 (UTC).
                assert!(result.is_err());
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }
    }

    #[test]
    #[ignore = "Integration test requires Bitcoin"]
    fn test_block_range_on_date() {
        match BITCOIN_NETWORK
            .as_ref()
            .expect("Integration test requires Bitcoin")
        {
            Network::Testnet => {
                let date = NaiveDate::from_ymd_opt(2022, 10, 20).unwrap();
                let result = block_height_range_on_date(date, None, None).unwrap();

                // The first testnet block mined on 2022-10-20 (UTC) was at height 2377360.
                // The last testnet block mined on 2022-10-20 (UTC) was at height 2377519.
                assert_eq!(result, (2377360, 2377519));
            }
            Network::Testnet4 => {
                let date = NaiveDate::from_ymd_opt(2025, 10, 20).unwrap();
                let result = block_height_range_on_date(date, None, None).unwrap();

                // The first testnet block mined on 2025-10-20 (UTC) was at height 107252.
                // The last testnet block mined on 2025-10-20 (UTC) was at height 107379.
                assert_eq!(result, (107252, 107379));
            }
            network @ _ => {
                panic!("No test fixtures for network: {:?}", network);
            }
        }
    }
}

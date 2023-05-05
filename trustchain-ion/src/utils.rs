//! Utils module.
use crate::config::ion_config;
use bitcoin::{BlockHash, BlockHeader, Transaction};
use bitcoincore_rpc::RpcApi;
use flate2::read::GzDecoder;
use futures::TryStreamExt;
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient};
use mongodb::{bson::doc, options::ClientOptions};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use trustchain_core::verifier::VerifierError;

use crate::{
    TrustchainBitcoinError, TrustchainIpfsError, TrustchainMongodbError, BITS_KEY,
    HASH_PREV_BLOCK_KEY, MERKLE_ROOT_KEY, MONGO_COLLECTION_OPERATIONS, MONGO_CREATE_OPERATION,
    MONGO_FILTER_DID_SUFFIX, MONGO_FILTER_TYPE, NONCE_KEY, TIMESTAMP_KEY, VERSION_KEY,
};

const ION_METHOD_WITH_DELIMITER: &str = "ion:";
const ION_OPERATION_COUNT_DELIMITER: &str = ".";
const DID_DELIMITER: &str = ":";

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
        0 => Err(VerifierError::NoDIDContentIdentifier(tx.txid().to_string())),
        1 => Ok(extracted.first().unwrap().to_string()),
        _ => Err(VerifierError::MultipleDIDContentIdentifiers(
            tx.txid().to_string(),
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
pub fn decode_ipfs_content(ipfs_file: &[u8]) -> Result<Value, TrustchainIpfsError> {
    // Decompress the content and deserialise to JSON.
    let mut decoder = GzDecoder::new(ipfs_file);
    let mut ipfs_content_str = String::new();
    decoder.read_to_string(&mut ipfs_content_str)?;
    Ok(serde_json::from_str(&ipfs_content_str)?)
}

/// Queries the ION MongoDB for a DID operation.
pub async fn query_mongodb(
    did: &str,
    client: Option<mongodb::Client>,
) -> Result<mongodb::bson::Document, TrustchainMongodbError> {
    // If necessary, construct a MongoDB client.
    let client = match client {
        Some(x) => x,
        None => {
            let client_options = ClientOptions::parse(&ion_config().mongo_connection_string)
                .await
                .map_err(TrustchainMongodbError::ErrorCreatingClient)?;
            mongodb::Client::with_options(client_options)
                .map_err(TrustchainMongodbError::ErrorCreatingClient)?
        }
    };

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

/// Gets a Bitcoin block header via the RPC API.
pub fn block_header(
    block_hash: &BlockHash,
    client: Option<&bitcoincore_rpc::Client>,
) -> Result<BlockHeader, TrustchainBitcoinError> {
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
        .get_tx_out_proof(&[tx.txid()], Some(block_hash))?)
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

#[cfg(test)]
mod tests {
    use core::panic;
    use std::io::Read;
    use std::str::FromStr;

    use super::*;
    use crate::sidetree::CoreIndexFile;
    use flate2::read::GzDecoder;
    use ssi::{
        did::{Document, ServiceEndpoint},
        jwk::Params,
    };
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

    #[tokio::test]
    #[ignore = "integration test requires IPFS"]
    async fn test_query_ipfs() {
        let cid = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";

        let ipfs_client = IpfsClient::default();
        let result = query_ipfs(cid, &ipfs_client).await.unwrap();

        // Decompress the content and deserialise to JSON.
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
    #[ignore = "integration test requires MongoDB"]
    async fn test_query_mongodb() {
        let suffix = "EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
        let doc = query_mongodb(suffix, None).await.unwrap();
        let block_height: i32 = doc.get_i32("txnTime").unwrap();
        assert_eq!(block_height, 2377445);
    }

    #[test]
    #[ignore = "integration test requires Bitcoin"]
    fn test_transaction() {
        // The transaction can be found on-chain inside this block (indexed 3, starting from 0):
        // https://blockstream.info/testnet/block/000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f
        let block_hash =
            BlockHash::from_str("000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f")
                .unwrap();
        let tx_index = 3;
        let result = transaction(&block_hash, tx_index, None);

        assert!(result.is_ok());
        let tx = result.unwrap();

        // Expected transaction ID:
        let expected = "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        assert_eq!(tx.txid().to_string(), expected);

        // Expect a different transaction ID to fail.
        let not_expected = "8dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        assert_ne!(tx.txid().to_string(), not_expected);
    }

    #[test]
    fn test_tx_to_op_return_data() {
        // The transaction, including OP_RETURN data, can be found on-chain:
        // https://blockstream.info/testnet/tx/9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c
        let expected = "ion:3.QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let tx: Transaction = serde_json::from_str(TEST_TRANSACTION).unwrap();
        let actual = tx_to_op_return_data(&tx).unwrap();
        assert_eq!(expected, actual);
    }
    #[test]
    fn test_tx_to_op_return_cid() {
        // The transaction, including OP_RETURN data, can be found on-chain:
        // https://blockstream.info/testnet/tx/9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c
        let expected = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let tx: Transaction = serde_json::from_str(TEST_TRANSACTION).unwrap();
        let actual = tx_to_op_return_cid(&tx).unwrap();
        assert_eq!(expected, actual);
    }
}

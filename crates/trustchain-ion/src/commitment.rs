//! Implementation of `Commitment` API for ION DID method.
use bitcoin::util::psbt::serialize::Deserialize;
use bitcoin::MerkleBlock;
use bitcoin::Transaction;
use ipfs_hasher::IpfsHasher;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use ssi::did::Document;
use std::convert::TryInto;
use std::marker::PhantomData;
use trustchain_core::commitment::TimestampCommitment;
use trustchain_core::commitment::{ChainedCommitment, CommitmentChain, CommitmentResult};
use trustchain_core::commitment::{Commitment, CommitmentError};
use trustchain_core::commitment::{DIDCommitment, TrivialCommitment};
use trustchain_core::utils::{HasEndpoints, HasKeys};
use trustchain_core::verifier::Timestamp;

use crate::sidetree::CoreIndexFile;
use crate::utils::tx_to_op_return_cid;
use crate::utils::{decode_block_header, decode_ipfs_content, reverse_endianness};
use crate::MERKLE_ROOT_KEY;
use crate::TIMESTAMP_KEY;

const CID_KEY: &str = "cid";
const DELTAS_KEY: &str = "deltas";

fn ipfs_hasher() -> fn(&[u8]) -> CommitmentResult<String> {
    |x| Ok(IpfsHasher::default().compute(x))
}

fn ipfs_decode_candidate_data() -> fn(&[u8]) -> CommitmentResult<Value> {
    |x| decode_ipfs_content(x, true).map_err(|_| CommitmentError::DataDecodingFailure)
}

fn block_header_hasher() -> fn(&[u8]) -> CommitmentResult<String> {
    // Candidate data the block header bytes.
    |x| {
        // Bitcoin block hash is a double SHA256 hash of the block header.
        // We use a generic sha2 crate to avoid trust in rust-bitcoin.
        let double_hash_hex = hex::encode(Sha256::digest(Sha256::digest(x)));
        // For leading (not trailing) zeros, convert the hex to big-endian.
        Ok(reverse_endianness(&double_hash_hex).unwrap())
    }
}

fn block_header_decoder() -> fn(&[u8]) -> CommitmentResult<Value> {
    |x| {
        if x.len() != 80 {
            return Err(CommitmentError::DataDecodingError(
                "Error: Bitcoin block header must be 80 bytes.".to_string(),
            ));
        };
        let decoded_header = decode_block_header(x.try_into().map_err(|err| {
            CommitmentError::DataDecodingError(format!(
                "Error: Bitcoin block header must be 80 bytes with error: {err}"
            ))
        })?);

        match decoded_header {
            Ok(x) => Ok(x),
            Err(e) => Err(CommitmentError::DataDecodingError(format!(
                "Error decoding Bitcoin block header: {}.",
                e
            ))),
        }
    }
}

/// Unit struct for incomplete commitments.
pub struct Incomplete;
/// Unit struct for complete commitments.
pub struct Complete;

/// A Commitment whose hash is an IPFS content identifier (CID) for an ION Index file.
pub struct IpfsIndexFileCommitment<T = Incomplete> {
    candidate_data: Vec<u8>,
    expected_data: Option<Value>,
    _state: PhantomData<T>, // Dummy field for type marker
}

impl IpfsIndexFileCommitment<Incomplete> {
    pub fn new(candidate_data: Vec<u8>) -> Self {
        Self {
            candidate_data,
            expected_data: None,
            _state: PhantomData::<Incomplete>,
        }
    }
}

impl IpfsIndexFileCommitment<Complete> {
    pub fn new(candidate_data: Vec<u8>, expected_data: Value) -> Self {
        Self {
            candidate_data,
            expected_data: Some(expected_data),
            _state: PhantomData::<Complete>,
        }
    }
}

impl<T> TrivialCommitment for IpfsIndexFileCommitment<T> {
    fn hasher(&self) -> fn(&[u8]) -> CommitmentResult<String> {
        ipfs_hasher()
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    fn decode_candidate_data(&self) -> fn(&[u8]) -> CommitmentResult<Value> {
        ipfs_decode_candidate_data()
    }

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        Box::new(IpfsIndexFileCommitment::<Complete>::new(
            self.candidate_data,
            expected_data,
        ))
    }
}

impl Commitment for IpfsIndexFileCommitment<Complete> {
    fn expected_data(&self) -> &serde_json::Value {
        // Safe to unwrap as a complete commitment must have expected data
        self.expected_data.as_ref().unwrap()
    }
}

/// A Commitment whose hash is an IPFS content identifier (CID) for an ION chunk file.
pub struct IpfsChunkFileCommitment<T = Incomplete> {
    candidate_data: Vec<u8>,
    delta_index: usize,
    expected_data: Option<Value>,
    _state: PhantomData<T>, // Dummy field for type marker
}
impl IpfsChunkFileCommitment<Incomplete> {
    pub fn new(candidate_data: Vec<u8>, delta_index: usize) -> Self {
        Self {
            candidate_data,
            delta_index,
            expected_data: None,
            _state: PhantomData::<Incomplete>,
        }
    }
}
impl IpfsChunkFileCommitment<Complete> {
    pub fn new(candidate_data: Vec<u8>, delta_index: usize, expected_data: Value) -> Self {
        Self {
            candidate_data,
            delta_index,
            expected_data: Some(expected_data),
            _state: PhantomData::<Complete>,
        }
    }
}

impl<T> TrivialCommitment for IpfsChunkFileCommitment<T> {
    fn hasher(&self) -> fn(&[u8]) -> CommitmentResult<String> {
        ipfs_hasher()
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    fn filter(&self) -> Option<Box<dyn Fn(&serde_json::Value) -> CommitmentResult<Value>>> {
        // Ignore all of the deltas in the chunk file except the one at index delta_index
        // (which is the one corresponding to the relevant DID).
        let delta_index = self.delta_index;
        Some(Box::new(move |value| {
            // Note: check if mix of create, recover and deactivate whether the correct index is used.
            // TODO: Remove in future releases.
            if let Value::Object(map) = value {
                match map.get(DELTAS_KEY) {
                    Some(Value::Array(deltas)) => Ok(deltas.get(delta_index).unwrap().clone()),
                    _ => Err(CommitmentError::DataDecodingFailure),
                }
            } else {
                Err(CommitmentError::DataDecodingFailure)
            }
        }))
    }
    fn decode_candidate_data(&self) -> fn(&[u8]) -> CommitmentResult<Value> {
        ipfs_decode_candidate_data()
    }
    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        Box::new(IpfsChunkFileCommitment::<Complete>::new(
            self.candidate_data,
            self.delta_index,
            expected_data,
        ))
    }
}

impl Commitment for IpfsChunkFileCommitment<Complete> {
    fn expected_data(&self) -> &serde_json::Value {
        // Safe to unwrap as a complete commitment must have expected data
        self.expected_data.as_ref().unwrap()
    }
}

/// A Commitment whose hash is a Bitcoin transaction ID.
pub struct TxCommitment<T = Incomplete> {
    candidate_data: Vec<u8>,
    expected_data: Option<Value>,
    _state: PhantomData<T>, // Dummy field for type marker
}

impl TxCommitment<Incomplete> {
    pub fn new(candidate_data: Vec<u8>) -> Self {
        Self {
            candidate_data,
            expected_data: None,
            _state: PhantomData::<Incomplete>,
        }
    }
}

impl TxCommitment<Complete> {
    pub fn new(candidate_data: Vec<u8>, expected_data: Value) -> Self {
        Self {
            candidate_data,
            expected_data: Some(expected_data),
            _state: PhantomData::<Complete>,
        }
    }
}

impl<T> TrivialCommitment for TxCommitment<T> {
    fn hasher(&self) -> fn(&[u8]) -> CommitmentResult<String> {
        // Candidate data is a Bitcoin transaction, whose hash is the transaction ID.
        |x| {
            let tx: Transaction = match Deserialize::deserialize(x) {
                Ok(tx) => tx,
                Err(e) => {
                    return Err(CommitmentError::FailedToComputeHash(format!(
                        "Failed to deserialize transaction: {}",
                        e
                    )));
                }
            };
            Ok(tx.txid().to_string())
        }
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    /// Deserializes the candidate data into a Bitcoin transaction, then
    /// extracts and returns the IPFS content identifier in the OP_RETURN data.
    fn decode_candidate_data(&self) -> fn(&[u8]) -> CommitmentResult<Value> {
        |x| {
            // Deserialize the transaction from the candidate data.
            let tx: Transaction = match Deserialize::deserialize(x) {
                Ok(tx) => tx,
                Err(e) => {
                    return Err(CommitmentError::DataDecodingError(format!(
                        "Failed to deserialize transaction: {}",
                        e
                    )));
                }
            };
            // // Extract the IPFS content identifier from the ION OP_RETURN data.
            let cid = tx_to_op_return_cid(&tx)
                .map_err(|e| CommitmentError::DataDecodingError(e.to_string()))?;
            Ok(json!({ CID_KEY: cid }))
        }
    }
    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        Box::new(TxCommitment::<Complete>::new(
            self.candidate_data,
            expected_data,
        ))
    }
}

impl Commitment for TxCommitment<Complete> {
    fn expected_data(&self) -> &serde_json::Value {
        // Safe to unwrap as a complete commitment must have expected data
        self.expected_data.as_ref().unwrap()
    }
}

/// A Commitment whose hash is the root of a Merkle tree of Bitcoin transaction IDs.
pub struct MerkleRootCommitment<T = Incomplete> {
    candidate_data: Vec<u8>,
    expected_data: Option<Value>,
    _state: PhantomData<T>, // Dummy field for type marker
}

impl MerkleRootCommitment<Incomplete> {
    pub fn new(candidate_data: Vec<u8>) -> Self {
        Self {
            candidate_data,
            expected_data: None,
            _state: PhantomData::<Incomplete>,
        }
    }
}
impl MerkleRootCommitment<Complete> {
    pub fn new(candidate_data: Vec<u8>, expected_data: Value) -> Self {
        Self {
            candidate_data,
            expected_data: Some(expected_data),
            _state: PhantomData::<Complete>,
        }
    }
}

impl<T> TrivialCommitment for MerkleRootCommitment<T> {
    fn hasher(&self) -> fn(&[u8]) -> CommitmentResult<String> {
        // Candidate data is a Merkle proof containing a branch of transaction IDs.
        |x| {
            let merkle_block: MerkleBlock = match bitcoin::consensus::deserialize(x) {
                Ok(mb) => mb,
                Err(e) => {
                    return Err(CommitmentError::FailedToComputeHash(format!(
                        "Failed to deserialize MerkleBlock: {:?}",
                        e
                    )));
                }
            };
            // Traverse the PartialMerkleTree to obtain the Merkle root.
            match merkle_block.txn.extract_matches(&mut vec![], &mut vec![]) {
                Ok(merkle_root) => Ok(merkle_root.to_string()),
                Err(e) => Err(CommitmentError::FailedToComputeHash(format!(
                    "Failed to obtain Merkle root from PartialMerkleTree: {:?}",
                    e
                ))),
            }
        }
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    /// Deserializes the candidate data into a Merkle proof.
    fn decode_candidate_data(&self) -> fn(&[u8]) -> CommitmentResult<Value> {
        |x| {
            let merkle_block: MerkleBlock = match bitcoin::consensus::deserialize(x) {
                Ok(mb) => mb,
                Err(e) => {
                    return Err(CommitmentError::DataDecodingError(format!(
                        "Failed to deserialize MerkleBlock: {:?}",
                        e
                    )));
                }
            };
            // Get the hashes in the Merkle proof as a vector of strings.
            let hashes_vec: Vec<String> = merkle_block
                .txn
                .hashes()
                .iter()
                .map(|x| x.to_string())
                .collect();

            // Convert to a JSON value.
            Ok(serde_json::json!(hashes_vec))
        }
    }

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        Box::new(MerkleRootCommitment::<Complete>::new(
            self.candidate_data,
            expected_data,
        ))
    }
}

impl Commitment for MerkleRootCommitment<Complete> {
    fn expected_data(&self) -> &serde_json::Value {
        // Safe to unwrap as a complete commitment must have expected data
        self.expected_data.as_ref().unwrap()
    }
}

/// A Commitment whose hash is the PoW hash of a Bitcoin block.
pub struct BlockHashCommitment<T = Incomplete> {
    candidate_data: Vec<u8>,
    expected_data: Option<Value>,
    _state: PhantomData<T>, // Dummy field for type marker
}

impl BlockHashCommitment<Incomplete> {
    pub fn new(candidate_data: Vec<u8>) -> Self {
        Self {
            candidate_data,
            expected_data: None,
            _state: PhantomData::<Incomplete>,
        }
    }
}

impl BlockHashCommitment<Complete> {
    pub fn new(candidate_data: Vec<u8>, expected_data: Value) -> Self {
        Self {
            candidate_data,
            expected_data: Some(expected_data),
            _state: PhantomData::<Complete>,
        }
    }
}

impl<T> TrivialCommitment for BlockHashCommitment<T> {
    fn hasher(&self) -> fn(&[u8]) -> CommitmentResult<String> {
        block_header_hasher()
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    /// Deserializes the candidate data into a Block header (as JSON).
    fn decode_candidate_data(&self) -> fn(&[u8]) -> CommitmentResult<Value> {
        block_header_decoder()
    }

    /// Override the filter method to ensure only the Merkle root content is considered.
    fn filter(&self) -> Option<Box<dyn Fn(&serde_json::Value) -> CommitmentResult<Value>>> {
        Some(Box::new(move |value| {
            if let Value::Object(map) = value {
                match map.get(MERKLE_ROOT_KEY) {
                    Some(Value::String(str)) => Ok(Value::String(str.clone())),
                    _ => Err(CommitmentError::DataDecodingFailure),
                }
            } else {
                Err(CommitmentError::DataDecodingFailure)
            }
        }))
    }

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        Box::new(BlockHashCommitment::<Complete>::new(
            self.candidate_data,
            expected_data,
        ))
    }
}

impl Commitment for BlockHashCommitment<Complete> {
    fn expected_data(&self) -> &serde_json::Value {
        // Safe to unwrap as a complete commitment must have expected data
        self.expected_data.as_ref().unwrap()
    }
}

/// A commitment to ION DID Document data.
pub struct IONCommitment {
    did_doc: Document,
    chained_commitment: ChainedCommitment,
}

impl IONCommitment {
    pub fn new(
        did_doc: Document,
        chunk_file: Vec<u8>,
        provisional_index_file: Vec<u8>,
        core_index_file: Vec<u8>,
        transaction: Vec<u8>,
        merkle_proof: Vec<u8>,
        block_header: Vec<u8>,
    ) -> CommitmentResult<Self> {
        // Extract the public keys and endpoints as the expected data.
        let keys = match did_doc.get_keys() {
            Some(x) => x,
            None => vec![],
        };
        let endpoints = match did_doc.get_endpoints() {
            Some(x) => x,
            None => vec![],
        };
        let expected_data = json!([keys, endpoints]);

        // Construct the core index file commitment first, to get the index of the chunk file delta for this DID.
        let core_index_file_commitment =
            IpfsIndexFileCommitment::<Incomplete>::new(core_index_file);
        let delta_index: usize = serde_json::from_value::<CoreIndexFile>(
            core_index_file_commitment.commitment_content()?,
        )?
        .did_create_operation_index(&did_doc.id)?;

        // Construct the first *full* Commitment, followed by a sequence of TrivialCommitments.
        let chunk_file_commitment =
            IpfsChunkFileCommitment::<Incomplete>::new(chunk_file, delta_index);
        let prov_index_file_commitment =
            IpfsIndexFileCommitment::<Incomplete>::new(provisional_index_file);
        let tx_commitment = TxCommitment::<Incomplete>::new(transaction);
        let merkle_root_commitment = MerkleRootCommitment::<Incomplete>::new(merkle_proof);
        let block_hash_commitment = BlockHashCommitment::<Incomplete>::new(block_header);

        // The following construction is only possible because each TrivialCommitment
        // knows how to convert itself to the correct Commitment type.
        // This explains why the TrivialCommitment trait is necessary.
        let mut iterated_commitment =
            ChainedCommitment::new(Box::new(chunk_file_commitment).to_commitment(expected_data));
        iterated_commitment.append(Box::new(prov_index_file_commitment))?;
        iterated_commitment.append(Box::new(core_index_file_commitment))?;
        iterated_commitment.append(Box::new(tx_commitment))?;
        iterated_commitment.append(Box::new(merkle_root_commitment))?;
        iterated_commitment.append(Box::new(block_hash_commitment))?;

        Ok(Self {
            did_doc,
            chained_commitment: iterated_commitment,
        })
    }

    pub fn chained_commitment(&self) -> &ChainedCommitment {
        &self.chained_commitment
    }
}

// Delegate all Commitment trait methods to the wrapped ChainedCommitment.
impl TrivialCommitment for IONCommitment {
    fn hasher(&self) -> fn(&[u8]) -> CommitmentResult<String> {
        self.chained_commitment.hasher()
    }

    fn hash(&self) -> CommitmentResult<String> {
        self.chained_commitment.hash()
    }

    fn candidate_data(&self) -> &[u8] {
        self.chained_commitment.candidate_data()
    }

    fn decode_candidate_data(&self) -> fn(&[u8]) -> CommitmentResult<Value> {
        self.chained_commitment.decode_candidate_data()
    }

    fn to_commitment(self: Box<Self>, _: serde_json::Value) -> Box<dyn Commitment> {
        self
    }
}

// Delegate all Commitment trait methods to the wrapped ChainedCommitment.
impl Commitment for IONCommitment {
    fn expected_data(&self) -> &serde_json::Value {
        // Safe to unwrap as a complete commitment must have expected data
        self.chained_commitment.expected_data()
    }
    // Essential to override verify otherwise calls will consider last commitment only.
    fn verify(&self, target: &str) -> CommitmentResult<()> {
        // Delegate verification to the chained commitment.
        self.chained_commitment.verify(target)?;
        Ok(())
    }
}

impl DIDCommitment for IONCommitment {
    fn did(&self) -> &str {
        &self.did_doc.id
    }

    fn did_document(&self) -> &Document {
        &self.did_doc
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A Commitment whose expected data is a Unix time and hasher
/// and candidate data are obtained from a given DIDCommitment.
pub struct BlockTimestampCommitment {
    candidate_data: Vec<u8>,
    expected_data: Timestamp,
}

impl BlockTimestampCommitment {
    pub fn new(candidate_data: Vec<u8>, expected_data: Timestamp) -> CommitmentResult<Self> {
        // The decoded candidate data must contain the timestamp such that it is found
        // by the json_contains function, otherwise the content verification will fail.
        Ok(Self {
            candidate_data,
            expected_data,
        })
    }
}

impl TrivialCommitment<Timestamp> for BlockTimestampCommitment {
    fn hasher(&self) -> fn(&[u8]) -> CommitmentResult<String> {
        block_header_hasher()
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    /// Deserializes the candidate data into a Block header (as JSON).
    fn decode_candidate_data(&self) -> fn(&[u8]) -> CommitmentResult<Value> {
        block_header_decoder()
    }

    /// Override the filter method to ensure only timestamp content is considered.
    fn filter(&self) -> Option<Box<dyn Fn(&serde_json::Value) -> CommitmentResult<Value>>> {
        Some(Box::new(move |value| {
            if let Value::Object(map) = value {
                match map.get(TIMESTAMP_KEY) {
                    Some(Value::Number(timestamp)) => Ok(Value::Number(timestamp.clone())),
                    _ => Err(CommitmentError::DataDecodingFailure),
                }
            } else {
                Err(CommitmentError::DataDecodingFailure)
            }
        }))
    }

    fn to_commitment(self: Box<Self>, _: Timestamp) -> Box<dyn Commitment<Timestamp>> {
        self
    }
}

impl Commitment<Timestamp> for BlockTimestampCommitment {
    fn expected_data(&self) -> &Timestamp {
        &self.expected_data
    }
}

impl TimestampCommitment for BlockTimestampCommitment {}

#[cfg(test)]
mod tests {
    use bitcoin::util::psbt::serialize::Serialize;
    use bitcoin::BlockHash;
    use ipfs_api_backend_hyper::IpfsClient;
    use std::str::FromStr;
    use trustchain_core::{data::TEST_ROOT_DOCUMENT, utils::json_contains};

    use super::*;
    use crate::{
        data::TEST_BLOCK_HEADER_HEX,
        utils::{block_header, merkle_proof, query_ipfs, transaction},
    };

    #[test]
    fn test_block_timestamp_commitment() {
        let expected_data: Timestamp = 1666265405;
        let candidate_data = hex::decode(TEST_BLOCK_HEADER_HEX).unwrap();
        let target = BlockTimestampCommitment::new(candidate_data.clone(), expected_data).unwrap();
        target.verify_content().unwrap();
        let pow_hash = "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f";
        target.verify(pow_hash).unwrap();

        // Both calls should instead error with incorrect timestamp
        let bad_expected_data: Timestamp = 1666265406;
        let target = BlockTimestampCommitment::new(candidate_data, bad_expected_data).unwrap();
        match target.verify_content() {
            Err(CommitmentError::FailedContentVerification(s1, s2)) => {
                assert_eq!(
                    (s1, s2),
                    (format!("{bad_expected_data}"), format!("{expected_data}"))
                )
            }
            _ => panic!(),
        };
        match target.verify(pow_hash) {
            Err(CommitmentError::FailedContentVerification(s1, s2)) => {
                assert_eq!(
                    (s1, s2),
                    (format!("{bad_expected_data}"), format!("{expected_data}"))
                )
            }
            _ => panic!(),
        };
    }

    #[test]
    fn test_block_hash_commitment_filter() {
        // The expected data is the Merkle root inside the block header.
        // For the testnet block at height 2377445, the Merkle root is:
        let expected_data =
            json!("7dce795209d4b5051da3f5f5293ac97c2ec677687098062044654111529cad69");
        let candidate_data = hex::decode(TEST_BLOCK_HEADER_HEX).unwrap();
        let target = BlockHashCommitment::<Complete>::new(candidate_data, expected_data);
        target.verify_content().unwrap();
        let pow_hash = "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f";
        target.verify(pow_hash).unwrap();
    }

    #[tokio::test]
    #[ignore = "Integration test requires IPFS"]
    async fn test_extract_suffix_idx() {
        let target = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let ipfs_client = IpfsClient::default();
        let candidate_data = query_ipfs(target, &ipfs_client).await.unwrap();
        let core_index_file_commitment = IpfsIndexFileCommitment::<Incomplete>::new(candidate_data);
        let operation_idx = serde_json::from_value::<CoreIndexFile>(
            core_index_file_commitment.commitment_content().unwrap(),
        )
        .unwrap()
        .did_create_operation_index("did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A");

        assert_eq!(1, operation_idx.unwrap());
    }

    #[tokio::test]
    #[ignore = "Integration test requires IPFS"]
    async fn test_ipfs_commitment() {
        let target = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";

        let ipfs_client = IpfsClient::default();

        let candidate_data_ = query_ipfs(target, &ipfs_client).await.unwrap();
        let candidate_data = candidate_data_.clone();
        // In the core index file we expect to find the provisionalIndexFileUri.
        let expected_data =
            r#"{"provisionalIndexFileUri":"QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let expected_data: serde_json::Value = serde_json::from_str(expected_data).unwrap();
        let commitment = IpfsIndexFileCommitment::<Complete>::new(candidate_data, expected_data);
        assert!(commitment.verify(target).is_ok());

        // We do *not* expect a different target to succeed.
        let bad_target = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J98";
        assert!(commitment.verify(bad_target).is_err());
        match commitment.verify(bad_target) {
            Err(CommitmentError::FailedHashVerification(..)) => (),
            _ => panic!("Expected FailedHashVerification error."),
        }

        // We do *not* expect to find a different provisionalIndexFileUri.
        let bad_expected_data =
            r#"{"provisionalIndexFileUri":"PmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let bad_expected_data = serde_json::from_str(bad_expected_data).unwrap();
        let candidate_data = candidate_data_;
        let commitment =
            IpfsIndexFileCommitment::<Complete>::new(candidate_data, bad_expected_data);
        assert!(commitment.verify(target).is_err());
        match commitment.verify(target) {
            Err(CommitmentError::FailedContentVerification(..)) => (),
            _ => panic!("Expected FailedContentVerification error."),
        };
    }

    #[test]
    #[ignore = "Integration test requires Bitcoin Core"]
    fn test_tx_commitment() {
        let target = "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";

        // Get the Bitcoin transaction.
        let block_hash_str = "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f";
        let block_hash = BlockHash::from_str(block_hash_str).unwrap();
        let tx = transaction(&block_hash, 3, None).unwrap();

        // We expect to find the IPFS CID for the ION core index file in the OP_RETURN data.
        let cid_str = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let expected_str = format!(r#"{{"{}":"{}"}}"#, CID_KEY, cid_str);
        let expected_data: serde_json::Value = serde_json::from_str(&expected_str).unwrap();
        let candidate_data = Serialize::serialize(&tx);

        let commitment = TxCommitment::<Complete>::new(candidate_data, expected_data);
        assert!(commitment.verify(target).is_ok());

        // We do *not* expect a different target to succeed.
        let bad_target = "8dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        assert!(commitment.verify(bad_target).is_err());
        match commitment.verify(bad_target) {
            Err(CommitmentError::FailedHashVerification(..)) => (),
            _ => panic!("Expected FailedHashVerification error."),
        };

        // We do *not* expect to find a different IPFS CID in the OP_RETURN data.
        let bad_cid_str = "PmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let bad_expected_str = format!(r#"{{"{}":"{}"}}"#, CID_KEY, bad_cid_str);
        let bad_expected_data: serde_json::Value = serde_json::from_str(&bad_expected_str).unwrap();
        let candidate_data = Serialize::serialize(&tx);
        let commitment = TxCommitment::<Complete>::new(candidate_data, bad_expected_data);
        assert!(commitment.verify(target).is_err());
        match commitment.verify(target) {
            Err(CommitmentError::FailedContentVerification(..)) => (),
            _ => panic!("Expected FailedContentVerification error."),
        };
    }

    #[test]
    #[ignore = "Integration test requires Bitcoin Core"]
    fn test_merkle_root_commitment() {
        // The commitment target is the Merkle root from the block header.
        // For the testnet block at height 2377445, the Merkle root is:
        let target = "7dce795209d4b5051da3f5f5293ac97c2ec677687098062044654111529cad69";
        // and the block hash is:
        let block_hash_str = "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f";

        // We expect to find the transaction ID in the Merkle proof (candidate data):
        let txid_str = "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        let expected_data = serde_json::json!(txid_str);

        // Get the Bitcoin transaction.
        let block_hash = BlockHash::from_str(block_hash_str).unwrap();
        let tx_index = 3;
        let tx = transaction(&block_hash, tx_index, None).unwrap();

        // The candidate data is a serialized Merkle proof.
        let candidate_data_ = merkle_proof(&tx, &block_hash, None).unwrap();
        let candidate_data = candidate_data_.clone();

        let commitment = MerkleRootCommitment::<Complete>::new(candidate_data, expected_data);
        assert!(commitment.verify(target).is_ok());

        // We do *not* expect a different target to succeed.
        let bad_target = "8dce795209d4b5051da3f5f5293ac97c2ec677687098062044654111529cad69";
        assert!(commitment.verify(bad_target).is_err());
        match commitment.verify(bad_target) {
            Err(CommitmentError::FailedHashVerification(..)) => (),
            _ => panic!("Expected FailedHashVerification error."),
        };

        // We do *not* expect to find an arbitrary transaction ID.
        let bad_txid_str = "2dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        let bad_expected_data = serde_json::json!(bad_txid_str);
        let candidate_data = candidate_data_;
        let commitment = MerkleRootCommitment::<Complete>::new(candidate_data, bad_expected_data);
        assert!(commitment.verify(target).is_err());
        match commitment.verify(target) {
            Err(CommitmentError::FailedContentVerification(..)) => (),
            _ => panic!("Expected FailedContentVerification error."),
        };
    }

    #[test]
    #[ignore = "Integration test requires Bitcoin Core"]
    fn test_block_hash_commitment() {
        // The commitment target is the block hash.
        let target = "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f";
        let block_hash = BlockHash::from_str(target).unwrap();

        // We expect to find the Merkle root in the block header.
        // For the testnet block at height 2377445, the Merkle root is:
        let merkle_root_str = "7dce795209d4b5051da3f5f5293ac97c2ec677687098062044654111529cad69";
        let expected_data = json!(merkle_root_str);

        // The candidate data is the serialized block header.
        let block_header = block_header(&block_hash, None).unwrap();
        let candidate_data = bitcoin::consensus::serialize(&block_header);
        let commitment =
            BlockHashCommitment::<Complete>::new(candidate_data.clone(), expected_data);
        commitment.verify(target).unwrap();

        // We do *not* expect a different target to succeed.
        let bad_target = "100000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f";
        assert!(commitment.verify(bad_target).is_err());
        match commitment.verify(bad_target) {
            Err(CommitmentError::FailedHashVerification(..)) => (),
            _ => panic!("Expected FailedHashVerification error."),
        };

        // We do *not* expect to find a different Merkle root.
        let bad_merkle_root_str =
            "6dce795209d4b5051da3f5f5293ac97c2ec677687098062044654111529cad69";
        let bad_expected_data = json!(bad_merkle_root_str);
        let commitment =
            BlockHashCommitment::<Complete>::new(candidate_data.clone(), bad_expected_data);
        assert!(commitment.verify(target).is_err());
        match commitment.verify(target) {
            Err(CommitmentError::FailedContentVerification(..)) => (),
            _ => panic!("Expected FailedContentVerification error."),
        };

        // We do *not* expect the (correct) timestamp to be valid expected data,
        // since the candidate data is filtered to contain only the Merkle root field.
        let wrong_expected_data_commitment =
            BlockHashCommitment::<Complete>::new(candidate_data.clone(), json!(1666265405));
        assert!(wrong_expected_data_commitment.verify(target).is_err());

        // Also test as timestamp commitment
        let expected_data = 1666265405;
        let commitment =
            BlockTimestampCommitment::new(candidate_data.clone(), expected_data).unwrap();
        commitment.verify_content().unwrap();
        commitment.verify(target).unwrap();
        let bad_expected_data = 1666265406;
        let commitment = BlockTimestampCommitment::new(candidate_data, bad_expected_data).unwrap();
        assert!(commitment.verify_content().is_err());
        assert!(commitment.verify(target).is_err());
    }

    #[tokio::test]
    #[ignore = "Integration test requires IPFS and Bitcoin Core"]
    async fn test_ion_commitment() {
        let did_doc = Document::from_json(TEST_ROOT_DOCUMENT).unwrap();

        let ipfs_client = IpfsClient::default();

        let chunk_file_cid = "QmWeK5PbKASyNjEYKJ629n6xuwmarZTY6prd19ANpt6qyN";
        let chunk_file = query_ipfs(chunk_file_cid, &ipfs_client).await.unwrap();

        let prov_index_file_cid = "QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs";
        let prov_index_file = query_ipfs(prov_index_file_cid, &ipfs_client).await.unwrap();

        let core_index_file_cid = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let core_index_file = query_ipfs(core_index_file_cid, &ipfs_client).await.unwrap();

        let block_hash_str = "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f";
        let block_hash = BlockHash::from_str(block_hash_str).unwrap();
        let tx_index = 3;
        let tx = transaction(&block_hash, tx_index, None).unwrap();
        let transaction = Serialize::serialize(&tx);

        let merkle_proof = merkle_proof(&tx, &block_hash, None).unwrap();

        let block_header = block_header(&block_hash, None).unwrap();
        let block_header = bitcoin::consensus::serialize(&block_header);

        let commitment = IONCommitment::new(
            did_doc,
            chunk_file,
            prov_index_file,
            core_index_file,
            transaction,
            merkle_proof,
            block_header,
        )
        .unwrap();

        let expected_data = commitment.chained_commitment.expected_data();

        println!("{:?}", expected_data);
        // The expected data contains public keys and service endpoints.
        match expected_data {
            serde_json::Value::Array(arr) => {
                assert_eq!(arr.len(), 2);
            }
            _ => panic!("Expected JSON Array."),
        }

        // Check each individual commitment.
        let commitments = commitment.chained_commitment.commitments();

        // The first one commits to the chunk file CID and is expected
        // to contain the same data as the iterated commitment.
        let chunk_file_commitment = commitments.get(0).unwrap();
        assert_eq!(chunk_file_commitment.hash().unwrap(), chunk_file_cid);
        assert_eq!(expected_data, chunk_file_commitment.expected_data());

        // Verify the chunk file commitment.
        assert!(&chunk_file_commitment.verify(chunk_file_cid).is_ok());

        // The second one commits to the provisional index file CID
        // and is expected to contain the chunk file CID.
        let prov_index_file_commitment = commitments.get(1).unwrap();
        assert_eq!(
            prov_index_file_commitment.hash().unwrap(),
            prov_index_file_cid
        );
        assert!(json_contains(
            &json!(chunk_file_cid),
            prov_index_file_commitment.expected_data()
        ));

        // Verify the provisional index file commitment.
        assert!(&prov_index_file_commitment
            .verify(prov_index_file_cid)
            .is_ok());

        // The third one commits to the core index file CID
        // and is expected to contain the provision index file CID.
        let core_index_file_commitment = commitments.get(2).unwrap();
        assert_eq!(
            core_index_file_commitment.hash().unwrap(),
            core_index_file_cid
        );
        assert!(json_contains(
            &json!(prov_index_file_cid),
            core_index_file_commitment.expected_data()
        ));

        // Verify the core index file commitment.
        assert!(&core_index_file_commitment
            .verify(core_index_file_cid)
            .is_ok());

        // The fourth one commits to the Bitcoin transaction ID
        // and is expected to contain the core index file CID.
        let tx_commitment = commitments.get(3).unwrap();
        let tx_id = "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        assert_eq!(tx_commitment.hash().unwrap(), tx_id);
        assert!(json_contains(
            &json!(core_index_file_cid),
            tx_commitment.expected_data()
        ));

        // Verify the transaction ID commitment.
        assert!(&tx_commitment.verify(tx_id).is_ok());

        // The fifth one commits to the Merkle root in the block header
        // and is expected to contain the Bitcoin transaction ID.
        let merkle_root_commitment = commitments.get(4).unwrap();
        let merkle_root = "7dce795209d4b5051da3f5f5293ac97c2ec677687098062044654111529cad69";
        assert_eq!(merkle_root_commitment.hash().unwrap(), merkle_root);
        assert!(json_contains(
            &json!(tx_id),
            merkle_root_commitment.expected_data()
        ));

        // Verify the Merkle root commitment.
        assert!(&merkle_root_commitment.verify(merkle_root).is_ok());

        // Finally, the sixth one commits to the block hash (PoW)
        // and is expected to contain the Merkle root.
        let block_hash_commitment = commitments.get(5).unwrap();
        assert_eq!(block_hash_commitment.hash().unwrap(), block_hash_str);
        assert!(json_contains(
            &json!(merkle_root),
            block_hash_commitment.expected_data()
        ));

        // Verify the Merkle root commitment.
        assert!(&merkle_root_commitment.verify(merkle_root).is_ok());

        // Verify the iterated commitment content (i.e. the expected_data).
        assert!(commitment.chained_commitment.verify_content().is_ok());
        assert!(commitment.chained_commitment.verify(block_hash_str).is_ok());

        // Verify the IONCommitment itself.
        assert!(commitment.verify(block_hash_str).is_ok());
    }
}

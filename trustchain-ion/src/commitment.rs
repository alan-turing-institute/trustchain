use bitcoin::util::psbt::serialize::Deserialize;
use bitcoin::MerkleBlock;
use bitcoin::{Script, Transaction};
use ipfs_hasher::IpfsHasher;
use serde_json::{json, Value};
use ssi::did::Document;
use std::convert::TryInto;
use trustchain_core::commitment::{ChainedCommitment, CommitmentChain};
use trustchain_core::commitment::{Commitment, CommitmentError};
use trustchain_core::commitment::{DIDCommitment, TrivialCommitment};
use trustchain_core::utils::{HasEndpoints, HasKeys};

use crate::sidetree::CoreIndexFile;
use crate::utils::{decode_block_header, decode_ipfs_content, reverse_endianness};
use crate::DELTAS_KEY;
use crate::{CID_KEY, DID_DELIMITER, ION_METHOD, ION_OPERATION_COUNT_DELIMITER};

fn ipfs_hasher() -> fn(&[u8]) -> Result<String, CommitmentError> {
    |x| Ok(IpfsHasher::default().compute(x))
}

fn ipfs_decode_candidate_data() -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
    |x| decode_ipfs_content(&x.to_owned()).map_err(|_| CommitmentError::DataDecodingError)
}

/// A Commitment whose hash is an IPFS content identifier (CID) for an ION Index file.
pub struct IpfsIndexFileCommitment {
    candidate_data: Vec<u8>,
    expected_data: Option<Value>,
}

impl IpfsIndexFileCommitment {
    pub fn new(candidate_data: Vec<u8>, expected_data: Option<Value>) -> Self {
        Self {
            candidate_data,
            expected_data,
        }
    }
}

impl TrivialCommitment for IpfsIndexFileCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        ipfs_hasher()
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
        ipfs_decode_candidate_data()
    }

    fn to_commitment(mut self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        self.expected_data = Some(expected_data);
        self
    }
}

impl Commitment for IpfsIndexFileCommitment {
    fn expected_data(&self) -> Result<&serde_json::Value, CommitmentError> {
        self.expected_data
            .as_ref()
            .ok_or(CommitmentError::EmptyExpectedData)
    }
}

impl TrivialCommitment for IpfsChunkFileCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        ipfs_hasher()
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    // TODO: change closure to take a reference.
    fn filter(
        &self,
    ) -> Option<Box<dyn Fn(serde_json::Value) -> Result<serde_json::Value, CommitmentError>>> {
        // Ignore all of the deltas in the chunk file except the one at index delta_index
        // (which is the one corresponding to the relevant DID).
        let delta_index = self.delta_index;
        Some(Box::new(move |value| {
            // Note: check if mix of create, recover and deactivate whether the correct index is used.
            // TODO: Remove in future releases.
            if let Value::Object(map) = value {
                match map.get(DELTAS_KEY) {
                    // TODO: create chunk file struct in crate::sidetree module.
                    Some(Value::Array(deltas)) => Ok(deltas.get(delta_index).unwrap().clone()),
                    _ => Err(CommitmentError::DataDecodingError),
                }
            } else {
                Err(CommitmentError::DataDecodingError)
            }
        }))
    }
    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
        ipfs_decode_candidate_data()
    }
    fn to_commitment(mut self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        self.expected_data = Some(expected_data);
        self
    }
}

/// A Commitment whose hash is an IPFS content identifier (CID) for an ION chunk file.
pub struct IpfsChunkFileCommitment {
    candidate_data: Vec<u8>,
    delta_index: usize,
    expected_data: Option<Value>,
}
impl IpfsChunkFileCommitment {
    pub fn new(candidate_data: Vec<u8>, delta_index: usize, expected_data: Option<Value>) -> Self {
        Self {
            candidate_data,
            delta_index,
            expected_data,
        }
    }
}

impl Commitment for IpfsChunkFileCommitment {
    fn expected_data(&self) -> Result<&serde_json::Value, CommitmentError> {
        self.expected_data
            .as_ref()
            .ok_or(CommitmentError::EmptyExpectedData)
    }
}
// End of IpfsCommitment.

/// A Commitment whose hash is a Bitcoin transaction ID.
pub struct TxCommitment {
    candidate_data: Vec<u8>,
    expected_data: Option<Value>,
}

impl TxCommitment {
    pub fn new(candidate_data: Vec<u8>, expected_data: Option<Value>) -> Self {
        Self {
            candidate_data,
            expected_data,
        }
    }
}

impl TrivialCommitment for TxCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        // Candidate data is a Bitcoin transaction, whose hash is the transaction ID.
        |x| {
            let tx: Transaction = match Deserialize::deserialize(x) {
                Ok(tx) => tx,
                Err(e) => {
                    eprintln!("Failed to deserialise transaction: {}", e);
                    return Err(CommitmentError::FailedToComputeHash);
                }
            };
            Ok(tx.txid().to_string())
        }
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    /// Deserialises the candidate data into a Bitcoin transaction, then
    /// extracts and returns the IPFS content identifier in the OP_RETURN data.
    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
        |x| {
            // Deserialise the transaction from the candidate data.
            let tx: Transaction = match Deserialize::deserialize(x) {
                Ok(tx) => tx,
                Err(e) => {
                    eprintln!("Failed to deserialise transaction: {}", e);
                    return Err(CommitmentError::DataDecodingError);
                }
            };
            // Extract the OP_RETURN data from the transaction.
            let tx_out_vec = &tx.output;
            // Get the output scripts that contain an OP_RETURN.
            let op_return_scripts: Vec<&Script> = tx_out_vec
                .iter()
                .filter_map(|x| match x.script_pubkey.is_op_return() {
                    true => Some(&x.script_pubkey),
                    false => None,
                })
                .collect();

            // Iterate over the OP_RETURN scripts. Extract any that contain the
            // substring 'ion:' and raise an error unless precisely one such script exists.
            let mut op_return_data: Option<String> = None;
            let ion_substr = format!("{}{}", ION_METHOD, DID_DELIMITER);
            for script in &op_return_scripts {
                match std::str::from_utf8(script.as_ref()) {
                    Ok(op_return_str) => match op_return_str.find(&ion_substr) {
                        Some(i) => {
                            if op_return_data.is_none() {
                                op_return_data = Some(op_return_str[i..].to_string())
                            // Trim any leading characters.
                            } else {
                                // Raise an error if multiple ION OP_RETURN scripts are found.
                                eprintln!("Error: multiple ION OP_RETURN scripts found.");
                                return Err(CommitmentError::DataDecodingError);
                            }
                        }
                        // Ignore the script if the 'ion:' substring is not found.
                        None => continue,
                    },
                    // Ignore the script if it cannot be converted to UTF-8.
                    Err(_) => continue,
                }
            }
            // Extract the IPFS content identifier from the ION OP_RETURN data.
            let (_, operation_count_plus_cid) = op_return_data
                .as_ref()
                .ok_or(CommitmentError::DataDecodingError)?
                .rsplit_once(DID_DELIMITER)
                .unwrap();
            let (_, cid) = operation_count_plus_cid
                .rsplit_once(ION_OPERATION_COUNT_DELIMITER)
                .unwrap();
            Ok(json!({ CID_KEY: cid }))
        }
    }
    fn to_commitment(mut self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        self.expected_data = Some(expected_data);
        self
    }
}

impl Commitment for TxCommitment {
    fn expected_data(&self) -> Result<&serde_json::Value, CommitmentError> {
        self.expected_data
            .as_ref()
            .ok_or(CommitmentError::EmptyExpectedData)
    }
}
// End of TxCommitment.

/// A Commitment whose hash is the root of a Merkle tree of Bitcoin transaction IDs.
pub struct MerkleRootCommitment {
    candidate_data: Vec<u8>,
    expected_data: Option<Value>,
}

impl MerkleRootCommitment {
    pub fn new(candidate_data: Vec<u8>, expected_data: Option<Value>) -> Self {
        Self {
            candidate_data,
            expected_data,
        }
    }
}

impl TrivialCommitment for MerkleRootCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        // Candidate data is a Merkle proof containing a branch of transaction IDs.
        |x| {
            let merkle_block: MerkleBlock = match bitcoin::consensus::deserialize(x) {
                Ok(mb) => mb,
                Err(e) => {
                    eprintln!("Failed to deserialise MerkleBlock: {:?}", e);
                    return Err(CommitmentError::FailedToComputeHash);
                }
            };
            // Traverse the PartialMerkleTree to obtain the Merkle root.
            match merkle_block.txn.extract_matches(&mut vec![], &mut vec![]) {
                Ok(merkle_root) => Ok(merkle_root.to_string()),
                Err(e) => {
                    eprintln!(
                        "Failed to obtain Merkle root from PartialMerkleTree: {:?}",
                        e
                    );
                    Err(CommitmentError::FailedToComputeHash)
                }
            }
        }
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    /// Deserialises the candidate data into a Merkle proof.
    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
        |x| {
            let merkle_block: MerkleBlock = match bitcoin::consensus::deserialize(x) {
                Ok(mb) => mb,
                Err(e) => {
                    eprintln!("Failed to deserialise MerkleBlock: {:?}", e);
                    return Err(CommitmentError::DataDecodingError);
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

    fn to_commitment(mut self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        // Box::new(MerkleRootCommitment::new(*self, Some(expected_data)))
        self.expected_data = Some(expected_data);
        self
    }
}

impl Commitment for MerkleRootCommitment {
    fn expected_data(&self) -> Result<&serde_json::Value, CommitmentError> {
        self.expected_data
            .as_ref()
            .ok_or(CommitmentError::EmptyExpectedData)
    }
}
// End of MerkleRootCommitment.

/// A Commitment whose hash is the PoW hash of a Bitcoin block.
pub struct BlockHashCommitment {
    candidate_data: Vec<u8>,
    expected_data: Option<Value>,
}

impl BlockHashCommitment {
    pub fn new(candidate_data: Vec<u8>, expected_data: Option<Value>) -> Self {
        Self {
            candidate_data,
            expected_data,
        }
    }
}

impl TrivialCommitment for BlockHashCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        // Candidate data the block header bytes.
        |x| {
            // Bitcoin block hash is a double SHA256 hash of the block header.
            // We use a generic SHA256 library to avoid trust in rust-bitcoin.
            let hash1_hex = sha256::digest(x);
            let hash1_bytes = hex::decode(hash1_hex).unwrap();
            let hash2_hex = sha256::digest(&*hash1_bytes);
            // For leading (not trailing) zeros, convert the hex to big-endian.
            Ok(reverse_endianness(&hash2_hex).unwrap())
        }
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    /// Deserialises the candidate data into a Block header (as JSON).
    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
        |x| {
            if x.len() != 80 {
                eprintln!("Error: Bitcoin block header must be 80 bytes.");
                return Err(CommitmentError::DataDecodingError);
            };
            let decoded_header = decode_block_header(
                x.try_into()
                    .expect("Bitcoin block header should be 80 bytes."),
            );
            match decoded_header {
                Ok(x) => Ok(x),
                Err(e) => {
                    eprintln!("Error decoding Bitcoin block header: {}.", e);
                    Err(CommitmentError::DataDecodingError)
                }
            }
        }
    }

    fn to_commitment(mut self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        // Box::new(BlockHashCommitment::new(*self, Some(expected_data)))
        self.expected_data = Some(expected_data);
        self
    }
}

impl Commitment for BlockHashCommitment {
    fn expected_data(&self) -> Result<&serde_json::Value, CommitmentError> {
        self.expected_data
            .as_ref()
            .ok_or(CommitmentError::EmptyExpectedData)
    }
}
// End of BlockHashCommitment.

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
    ) -> Result<Self, CommitmentError> {
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
        let core_index_file_commitment = IpfsIndexFileCommitment::new(core_index_file, None);
        let delta_index: usize = serde_json::from_value::<CoreIndexFile>(
            core_index_file_commitment.commitment_content()?,
        )?
        .did_create_operation_index(&did_doc.id)?;

        // Construct the first *full* Commitment, followed by a sequence of TrivialCommitments.
        let chunk_file_commitment =
            IpfsChunkFileCommitment::new(chunk_file, delta_index, Some(expected_data));
        let prov_index_file_commitment = IpfsIndexFileCommitment::new(provisional_index_file, None);
        let tx_commitment = TxCommitment::new(transaction, None);
        let merkle_root_commitment = MerkleRootCommitment::new(merkle_proof, None);
        let block_hash_commitment = BlockHashCommitment::new(block_header, None);

        // The following construction is only possible because each TrivialCommitment
        // knows how to convert itself to the correct Commitment type.
        // This explains why the TrivialCommitment trait is necessary.
        let mut iterated_commitment = ChainedCommitment::new(Box::new(chunk_file_commitment));
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

    // TODO: remove unused method?
    fn verify(&self, target: &str) -> Result<(), CommitmentError> {
        // Delegate verification to the chained commitment.
        Commitment::verify(&self.chained_commitment, target)?;
        Ok(())
    }
}

// Delegate all Commitment trait methods to the wrapped ChainedCommitment.
impl TrivialCommitment for IONCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        self.chained_commitment.hasher()
    }

    fn hash(&self) -> Result<String, CommitmentError> {
        // TODO: this needs to be reconsidered if replacing the use of hash() method in Commitment::verify()
        self.chained_commitment.hash()
    }

    fn candidate_data(&self) -> &[u8] {
        self.chained_commitment.candidate_data()
    }

    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
        self.chained_commitment.decode_candidate_data()
    }

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        self
    }
}

// Delegate all Commitment trait methods to the wrapped ChainedCommitment.
impl Commitment for IONCommitment {
    fn expected_data(&self) -> Result<&serde_json::Value, CommitmentError> {
        self.chained_commitment.expected_data()
    }
}

impl CommitmentChain for IONCommitment {
    fn commitments(&self) -> &Vec<Box<dyn Commitment>> {
        self.chained_commitment.commitments()
    }

    fn mut_commitments(&mut self) -> &mut Vec<Box<dyn Commitment>> {
        self.chained_commitment.mut_commitments()
    }

    fn append(
        &mut self,
        trivial_commitment: Box<dyn TrivialCommitment>,
    ) -> Result<(), CommitmentError> {
        self.chained_commitment.append(trivial_commitment)
    }
}

impl DIDCommitment for IONCommitment {
    fn did(&self) -> &str {
        &self.did_doc.id
    }

    fn did_document(&self) -> &Document {
        &self.did_doc
    }

    fn timestamp_candidate_data(&self) -> Result<&[u8], CommitmentError> {
        // The candidate data for the timestamp is the Bitcoin block header,
        // which is the candidate data in the last commitment in the chain
        // (i.e. the BlockHashCommitment).
        if let Some(commitment) = self.chained_commitment.commitments().last() {
            return Ok(commitment.candidate_data());
        }
        Err(CommitmentError::EmptyChainedCommitment)
    }

    fn decode_timestamp_candidate_data(
        &self,
    ) -> Result<fn(&[u8]) -> Result<serde_json::Value, CommitmentError>, CommitmentError> {
        // The required candidate data decoder (function) is the one for the
        // Bitcoin block header, which is the decoder in the last commitment
        // in the chain (i.e. the BlockHashCommitment).
        if let Some(commitment) = self.chained_commitment.commitments().last() {
            return Ok(commitment.decode_candidate_data());
        }
        Err(CommitmentError::EmptyChainedCommitment)
    }
}
// End of IONCommitment

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use bitcoin::util::psbt::serialize::Serialize;
    use bitcoin::BlockHash;
    use ipfs_api_backend_actix::IpfsClient;
    use trustchain_core::{data::TEST_ROOT_DOCUMENT, utils::json_contains};

    use super::*;
    use crate::{
        utils::{block_header, merkle_proof, query_ipfs, transaction},
        CID_KEY, MERKLE_ROOT_KEY, TIMESTAMP_KEY,
    };

    #[test]
    #[ignore = "Integration test requires IPFS"]
    fn test_extract_suffix_idx() {
        let target = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let ipfs_client = IpfsClient::default();
        let candidate_data = query_ipfs(target, &ipfs_client).unwrap();
        let core_index_file_commitment = IpfsIndexFileCommitment::new(candidate_data, None);
        let operation_idx = serde_json::from_value::<CoreIndexFile>(
            core_index_file_commitment.commitment_content().unwrap(),
        )
        .unwrap()
        .did_create_operation_index("did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A");

        assert_eq!(1, operation_idx.unwrap());
    }

    #[test]
    #[ignore = "Integration test requires IPFS"]
    fn test_ipfs_commitment() {
        let target = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";

        let ipfs_client = IpfsClient::default();

        let candidate_data_ = query_ipfs(target, &ipfs_client).unwrap();
        let candidate_data = candidate_data_.clone();
        // In the core index file we expect to find the provisionalIndexFileUri.
        let expected_data =
            r#"{"provisionalIndexFileUri":"QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let expected_data: serde_json::Value = serde_json::from_str(expected_data).unwrap();
        let commitment = IpfsIndexFileCommitment::new(candidate_data, Some(expected_data));
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
        let commitment = IpfsIndexFileCommitment::new(candidate_data, Some(bad_expected_data));
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

        let commitment = TxCommitment::new(candidate_data, Some(expected_data));
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
        let commitment = TxCommitment::new(candidate_data, Some(bad_expected_data));
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

        let commitment = MerkleRootCommitment::new(candidate_data, Some(expected_data));
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
        let commitment = MerkleRootCommitment::new(candidate_data, Some(bad_expected_data));
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
        let expected_str = format!(r#"{{"{}":"{}"}}"#, MERKLE_ROOT_KEY, merkle_root_str);
        let expected_data: serde_json::Value = serde_json::from_str(&expected_str).unwrap();

        // The candidate data is the serialized block header.
        let block_header = block_header(&block_hash, None).unwrap();
        let candidate_data_ = bitcoin::consensus::serialize(&block_header);
        let candidate_data = candidate_data_.clone();

        let commitment = BlockHashCommitment::new(candidate_data, Some(expected_data));
        assert!(commitment.verify(target).is_ok());

        // Check the timestamp is a u32 Unix time.
        let binding = commitment.commitment_content().unwrap();
        let actual_timestamp = binding.get(TIMESTAMP_KEY).unwrap();
        assert_eq!(actual_timestamp, &json!(1666265405));

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
        let bad_expected_data = serde_json::json!(bad_merkle_root_str);
        let candidate_data = candidate_data_;
        let commitment = BlockHashCommitment::new(candidate_data, Some(bad_expected_data));
        assert!(commitment.verify(target).is_err());
        match commitment.verify(target) {
            Err(CommitmentError::FailedContentVerification(..)) => (),
            _ => panic!("Expected FailedContentVerification error."),
        };
    }

    #[test]
    #[ignore = "Integration test requires IPFS and Bitcoin Core"]
    fn test_ion_commitment() {
        let did_doc = Document::from_json(TEST_ROOT_DOCUMENT).unwrap();

        let ipfs_client = IpfsClient::default();

        let chunk_file_cid = "QmWeK5PbKASyNjEYKJ629n6xuwmarZTY6prd19ANpt6qyN";
        let chunk_file = query_ipfs(chunk_file_cid, &ipfs_client).unwrap();

        let prov_index_file_cid = "QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs";
        let prov_index_file = query_ipfs(prov_index_file_cid, &ipfs_client).unwrap();

        let core_index_file_cid = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let core_index_file = query_ipfs(core_index_file_cid, &ipfs_client).unwrap();

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

        let expected_data = commitment.chained_commitment.expected_data().unwrap();

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
        assert_eq!(
            expected_data,
            chunk_file_commitment.expected_data().unwrap()
        );

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
            prov_index_file_commitment.expected_data().unwrap()
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
            core_index_file_commitment.expected_data().unwrap()
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
            tx_commitment.expected_data().unwrap()
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
            merkle_root_commitment.expected_data().unwrap()
        ));

        // Verify the Merkle root commitment.
        assert!(&merkle_root_commitment.verify(merkle_root).is_ok());

        // Finally, the sixth one commits to the block hash (PoW)
        // and is expected to contain the Merkle root.
        let block_hash_commitment = commitments.get(5).unwrap();
        assert_eq!(block_hash_commitment.hash().unwrap(), block_hash_str);
        assert!(json_contains(
            &json!(merkle_root),
            block_hash_commitment.expected_data().unwrap()
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

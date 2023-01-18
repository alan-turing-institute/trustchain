use bitcoin::util::psbt::serialize::Deserialize;
use bitcoin::MerkleBlock;
use bitcoin::{Script, Transaction};
use flate2::read::GzDecoder;
use ipfs_hasher::IpfsHasher;
use serde_json::{json, Map};
use ssi::did::Document;
use std::collections::HashMap;
use std::io::Read;
use trustchain_core::commitment::TrivialCommitment;
use trustchain_core::commitment::{Commitment, CommitmentError};
use trustchain_core::commitment::{IterableCommitment, IteratedCommitment};

use crate::utils::reverse_endianness;
use crate::HASH_PREV_BLOCK_KEY;
use crate::MERKLE_ROOT_KEY;
use crate::NONCE_KEY;
use crate::TIMESTAMP_KEY;
use crate::VERSION_KEY;
use crate::{BITS_KEY, SERVICE_KEY, VERIFICATION_METHOD_KEY};
use crate::{CID_KEY, DID_DELIMITER, ION_METHOD, ION_OPERATION_COUNT_DELIMITER};

/// A TrivialCommitment whose hash is an IPFS content identifier (CID).
pub struct TrivialIpfsCommitment {
    candidate_data: Vec<u8>,
}

impl TrivialIpfsCommitment {
    pub fn new(candidate_data: Vec<u8>) -> Self {
        Self { candidate_data }
    }
}

impl TrivialCommitment for TrivialIpfsCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        |x| {
            let ipfs_hasher = IpfsHasher::default();
            Ok(ipfs_hasher.compute(x))
        }
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
        |x| {
            // Convert the Gzipped IPFS file (bytes) to a JSON Value.
            let mut decoder = GzDecoder::new(x);
            let mut ipfs_content_str = String::new();
            match decoder.read_to_string(&mut ipfs_content_str) {
                Ok(_) => {
                    match serde_json::from_str(&ipfs_content_str) {
                        Ok(value) => return Ok(value),
                        Err(e) => {
                            eprintln!("Error deserialising IPFS content to JSON: {}", e);
                            return Err(CommitmentError::DataDecodingError);
                        }
                    };
                }
                Err(e) => {
                    eprintln!("Error decoding IPFS content: {}", e);
                    return Err(CommitmentError::DataDecodingError);
                }
            }
        }
    }

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        Box::new(IpfsCommitment::new(*self, expected_data))
    }
}

/// A Commitment whose hash is an IPFS content identifier (CID).
pub struct IpfsCommitment {
    trivial_commitment: TrivialIpfsCommitment,
    expected_data: serde_json::Value,
}

impl IpfsCommitment {
    pub fn new(
        trivial_commitment: TrivialIpfsCommitment,
        expected_data: serde_json::Value,
    ) -> Self {
        Self {
            trivial_commitment,
            expected_data,
        }
    }
}

impl TrivialCommitment for IpfsCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        self.trivial_commitment.hasher()
    }

    fn candidate_data(&self) -> &[u8] {
        self.trivial_commitment.candidate_data()
    }

    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
        self.trivial_commitment.decode_candidate_data()
    }

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        Box::new(*self)
    }
}

impl Commitment for IpfsCommitment {
    fn expected_data(&self) -> &serde_json::Value {
        &self.expected_data
    }
}
// End of IpfsCommitment.

/// A TrivialCommitment whose hash is a Bitcoin transaction ID.
pub struct TrivialTxCommitment {
    candidate_data: Vec<u8>,
}

impl TrivialTxCommitment {
    pub fn new(candidate_data: Vec<u8>) -> Self {
        Self { candidate_data }
    }
}

impl TrivialCommitment for TrivialTxCommitment {
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
                    return Err(CommitmentError::FailedToComputeHash);
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
            let mut op_return_data = "";
            let ion_substr = format!("{}{}", ION_METHOD, DID_DELIMITER);
            for script in &op_return_scripts {
                match std::str::from_utf8(&script.as_ref()) {
                    Ok(op_return_str) => match op_return_str.find(&ion_substr) {
                        Some(i) => {
                            if op_return_data.len() == 0 {
                                op_return_data = &op_return_str[i..] // Trim any leading characters.
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
            if op_return_data.len() == 0 {
                eprintln!("Error: no ION OP_RETURN script found.");
                return Err(CommitmentError::DataDecodingError);
            }
            // Extract the IPFS content identifier from the ION OP_RETURN data.
            let (_, operation_count_plus_cid) = op_return_data.rsplit_once(DID_DELIMITER).unwrap();
            let (_, cid) = operation_count_plus_cid
                .rsplit_once(ION_OPERATION_COUNT_DELIMITER)
                .unwrap();
            let cid_json_str = format!(r#"{{"{}":"{}"}}"#, CID_KEY, cid);
            if let Ok(value) = serde_json::from_str(&cid_json_str) {
                Ok(value)
            } else {
                eprintln!("Error: failed to construct candidate data JSON from IPFS CID.");
                Err(CommitmentError::DataDecodingError)
            }
        }
    }

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        Box::new(TxCommitment::new(*self, expected_data))
    }
}

/// A Commitment whose hash is a Bitcoin transaction ID.
pub struct TxCommitment {
    trivial_commitment: TrivialTxCommitment,
    expected_data: serde_json::Value,
}

impl TxCommitment {
    pub fn new(trivial_commitment: TrivialTxCommitment, expected_data: serde_json::Value) -> Self {
        Self {
            trivial_commitment,
            expected_data,
        }
    }
}

impl TrivialCommitment for TxCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        self.trivial_commitment.hasher()
    }

    fn candidate_data(&self) -> &[u8] {
        self.trivial_commitment.candidate_data()
    }

    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
        self.trivial_commitment.decode_candidate_data()
    }

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        Box::new(*self)
    }
}

impl Commitment for TxCommitment {
    fn expected_data(&self) -> &serde_json::Value {
        &self.expected_data
    }
}
// End of TxCommitment.

/// A TrivialCommitment whose hash is the root of a Merkle tree of Bitcoin transaction IDs.
pub struct TrivialMerkleRootCommitment {
    candidate_data: Vec<u8>,
}

impl TrivialMerkleRootCommitment {
    pub fn new(candidate_data: Vec<u8>) -> Self {
        Self { candidate_data }
    }
}

impl TrivialCommitment for TrivialMerkleRootCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        // Candidate data is a Merkle proof containing a branch of transaction IDs.
        |x| {
            let merkle_block: MerkleBlock = match bitcoin::consensus::deserialize(&x) {
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
                    return Err(CommitmentError::FailedToComputeHash);
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

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        Box::new(MerkleRootCommitment::new(*self, expected_data))
    }
}

/// A Commitment whose hash is the root of a Merkle tree of Bitcoin transaction IDs.
pub struct MerkleRootCommitment {
    trivial_commitment: TrivialMerkleRootCommitment,
    expected_data: serde_json::Value,
}

impl MerkleRootCommitment {
    pub fn new(
        trivial_commitment: TrivialMerkleRootCommitment,
        expected_data: serde_json::Value,
    ) -> Self {
        Self {
            trivial_commitment,
            expected_data,
        }
    }
}

impl TrivialCommitment for MerkleRootCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        self.trivial_commitment.hasher()
    }

    fn candidate_data(&self) -> &[u8] {
        self.trivial_commitment.candidate_data()
    }

    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
        self.trivial_commitment.decode_candidate_data()
    }

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        Box::new(*self)
    }
}

impl Commitment for MerkleRootCommitment {
    fn expected_data(&self) -> &serde_json::Value {
        &self.expected_data
    }
}
// End of MerkleRootCommitment.

/// A TrivialCommitment whose hash is the PoW hash of a Bitcoin block.
pub struct TrivialBlockHashCommitment {
    candidate_data: Vec<u8>,
}

impl TrivialBlockHashCommitment {
    pub fn new(candidate_data: Vec<u8>) -> Self {
        Self { candidate_data }
    }
}

impl TrivialCommitment for TrivialBlockHashCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        // Candidate data the block header bytes.
        |x| {
            // Bitcoin block hash is a double SHA256 hash of the block header.
            // We use a generic SHA256 library to avoid trust in rust-bitcoin.
            let hash1_hex = sha256::digest(&*x);
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
        |x| decode_block_header(&x)
    }

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        Box::new(BlockHashCommitment::new(*self, expected_data))
    }
}

/// A Commitment whose hash is the root of a Merkle tree of Bitcoin transaction IDs.
pub struct BlockHashCommitment {
    trivial_commitment: TrivialBlockHashCommitment,
    expected_data: serde_json::Value,
}

impl BlockHashCommitment {
    pub fn new(
        trivial_commitment: TrivialBlockHashCommitment,
        expected_data: serde_json::Value,
    ) -> Self {
        Self {
            trivial_commitment,
            expected_data,
        }
    }
}

impl TrivialCommitment for BlockHashCommitment {
    fn hasher(&self) -> fn(&[u8]) -> Result<String, CommitmentError> {
        self.trivial_commitment.hasher()
    }

    fn candidate_data(&self) -> &[u8] {
        self.trivial_commitment.candidate_data()
    }

    fn decode_candidate_data(&self) -> fn(&[u8]) -> Result<serde_json::Value, CommitmentError> {
        self.trivial_commitment.decode_candidate_data()
    }

    fn to_commitment(self: Box<Self>, expected_data: serde_json::Value) -> Box<dyn Commitment> {
        Box::new(*self)
    }
}

impl Commitment for BlockHashCommitment {
    fn expected_data(&self) -> &serde_json::Value {
        &self.expected_data
    }
}
// End of BlockHashCommitment.

/// Decodes a Bitcoin block from 80 bytes of data.
pub fn decode_block_header(bytes: &[u8]) -> Result<serde_json::Value, CommitmentError> {
    // Format is explained here: https://en.bitcoin.it/wiki/Block_hashing_algorithm
    if bytes.len() != 80 {
        eprintln!("Error: Bitcoin block header must be 80 bytes.");
        return Err(CommitmentError::DataDecodingError);
    };

    // Deconstruct the header bytes into big-endian hex. Safe to unwrap as we begin with bytes.
    let version = reverse_endianness(&hex::encode(&bytes[0..4])).unwrap();
    let hash_prev_block = reverse_endianness(&hex::encode(&bytes[4..36])).unwrap();
    let merkle_root = reverse_endianness(&hex::encode(&bytes[36..68])).unwrap();
    let timestamp = reverse_endianness(&hex::encode(&bytes[68..72])).unwrap();
    let bits = reverse_endianness(&hex::encode(&bytes[72..76])).unwrap();
    let nonce = reverse_endianness(&hex::encode(&bytes[76..])).unwrap();

    // Convert to JSON.
    let mut map = HashMap::new();
    map.insert(VERSION_KEY, version);
    map.insert(HASH_PREV_BLOCK_KEY, hash_prev_block);
    map.insert(MERKLE_ROOT_KEY, merkle_root);
    map.insert(TIMESTAMP_KEY, timestamp);
    map.insert(BITS_KEY, bits);
    map.insert(NONCE_KEY, nonce);

    Ok(serde_json::json!(map))
}

/// An iterated commitment to ION DID Document data.
pub struct IONCommitment {
    did_doc: Document,
    iterated_commitment: IteratedCommitment,
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
        // Construct the first Commitment, followed by a sequence of TrivialCommitments.

        // Discard all except the verificationMethod and services elements.
        let did_doc_map = json!(&did_doc).as_object().unwrap().clone();
        let filtered_doc_map: Map<String, serde_json::Value> = did_doc_map
            .into_iter()
            .filter(|(key, _value)| key.eq(&VERIFICATION_METHOD_KEY) || key.eq(&SERVICE_KEY))
            .collect();
        let expected_data = json!(&filtered_doc_map);

        let chunk_file_commitment = IpfsCommitment::new(
            TrivialIpfsCommitment {
                candidate_data: chunk_file,
            },
            expected_data,
        );
        let prov_index_file_commitment = TrivialIpfsCommitment {
            candidate_data: provisional_index_file,
        };
        let core_index_file_commitment = TrivialIpfsCommitment {
            candidate_data: core_index_file,
        };
        let tx_commitment = TrivialTxCommitment {
            candidate_data: transaction,
        };
        let merkle_root_commitment = TrivialMerkleRootCommitment {
            candidate_data: merkle_proof,
        };
        let block_hash_commitment = TrivialBlockHashCommitment {
            candidate_data: block_header,
        };

        let mut iterated_commitment = IteratedCommitment::new(Box::new(chunk_file_commitment));
        iterated_commitment.append(Box::new(prov_index_file_commitment));
        iterated_commitment.append(Box::new(core_index_file_commitment));
        iterated_commitment.append(Box::new(tx_commitment));
        iterated_commitment.append(Box::new(merkle_root_commitment));
        iterated_commitment.append(Box::new(block_hash_commitment));

        Ok(Self {
            did_doc,
            iterated_commitment,
        })
    }

    fn verify(&self, target: &str) -> Result<(), CommitmentError> {
        // Delegate verification to the iterated commitment (as a Commitment).
        Commitment::verify(&self.iterated_commitment, target)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use bitcoin::util::psbt::serialize::Serialize;
    use bitcoin::BlockHash;
    use trustchain_core::data::TEST_ROOT_DOCUMENT;

    use super::*;
    use crate::{
        utils::query_ipfs,
        verifier::{block_header, merkle_proof, transaction},
        CID_KEY, MERKLE_ROOT_KEY, SERVICE_KEY,
    };

    #[test]
    #[ignore = "Integration test requires IPFS"]
    fn test_ipfs_commitment() {
        let target = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let candidate_data_ = query_ipfs(target, None).unwrap();
        let candidate_data = candidate_data_.clone();
        // In the core index file we expect to find the provisionalIndexFileUri.
        let expected_data =
            r#"{"provisionalIndexFileUri":"QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let expected_data: serde_json::Value = serde_json::from_str(expected_data).unwrap();
        let commitment =
            IpfsCommitment::new(TrivialIpfsCommitment { candidate_data }, expected_data);
        assert!(commitment.verify(target).is_ok());

        // We do *not* expect a different target to succeed.
        let bad_target = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J98";
        assert!(commitment.verify(bad_target).is_err());
        match commitment.verify(bad_target) {
            Err(CommitmentError::FailedHashVerification) => (),
            _ => panic!("Expected FailedHashVerification error."),
        }

        // We do *not* expect to find a different provisionalIndexFileUri.
        let bad_expected_data =
            r#"{"provisionalIndexFileUri":"PmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let bad_expected_data = serde_json::from_str(bad_expected_data).unwrap();
        let candidate_data = candidate_data_.clone();
        let commitment =
            IpfsCommitment::new(TrivialIpfsCommitment { candidate_data }, bad_expected_data);
        assert!(commitment.verify(target).is_err());
        match commitment.verify(target) {
            Err(CommitmentError::FailedContentVerification) => (),
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

        let commitment = TxCommitment::new(TrivialTxCommitment { candidate_data }, expected_data);
        assert!(commitment.verify(target).is_ok());

        // We do *not* expect a different target to succeed.
        let bad_target = "8dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        assert!(commitment.verify(bad_target).is_err());
        match commitment.verify(bad_target) {
            Err(CommitmentError::FailedHashVerification) => (),
            _ => panic!("Expected FailedHashVerification error."),
        };

        // We do *not* expect to find a different IPFS CID in the OP_RETURN data.
        let bad_cid_str = "PmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let bad_expected_str = format!(r#"{{"{}":"{}"}}"#, CID_KEY, bad_cid_str);
        let bad_expected_data: serde_json::Value = serde_json::from_str(&bad_expected_str).unwrap();
        let candidate_data = Serialize::serialize(&tx);
        let commitment =
            TxCommitment::new(TrivialTxCommitment { candidate_data }, bad_expected_data);
        assert!(commitment.verify(target).is_err());
        match commitment.verify(target) {
            Err(CommitmentError::FailedContentVerification) => (),
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
        let candidate_data_ = merkle_proof(tx, &block_hash, None).unwrap();
        let candidate_data = candidate_data_.clone();

        let commitment = MerkleRootCommitment::new(
            TrivialMerkleRootCommitment { candidate_data },
            expected_data,
        );
        assert!(commitment.verify(target).is_ok());

        // We do *not* expect a different target to succeed.
        let bad_target = "8dce795209d4b5051da3f5f5293ac97c2ec677687098062044654111529cad69";
        assert!(commitment.verify(bad_target).is_err());
        match commitment.verify(bad_target) {
            Err(CommitmentError::FailedHashVerification) => (),
            _ => panic!("Expected FailedHashVerification error."),
        };

        // We do *not* expect to find an arbitrary transaction ID.
        let bad_txid_str = "2dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        let bad_expected_data = serde_json::json!(bad_txid_str);
        let candidate_data = candidate_data_.clone();
        let commitment = MerkleRootCommitment::new(
            TrivialMerkleRootCommitment { candidate_data },
            bad_expected_data,
        );
        assert!(commitment.verify(target).is_err());
        match commitment.verify(target) {
            Err(CommitmentError::FailedContentVerification) => (),
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

        let commitment =
            BlockHashCommitment::new(TrivialBlockHashCommitment { candidate_data }, expected_data);
        assert!(commitment.verify(target).is_ok());

        // We do *not* expect a different target to succeed.
        let bad_target = "100000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f";
        assert!(commitment.verify(bad_target).is_err());
        match commitment.verify(bad_target) {
            Err(CommitmentError::FailedHashVerification) => (),
            _ => panic!("Expected FailedHashVerification error."),
        };

        // We do *not* expect to find a different Merkle root.
        let bad_merkle_root_str =
            "6dce795209d4b5051da3f5f5293ac97c2ec677687098062044654111529cad69";
        let bad_expected_data = serde_json::json!(bad_merkle_root_str);
        let candidate_data = candidate_data_.clone();
        let commitment = BlockHashCommitment::new(
            TrivialBlockHashCommitment { candidate_data },
            bad_expected_data,
        );
        assert!(commitment.verify(target).is_err());
        match commitment.verify(target) {
            Err(CommitmentError::FailedContentVerification) => (),
            _ => panic!("Expected FailedContentVerification error."),
        };
    }

    #[test]
    #[ignore = "Integration test requires IPFS and Bitcoin Core"]
    fn test_ion_commitment() {
        let did_doc = Document::from_json(TEST_ROOT_DOCUMENT).unwrap();

        let chunk_file_cid = "QmWeK5PbKASyNjEYKJ629n6xuwmarZTY6prd19ANpt6qyN";
        let chunk_file = query_ipfs(chunk_file_cid, None).unwrap();

        let prov_index_file_cid = "QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs";
        let prov_index_file = query_ipfs(prov_index_file_cid, None).unwrap();

        let core_index_file_cid = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let core_index_file = query_ipfs(core_index_file_cid, None).unwrap();

        let block_hash_str = "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f";
        let block_hash = BlockHash::from_str(block_hash_str).unwrap();
        let tx_index = 3;
        let tx = transaction(&block_hash, tx_index, None).unwrap();
        let transaction = Serialize::serialize(&tx);

        let merkle_proof = merkle_proof(tx, &block_hash, None).unwrap();

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

        let expected_data = commitment.iterated_commitment.expected_data();

        // The expected data contains public keys and service endpoints.
        match expected_data {
            serde_json::Value::Object(map) => {
                assert!(map.contains_key(VERIFICATION_METHOD_KEY));
                assert!(map.contains_key(SERVICE_KEY));
            }
            _ => panic!("Expected JSON Map."),
        }

        let target = block_hash_str;

        match commitment.verify(target) {
            Ok(_) => todo!(),
            Err(e) => println!("{:?}", e),
        }

        assert!(commitment.verify(target).is_ok());
    }
}

use bitcoin::util::psbt::serialize::Deserialize;
use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::MerkleBlock;
use bitcoin::{Script, Transaction};
use flate2::read::GzDecoder;
use ipfs_hasher::IpfsHasher;
use std::io::Read;
use trustchain_core::commitment::{Commitment, CommitmentError};

use crate::{CID_KEY, DID_DELIMITER, ION_METHOD, ION_OPERATION_COUNT_DELIMITER};

/// A Commitment whose target is an IPFS content identifier (CID).
pub struct IpfsCommitment {
    target: String,
    candidate_data: Vec<u8>,
    expected_data: serde_json::Value,
}

impl IpfsCommitment {
    pub fn new(target: String, candidate_data: Vec<u8>, expected_data: serde_json::Value) -> Self {
        Self {
            target,
            candidate_data,
            expected_data,
        }
    }
}

impl Commitment for IpfsCommitment {
    fn target(&self) -> &str {
        &self.target
    }

    fn hasher(&self) -> Box<dyn Fn(&[u8]) -> Result<String, CommitmentError>> {
        let ipfs_hasher = IpfsHasher::default();
        Box::new(move |x| Ok(ipfs_hasher.compute(x)))
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    fn decode_candidate_data(&self) -> Result<serde_json::Value, CommitmentError> {
        let mut decoder = GzDecoder::new(self.candidate_data());
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

    fn expected_data(&self) -> &serde_json::Value {
        &self.expected_data
    }
}

/// A Commitment whose target is a Bitcoin transaction ID.
pub struct TxCommitment {
    target: String,
    candidate_data: Vec<u8>,
    expected_data: serde_json::Value,
}

impl TxCommitment {
    pub fn new(target: String, candidate_data: Vec<u8>, expected_data: serde_json::Value) -> Self {
        Self {
            target,
            candidate_data,
            expected_data,
        }
    }
}

impl Commitment for TxCommitment {
    fn target(&self) -> &str {
        &self.target
    }

    fn hasher(&self) -> Box<dyn Fn(&[u8]) -> Result<String, CommitmentError>> {
        // Candidate data is a Bitcoin transaction, whose hash is the transaction ID.
        Box::new(move |x| {
            let tx: Transaction = match Deserialize::deserialize(x) {
                Ok(tx) => tx,
                Err(e) => {
                    eprintln!("Failed to deserialise transaction: {}", e);
                    return Err(CommitmentError::FailedToComputeHash);
                }
            };
            Ok(tx.txid().to_string())
        })
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    /// Deserialises the candidate data into a Bitcoin transaction, then
    /// extracts and returns the IPFS content identifier in the OP_RETURN data.
    fn decode_candidate_data(&self) -> Result<serde_json::Value, CommitmentError> {
        // Deserialise the transaction from the candidate data.
        let bytes = self.candidate_data();
        let tx: Transaction = match Deserialize::deserialize(bytes) {
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

    fn expected_data(&self) -> &serde_json::Value {
        &self.expected_data
    }
}

/// A Commitment whose target is the root of a Merkle tree of Bitcoin transaction IDs.
pub struct MerkleRootCommitment {
    target: String,
    candidate_data: Vec<u8>,
    expected_data: serde_json::Value,
}

impl MerkleRootCommitment {
    pub fn new(target: String, candidate_data: Vec<u8>, expected_data: serde_json::Value) -> Self {
        Self {
            target,
            candidate_data,
            expected_data,
        }
    }
}

impl Commitment for MerkleRootCommitment {
    fn target(&self) -> &str {
        &self.target
    }

    fn hasher(&self) -> Box<dyn Fn(&[u8]) -> Result<String, CommitmentError>> {
        // Candidate data is a Merkle proof containing a branch of transaction IDs.
        Box::new(move |x| {
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
        })
    }

    fn candidate_data(&self) -> &[u8] {
        &self.candidate_data
    }

    /// Deserialises the candidate data into a Merkle proof.
    fn decode_candidate_data(&self) -> Result<serde_json::Value, CommitmentError> {
        let bytes = self.candidate_data();
        let merkle_block: MerkleBlock = match bitcoin::consensus::deserialize(&bytes) {
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

    fn expected_data(&self) -> &serde_json::Value {
        &self.expected_data
    }
}

// // TODO.
// /// Represents a commitment to a DID by a Bitcoin block hash.
// pub struct DIDCommitment {

//     target: String,
//     candidate_data: Vec<u8>,
//     expected_data: serde_json::Value,
// }

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use bitcoin::{consensus::serialize, BlockHash};

    use super::*;
    use crate::{
        utils::query_ipfs,
        verifier::{merkle_proof, transaction},
        CID_KEY, TXID_KEY,
    };

    #[test]
    #[ignore = "Integration test requires IPFS"]
    fn test_ipfs_commitment() {
        let cid = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let candidate_data = query_ipfs(cid, None).unwrap();
        // In the core index file we expect to find the provisionalIndexFileUri.
        let expected_data =
            r#"{"provisionalIndexFileUri":"QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let expected_data: serde_json::Value = serde_json::from_str(expected_data).unwrap();
        let commitment = IpfsCommitment::new(
            cid.to_string(),
            candidate_data.clone(),
            expected_data.clone(),
        );

        assert!(commitment.verify().is_ok());

        // We do *not* expect a different target to succeed.
        let bad_target = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J98";
        let commitment = IpfsCommitment::new(
            bad_target.to_string(),
            candidate_data.clone(),
            expected_data,
        );

        assert!(commitment.verify().is_err());

        // We do *not* expect to find a different provisionalIndexFileUri.
        let expected_data =
            r#"{"provisionalIndexFileUri":"PmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let expected_data = serde_json::from_str(expected_data).unwrap();
        let commitment = IpfsCommitment::new(cid.to_string(), candidate_data, expected_data);

        assert!(commitment.verify().is_err());
    }

    #[test]
    #[ignore = "Integration test requires Bitcoin Core"]
    fn test_tx_commitment() {
        let txid = "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";

        // Get the Bitcoin transaction.
        let block_hash_str = "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f";
        let block_hash = BlockHash::from_str(block_hash_str).unwrap();
        let tx = transaction(&block_hash, 3, None).unwrap();

        // We expect to find the IPFS CID for the ION core index file.
        let cid_str = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let expected_str = format!(r#"{{"{}":"{}"}}"#, CID_KEY, cid_str);
        let expected_data: serde_json::Value = serde_json::from_str(&expected_str).unwrap();
        let candidate_data = Serialize::serialize(&tx);
        let commitment = TxCommitment::new(
            txid.to_string(),
            candidate_data.clone(),
            expected_data.clone(),
        );

        assert!(commitment.verify().is_ok());

        // We do *not* expect a different target to succeed.
        let not_txid = "8dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";

        let commitment =
            TxCommitment::new(not_txid.to_string(), candidate_data.clone(), expected_data);

        assert!(commitment.verify().is_err());

        // We do *not* expect to find a different IPFS CID.
        let expected_str = format!(
            r#"{{"{}":"PmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97"}}"#,
            CID_KEY
        );
        let expected_data: serde_json::Value = serde_json::from_str(&expected_str).unwrap();
        let candidate_data = Serialize::serialize(&tx);
        let commitment = TxCommitment::new(
            txid.to_string(),
            candidate_data.clone(),
            expected_data.clone(),
        );

        assert!(commitment.verify().is_err());
    }

    #[test]
    #[ignore = "Integration test requires Bitcoin Core"]
    fn test_merkle_root_commitment() {
        // The commitment target is the Merkle root from the block header.
        // For the testnet block at height 2377445, the Merkle root is:
        let target = "7dce795209d4b5051da3f5f5293ac97c2ec677687098062044654111529cad69";
        // and the block hash is:
        let block_hash_str = "000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f";

        // We can expect to find the transaction ID in the Merkle proof (candidate data):
        let txid_str = "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        let expected_data = serde_json::json!(txid_str);

        // Get the Bitcoin transaction.
        let block_hash = BlockHash::from_str(block_hash_str).unwrap();
        let tx_index = 3;
        let tx = transaction(&block_hash, tx_index, None).unwrap();

        // The candidate data is a serialized Merkle proof.
        let candidate_data = merkle_proof(tx, &block_hash, None).unwrap();

        let commitment = MerkleRootCommitment::new(
            target.to_string(),
            candidate_data.clone(),
            expected_data.clone(),
        );
        assert!(commitment.verify().is_ok());

        // We do *not* expect a different target to succeed.
        let bad_target = "8dce795209d4b5051da3f5f5293ac97c2ec677687098062044654111529cad69";
        let commitment = MerkleRootCommitment::new(
            bad_target.to_string(),
            candidate_data.clone(),
            expected_data.clone(),
        );
        assert!(commitment.verify().is_err());

        // We do *not* expect to find a different transaction ID.
        let bad_txid_str = "2dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        let bad_expected_data = serde_json::json!(bad_txid_str);
        let commitment = MerkleRootCommitment::new(
            target.to_string(),
            candidate_data.clone(),
            bad_expected_data.clone(),
        );
        assert!(commitment.verify().is_err());
    }
}

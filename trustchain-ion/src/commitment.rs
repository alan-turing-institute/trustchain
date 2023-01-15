use flate2::read::GzDecoder;
use ipfs_hasher::IpfsHasher;
use std::io::Read;
use trustchain_core::commitment::{Commitment, CommitmentError};

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

    fn hasher(&self) -> Box<dyn Fn(&[u8]) -> String> {
        let ipfs_hasher = IpfsHasher::default();
        Box::new(move |x| ipfs_hasher.compute(x))
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

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils::query_ipfs;

    #[test]
    #[ignore = "Integration test requires IPFS"]
    fn test_ipfs_commitment() {
        let cid = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let candidate_data = query_ipfs(cid, None).unwrap();
        // In the core index file we expect to find the provisionalIndexFileUri.
        let expected_data =
            r#"{"provisionalIndexFileUri":"QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let expected_data = serde_json::from_str(expected_data).unwrap();
        let commitment =
            IpfsCommitment::new(cid.to_string(), candidate_data.clone(), expected_data);

        assert!(commitment.verify().is_ok());

        // We do *not* expect to find a different provisionalIndexFileUri.
        let expected_data =
            r#"{"provisionalIndexFileUri":"PmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs"}"#;
        let expected_data = serde_json::from_str(expected_data).unwrap();
        let commitment = IpfsCommitment::new(cid.to_string(), candidate_data, expected_data);

        assert!(commitment.verify().is_err());
    }
}

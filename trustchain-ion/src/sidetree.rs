use did_ion::sidetree::SuffixData;
use serde::{Deserialize, Serialize};

/// Data structure for suffix data in create operations.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSuffixData {
    suffix_data: SuffixData,
}
/// Data structure for suffix data for non-create operations.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OtherOperationSuffixData {
    did_suffix: String,
    reveal_value: String,
}

/// Data structure for core index file operations key.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CoreIndexFileOperations {
    create: Option<Vec<CreateSuffixData>>,
    recover: Option<Vec<OtherOperationSuffixData>>,
    deactivate: Option<Vec<OtherOperationSuffixData>>,
}
/// Data structure for core index file.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CoreIndexFile {
    core_proof_file_uri: Option<String>,
    provisional_index_file_uri: Option<String>,
    writer_lock_id: Option<String>,
    operations: CoreIndexFileOperations,
}

#[cfg(test)]
mod tests {
    use crate::data::TEST_CORE_INDEX_FILE_CONTENT;

    use super::*;

    /// Example data structure from [sidetree](https://identity.foundation/sidetree/spec/#core-index-file).
    const CORE_INDEX_FILE_STRUCTURE: &str = r#"
    {
        "coreProofFileUri": "CAS_URI",
        "provisionalIndexFileUri": "CAS_URI",
        "writerLockId": "OPTIONAL_LOCKING_VALUE",
        "operations": {
          "create": [
            {
              "suffixData": {
                "type": "TYPE_STRING",
                "deltaHash": "DELTA_HASH",
                "recoveryCommitment": "COMMITMENT_HASH"
              }
            }
          ],
          "recover": [
            {
              "didSuffix": "SUFFIX_STRING",
              "revealValue": "MULTIHASH_OF_JWK"
            }
          ],
          "deactivate": [
            {
              "didSuffix": "SUFFIX_STRING",
              "revealValue": "MULTIHASH_OF_JWK"
            }
          ]
        }
    }"#;
    #[test]
    fn test_parse_core_index_file_from_sidetree() {
        let core_index_file: CoreIndexFile =
            serde_json::from_str(CORE_INDEX_FILE_STRUCTURE).unwrap();
        assert!(serde_json::to_string_pretty(&core_index_file).is_ok());
    }
    #[test]
    fn test_parse_core_index_file_from_data() {
        let core_index_file: CoreIndexFile =
            serde_json::from_str(TEST_CORE_INDEX_FILE_CONTENT).unwrap();
        assert!(serde_json::to_string_pretty(&core_index_file).is_ok());
    }
}

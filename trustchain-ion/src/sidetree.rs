use did_ion::{
    sidetree::{Sidetree, SuffixData},
    ION,
};
use serde::{Deserialize, Serialize};

/// Data structure for suffix data of create operations within a [Core Index File](https://identity.foundation/sidetree/spec/#core-index-file).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSuffixData {
    /// DID Suffix data.
    pub suffix_data: SuffixData,
}
/// Data structure for suffix data of recover and deactivate operations within a [Core Index File](https://identity.foundation/sidetree/spec/#core-index-file).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtherOperationSuffixData {
    /// DID suffix.
    pub did_suffix: String,
    /// Reveal value for operation.
    pub reveal_value: String,
}

/// Data structure for operations contained within a [Core Index File](https://identity.foundation/sidetree/spec/#core-index-file).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreIndexFileOperations {
    /// Suffix data associated with create operations.
    pub create: Option<Vec<CreateSuffixData>>,
    /// Suffix data associated with recover operations.
    pub recover: Option<Vec<OtherOperationSuffixData>>,
    /// Suffix data associated with deactivate operations.
    pub deactivate: Option<Vec<OtherOperationSuffixData>>,
}
/// Data structure for a Sidetree [Core Index File](https://identity.foundation/sidetree/spec/#core-index-file).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreIndexFile {
    /// URI of associated [core proof file](https://identity.foundation/sidetree/spec/#core-proof-file).
    pub core_proof_file_uri: Option<String>,
    /// URI of associated [provisional index file](https://identity.foundation/sidetree/spec/#provisional-index-file).
    pub provisional_index_file_uri: Option<String>,
    /// Optional [writer lock property](https://identity.foundation/sidetree/spec/#writer-lock-property).
    pub writer_lock_id: Option<String>,
    /// Data associated with any create, recover or deactivate operations.
    pub operations: Option<CoreIndexFileOperations>,
}

impl CoreIndexFile {
    /// Returns a vector of DID suffixes being created in the core index file.
    pub fn created_did_suffixes(&self) -> Vec<String> {
        if let Some(ops) = self.operations.as_ref() {
            if let Some(created) = ops.create.as_ref() {
                created
                    .iter()
                    .filter_map(|create_suffix_data| {
                        if let Ok(suffix) =
                            ION::serialize_suffix_data(&create_suffix_data.suffix_data)
                        {
                            Some(suffix.to_string())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    }
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
    #[test]
    fn test_created_did_suffixes() {
        let core_index_file: CoreIndexFile =
            serde_json::from_str(TEST_CORE_INDEX_FILE_CONTENT).unwrap();
        let expected = vec![
            "EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
            "EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
            "EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
        ];
        let actual = core_index_file.created_did_suffixes();
        assert_eq!(expected, actual);
    }
}

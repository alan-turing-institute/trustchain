use did_ion::{
    sidetree::{Delta, Sidetree, SuffixData},
    ION,
};
use serde::{Deserialize, Serialize};
use trustchain_core::{commitment::CommitmentError, utils::get_did_suffix};

/// Data structure for suffix data of create operations within a [Core Index File](https://identity.foundation/sidetree/spec/#core-index-file).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSuffixData {
    /// DID Suffix data.
    pub suffix_data: SuffixData,
}
/// Data structure for suffix data of recover and deactivate operations within a [Core Index File](https://identity.foundation/sidetree/spec/#core-index-file).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OtherOperationSuffixData {
    /// DID suffix.
    pub did_suffix: String,
    /// Reveal value for operation.
    pub reveal_value: String,
}

/// Data structure for operations contained within a [Core Index File](https://identity.foundation/sidetree/spec/#core-index-file).
#[derive(Clone, Debug, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub fn created_did_suffixes(&self) -> Option<Vec<String>> {
        Some(
            self.operations
                .as_ref()?
                .create
                .as_ref()?
                .iter()
                .filter_map(|create_suffix_data| {
                    Some(
                        ION::serialize_suffix_data(&create_suffix_data.suffix_data)
                            .ok()?
                            .to_string(),
                    )
                })
                .collect::<Vec<_>>(),
        )
    }
    /// Returns the index of the create operation for the given DID.
    pub fn did_create_operation_index(&self, did: &str) -> Result<usize, CommitmentError> {
        // TODO: to be generalized to roots that have been updated
        let did_suffix = get_did_suffix(did);
        self.created_did_suffixes()
            .ok_or(CommitmentError::FailedContentVerification(
                did.to_string(),
                serde_json::to_string(self).unwrap(),
            ))?
            .into_iter()
            .position(|v| v == did_suffix)
            .ok_or(CommitmentError::FailedContentVerification(
                did.to_string(),
                serde_json::to_string(self).unwrap(),
            ))
    }
}

/// Data structure for operations contained within a [Provisional Index File](https://identity.foundation/sidetree/spec/#provisional-index-file).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionalIndexFileOperations {
    /// Suffix data associated with update operations.
    pub update: Vec<OtherOperationSuffixData>,
}

/// Data structure for Chunk File URI.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkFileUri {
    /// Chunk file URI.
    pub chunk_file_uri: String,
}

/// Data structure for a Sidetree [Provisional Index File](https://identity.foundation/sidetree/spec/#provisional-index-file).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionalIndexFile {
    /// [Provisional Proof File](https://identity.foundation/sidetree/spec/#provisional-proof-file) URI associated with any update operations.
    pub provisional_proof_file_uri: Option<String>,
    /// Array of associated Chunk File URI.
    pub chunks: Option<Vec<ChunkFileUri>>,
    /// Data for any update operations.
    pub operations: Option<ProvisionalIndexFileOperations>,
}

/// Data structure for a Sidetree [Chunk File](https://identity.foundation/sidetree/spec/#chunk-files).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkFile {
    /// Array of [Delta Entry](https://identity.foundation/sidetree/spec/#chunk-file-delta-entry) objects.
    pub deltas: Vec<Delta>,
}

#[cfg(test)]
mod tests {
    use crate::data::{
        TEST_CHUNK_FILE_CONTENT, TEST_CORE_INDEX_FILE_CONTENT, TEST_PROVISIONAL_INDEX_FILE_CONTENT,
    };

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

    /// Example data structure from [sidetree](https://identity.foundation/sidetree/spec/#provisional-index-file).
    const PROVISIONAL_INDEX_FILE_STRUCTURE: &str = r#"
    {
        "provisionalProofFileUri": "CAS_URI",
        "chunks": [
          { "chunkFileUri": "CAS_URI" }
        ],
        "operations": {
          "update": [
            {
              "didSuffix": "SUFFIX_STRING",
              "revealValue": "MULTIHASH_OF_JWK"
            }
          ]
        }
      }
      "#;

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
    fn test_parse_provisional_index_file_from_sidetree() {
        let provisional_index_file: ProvisionalIndexFile =
            serde_json::from_str(PROVISIONAL_INDEX_FILE_STRUCTURE).unwrap();
        assert!(serde_json::to_string_pretty(&provisional_index_file).is_ok());
    }
    #[test]
    fn test_parse_provisional_index_file_from_data() {
        let provisional_index_file: ProvisionalIndexFile =
            serde_json::from_str(TEST_PROVISIONAL_INDEX_FILE_CONTENT).unwrap();
        assert!(serde_json::to_string_pretty(&provisional_index_file).is_ok());
    }
    #[test]
    fn test_parse_chunk_file_from_data() {
        let chunk_file: ChunkFile = serde_json::from_str(TEST_CHUNK_FILE_CONTENT).unwrap();
        assert!(serde_json::to_string_pretty(&chunk_file).is_ok());
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
        let actual = core_index_file.created_did_suffixes().unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_extract_suffix_idx() {
        let core_index_file: CoreIndexFile =
            serde_json::from_str(TEST_CORE_INDEX_FILE_CONTENT).unwrap();
        let expected = 1;
        let actual = core_index_file
            .did_create_operation_index("EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A")
            .unwrap();
        assert_eq!(expected, actual);
    }
}

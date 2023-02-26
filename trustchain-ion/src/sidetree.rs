use std::collections::HashMap;

use did_ion::sidetree::SuffixData;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const CORE_INDEX_FILE_STRUCTURE: &str = r#"
{
    "coreProofFileUri": CAS_URI,
    "provisionalIndexFileUri": CAS_URI,
    "writerLockId": OPTIONAL_LOCKING_VALUE,
    "operations": {
      "create": [
        {
          "suffixData": {
            "type": TYPE_STRING,
            "deltaHash": DELTA_HASH,
            "recoveryCommitment": COMMITMENT_HASH
          }
        },
        {...}
      ],
      "recover": [
        {
          "didSuffix": SUFFIX_STRING,
          "revealValue": MULTIHASH_OF_JWK
        },
        {...}
      ],
      "deactivate": [
        {
          "didSuffix": SUFFIX_STRING,
          "revealValue": MULTIHASH_OF_JWK
        },
        {...}
      ]
    }
}"#;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SuffixReveal {
    did_suffix: String,
    reveal_value: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CoreOperations {
    create: Option<Vec<SuffixData>>,
    recover: Option<Vec<SuffixReveal>>,
    deactivate: Option<Vec<SuffixReveal>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CoreIndexFile {
    core_proof_file_uri: Option<String>,
    provisional_index_file_uri: Option<String>,
    writer_lock_id: Option<String>,
    operations: CoreOperations,
}

#[cfg(test)]
mod tests {
    use super::{CoreIndexFile, CORE_INDEX_FILE_STRUCTURE};

    #[test]
    fn test_parse_core_index_file() {
        let core_index_file: CoreIndexFile =
            serde_json::from_str(CORE_INDEX_FILE_STRUCTURE).unwrap();
        println!(
            "{}",
            serde_json::to_string_pretty(&core_index_file).unwrap()
        );
    }
}

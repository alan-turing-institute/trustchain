use serde_json::{Map, Value};
use ssi::did_resolve::{DocumentMetadata, Metadata};
use std::convert::TryFrom;
use trustchain_core::key_manager::KeyType;

use did_ion::sidetree::DIDStatePatch;
use did_ion::sidetree::PublicKeyJwk;
use did_ion::sidetree::{ServiceEndpointEntry, Sidetree};
use did_ion::ION;

use ssi::did::ServiceEndpoint;
use ssi::jwk::JWK;

use thiserror::Error;

/// An error relating for rustchain-ion crate.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustchainIONError {
    #[error("Key cannot be converted to commmitment value.")]
    FailedToConvertToCommitment,
    #[error("Commitment value could not be extracted from document metadata.")]
    FailedToExtractCommitment,
    #[error("Incorrect key type is provided.")]
    IncorrectKeyType,
}

/// Checks whether there is a proof field in document metadata.
pub fn is_proof_in_doc_meta(doc_meta: &DocumentMetadata) -> bool {
    if let Some(property_set) = doc_meta.property_set.as_ref() {
        property_set.contains_key(&"proof".to_string())
    } else {
        false
    }
}

/// Function to return a patch for adding a proof service.
pub fn add_proof_service(did: &str, proof: &str) -> DIDStatePatch {
    let mut obj: Map<String, Value> = Map::new();
    obj.insert("controller".to_string(), Value::from(did));
    obj.insert("proofValue".to_string(), Value::from(proof.to_owned()));
    DIDStatePatch::AddServices {
        services: vec![ServiceEndpointEntry {
            id: "trustchain-controller-proof".to_string(),
            r#type: "TrustchainProofService".to_string(),
            service_endpoint: ServiceEndpoint::Map(serde_json::Value::Object(obj.clone())),
        }],
    }
}

/// Function to confirm whether a given key is the `commitment` in document metadata
pub fn is_commitment_key(doc_meta: &DocumentMetadata, key: &JWK, key_type: KeyType) -> bool {
    if let Ok(expected_commitment) = key_to_commitment(key) {
        if let Ok(actual_commitment) = extract_commitment(doc_meta, key_type) {
            actual_commitment == expected_commitment
        } else {
            // TODO: handle error
            panic!()
        }
    } else {
        // TODO: handle error
        panic!()
    }
}

/// Extracts commitment of passed key type from document metadata.s
fn extract_commitment(
    doc_meta: &DocumentMetadata,
    key_type: KeyType,
) -> Result<String, TrustchainIONError> {
    todo!()
}

/// Converts a given JWK into a commitment.
fn key_to_commitment(next_update_key: &JWK) -> Result<String, TrustchainIONError> {
    // https://docs.rs/did-ion/latest/src/did_ion/sidetree.rs.html#L214
    // 1. Convert next_update_key to public key (pk)
    // 2. Get commitment value from the pk
    // 3. Return value
    match &PublicKeyJwk::try_from(next_update_key.to_public()) {
        Ok(pk_jwk) => match ION::commitment_scheme(pk_jwk) {
            Ok(commitment) => Ok(commitment),
            Err(_) => Err(TrustchainIONError::FailedToConvertToCommitment),
        },
        Err(_) => Err(TrustchainIONError::FailedToConvertToCommitment),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use trustchain_core::data::{
        TEST_SIDETREE_DOCUMENT_METADATA, TEST_TRUSTCHAIN_DOCUMENT_METADATA,
    };

    #[test]
    fn test_is_proof_in_doc_meta() -> Result<(), Box<dyn std::error::Error>> {
        let tc_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT_METADATA)?;
        assert!(is_proof_in_doc_meta(&tc_doc_meta));

        let sidetree_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_SIDETREE_DOCUMENT_METADATA)?;
        assert!(!is_proof_in_doc_meta(&sidetree_doc_meta));

        Ok(())
    }

    #[test]
    fn test_extract_commitment() -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }

    #[test]
    fn test_is_commitment_key() -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }

    #[test]
    fn test_add_proof_service() -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }
    #[test]
    fn test_key_to_commitment() -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }
}

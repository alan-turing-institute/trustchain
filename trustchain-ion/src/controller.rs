use crate::TrustchainIONError;
// use crate::subject::IONSubject;
use crate::attestor::IONAttestor;
use did_ion::sidetree::{DIDStatePatch, PublicKeyJwk, ServiceEndpointEntry, Sidetree};
use did_ion::ION;
use serde_json::{Map, Value};
use ssi::did::ServiceEndpoint;
use ssi::did_resolve::{DocumentMetadata, Metadata};
use ssi::jwk::JWK;
use std::convert::TryFrom;
use trustchain_core::attestor::Attestor;
use trustchain_core::controller::Controller;
use trustchain_core::key_manager::{ControllerKeyManager, KeyManager, KeyManagerError, KeyType};
use trustchain_core::subject::Subject;
impl KeyManager for IONController {}
impl ControllerKeyManager for IONController {}

/// Type for holding controller data.
pub struct ControllerData {
    did: String,
    controlled_did: String,
    update_key: JWK,
    recovery_key: JWK,
}

impl ControllerData {
    pub fn new(did: String, controlled_did: String, update_key: JWK, recovery_key: JWK) -> Self {
        ControllerData {
            did,
            controlled_did,
            update_key,
            recovery_key,
        }
    }
}

impl TryFrom<ControllerData> for IONController {
    type Error = Box<dyn std::error::Error>;
    fn try_from(data: ControllerData) -> Result<Self, Self::Error> {
        let controller = IONController {
            did: data.did,
            controlled_did: data.controlled_did,
        };
        // Attempt to save the update key, but do not overwrite existing key data.
        controller.save_key(
            controller.controlled_did_suffix(),
            KeyType::UpdateKey,
            &data.update_key,
            false,
        )?;
        // Attempt to save the recovery key, but do not overwrite existing key data.
        controller.save_key(
            controller.controlled_did_suffix(),
            KeyType::RecoveryKey,
            &data.recovery_key,
            false,
        )?;
        Ok(controller)
    }
}

/// Struct for IONController.
pub struct IONController {
    did: String,
    controlled_did: String,
}

impl IONController {
    /// Constructs a new IONController instance from existing Subject and Controller DIDs.
    pub fn new(did: &str, controlled_did: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            did: did.to_owned(),
            controlled_did: controlled_did.to_owned(),
        })
    }

    // TODO: consider moving the create operation into this struct.
    // fn create(doc: DocumentState) -> IONController {
    //     todo!()
    // }
}

impl Subject for IONController {
    fn did(&self) -> &str {
        &self.did
    }
}

impl Controller for IONController {
    fn controlled_did(&self) -> &str {
        &self.controlled_did
    }

    fn update_key(&self) -> Result<JWK, KeyManagerError> {
        let update_key = self.read_update_key(self.controlled_did_suffix())?;
        Ok(update_key)
    }

    fn next_update_key(&self) -> Result<Option<JWK>, KeyManagerError> {
        let next_update_key = self.read_next_update_key(self.controlled_did_suffix())?;
        Ok(Some(next_update_key))
    }

    fn generate_next_update_key(&self) -> Result<(), KeyManagerError> {
        let key = self.generate_key();
        self.save_key(
            self.controlled_did_suffix(),
            KeyType::NextUpdateKey,
            &key,
            false,
        )?;
        Ok(())
    }

    fn recovery_key(&self) -> Result<JWK, KeyManagerError> {
        let recovery_key = self.read_recovery_key(self.controlled_did_suffix())?;
        Ok(recovery_key)
    }

    fn to_attestor(&self) -> Box<dyn Attestor> {
        Box::new(IONAttestor::new(&self.did))
    }
}

impl IONController {
    /// Checks whether there is a proof field in document metadata.
    pub fn is_proof_in_doc_meta(&self, doc_meta: &DocumentMetadata) -> bool {
        if let Some(property_set) = doc_meta.property_set.as_ref() {
            property_set.contains_key(&"proof".to_string())
        } else {
            false
        }
    }

    /// Function to return a patch for adding a proof service.
    pub fn add_proof_service(&self, did: &str, proof: &str) -> DIDStatePatch {
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
    pub fn is_commitment_key(
        &self,
        doc_meta: &DocumentMetadata,
        key: &JWK,
        key_type: KeyType,
    ) -> bool {
        if let Ok(expected_commitment) = self.key_to_commitment(key) {
            if let Ok(actual_commitment) = self.extract_commitment(doc_meta, key_type) {
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
        &self,
        doc_meta: &DocumentMetadata,
        key_type: KeyType,
    ) -> Result<String, TrustchainIONError> {
        if let Some(property_set) = doc_meta.property_set.as_ref() {
            if let Some(Metadata::Map(method)) = property_set.get(&"method".to_string()) {
                let k = match key_type {
                    KeyType::UpdateKey => "updateCommitment",
                    KeyType::NextUpdateKey => "updateCommitment",
                    KeyType::RecoveryKey => "recoveryCommitment",
                    _ => return Err(TrustchainIONError::IncorrectKeyType),
                };
                if let Some(Metadata::String(s)) = method.get(k) {
                    Ok(s.to_owned())
                } else {
                    Err(TrustchainIONError::FailedToExtractCommitment)
                }
            } else {
                Err(TrustchainIONError::FailedToExtractCommitment)
            }
        } else {
            Err(TrustchainIONError::FailedToExtractCommitment)
        }
    }

    /// Converts a given JWK into a commitment.
    fn key_to_commitment(&self, next_update_key: &JWK) -> Result<String, TrustchainIONError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use trustchain_core::data::{
        TEST_RECOVERY_KEY, TEST_SIDETREE_DOCUMENT_METADATA, TEST_TRUSTCHAIN_DOCUMENT_METADATA,
        TEST_UPDATE_KEY,
    };
    use trustchain_core::utils::init;

    // Make an IONController using this test function
    fn test_controller(
        did: &str,
        controlled_did: &str,
    ) -> Result<IONController, Box<dyn std::error::Error>> {
        let update_key: JWK = serde_json::from_str(TEST_UPDATE_KEY)?;
        let recovery_key: JWK = serde_json::from_str(TEST_RECOVERY_KEY)?;
        IONController::try_from(ControllerData::new(
            did.to_string(),
            controlled_did.to_string(),
            update_key,
            recovery_key,
        ))
    }

    #[test]
    fn test_try_from() -> Result<(), Box<dyn std::error::Error>> {
        init();
        let update_key: JWK = serde_json::from_str(TEST_UPDATE_KEY)?;
        let recovery_key: JWK = serde_json::from_str(TEST_RECOVERY_KEY)?;
        let did = "did:example:did_try_from";
        let controlled_did = "did:example:controlled_did_try_from";
        let controlled_did_suffix = "controlled_did_try_from";

        // Make controller using try_from()
        let target = test_controller(did, controlled_did)?;

        assert_eq!(target.controlled_did_suffix(), controlled_did_suffix);

        let loaded_update_key = target.update_key()?;
        assert_eq!(loaded_update_key, update_key);

        let loaded_recovery_key = target.recovery_key()?;
        assert_eq!(loaded_recovery_key, recovery_key);

        Ok(())
    }

    #[test]
    fn test_to_attestor() -> Result<(), Box<dyn std::error::Error>> {
        init();
        let did = "did:example:did_to_attestor";
        let controlled_did = "did:example:controlled_did_to_attestor";
        let did_suffix = "did_to_attestor";
        let controlled_did_suffix = "controlled_did_to_attestor";
        let target = test_controller(did, controlled_did)?;
        assert_eq!(target.did(), did);
        assert_ne!(target.did(), controlled_did);
        assert_eq!(target.did_suffix(), did_suffix);
        assert_ne!(target.did_suffix(), controlled_did_suffix);

        let result = target.to_attestor();
        assert_eq!(result.did(), did);
        assert_ne!(result.did(), controlled_did);
        assert_eq!(result.did_suffix(), did_suffix);
        assert_ne!(result.did_suffix(), controlled_did_suffix);
        Ok(())
    }

    #[test]
    fn test_is_proof_in_doc_meta() -> Result<(), Box<dyn std::error::Error>> {
        init();
        let did = "did:example:did_is_proof_in_doc_meta";
        let controlled_did = "did:example:controlled_is_proof_in_doc_meta";
        let controller = test_controller(did, controlled_did)?;

        let tc_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT_METADATA)?;
        assert!(controller.is_proof_in_doc_meta(&tc_doc_meta));

        let sidetree_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_SIDETREE_DOCUMENT_METADATA)?;
        assert!(!controller.is_proof_in_doc_meta(&sidetree_doc_meta));

        Ok(())
    }

    #[test]
    fn test_extract_commitment() -> Result<(), Box<dyn std::error::Error>> {
        init();
        let did = "did:example:did_extract_commitment";
        let controlled_did = "did:example:controlled_extract_commitment";
        let controller = test_controller(did, controlled_did)?;
        let expected_recovery_commitment = "EiDZpHjQ5x7aRRqv6aUtmOdHsxWktAm1kU1IZl1w7iexsw";
        let expected_update_commitment = "EiBWPR1JNdAQ4j3ZMqurb4rt10NA7s17lztFF9OIcEO3ew";
        let doc_meta: DocumentMetadata = serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT_METADATA)?;

        let update_commiment = controller.extract_commitment(&doc_meta, KeyType::UpdateKey)?;
        assert_eq!(expected_update_commitment, update_commiment.as_str());

        let next_update_commiment =
            controller.extract_commitment(&doc_meta, KeyType::NextUpdateKey)?;
        assert_eq!(expected_update_commitment, next_update_commiment.as_str());

        let recovery_commiment = controller.extract_commitment(&doc_meta, KeyType::RecoveryKey)?;
        assert_eq!(expected_recovery_commitment, recovery_commiment.as_str());
        Ok(())
    }

    #[test]
    fn test_key_to_commitment() -> Result<(), Box<dyn std::error::Error>> {
        init();
        let did = "did:example:did_key_to_commitment";
        let controlled_did = "did:example:controlled_key_to_commitment";
        let update_key: JWK = serde_json::from_str(TEST_UPDATE_KEY)?;
        let recovery_key: JWK = serde_json::from_str(TEST_RECOVERY_KEY)?;

        let controller = test_controller(did, controlled_did)?;

        let expected_recovery_commitment = "EiDZpHjQ5x7aRRqv6aUtmOdHsxWktAm1kU1IZl1w7iexsw";
        let expected_update_commitment = "EiBWPR1JNdAQ4j3ZMqurb4rt10NA7s17lztFF9OIcEO3ew";

        let update_commitment = controller.key_to_commitment(&update_key)?;
        let recovery_commitment = controller.key_to_commitment(&recovery_key)?;

        assert_eq!(expected_update_commitment, update_commitment);
        assert_eq!(expected_recovery_commitment, recovery_commitment);

        Ok(())
    }

    #[test]
    fn test_is_commitment_key() -> Result<(), Box<dyn std::error::Error>> {
        init();
        let did = "did:example:did_is_commitment_key";
        let controlled_did = "did:example:controlled_is_commitment_key";
        let update_key: JWK = serde_json::from_str(TEST_UPDATE_KEY)?;
        let recovery_key: JWK = serde_json::from_str(TEST_RECOVERY_KEY)?;
        let controller = test_controller(did, controlled_did)?;
        let doc_meta: DocumentMetadata = serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT_METADATA)?;

        assert!(controller.is_commitment_key(&doc_meta, &update_key, KeyType::UpdateKey));
        assert!(controller.is_commitment_key(&doc_meta, &recovery_key, KeyType::RecoveryKey));
        Ok(())
    }

    #[test]
    fn test_add_proof_service() -> Result<(), Box<dyn std::error::Error>> {
        // TODO: consider whether more checks than just successful call required
        init();
        let did = "did:example:did_add_proof_service";
        let controlled_did = "did:example:controlled_add_proof_service";
        let controller = test_controller(did, controlled_did)?;
        let proof = "test_proof_information".to_string();
        let _ = controller.add_proof_service(controlled_did, &proof);
        Ok(())
    }
}

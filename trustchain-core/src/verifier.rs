use crate::chain::{Chain, DIDChain};
use crate::resolver::{Resolver, ResolverError};
use crate::utils::canonicalize;
use crate::{controller, ROOT_EVENT_TIME};
use serde_json::to_string_pretty as to_json;
use ssi::did::{VerificationMethod, VerificationMethodMap};
use ssi::did_resolve::Metadata;
use ssi::did_resolve::ResolutionMetadata;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use ssi::one_or_many::OneOrMany;
use ssi::{
    did::Document,
    did_resolve::{DIDResolver, DocumentMetadata},
    ldp::JsonWebSignature2020,
};
use thiserror::Error;

/// An error relating to Trustchain verification.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerifierError {
    /// Invalid payload in proof compared to resolved document.
    #[error("Invalid payload provided in proof for dDID: {0}.")]
    InvalidPayload(String),
    /// Invalid payload in proof compared to resolved document.
    #[error("Invalid signature for proof in dDID: {0}.")]
    InvalidSignature(String),
    /// Invalid root DID after self-controller reached in path.
    #[error("Invalid root DID: {0}.")]
    InvalidRoot(String),
    /// DID not resolvable.
    #[error("DID: {0} is not resolvable.")]
    UnresolvableDID(String),
    /// Failed to build DID chain.
    #[error("Failed to build chain: {0}.")]
    ChainBuildFailure(String),
    /// Chain verification failed.
    #[error("Chain verification failed: {0}.")]
    InvalidChain(String),
    /// No proof value present.
    #[error("No proof could be retrieved from document metadata.")]
    FailureToGetProof,
    /// Failure to get controller from document.
    #[error("No controller could be retrieved from document.")]
    FailureToGetController,
    /// Failure to get DID operation.
    #[error("Error getting {0} DID operation: {1}")]
    FailureToGetDIDOperation(String, String),
    /// Invalid block height.
    #[error("Invalid block height: {0}")]
    InvalidBlockHeight(i32),
    /// Invalid transaction index.
    #[error("Invalid transaction index: {0}")]
    InvalidTransactionIndex(i32),
}

/// Verifier of root and downstream DIDs.
pub trait Verifier<T: Sync + Send + DIDResolver> {
    /// Verify a downstream DID by tracing its chain back to the root.
    fn verify(&self, did: &str, root_timestamp: u32) -> Result<(), VerifierError> {
        // Build a chain from the given DID to the root.
        let chain = match DIDChain::new(did, &self.resolver()) {
            Ok(x) => x,
            Err(e) => return Err(VerifierError::ChainBuildFailure(e.to_string())),
        };

        // Verify the proofs in the chain.
        match chain.verify_proofs() {
            Ok(_) => (),
            Err(e) => return Err(VerifierError::InvalidChain(e.to_string())),
        };

        // Verify the root timestamp.
        let root = chain.root();
        if self.verified_timestamp(root) != root_timestamp {
            return Err(VerifierError::InvalidRoot(root.to_string()));
        }
        Ok(())
    }

    /// Get the verified timestamp for a DID as a Unix time.
    fn verified_timestamp(&self, did: &str) -> u32;
    // /// Get the resolver used for DID verification.
    fn resolver(&self) -> &Resolver<T>;
}

/// Gets controller from the passed document.
fn get_controller(doc: &Document) -> Result<String, VerifierError> {
    // Get property set
    if let Some(OneOrMany::One(controller)) = doc.controller.as_ref() {
        Ok(controller.to_string())
    } else {
        Err(VerifierError::FailureToGetController)
    }
}
/// Gets proof from DocumentMetadata.
fn get_proof(doc_meta: &DocumentMetadata) -> Result<&str, VerifierError> {
    // Get property set
    if let Some(property_set) = doc_meta.property_set.as_ref() {
        // Get proof
        if let Some(Metadata::Map(proof)) = property_set.get("proof") {
            // Get proof value
            if let Some(Metadata::String(proof_value)) = proof.get("proofValue") {
                Ok(proof_value)
            } else {
                Err(VerifierError::FailureToGetProof)
            }
        } else {
            Err(VerifierError::FailureToGetProof)
        }
    } else {
        Err(VerifierError::FailureToGetProof)
    }
}

/// TODO: Extract payload from JWS
fn decode(proof_value: &JsonWebSignature2020) -> String {
    todo!()
}

// TODO: Hash a canonicalized object
fn hash(canonicalized_value: &str) -> String {
    todo!()
}

/// Extracts vec of public keys from a doc.
fn extract_keys(doc: &Document) -> Vec<JWK> {
    let mut public_keys: Vec<JWK> = Vec::new();
    if let Some(verification_methods) = doc.verification_method.as_ref() {
        for verification_method in verification_methods {
            if let VerificationMethod::Map(VerificationMethodMap {
                public_key_jwk: Some(key),
                ..
            }) = verification_method
            {
                public_keys.push(key.clone());
            } else {
                continue;
            }
        }
    }
    public_keys
}

// TODO: Check whether correct signature on proof_value given vec of public keys
fn verify_jws(proof_value: &JsonWebSignature2020, public_keys: &Vec<JWK>) -> bool {
    todo!()
}

// TODO: Get the created at time from document metadata for comparison with ROOT_EVENT_TIME
fn get_created_at(doc_meta: &DocumentMetadata) -> u64 {
    todo!()
}

// TODO: add tests for each of the verifier error cases
// TODO: add test DID document and document metadata
#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{
        TEST_ROOT_DOCUMENT, TEST_ROOT_DOCUMENT_METADATA, TEST_ROOT_PLUS_1_DOCUMENT,
        TEST_ROOT_PLUS_1_DOCUMENT_METADATA, TEST_ROOT_PLUS_2_DOCUMENT_METADATA,
    };

    const ROOT_SIGNING_KEYS: &str = r##"
    [
        {
            "kty": "EC",
            "crv": "secp256k1",
            "x": "7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso",
            "y": "kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"
        }
    ]
    "##;

    #[test]
    fn test_get_proof() -> Result<(), Box<dyn std::error::Error>> {
        let root_doc_meta: DocumentMetadata = serde_json::from_str(TEST_ROOT_DOCUMENT_METADATA)?;
        let root_plus_1_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_ROOT_PLUS_1_DOCUMENT_METADATA)?;
        let root_plus_2_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_ROOT_PLUS_2_DOCUMENT_METADATA)?;

        let root_proof = get_proof(&root_doc_meta);
        let root_plus_1_proof = get_proof(&root_plus_1_doc_meta);
        let root_plus_2_proof = get_proof(&root_plus_2_doc_meta);

        assert!(root_proof.is_err());
        assert!(root_plus_1_proof.is_ok());
        assert!(root_plus_2_proof.is_ok());
        Ok(())
    }

    #[test]
    fn test_extract_keys() -> Result<(), Box<dyn std::error::Error>> {
        let expected_root_keys: Vec<JWK> = serde_json::from_str(ROOT_SIGNING_KEYS)?;
        let root_doc: Document = serde_json::from_str(TEST_ROOT_DOCUMENT)?;
        let actual_root_keys = extract_keys(&root_doc);
        assert_eq!(actual_root_keys, expected_root_keys);
        Ok(())
    }

    #[test]
    fn test_get_controller() -> Result<(), Box<dyn std::error::Error>> {
        let doc: Document = serde_json::from_str(TEST_ROOT_PLUS_1_DOCUMENT)?;
        let expected_controller = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
        let actual_controller = get_controller(&doc)?;
        assert_eq!(expected_controller, actual_controller);
        Ok(())
    }
}

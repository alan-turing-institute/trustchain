use crate::resolver::{Resolver, ResolverError};
use crate::utils::canonicalize;
use ssi::did::{VerificationMethod, VerificationMethodMap};
use ssi::did_resolve::Metadata;
use ssi::jwk::JWK;
use ssi::{
    did::{self, Document},
    did_resolve::{DIDResolver, DocumentMetadata},
    ldp::JsonWebSignature2020,
    one_or_many::OneOrMany,
};
use std::{collections::HashMap, convert::TryFrom};
use thiserror::Error;

/// An error relating to a DID chain.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChainError {
    // #[error("Invalid data. Failed to prepend DID: {0}.")]
    // PrependFailed(String),
    #[error("Failed to resolve DID: {0}.")]
    ResolutionFailure(String),
    #[error("Found multiple controllers in DID: {0}.")]
    MultipleControllers(String),
    /// No proof value present.
    #[error("No proof could be retrieved from document metadata.")]
    FailureToGetProof,
    /// Failure to get controller from document.
    #[error("No controller could be retrieved from document.")]
    FailureToGetController,
}

/// A chain of DIDs.
pub trait Chain {
    // /// Constructs a new DID chain.
    // fn new<T: DIDResolver + Sync + Send>(did: &str, resolver: &Resolver<T>) -> Result<Box<Self>, ChainError>;
    /// Returns the length of the DID chain.
    fn len(&self) -> usize;
    /// Returns the level of the given DID in the chain.
    fn level(&self, did: &str) -> Option<usize>;
    /// Gets the root DID.
    fn root(&self) -> &str;
    /// Gets the leaf node DID.
    fn leaf(&self) -> &str;
    /// Gets the next upstream DID.
    fn upstream(&self, did: &str) -> Option<&str>;
    /// Gets the next downstream DID.
    fn downstream(&self, did: &str) -> Option<&str>;
    /// Gets data for the given DID.
    fn data(&self, did: &str) -> Option<(Document, DocumentMetadata)>;
    /// Verify all of the proofs in the chain.
    fn verify_proofs(&self) -> Result<(), ChainError>;
}

// TODO: the functions below need completing. Comments:
//   - Some are already implemented in resolver.
//   - Some may benefit from being part of a struct impl.

/// Gets controller from the passed document.
fn get_controller(doc: &Document) -> Result<String, ChainError> {
    // Get property set
    if let Some(OneOrMany::One(controller)) = doc.controller.as_ref() {
        Ok(controller.to_string())
    } else {
        Err(ChainError::FailureToGetController)
    }
}
/// Gets proof from DocumentMetadata.
fn get_proof(doc_meta: &DocumentMetadata) -> Result<&str, ChainError> {
    // Get property set
    if let Some(property_set) = doc_meta.property_set.as_ref() {
        // Get proof
        if let Some(Metadata::Map(proof)) = property_set.get("proof") {
            // Get proof value
            if let Some(Metadata::String(proof_value)) = proof.get("proofValue") {
                Ok(proof_value)
            } else {
                Err(ChainError::FailureToGetProof)
            }
        } else {
            Err(ChainError::FailureToGetProof)
        }
    } else {
        Err(ChainError::FailureToGetProof)
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

pub struct DIDChain {
    // An map from DID strings to resolved tuples.
    did_map: HashMap<String, (Document, DocumentMetadata)>,

    // Vector to keep track of the level of each DID.
    level_vec: Vec<String>,
}

impl DIDChain {
    // Public constructor.
    pub fn new<T: DIDResolver + Sync + Send>(
        did: &str,
        resolver: &Resolver<T>,
    ) -> Result<Self, ChainError> {
        // Result<Box<Self>, ChainError> {

        // Construct an empty chain.
        let mut chain = DIDChain::empty();

        // Start from the passed DID.
        let mut ddid: String = did.to_string();

        // Loop up the DID chain until the root is reached or an error occurs.
        loop {
            // Resolve the current DID.
            let resolved = resolver.resolve_as_result(&ddid);

            if let Ok((_, Some(ddoc), Some(ddoc_meta))) = resolved {
                // Clone the controller information before moving ddoc into the chain.
                let controller = ddoc.controller.to_owned();

                // Prepend the current DID to the chain.
                chain.prepend((ddoc, ddoc_meta));

                // Extract the controller from the DID document.
                // If there is no controller, this is the root.
                // If there is more than one controller, return an error.
                // TODO: multiple controllers is a verfication error, not a chain error.
                let udid = match controller {
                    None => {
                        return Ok(chain); // Ok(Box::new(chain))
                    }
                    Some(x) => match x.to_owned() {
                        OneOrMany::One(udid) => udid,
                        OneOrMany::Many(_) => return Err(ChainError::MultipleControllers(ddid)),
                    },
                };

                // If ddid is not the root, return to start of loop on the controller's DID.
                ddid = udid;
            } else {
                // If any resolution attempt fails, return an error.
                return Err(ChainError::ResolutionFailure(ddid));
            }
        }
    }

    /// Private constructor of an empty DIDChain.
    fn empty() -> Self {
        Self {
            did_map: HashMap::<String, (Document, DocumentMetadata)>::new(),
            level_vec: Vec::<String>::new(),
        }
    }

    /// Prepend a DID to the chain.
    fn prepend(&mut self, tuple: (Document, DocumentMetadata)) {
        let (doc, doc_meta) = tuple;
        &self.level_vec.push(doc.id.to_owned());
        &self.did_map.insert(doc.id.to_owned(), (doc, doc_meta));
    }
}

impl Chain for DIDChain {
    fn len(&self) -> usize {
        self.level_vec.len().to_owned()
    }

    fn level(&self, did: &str) -> Option<usize> {
        if !&self.level_vec.contains(&did.to_owned()) {
            return None;
        }

        // Subtract level vector index from the length.
        let index = &self.level_vec.iter().position(|x| x == did).unwrap();
        Some(&self.len() - 1 - index)
    }

    fn root(&self) -> &str {
        match &self.len() > &0 {
            true => &self.level_vec.last().unwrap(),
            // The public constructor prevents an empty chain from existing.
            false => panic!("Empty chain!"),
        }
    }

    fn leaf(&self) -> &str {
        match &self.len() > &0 {
            true => &self.level_vec.first().unwrap(),
            // The public constructor prevents an empty chain from existing.
            false => panic!("Empty chain!"),
        }
    }

    fn verify_proofs(&self) -> Result<(), ChainError> {
        // TODO: move some of the chain verification logic from the
        // original Verifier::verify implementation into this method.
        // (See file verifier.rs)

        // TODO: verify signatures in parallel.

        // Start from the leaf node.
        let did = self.leaf();

        while did != self.root() {
            // Get the DID & its data.
            let (did_doc, did_doc_meta) = self.data(&did).unwrap();

            // Get the upstream DID & its data.
            let udid = &self.upstream(did).unwrap();
            let (udid_doc, udid_doc_meta) = self.data(&udid).unwrap();

            // Extract the controller proof from the document metadata.
            // let proof = get_proof(&did_doc_meta);

            todo!();
            // TODO FROM HERE:
            // - Add a get_proof_payload(&doc_meta) function inside the Verifier module.
            // - Call it to get the proof_payload.
            // - Check whether "payload" is the correct term (in JWS).
            // - Create a util function: fn hash(Document);

            // Verify the payload of the JWS proofvalue matches the DID document.
            // TODO (see below)

            // Reconstruct the actual payload.
            // let actual_payload = hash(&canonicalize(&udid_doc).unwrap());
        }
        Ok(())

        //             // 0.2 Extract proof from document metadata
        //             let proof = get_proof(&ddoc_meta);

        //             // 1. Verify the payload of the JWS proofvalue is equal to the doc
        //             // 1.1 Get proof payload
        //             let proof_payload = decode(&proof);

        //             // 1.2 Reconstruct payload
        //             let actual_payload = hash(&canonicalize(&ddoc).unwrap());

        //             // 1.3 Check equality
        //             if proof_payload != actual_payload {
        //                 return Err(VerifierError::InvalidPayload(ddid.to_string()));
        //             }

        //             // 2. Check the signature itself is valid
        //             // Resolve the uDID (either get hashmap entry or resolve)
        //             let udid_resolution = self
        //                 .visited
        //                 .entry(udid.clone())
        //                 .or_insert(self.resolver.resolve_as_result(&udid));

        //             if let Ok((_, Some(udoc), Some(udoc_meta))) = udid_resolution {
        //                 // 2.1 Extract keys from the uDID document
        //                 let udid_pks: Vec<JWK> = extract_keys(&udoc);

        //                 // // 2.2 Loop over the keys until signature is valid
        //                 let one_valid_key: bool = verify_jws(&proof, &udid_pks);

        //                 // // 2.3 If one_valid_key is false, return error
        //                 if !one_valid_key {
        //                     return Err(VerifierError::InvalidSignature(ddid.to_string()));
        //                 }

        //                 // 2.4 Get uDID controller (uuDID)
        //                 let uudid: &str = get_controller(&udoc);

        //                 // 2.5 If uuDID is the same as uDID, this is a root,
        //                 // check "created_at" property matches hard coded ROOT_EVENT_TIME
        //                 if uudid == udid {
        //                     let created_at = get_created_at(&udoc_meta);
        //                     if created_at == ROOT_EVENT_TIME {
        //                         return Ok(());
        //                     } else {
        //                         return Err(VerifierError::InvalidRoot(uudid.to_string()));
        //                     }
        //                 } else {
        //                     // 2.6 If not a root, set ddid as udid, and return to start of loop
        //                     ddid = udid;
        //                 }
        //             } else {
        //                 // Return an error as uDID not resolvable
        //                 return Err(VerifierError::UnresolvableDID(udid.to_string()));
        //             }
    }

    fn upstream(&self, did: &str) -> Option<&str> {
        todo!()
    }

    fn downstream(&self, did: &str) -> Option<&str> {
        todo!()
    }

    fn data(&self, did: &str) -> Option<(Document, DocumentMetadata)> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::*;
    use crate::data::{
        TEST_ROOT_DOCUMENT, TEST_ROOT_DOCUMENT_METADATA, TEST_ROOT_PLUS_1_DOCUMENT,
        TEST_ROOT_PLUS_1_DOCUMENT_METADATA, TEST_ROOT_PLUS_2_DOCUMENT,
        TEST_ROOT_PLUS_2_DOCUMENT_METADATA, TEST_SIDETREE_DOCUMENT,
        TEST_SIDETREE_DOCUMENT_METADATA, TEST_TRUSTCHAIN_DOCUMENT,
        TEST_TRUSTCHAIN_DOCUMENT_METADATA,
    };
    // use crate::data::{
    //     TEST_SIDETREE_DOCUMENT, TEST_SIDETREE_DOCUMENT_METADATA,
    //     TEST_SIDETREE_DOCUMENT_MULTIPLE_PROOF, TEST_SIDETREE_DOCUMENT_SERVICE_AND_PROOF,
    //     TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF, TEST_SIDETREE_DOCUMENT_WITH_CONTROLLER,
    //     TEST_TRUSTCHAIN_DOCUMENT, TEST_TRUSTCHAIN_DOCUMENT_METADATA,
    // };

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

    use crate::utils::canonicalize;
    use ssi::did_resolve::HTTPDIDResolver;

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

    // Helper function returns a resolved tuple.
    fn resolved_tuple() -> (Document, DocumentMetadata) {
        (
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load."),
            serde_json::from_str(TEST_SIDETREE_DOCUMENT_METADATA)
                .expect("Document failed to load."),
        )
    }

    // Helper function returns a chain of three DIDs.
    fn test_chain() -> Result<DIDChain, Box<dyn std::error::Error>> {
        let mut chain = DIDChain::empty();

        let root_doc: Document = serde_json::from_str(TEST_ROOT_DOCUMENT)?;
        let level1_doc: Document = serde_json::from_str(TEST_ROOT_PLUS_1_DOCUMENT)?;
        let level2_doc: Document = serde_json::from_str(TEST_ROOT_PLUS_2_DOCUMENT)?;

        let root_doc_meta: DocumentMetadata = serde_json::from_str(TEST_ROOT_DOCUMENT_METADATA)?;
        let level1_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_ROOT_PLUS_1_DOCUMENT_METADATA)?;
        let level2_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_ROOT_PLUS_2_DOCUMENT_METADATA)?;

        chain.prepend((level2_doc, level2_doc_meta));
        chain.prepend((level1_doc, level1_doc_meta));
        chain.prepend((root_doc, root_doc_meta));
        Ok(chain)
    }

    // Helper function returns an invalid chain of three DIDs.
    fn test_invalid_chain() -> Result<DIDChain, Box<dyn std::error::Error>> {
        let mut chain = DIDChain::empty();

        let root_doc: Document = serde_json::from_str(TEST_ROOT_DOCUMENT)?;
        let level1_doc: Document = serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT)?;
        let level2_doc: Document = serde_json::from_str(TEST_ROOT_PLUS_2_DOCUMENT)?;

        let root_doc_meta: DocumentMetadata = serde_json::from_str(TEST_ROOT_DOCUMENT_METADATA)?;
        let level1_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT_METADATA)?;
        let level2_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_ROOT_PLUS_2_DOCUMENT_METADATA)?;

        chain.prepend((level2_doc, level2_doc_meta));
        chain.prepend((level1_doc, level1_doc_meta));
        chain.prepend((root_doc, root_doc_meta));
        Ok(chain)
    }

    #[test]
    fn test_len_level_prepend() {
        let mut target = DIDChain::empty();
        let expected_ddid = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ";

        // Check that the chain is initially empty.
        assert_eq!(target.len(), 0);
        assert!(target.level(expected_ddid).is_none());

        // Prepend a DID to the chain
        target.prepend(resolved_tuple());

        // Check that the chain now has one node.
        assert_eq!(target.len(), 1);

        // Check that the HashMap key matches the DID.
        assert_eq!(target.did_map.keys().len(), 1);
        assert!(target.did_map.contains_key(expected_ddid));

        // Check the level.
        assert!(target.level(expected_ddid).is_some());
        assert_eq!(target.level(expected_ddid).unwrap(), 0);

        // TODO: prepend another DID and repeat the above tests.
        // let did1 = ""
    }

    fn test_root() {
        let target = test_chain().unwrap();
        assert_eq!(
            target.root(),
            "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
        )
    }

    fn test_verify_proofs() {
        let target = test_chain().unwrap();
        assert!(target.verify_proofs().is_ok());
        let target = test_invalid_chain().unwrap();
        assert!(target.verify_proofs().is_err());
    }

    // TODO: other unit tests.
}

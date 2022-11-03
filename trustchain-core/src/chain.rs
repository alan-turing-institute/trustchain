use crate::resolver::Resolver;
use crate::utils::{canonicalize, decode, decode_verify, hash};
use crate::ROOT_EVENT_TIME;
use serde::{Deserialize, Serialize};
use ssi::did::{Service, ServiceEndpoint, VerificationMethod, VerificationMethodMap};
use ssi::did_resolve::Metadata;
use ssi::jwk::JWK;
use ssi::{
    did::Document,
    did_resolve::{DIDResolver, DocumentMetadata},
    one_or_many::OneOrMany,
};
use std::collections::HashMap;
use std::fmt;
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
    /// Failure to verify JWT.
    #[error("No keys are valid for the JWT provided.")]
    InvalidKeys,
    /// Failure to verify payload.
    #[error("Payload of JWT does not match reconstructed payload.")]
    InvalidPayload,
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
    fn upstream(&self, did: &str) -> Option<&String>;
    /// Gets the next downstream DID.
    fn downstream(&self, did: &str) -> Option<&String>;
    /// Gets data for the given DID.
    fn data(&self, did: &str) -> Option<&(Document, DocumentMetadata)>;
    /// Verify all of the proofs in the chain.
    fn verify_proofs(&self) -> Result<(), ChainError>;
    /// Return view of chain in correct order
    fn as_vec(&self) -> &Vec<String>;
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

#[derive(Debug, Serialize, Deserialize)]
pub struct DIDChain {
    // An map from DID strings to resolved tuples.
    did_map: HashMap<String, (Document, DocumentMetadata)>,

    // Vector to keep track of the level of each DID.
    level_vec: Vec<String>,
}

fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s.to_string(),
        Some((idx, _)) => (s[..idx - 3].to_string() + "..."),
    }
}

fn get_service_endpoint_string(doc: &Document) -> Option<String> {
    match doc.select_service("TrustchainID") {
        Some(Service {
            service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(service_endpoint))),
            ..
        }) => Some(service_endpoint.to_string()),
        _ => None,
    }
}

/// Struct for displaying DID in a box.
pub struct PrettyDID {
    did: String,
    level: usize,
    endpoint: Option<String>,
}

/// Max width in chars for printing
const MAX_WIDTH: usize = 79;

impl PrettyDID {
    fn new(did: &str, level: usize, endpoint: Option<String>) -> Self {
        Self {
            did: did.to_string(),
            level,
            endpoint,
        }
    }
    fn get_width(&self) -> usize {
        format!(" DID: {} ", self.did).len().min(MAX_WIDTH)
    }
    fn get_text_width(&self) -> usize {
        self.get_width() - 2
    }
    fn get_strings(&self) -> [String; 3] {
        let text_width = self.get_text_width();
        let level_string = truncate(&format!("Level: {}", self.level), text_width);
        let did_string = truncate(&format!("DID: {}", self.did), text_width);
        let endpoint_string = match &self.endpoint {
            Some(s) => truncate(&format!("Endpoint: {}", s), text_width),
            _ => truncate(&format!("Endpoint: {}", ""), text_width),
        };
        [level_string, did_string, endpoint_string]
    }
    pub fn to_node_string(&self) -> String {
        let strings = self.get_strings();
        strings.join("\n")
    }
}

impl From<(&Document, usize)> for PrettyDID {
    fn from(doc_level_pair: (&Document, usize)) -> Self {
        let did = doc_level_pair.0.id.clone();
        let endpoint = get_service_endpoint_string(doc_level_pair.0);
        Self {
            did,
            level: doc_level_pair.1,
            endpoint,
        }
    }
}

impl fmt::Display for PrettyDID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Style:
        // "+---------------+"
        // "| level: ...    |"
        // "| did: ...      |"  ✔
        // "| endpoint: ... |"
        // "+---------------+"
        let box_width = self.get_width();
        let text_width = box_width - 2;
        let [level_string, did_string, endpoint_string] = self.get_strings();
        writeln!(f, "+{}+", "-".repeat(box_width))?;
        writeln!(f, "| {0:<1$} |   ", level_string, text_width)?;
        writeln!(f, "| {0:<1$} |  ✔", did_string, text_width)?;
        writeln!(f, "| {0:<1$} |   ", endpoint_string, text_width)?;
        writeln!(f, "+{}+", "-".repeat(box_width))?;
        Ok(())
    }
}

impl fmt::Display for DIDChain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Style:
        // "+----------------+"
        // "| PrettyDID: ... |"  ✓
        // "+----------------+"
        //        ⛓⛓⛓⛓
        // "+----------------+"
        // "| PrettyDID: ... |"  ✓
        // "+----------------+"
        let title = "₿ DON'T TRUST, VERIFY! ₿";
        let box_width = format!(" DID: {} ", self.root()).len().min(MAX_WIDTH);
        writeln!(f, "{0:^1$}\n", title, box_width + 2)?;
        for (i, did) in self.level_vec.iter().enumerate() {
            let service_endpoint_string = match self.data(did) {
                Some((doc, _)) => get_service_endpoint_string(doc),
                _ => None,
            };
            if i == 0 {
                writeln!(
                    f,
                    "{0:^1$}",
                    format!("🕑 Block Height {0} 🕑", ROOT_EVENT_TIME),
                    box_width
                )?;
            }
            write!(f, "{}", PrettyDID::new(did, i, service_endpoint_string))?;
            let link_string = "⛓⛓⛓⛓";
            if self.downstream(did).is_some() {
                writeln!(f, "{0:^1$}", link_string, box_width)?;
                writeln!(f, "{0:^1$}", link_string, box_width)?;
            }
        }
        Ok(())
    }
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
                        chain.level_vec.reverse();
                        return Ok(chain);
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
        self.level_vec.push(doc.id.to_owned());
        self.did_map.insert(doc.id.to_owned(), (doc, doc_meta));
    }
}

impl Chain for DIDChain {
    fn as_vec(&self) -> &Vec<String> {
        &self.level_vec
    }

    fn len(&self) -> usize {
        self.level_vec.len().to_owned()
    }

    fn level(&self, did: &str) -> Option<usize> {
        if !&self.level_vec.contains(&did.to_owned()) {
            return None;
        }

        // Subtract level vector index from the length.
        let index = self.level_vec.iter().position(|x| x == did).unwrap();
        Some(index)
    }

    fn root(&self) -> &str {
        match self.len() > 0 {
            true => self.level_vec.first().unwrap(),
            // The public constructor prevents an empty chain from existing.
            false => panic!("Empty chain!"),
        }
    }

    fn leaf(&self) -> &str {
        match self.len() > 0 {
            true => self.level_vec.last().unwrap(),
            // The public constructor prevents an empty chain from existing.
            false => panic!("Empty chain!"),
        }
    }

    fn verify_proofs(&self) -> Result<(), ChainError> {
        // TODO: verify signatures in parallel.

        // Start from the leaf node.
        let mut did = self.leaf();

        while did != self.root() {
            // 0. Get the DID & its data.
            let (did_doc, did_doc_meta) = self.data(did).unwrap();

            // Get the upstream DID & its data.
            let udid = &self.upstream(did).unwrap();
            let (udid_doc, _) = self.data(udid).unwrap();

            // Extract the controller proof from the document metadata.
            let proof = get_proof(&did_doc_meta)?;

            // 1. Reconstruct the actual payload.
            let actual_payload = hash(&canonicalize(&did_doc).unwrap());

            // Decode the payload from the proof
            let decoded_payload = decode(proof);

            if let Ok(decoded_payload) = decoded_payload {
                if actual_payload != decoded_payload {
                    return Err(ChainError::InvalidPayload);
                }
            } else {
                return Err(ChainError::InvalidPayload);
            }

            // 2. Check the keys
            // Get keys
            let keys = extract_keys(&udid_doc);

            // Check at least one key valid
            let mut one_valid_key = false;
            for key in &keys {
                match decode_verify(proof, key) {
                    Ok(_) => {
                        one_valid_key = true;
                        break;
                    }
                    Err(_) => continue,
                };
            }
            match one_valid_key {
                true => (),
                false => return Err(ChainError::InvalidKeys),
            }

            // 3. Set: did <- udid
            did = udid;
        }
        Ok(())
    }

    fn upstream(&self, did: &str) -> Option<&String> {
        let index = self.level_vec.iter().position(|x| x == did).unwrap();
        if index != 0 {
            let index_prev = index - 1;
            self.level_vec.get(index_prev)
        } else {
            None
        }
    }

    fn downstream(&self, did: &str) -> Option<&String> {
        let index = self.level_vec.iter().position(|x| x == did).unwrap();
        if index != self.level_vec.len() - 1 {
            let index_next = index + 1;
            self.level_vec.get(index_next)
        } else {
            None
        }
    }

    fn data(&self, did: &str) -> Option<&(Document, DocumentMetadata)> {
        self.did_map.get(did)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::data::{
        TEST_ROOT_DOCUMENT, TEST_ROOT_DOCUMENT_METADATA, TEST_ROOT_PLUS_1_DOCUMENT,
        TEST_ROOT_PLUS_1_DOCUMENT_METADATA, TEST_ROOT_PLUS_2_DOCUMENT,
        TEST_ROOT_PLUS_2_DOCUMENT_METADATA, TEST_SIDETREE_DOCUMENT,
        TEST_SIDETREE_DOCUMENT_METADATA, TEST_TRUSTCHAIN_DOCUMENT,
        TEST_TRUSTCHAIN_DOCUMENT_METADATA,
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

    // Helper function returns a resolved tuple.
    fn resolved_tuple() -> (Document, DocumentMetadata) {
        (
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load."),
            serde_json::from_str(TEST_SIDETREE_DOCUMENT_METADATA)
                .expect("Document failed to load."),
        )
    }

    // Helper function returns a chain of three DIDs.
    pub fn test_chain() -> Result<DIDChain, Box<dyn std::error::Error>> {
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
        chain.level_vec.reverse();
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
        chain.level_vec.reverse();
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

    #[test]
    fn test_as_vec() {
        let target = test_chain().unwrap();
        let mut expected_vec = Vec::new();
        expected_vec
            .push("did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg".to_string()); //ROOT DID
        expected_vec
            .push("did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A".to_string()); // LEVEL ONE DID
        expected_vec
            .push("did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string()); // LEVEL TWO DID
        assert_eq!(target.as_vec(), &expected_vec);
    }

    #[test]
    fn test_root() {
        let target = test_chain().unwrap();
        assert_eq!(
            target.root(),
            "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
        )
    }

    #[test]
    fn test_leaf() {
        let target = test_chain().unwrap();
        assert_eq!(
            target.leaf(),
            "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"
        )
    }

    #[test]
    fn test_verify_proofs() {
        let target = test_chain().unwrap();
        assert!(target.verify_proofs().is_ok());
        let target = test_invalid_chain().unwrap();
        assert!(target.verify_proofs().is_err());
    }

    #[test]
    fn test_level() {
        // test the level returned for each node in the test chain
        let target = test_chain().unwrap();
        let expected_root_did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
        assert_eq!(target.level(expected_root_did).unwrap(), 0);

        let expected_level1_did = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A";
        let expected_level2_did = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q";
        assert_eq!(target.level(expected_level1_did).unwrap(), 1);
        assert_eq!(target.level(expected_level2_did).unwrap(), 2);
    }

    #[test]
    fn test_upstream() {
        let target = test_chain().unwrap();
        let did = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q";
        let expected_udid = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A";
        let expected_uudid = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";

        let target_udid = match target.upstream(did) {
            Some(s) => s,
            _ => panic!(),
        };
        assert_eq!(target_udid, expected_udid);

        let target_uudid = match target.upstream(target_udid) {
            Some(s) => s,
            _ => panic!(),
        };
        assert_eq!(target_uudid, expected_uudid);

        let target_uuudid = target.upstream(target_uudid);
        assert_eq!(target_uuudid, None);
    }

    #[test]
    fn test_downstream() {
        let target = test_chain().unwrap();
        let did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
        let expected_ddid = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A";
        let expected_dddid = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q";

        match target.downstream(did) {
            Some(s) => assert_eq!(s, expected_ddid),
            _ => panic!(),
        };
        match target.downstream(target.downstream(did).unwrap()) {
            Some(s) => assert_eq!(s, expected_dddid),
            _ => panic!(),
        };
        assert!(target
            .downstream(target.downstream(target.downstream(did).unwrap()).unwrap())
            .is_none());
    }

    #[test]
    fn test_data() -> Result<(), Box<dyn std::error::Error>> {
        let target = test_chain().unwrap();
        let did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
        let level1_did = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A";
        let level2_did = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q";

        let root_doc: Document = serde_json::from_str(TEST_ROOT_DOCUMENT)?;
        let level1_doc: Document = serde_json::from_str(TEST_ROOT_PLUS_1_DOCUMENT)?;
        let level2_doc: Document = serde_json::from_str(TEST_ROOT_PLUS_2_DOCUMENT)?;

        let root_doc_meta: DocumentMetadata = serde_json::from_str(TEST_ROOT_DOCUMENT_METADATA)?;
        let level1_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_ROOT_PLUS_1_DOCUMENT_METADATA)?;
        let level2_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_ROOT_PLUS_2_DOCUMENT_METADATA)?;

        if let Some((doc, doc_meta)) = target.data(did) {
            assert_eq!(doc, &root_doc);
            assert_eq!(
                canonicalize(&doc_meta).unwrap(),
                canonicalize(&root_doc_meta).unwrap()
            );
        } else {
            panic!();
        }
        if let Some((doc, doc_meta)) = target.data(level1_did) {
            assert_eq!(doc, &level1_doc);
            assert_eq!(
                canonicalize(&doc_meta).unwrap(),
                canonicalize(&level1_doc_meta).unwrap()
            );
        } else {
            panic!()
        }
        if let Some((doc, doc_meta)) = target.data(level2_did) {
            assert_eq!(doc, &level2_doc);
            assert_eq!(
                canonicalize(&doc_meta).unwrap(),
                canonicalize(&level2_doc_meta).unwrap()
            );
        } else {
            panic!()
        }
        Ok(())
    }

    #[test]
    fn test_print_chain() -> Result<(), Box<dyn std::error::Error>> {
        let target = test_chain().unwrap();
        println!("{}", target);
        Ok(())
    }
}

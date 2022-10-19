use std::collections::HashMap;
use thiserror::Error;

use ssi::{
    did::{self, Document},
    did_resolve::DocumentMetadata,
};

/// An error relating to a DID chain.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChainError {
    #[error("Failed to prepend to DID chain. Invalid data.")]
    PrependFailed,
}

/// A chain of DIDs.
trait Chain {
    /// Prepend a DID to the chain.
    fn prepend(&self, tuple: (Document, DocumentMetadata)) -> Result<(), ChainError>;

    /// Returns the length of the DID chain.
    fn len(&self) -> usize;

    /// Returns the level of the given DID in the chain.
    fn level(&self, did: &str) -> Option<u8>;
}

struct DIDChain {
    // An map from DID strings to resolved tuples.
    did_map: HashMap<String, (Document, DocumentMetadata)>,

    // Vector to keep track of the level of each DID.
    level_vec: Vec<u8>,
}

impl DIDChain {
    fn new() -> Self {
        Self {
            did_map: HashMap::<String, (Document, DocumentMetadata)>::new(),
            level_vec: Vec::<u8>::new(),
        }
    }
}

impl Chain for DIDChain {
    fn prepend(&self, tuple: (Document, DocumentMetadata)) -> Result<(), ChainError> {
        todo!()
    }

    fn len(&self) -> usize {
        self.level_vec.len().to_owned()
    }

    fn level(&self, did: &str) -> Option<u8> {
        // Subtract level vector index from the length.

        // &self.len() - level_vec.iter().position(|&x| x == did).unwrap()
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{TEST_SIDETREE_DOCUMENT, TEST_SIDETREE_DOCUMENT_METADATA};

    // Helper function returns a resolved tuple.
    fn resolved_tuple() -> (Document, DocumentMetadata) {
        (
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load."),
            serde_json::from_str(TEST_SIDETREE_DOCUMENT_METADATA)
                .expect("Document failed to load."),
        )
    }

    #[test]
    fn test_chain() {
        let mut target = DIDChain::new();

        let did0 = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ";

        assert_eq!(target.len(), 0);
        assert!(target.level(did0).is_none());

        // Prepend a DID to the chain
        target.prepend(resolved_tuple());

        // Check that the HashMap key matches the DID.
        assert_eq!(target.did_map.keys().len(), 1);
        assert!(target.did_map.contains_key(did0));

        assert_eq!(target.len(), 1);
        assert!(target.level(did0).is_some());
        assert_eq!(target.level(did0).unwrap(), 0);

        // let did1 = ""
    }

    // fn test_prepend() {
    //     let mut target = DIDChain::new();
    //     let result = target.prepend(());
    //     assert!(result.is_err());
}

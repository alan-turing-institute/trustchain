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
    fn prepend(&mut self, tuple: (Document, DocumentMetadata));

    /// Returns the length of the DID chain.
    fn len(&self) -> usize;

    /// Returns the level of the given DID in the chain.
    fn level(&self, did: &str) -> Option<usize>;
}

struct DIDChain {
    // An map from DID strings to resolved tuples.
    did_map: HashMap<String, (Document, DocumentMetadata)>,

    // Vector to keep track of the level of each DID.
    level_vec: Vec<String>,
}

impl DIDChain {
    fn new() -> Self {
        Self {
            did_map: HashMap::<String, (Document, DocumentMetadata)>::new(),
            level_vec: Vec::<String>::new(),
        }
    }
}

impl<'a> Chain for DIDChain {
    fn prepend(&mut self, tuple: (Document, DocumentMetadata)) {
        let (doc, doc_meta) = tuple;
        &self.level_vec.push(doc.id.to_owned());
        &self.did_map.insert(doc.id.to_owned(), (doc, doc_meta));
    }

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

    // fn test_prepend() {
    //     let mut target = DIDChain::new();
    //     let result = target.prepend(());
    //     assert!(result.is_err());
}

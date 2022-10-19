use std::collections::HashMap;

use ssi::{
    did::{self, Document},
    did_resolve::{DocumentMetadata, ResolutionMetadata},
};

/// A chain of DIDs.
trait Chain {
    /// Prepend a DID to the chain.
    fn prepend(
        &self,
        did: &str,
        tuple: (
            ResolutionMetadata,
            Option<Document>,
            Option<DocumentMetadata>,
        ),
    );

    /// Returns the length of the DID chain.
    fn len(&self) -> usize;

    /// Returns the level of the given DID in the chain.
    fn level(&self, did: &str) -> Option<u8>;
}

struct DIDChain {
    // An map from DID strings to resolved tuples.
    did_map: HashMap<
        String,
        (
            ResolutionMetadata,
            Option<Document>,
            Option<DocumentMetadata>,
        ),
    >,

    // Vector to keep track of the level of each DID.
    level_vec: Vec<u8>,
}

impl Chain for DIDChain {
    fn prepend(
        &self,
        did: &str,
        tuple: (
            ResolutionMetadata,
            Option<Document>,
            Option<DocumentMetadata>,
        ),
    ) {
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
    // use crate::data::{
    //     TEST_SIDETREE_DOCUMENT, TEST_SIDETREE_DOCUMENT_METADATA,
    //     TEST_SIDETREE_DOCUMENT_MULTIPLE_PROOF, TEST_SIDETREE_DOCUMENT_SERVICE_AND_PROOF,
    //     TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF, TEST_SIDETREE_DOCUMENT_WITH_CONTROLLER,
    //     TEST_TRUSTCHAIN_DOCUMENT, TEST_TRUSTCHAIN_DOCUMENT_METADATA,
    // };

    #[test]
    fn test_prepend() {

        // let target = Chain::new();
    }

    #[test]
    fn test_len() {
        todo!();
    }

    #[test]
    fn test_level() {
        todo!();
    }
}

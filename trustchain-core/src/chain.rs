use std::{collections::HashMap, convert::TryFrom};
use thiserror::Error;

use crate::resolver::{Resolver, ResolverError};
use ssi::{
    did::{self, Document},
    did_resolve::{DIDResolver, DocumentMetadata},
    one_or_many::OneOrMany,
};

/// An error relating to a DID chain.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChainError {
    // #[error("Invalid data. Failed to prepend DID: {0}.")]
    // PrependFailed(String),
    #[error("No chain nodes found for DID: {0}.")]
    NoChainNodes(String),
    #[error("Found multiple controllers in DID: {0}.")]
    MultipleControllers(String),
}

/// A chain of DIDs.
pub trait Chain {
    // /// Constructs a new DID chain.
    // fn new<T: DIDResolver + Sync + Send>(did: &str, resolver: &Resolver<T>) -> Result<Box<Self>, ChainError>;
    /// Returns the length of the DID chain.
    fn len(&self) -> usize;
    /// Returns the level of the given DID in the chain.
    fn level(&self, did: &str) -> Option<usize>;
    /// Returns the root DID.
    fn root(&self) -> &str;
    /// Verifies the chain.
    fn verify(&self, root_timestamp: u32) -> Result<(), ChainError>;
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
                return Err(ChainError::NoChainNodes(ddid));
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

    fn verify(&self, root_timestamp: u32) -> Result<(), ChainError> {
        // TODO: move the chain verification logic from the
        // original Verifier::verify implementation into this method.
        // (See file verifier.rs)

        todo!()
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

    // TODO: test the new constructor.

    // TODO?:
    // fn test_prepend() {
    //     let mut target = DIDChain::new();
    //     let result = target.prepend(());
    //     assert!(result.is_err());
}

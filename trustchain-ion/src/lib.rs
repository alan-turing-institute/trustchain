use ssi::did::{Document, ServiceEndpoint};
use ssi::did_resolve::DocumentMetadata;

pub fn is_proof_in_doc_meta(doc_meta: &DocumentMetadata) -> bool {
    if let Some(property_set) = doc_meta.property_set.as_ref() {
        // if let Some(_) = property_set.get(&"proof".to_string()) {
        if property_set.contains_key(&"proof".to_string()) {
            true
        } else {
            false
        }
    } else {
        false
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

    // #[test]
}

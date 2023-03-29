use serde::{Deserialize, Serialize};
use ssi::{
    did::Document,
    did_resolve::{DocumentMetadata, ResolutionResult},
};
use trustchain_core::chain::{Chain, DIDChain};

// TODO: consider refactor into trait
pub fn to_resolution_result(doc: Document, doc_meta: DocumentMetadata) -> ResolutionResult {
    ResolutionResult {
        context: Some(serde_json::Value::String(
            "https://w3id.org/did-resolution/v1".to_string(),
        )),
        did_document: Some(doc),
        did_resolution_metadata: None,
        did_document_metadata: Some(doc_meta),
        property_set: None,
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DIDChainResolutionResult {
    did_chain: Vec<ResolutionResult>,
}

impl DIDChainResolutionResult {
    pub fn new(did_chain: &DIDChain) -> Self {
        Self {
            did_chain: did_chain
                .to_vec()
                .into_iter()
                .map(|(doc, doc_meta)| to_resolution_result(doc, doc_meta))
                .collect::<Vec<_>>(),
        }
    }
}

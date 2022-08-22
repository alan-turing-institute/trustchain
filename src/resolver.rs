use did_ion::sidetree::SidetreeClient;
use did_ion::ION;
use futures::executor::block_on;
// use serde_json::{to_string_pretty as to_json, Map, Value};
use ssi::did::{Document, Service};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
};
use ssi::error::Error;
use ssi::one_or_many::OneOrMany;
use std::thread::sleep;
use std::time::Duration;
use tokio::runtime::Runtime;

pub struct Resolver {
    runtime: Runtime,
    ion_client: SidetreeClient<ION>,
}

impl Resolver {
    pub fn new() -> Self {
        // Make runtime
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        // Make client
        let ion_server_uri: &str = "http://localhost:3000/";
        let ion_client = SidetreeClient::<ION>::new(Some(ion_server_uri.to_string()));

        Self {
            runtime,
            ion_client,
        }
    }

    async fn http_resolve(
        &self,
        did_short: &String,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let resolver = self.ion_client.resolver.as_ref().unwrap();
        let (res_meta, doc, doc_meta) = resolver
            .resolve(&did_short[..], &ResolutionInputMetadata::default())
            .await;

        (res_meta, doc, doc_meta)
    }
    pub fn resolve(
        &self,
        did_short: &str,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        self.runtime.block_on(async {
            let (res_meta, doc, doc_meta) = loop {
                // Do resolve and extract data from future
                let tup = block_on(self.http_resolve(&did_short.to_string()));
                if tup.1.is_some() {
                    break tup;
                }
                sleep(Duration::new(1, 0));
                println!("Trying again...");
            };

            (res_meta, doc, doc_meta)
        })
    }

    fn get_proof_idx(&self, doc: &Document) -> Option<usize> {
        // Get index of proof
        let fragment = "controller-proof";
        for (idx, service) in doc.service.iter().flatten().enumerate() {
            if let [service_fragment, _] =
                service.id.rsplitn(2, '#').collect::<Vec<&str>>().as_slice()
            {
                if service_fragment == &fragment {
                    return Some(idx);
                }
            }
        }
        None
    }

    fn get_proof_service<'a>(&'a self, doc: &'a Document) -> Option<&'a Service> {
        //
        let idx = self.get_proof_idx(doc);
        match idx {
            Some(x) => Some(&doc.service.as_ref().unwrap()[x]),
            _ => None,
        }
    }

    fn remove_proof_service(&self, doc_with_proof: &Document) -> Document {
        // Check if the Trustchain proof service exists in document
        // https://docs.rs/ssi/latest/ssi/did/struct.Document.html#method.select_service
        // https://docs.rs/ssi/latest/src/ssi/did.rs.html#1251-1262
        let mut doc = doc_with_proof.clone();
        if doc.service.is_some() {
            if let Some(idx) = self.get_proof_idx(&doc) {
                let services = doc.service.as_mut().unwrap();
                services.remove(idx);
                if services.len() == 0 {
                    doc.service = None;
                }
            }
        }
        doc
    }

    pub fn ion_to_trustchain_doc(&self, doc: &Document, controller_did: &str) -> Document {
        // Check if the Trustchain proof service exists in document
        let doc = self.remove_proof_service(doc);

        // Add controller
        let doc = self
            .add_controller(&doc, controller_did)
            .expect("Controller already present in document.");

        doc
    }

    fn add_proof(&self, doc_meta: &DocumentMetadata) -> DocumentMetadata {
        // Check if the Trustchain proof service exists in document
        // https://docs.rs/ssi/latest/ssi/did/struct.Document.html#method.select_service
        // https://docs.rs/ssi/latest/src/ssi/did.rs.html#1251-1262

        todo!();
        doc_meta.clone()
    }
    pub fn ion_to_trustchain_doc_metadata(&self, doc_meta: &DocumentMetadata) -> DocumentMetadata {
        // Check if the Trustchain proof service exists in document
        let doc_meta = self.add_proof(doc_meta);

        doc_meta
    }

    /// Adding the controller to an ion resolved document. Controller is the upstream DID of the downstream DID's document.
    fn add_controller(
        &self,
        ion_did_doc: &Document,
        controller_did: &str,
    ) -> Result<Document, Error> {
        // TODO check the did_doc fits the ion resolved format

        // Making a clone of the did document (Note: this is expensive)
        let mut doc_clone = ion_did_doc.clone();

        // Check controller is empty and if not throw error.
        if doc_clone.controller.is_some() {
            return Err(Error::ControllerLimit);
        }

        // Adding the passed controller did to the document
        doc_clone.controller = Some(OneOrMany::One(controller_did.to_string()));

        // Return new document with controller
        Ok(doc_clone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{TEST_ION_DOCUMENT, TEST_ION_DOCUMENT_WITH_CONTROLLER};

    #[test]
    fn add_controller() {
        let controller_did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";

        let did_doc = Document::from_json(TEST_ION_DOCUMENT).expect("Document failed to load.");

        let resolver = Resolver::new();
        let result = resolver
            .add_controller(&did_doc, &controller_did)
            .expect("Different Controller already present.");

        let expected = Document::from_json(TEST_ION_DOCUMENT_WITH_CONTROLLER)
            .expect("Document failed to load.");
        assert_eq!(result, expected);
    }
    #[test]
    #[should_panic]
    fn add_controller_fail() {
        // TODO Check correct error is returned, but for now just assert panic

        let controller_did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";

        let did_doc = Document::from_json(TEST_ION_DOCUMENT_WITH_CONTROLLER)
            .expect("Document failed to load.");

        let resolver = Resolver::new();
        let result = resolver
            .add_controller(&did_doc, &controller_did)
            .expect("Different Controller already present.");

        let expected = Document::from_json(TEST_ION_DOCUMENT_WITH_CONTROLLER)
            .expect("Document failed to load.");
        assert_ne!(result, expected);
    }

    #[test]
    #[should_panic]
    fn remove_proof_service() {
        // Write a test for removing the proof service from an ION-resolved did doc
        todo!()
    }

    #[test]
    #[should_panic]
    fn get_proof_service() {
        // Write a test to get proof service from an ION-resolved did doc
        todo!()
    }

    #[test]
    fn convert_ion_to_trustchain_doc() {
        // Write a test to convert an ION-resolved did document to the trustchain resolved format
        todo!()
    }

    #[test]
    fn convert_ion_to_trustchain_doc_metadata() {
        // Write a test to convert ION-resolved did document metadata to trustchain format
        // See https://github.com/alan-turing-institute/trustchain/issues/11
        todo!()
    }
}

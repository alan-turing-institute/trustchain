use did_ion::sidetree::SidetreeClient;
use did_ion::ION;
use futures::executor::block_on;
use serde_json::{to_string_pretty as to_json, Map, Value};
use ssi::did::Document;
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
};
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

    fn add_controller(self, did_doc: &Document, controller_did: &str) -> Document {
        /// Adding the controller to the document. Controller is the upstream DID of the downstream DID's document.
        // Making a clone of the did document (Note: this is expensive)
        let mut doc_clone = did_doc.clone();

        // if doc_clone.controller.is_some() {
        //     // if &doc_clone.controller.unwrap().unwrap()[..] == controller_did
        //     if doc_clone.controller.unwrap().unwrap().as_str() == controller_did{
        //         return doc_clone;
        //     }
        // }

        // Adding the passed controller did to the document
        doc_clone.controller = Some(OneOrMany::One(controller_did.to_string()));

        // Return new document with controller
        doc_clone
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{TEST_ION_DOCUMENT, TEST_ION_DOCUMENT_WITH_CONTROLLER};

    #[test]
    fn test_add_controller() {
        let controller_did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";

        let did_doc = Document::from_json(TEST_ION_DOCUMENT).expect("Document failed to load.");

        let resolver = Resolver::new();
        let result = resolver.add_controller(&did_doc, &controller_did);

        let expected = Document::from_json(TEST_ION_DOCUMENT_WITH_CONTROLLER)
            .expect("Document failed to load.");
        assert_eq!(result, expected);
    }
}

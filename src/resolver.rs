use did_ion::sidetree::SidetreeClient;
use did_ion::ION;
use futures::executor::block_on;
// use serde_json::{to_string_pretty as to_json, Map, Value};
use ssi::did::{Document, Service};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
};
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

    fn remove_proof_service(&self, mut doc: Document) -> Document {
        // Check if the Trustchain proof service exists in document
        // https://docs.rs/ssi/latest/ssi/did/struct.Document.html#method.select_service
        // https://docs.rs/ssi/latest/src/ssi/did.rs.html#1251-1262

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

    pub fn convert_to_trustchain(&self, doc: Document) -> Document {
        // Check if the Trustchain proof service exists in document
        let doc = self.remove_proof_service(doc);

        // Add controller
        // let doc = self.add_controller(doc, controller);

        doc
    }
}

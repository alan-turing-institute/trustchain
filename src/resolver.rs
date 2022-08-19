use did_ion::sidetree::SidetreeClient;
use did_ion::ION;
use futures::executor::block_on;
use serde_json::{to_string_pretty as to_json, Map, Value};
use ssi::did::Document;
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
}

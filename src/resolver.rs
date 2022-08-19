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

    fn add_controller(self, did_doc: &Document, controller_did: &str) -> Document {

        // let did_doc_json : Map<String, Value> = from_str(did_doc).unwrap();
    
        // // If the controller field already exists, check the DID is correct.
        // // IMP: make sure we're checking the controller field in the root
        // // level of the DID document (i.e. at the same level as the id field).
    
        // if did_doc_json.contains_key("controller") {
        //     if did_doc.get("controller") == controller_did {
        //         // Nothing to do.
        //         return did_doc
        //     }
        //     else {
        //         panic // Controller DID conflict
        //     }
        // }
    
        // let doc_clone = did_doc.clone();
        // doc_clone.add("controller : {controller_did}");s
        // doc_clone
        Document::new("")
    }
}
    
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_controller() {

        // let did_doc = String::from("{
        //     \"@context\" : [
        //         \"https://www.w3.org/ns/did/v1\",
        //         {
        //             \"@base\" : \"did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ\"
        //         }
        //     ],
        //     \"id\" : \"did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ\"
        //     }");

        let controller_did = String::from("did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP");
        
        let resolver = Resolver::new();
        let result = resolver.add_controller(&did_doc, &controller_did);

        let expected = String::from("{
        \"@context\" : [
            \"https://www.w3.org/ns/did/v1\",
            {
                \"@base\" : \"did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ\"
            }
        ],
        \"id\" : \"did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ\",
        \"controller\" : \"did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP\",
        }");
        assert_eq!(result, expected);
    }
}
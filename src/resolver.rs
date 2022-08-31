use did_ion::sidetree::SidetreeClient;
use did_ion::ION;
use futures::executor::block_on;
use serde_json::to_string_pretty as to_json;
use serde_json::Value;
use ssi::did::{Document, Service, ServiceEndpoint};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, Metadata, ResolutionInputMetadata, ResolutionMetadata,
};
use ssi::error::Error;
use ssi::one_or_many::OneOrMany;
use std::collections::HashMap;
use std::thread::sleep;
use std::time::Duration;
use thiserror::Error;
use tokio::runtime::Runtime;

/// An error having to do with Trustchain resolution.
#[derive(Error, Debug)]
pub enum ResolverError {
    #[error("Controller is already present in DID document.")]
    ControllerAlreadyPresent,
    #[error("Failed to convert to Truschain document and metadata.")]
    FailedToConvertToTrustchain,
    #[error("Multiple 'TrustchainProofService' entries are present.")]
    MultipleTrustchainProofService,
    #[error("No 'TrustchainProofService' is present.")]
    NoTrustchainProofService,
    #[error("Cannot connect to ION server.")]
    ConnectionFailure,
    #[error("DID: {0} does not exist.")]
    NonExistentDID(&'static str),
}

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

    /// Trustchain resolve function returning resolution metadata, DID document and DID document metadata from a passed DID.
    pub fn resolve(
        &self,
        did_short: &str,
    ) -> Result<
        (
            ResolutionMetadata,
            Option<Document>,
            Option<DocumentMetadata>,
        ),
        ResolverError,
    > {
        self.runtime.block_on(async {
            // ION resolved resolution metadata, document and document metadata
            let (ion_res_meta, ion_doc, ion_doc_meta) = loop {
                // Do resolve and extract data from future
                let tup = block_on(self.http_resolve(&did_short.to_string()));
                if tup.1.is_some() {
                    break tup;
                }
                sleep(Duration::new(1, 0));
                println!("Trying again...");
            };
            // If a document and document metadata are returned, try to convert
            if let (Some(ion_doc), Some(ion_doc_meta)) = (ion_doc, ion_doc_meta) {
                // Convert to trustchain versions
                let tc_result = self.ion_to_trustchain(ion_res_meta, ion_doc, ion_doc_meta);
                match tc_result {
                    Ok((tc_res_meta, tc_doc, tc_doc_meta)) => {
                        Ok((tc_res_meta, Some(tc_doc), Some(tc_doc_meta)))
                    }
                    Err(ResolverError::FailedToConvertToTrustchain) => {
                        Err(ResolverError::FailedToConvertToTrustchain)
                    }
                    _ => panic!(),
                }
            } else {
                // If doc or doc_meta None, return ION resolution as is
                Ok((ion_res_meta, None, None))
            }
        })
    }

    fn get_proof_idx(&self, doc: &Document) -> Result<usize, ResolverError> {
        // Get index of proof
        let mut idxs: Vec<usize> = Vec::new();
        let fragment = "trustchain-controller-proof";
        for (idx, service) in doc.service.iter().flatten().enumerate() {
            if let [service_fragment, _] =
                service.id.rsplitn(2, '#').collect::<Vec<&str>>().as_slice()
            {
                if service_fragment == &fragment {
                    idxs.push(idx);
                }
            }
        }
        match idxs.len() {
            0 => Err(ResolverError::NoTrustchainProofService),
            1 => Ok(idxs[0]),
            _ => Err(ResolverError::MultipleTrustchainProofService),
        }
    }

    fn get_proof_service<'a>(&'a self, doc: &'a Document) -> Result<&Service, ResolverError> {
        // Extract proof service as an owned service
        let idxs = self.get_proof_idx(doc);
        match idxs {
            Ok(idx) => Ok(&doc.service.as_ref().unwrap()[idx]),
            Err(e) => Err(e),
        }
    }

    fn remove_proof_service(&self, mut doc: Document) -> Document {
        // Check if the Trustchain proof service exists in document
        // https://docs.rs/ssi/latest/ssi/did/struct.Document.html#method.select_service
        // https://docs.rs/ssi/latest/src/ssi/did.rs.html#1251-1262
        // let mut doc = doc_with_proof.clone();
        if doc.service.is_some() {
            let idx_result = self.get_proof_idx(&doc);
            match idx_result {
                Ok(idx) => {
                    let services = doc.service.as_mut().unwrap();
                    services.remove(idx);
                    if services.len() == 0 {
                        doc.service = None;
                    }
                }
                // Currently just return doc as it is if there is either zero or multiple
                // proof services
                Err(_) => (),
            }
        }
        doc
    }

    pub fn ion_to_trustchain_doc(&self, doc: &Document, controller_did: &str) -> Document {
        // Make a clone of the document so passed document remains the same
        let doc_clone = doc.clone();

        // Check if the Trustchain proof service exists in document
        let doc_clone = self.remove_proof_service(doc_clone);

        // Add controller
        let doc_clone = self
            .add_controller(doc_clone, controller_did)
            .expect("Controller already present in document.");

        // Remove proof service
        let doc_clone = self.remove_proof_service(doc_clone);

        doc_clone
    }

    /// Performing conversion of the ion resolved objects to trustchain objects
    pub fn ion_to_trustchain(
        &self,
        ion_res_meta: ResolutionMetadata,
        ion_doc: Document,
        ion_doc_meta: DocumentMetadata,
    ) -> Result<(ResolutionMetadata, Document, DocumentMetadata), ResolverError> {
        // Get controller DID
        let service = self.get_proof_service(&ion_doc);

        if let Ok(service) = service {
            let controller_did = self.get_from_proof_service(&service, "controller");

            // Convert doc
            let doc = self.ion_to_trustchain_doc(&ion_doc, controller_did.unwrap().as_str());

            // Convert metadata
            let doc_meta = self.ion_to_trustchain_doc_metadata(&ion_doc, ion_doc_meta);

            // TODO: Convert resolution metadata
            let res_meta = ion_res_meta;

            // Return tuple
            Ok((res_meta, doc, doc_meta))
        } else {
            // TODO: If proof service is not present or multiple, just return Ok for now.
            Ok((ion_res_meta, ion_doc, ion_doc_meta))
        }
    }

    fn get_from_proof_service(&self, proof_service: &Service, key: &str) -> Option<String> {
        // Destructure nested enums and extract controller from a proof service
        let controller_did: Option<String> = match proof_service.service_endpoint.as_ref() {
            Some(OneOrMany::One(ServiceEndpoint::Map(Value::Object(v)))) => match &v[key] {
                Value::String(s) => Some(s.to_string()),
                _ => None,
            },
            _ => None,
        };
        controller_did
    }

    fn add_proof(&self, doc: &Document, mut doc_meta: DocumentMetadata) -> DocumentMetadata {
        // Check if the Trustchain proof service exists in document
        // Get proof service
        let proof_service = self.get_proof_service(doc);
        // If not None
        if let Ok(proof_service) = proof_service {
            // Get proof value and controller (uDID)
            let proof_value = self.get_from_proof_service(proof_service, "proofValue");
            let controller = self.get_from_proof_service(proof_service, "controller");
            // If not None, add to new HashMap
            if let (Some(property_set), Some(proof_value), Some(controller)) =
                (doc_meta.property_set.as_mut(), proof_value, controller)
            {
                // Make new HashMap; add keys and values
                let mut proof_hash_map: HashMap<String, Metadata> = HashMap::new();
                proof_hash_map.insert(String::from("id"), Metadata::String(controller));
                proof_hash_map.insert(
                    String::from("type"),
                    Metadata::String("JsonWebSignature2020".to_string()),
                );
                proof_hash_map.insert(String::from("proofValue"), Metadata::String(proof_value));

                // Insert new HashMap of Metadata::Map()
                property_set.insert(String::from("proof"), Metadata::Map(proof_hash_map));
                return doc_meta;
            }
        }
        doc_meta
    }
    pub fn ion_to_trustchain_doc_metadata(
        &self,
        doc: &Document,
        doc_meta: DocumentMetadata,
    ) -> DocumentMetadata {
        // Add proof to ION document metadata if it exists
        let doc_meta = self.add_proof(doc, doc_meta);

        doc_meta
    }

    /// Adding the controller to an ion resolved document. Controller is the upstream DID of the downstream DID's document.
    fn add_controller(
        &self,
        mut doc: Document,
        controller_did: &str,
    ) -> Result<Document, ResolverError> {
        // TODO check the doc fits the ion resolved format

        // Check controller is empty and if not throw error.
        if doc.controller.is_some() {
            return Err(ResolverError::ControllerAlreadyPresent);
        }

        // Adding the passed controller did to the document
        doc.controller = Some(OneOrMany::One(controller_did.to_string()));

        // Return new document with controller
        Ok(doc)
    }
}

#[cfg(test)]
mod tests {
    use did_ion::sidetree::Sidetree;

    use super::*;
    use crate::data::{
        TEST_ION_DOCUMENT, TEST_ION_DOCUMENT_METADATA, TEST_ION_DOCUMENT_WITH_CONTROLLER,
        TEST_TRUSTCHAIN_DOCUMENT, TEST_TRUSTCHAIN_DOCUMENT_METADATA,
    };
    #[test]
    fn add_controller() {
        let controller_did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";

        let did_doc = Document::from_json(TEST_ION_DOCUMENT).expect("Document failed to load.");

        let resolver = Resolver::new();
        let result = resolver
            .add_controller(did_doc, &controller_did)
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
            .add_controller(did_doc, &controller_did)
            .expect("Different Controller already present.");

        let expected = Document::from_json(TEST_ION_DOCUMENT_WITH_CONTROLLER)
            .expect("Document failed to load.");
        assert_ne!(result, expected);
    }

    #[test]
    fn remove_proof_service() {
        // Write a test for removing the proof service from an ION-resolved did doc
        // Test to get proof service from an ION-resolved did doc
        let ion_doc = Document::from_json(TEST_ION_DOCUMENT).expect("Document failed to load.");
        let resolver = Resolver::new();
        let ion_doc_no_proof_service = resolver.remove_proof_service(ion_doc);
        assert!(ion_doc_no_proof_service.service.is_none());
    }

    #[test]
    fn get_proof_service() {
        // Test to get proof service from an ION-resolved did doc
        let ion_doc = Document::from_json(TEST_ION_DOCUMENT).expect("Document failed to load.");
        let resolver = Resolver::new();
        let proof_service = resolver.get_proof_service(&ion_doc).unwrap();
        assert_eq!(proof_service.id, "#trustchain-controller-proof");
    }

    #[test]
    #[should_panic]
    fn get_proof_service_with_many_proof_services() {
        // Write a test to get proof service from an ION-resolved did doc
        todo!()
    }

    #[test]
    fn ion_to_trustchain_doc() {
        // Write a test to convert an ION-resolved did document to the trustchain resolved format
        let ion_doc = Document::from_json(TEST_ION_DOCUMENT).expect("Document failed to load.");
        let tc_doc =
            Document::from_json(TEST_TRUSTCHAIN_DOCUMENT).expect("Document failed to load.");

        let resolver = Resolver::new();
        let proof_service = resolver.get_proof_service(&ion_doc).unwrap();
        let controller = resolver
            .get_from_proof_service(&proof_service, "controller")
            .unwrap();
        let actual = resolver.ion_to_trustchain_doc(&ion_doc, controller.as_str());
        // println!("{}", to_json(&tc_doc).unwrap());
        println!("{}", to_json(&actual).unwrap());
        assert_eq!(
            ION::json_canonicalization_scheme(&tc_doc).expect("Failed to canonicalize."),
            ION::json_canonicalization_scheme(&actual).expect("Failed to canonicalize.")
        );
    }

    #[test]
    fn ion_to_trustchain_doc_metadata() {
        // Write a test to convert ION-resolved did document metadata to trustchain format
        // See https://github.com/alan-turing-institute/trustchain/issues/11
        // Load test ION doc
        let ion_doc = Document::from_json(TEST_ION_DOCUMENT).expect("Document failed to load doc.");

        // Load test ION metadata
        let ion_meta: DocumentMetadata =
            serde_json::from_str(TEST_ION_DOCUMENT_METADATA).expect("Failed to load metadata");

        // Load and canoncalize the Trustchain document metadata
        let expected_tc_meta: DocumentMetadata =
            serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT_METADATA)
                .expect("Failed to load metadata");
        let expected_tc_meta = ION::json_canonicalization_scheme(&expected_tc_meta)
            .expect("Cannot add proof and canonicalize.");

        // Make new resolver
        let resolver = Resolver::new();

        // Actual Trustchain metadata
        let actual_tc_meta = ION::json_canonicalization_scheme(
            &resolver.ion_to_trustchain_doc_metadata(&ion_doc, ion_meta),
        )
        .expect("Cannot add proof and canonicalize.");
        assert_eq!(expected_tc_meta, actual_tc_meta);
    }

    #[test]
    fn get_from_proof_service() {
        // Write a test to extract the controller did from the service field in an IOn-resolved DID document
        let did_doc = Document::from_json(TEST_ION_DOCUMENT).expect("Document failed to load.");

        let resolver = Resolver::new();
        let service = resolver.get_proof_service(&did_doc).unwrap();

        let controller = resolver
            .get_from_proof_service(&service, "controller")
            .unwrap();

        assert_eq!(
            controller,
            "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ".to_string()
        )
    }
    #[test]
    fn add_proof() {
        // Load test ION doc
        let ion_doc = Document::from_json(TEST_ION_DOCUMENT).expect("Document failed to load doc.");

        // Load test ION metadata
        let ion_meta: DocumentMetadata =
            serde_json::from_str(TEST_ION_DOCUMENT_METADATA).expect("Failed to load metadata");

        // Load and canoncalize the Trustchain document metadata
        let expected_tc_meta: DocumentMetadata =
            serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT_METADATA)
                .expect("Failed to load metadata");
        let expected_tc_meta = ION::json_canonicalization_scheme(&expected_tc_meta)
            .expect("Cannot add proof and canonicalize.");

        // Make new resolver
        let resolver = Resolver::new();

        // Canonicalize
        let actual_tc_meta =
            ION::json_canonicalization_scheme(&resolver.add_proof(&ion_doc, ion_meta))
                .expect("Cannot add proof and canonicalize.");
        assert_eq!(expected_tc_meta, actual_tc_meta);
    }
}

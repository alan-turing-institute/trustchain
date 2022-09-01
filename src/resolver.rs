use did_ion::sidetree::{Sidetree, SidetreeClient};
use futures::executor::block_on;
use serde_json::Value;
use ssi::did::{Document, Service, ServiceEndpoint};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, Metadata, ResolutionInputMetadata, ResolutionMetadata,
};
use ssi::one_or_many::OneOrMany;
use std::collections::HashMap;
use std::marker::Send;
use thiserror::Error;
use tokio::runtime::Runtime;

/// An error relating to Trustchain resolution.
#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResolverError {
    /// Controller is already present in DID document.
    #[error("Controller is already present in DID document.")]
    ControllerAlreadyPresent,
    /// Failed to convert to Truschain document and metadata.
    #[error("Failed to convert to Truschain document and metadata.")]
    FailedToConvertToTrustchain,
    /// Multiple 'TrustchainProofService' entries are present.
    #[error("Multiple 'TrustchainProofService' entries are present.")]
    MultipleTrustchainProofService,
    /// No 'TrustchainProofService' is present.
    #[error("No 'TrustchainProofService' is present.")]
    NoTrustchainProofService,
    /// Cannot connect to sidetree server.
    #[error("Cannot connect to sidetree server.")]
    ConnectionFailure,
    /// DID does not exist.
    #[error("DID: {0} does not exist.")]
    NonExistentDID(String),
}

/// Struct for performing resolution from a sidetree server to generate Trustchain DID document and DID document metadata.
pub struct Resolver<T: Sidetree + Sync + Send> {
    /// Runtime for calling async functions.
    runtime: Runtime,
    /// Client for performing server resolutions.
    sidetree_client: SidetreeClient<T>,
}

impl<T: Sidetree + Sync + Send> Resolver<T> {
    /// Produces a new resolver.
    pub fn new() -> Self {
        // Make runtime
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        // Make client
        let sidetree_server_uri: &str = "http://localhost:3000/";
        let sidetree_client = SidetreeClient::<T>::new(Some(sidetree_server_uri.to_string()));

        Self {
            runtime,
            sidetree_client,
        }
    }

    /// Async function wrapping sidetree client resolution.
    async fn http_resolve(
        &self,
        did_short: &String,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let resolver = self.sidetree_client.resolver.as_ref().unwrap();
        let (res_meta, doc, doc_meta) = resolver
            .resolve(&did_short[..], &ResolutionInputMetadata::default())
            .await;

        (res_meta, doc, doc_meta)
    }

    /// Trustchain resolve function returning resolution metadata, DID document and DID document metadata from a passed DID.
    pub fn resolve(
        &self,
        did: &str,
    ) -> Result<
        (
            ResolutionMetadata,
            Option<Document>,
            Option<DocumentMetadata>,
        ),
        ResolverError,
    > {
        self.runtime.block_on(async {
            // sidetree resolved resolution metadata, document and document metadata
            let (sidetree_res_meta, sidetree_doc, sidetree_doc_meta) =
                block_on(self.http_resolve(&did.to_string()));

            // Handle cases when: 1. cannot connect to server; 2. Did not find DID.
            if let Some(sidetree_res_meta_error) = &sidetree_res_meta.error {
                if sidetree_res_meta_error
                    .starts_with("Error sending HTTP request: error sending request for url")
                {
                    return Err(ResolverError::ConnectionFailure);
                } else if sidetree_res_meta_error == "invalidDid" {
                    return Err(ResolverError::NonExistentDID(did.to_string()));
                } else {
                    eprintln!("Unhandled error message: {}", sidetree_res_meta_error);
                    panic!();
                }
            }

            // If a document and document metadata are returned, try to convert
            if let (Some(sidetree_doc), Some(sidetree_doc_meta)) = (sidetree_doc, sidetree_doc_meta)
            {
                // Convert to trustchain versions
                let tc_result =
                    self.sidetree_to_trustchain(sidetree_res_meta, sidetree_doc, sidetree_doc_meta);
                match tc_result {
                    // Map the tuple of non-option types to have tuple with optional document
                    // document metadata
                    Ok((tc_res_meta, tc_doc, tc_doc_meta)) => {
                        Ok((tc_res_meta, Some(tc_doc), Some(tc_doc_meta)))
                    }
                    // If cannot convert, return the relevant error
                    Err(ResolverError::FailedToConvertToTrustchain) => {
                        Err(ResolverError::FailedToConvertToTrustchain)
                    }
                    // If not defined error, panic!()
                    _ => panic!(),
                }
            } else {
                // If doc or doc_meta None, return sidetree resolution as is
                Ok((sidetree_res_meta, None, None))
            }
        })
    }

    /// Get a result of index of a single Trustchain proof service, otherwise relevant error.
    fn get_proof_idx(&self, doc: &Document) -> Result<usize, ResolverError> {
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

    /// Get a result of reference to a single Trustchain proof service, otherwise relevant error.
    fn get_proof_service<'a>(&'a self, doc: &'a Document) -> Result<&Service, ResolverError> {
        // Extract proof service as an owned service
        let idxs = self.get_proof_idx(doc);
        match idxs {
            Ok(idx) => Ok(&doc.service.as_ref().unwrap()[idx]),
            Err(e) => Err(e),
        }
    }

    /// Remove Trustchain proof service from passed document.
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

    /// Convert a document from a sidetree resolved to a Trustchain resolved format.
    pub fn sidetree_to_trustchain_doc(&self, doc: &Document, controller_did: &str) -> Document {
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

    /// Performing conversion of the sidetree resolved objects to trustchain objects
    pub fn sidetree_to_trustchain(
        &self,
        sidetree_res_meta: ResolutionMetadata,
        sidetree_doc: Document,
        sidetree_doc_meta: DocumentMetadata,
    ) -> Result<(ResolutionMetadata, Document, DocumentMetadata), ResolverError> {
        // Get controller DID
        let service = self.get_proof_service(&sidetree_doc);

        if let Ok(service) = service {
            let controller_did = self.get_from_proof_service(&service, "controller");

            // Convert doc
            let doc =
                self.sidetree_to_trustchain_doc(&sidetree_doc, controller_did.unwrap().as_str());

            // Convert metadata
            let doc_meta =
                self.sidetree_to_trustchain_doc_metadata(&sidetree_doc, sidetree_doc_meta);

            // Convert resolution metadata
            let res_meta = sidetree_res_meta;

            // Return tuple
            Ok((res_meta, doc, doc_meta))
        } else {
            // TODO: If proof service is not present or multiple, just return Ok for now.
            Ok((sidetree_res_meta, sidetree_doc, sidetree_doc_meta))
        }
    }

    /// Get the value of a key in a Trustchain proof service.
    fn get_from_proof_service<'a>(
        &self,
        proof_service: &'a Service,
        key: &str,
    ) -> Option<&'a String> {
        // Destructure nested enums and extract controller from a proof service
        let value: Option<&String> = match proof_service.service_endpoint.as_ref() {
            Some(OneOrMany::One(ServiceEndpoint::Map(Value::Object(v)))) => match &v[key] {
                Value::String(s) => Some(s),
                _ => None,
            },
            _ => None,
        };
        value
    }

    /// Adds proof to a passed DocumentMetadata from Document
    fn add_proof(&self, doc: &Document, mut doc_meta: DocumentMetadata) -> DocumentMetadata {
        // Check if the Trustchain proof service exists in document

        // Get proof service
        let proof_service = self.get_proof_service(doc);

        // Handle result
        match proof_service {
            // If there is exactly one proof service, add it to metadata
            Ok(proof_service) => {
                // Get proof value and controller (uDID)
                let proof_value = self.get_from_proof_service(proof_service, "proofValue");
                let controller = self.get_from_proof_service(proof_service, "controller");
                // If not None, add to new HashMap
                if let (Some(property_set), Some(proof_value), Some(controller)) =
                    (doc_meta.property_set.as_mut(), proof_value, controller)
                {
                    // Make new HashMap; add keys and values
                    let mut proof_hash_map: HashMap<String, Metadata> = HashMap::new();
                    proof_hash_map
                        .insert(String::from("id"), Metadata::String(controller.to_owned()));
                    proof_hash_map.insert(
                        String::from("type"),
                        Metadata::String("JsonWebSignature2020".to_string()),
                    );
                    proof_hash_map.insert(
                        String::from("proofValue"),
                        Metadata::String(proof_value.to_owned()),
                    );

                    // Insert new HashMap of Metadata::Map()
                    property_set.insert(String::from("proof"), Metadata::Map(proof_hash_map));
                    return doc_meta;
                }
            }
            // If there are zero or multiple proof services, do nothing
            Err(_) => (),
        }
        doc_meta
    }

    /// Convert document metadata from a sidetree resolved to a Trustchain resolved format.
    pub fn sidetree_to_trustchain_doc_metadata(
        &self,
        doc: &Document,
        doc_meta: DocumentMetadata,
    ) -> DocumentMetadata {
        // Add proof to sidetree document metadata if it exists
        let doc_meta = self.add_proof(doc, doc_meta);

        doc_meta
    }

    /// Adding the controller to an sidetree resolved document. Controller is the upstream DID of the downstream DID's document.
    fn add_controller(
        &self,
        mut doc: Document,
        controller_did: &str,
    ) -> Result<Document, ResolverError> {
        // TODO check the doc fits the sidetree resolved format

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
    use super::*;
    use crate::data::{
        TEST_SIDETREE_DOCUMENT, TEST_SIDETREE_DOCUMENT_METADATA,
        TEST_SIDETREE_DOCUMENT_MULTIPLE_PROOF, TEST_SIDETREE_DOCUMENT_WITH_CONTROLLER,
        TEST_TRUSTCHAIN_DOCUMENT, TEST_TRUSTCHAIN_DOCUMENT_METADATA,
    };
    use did_ion::sidetree::Sidetree;
    use did_ion::ION;
    #[test]
    fn add_controller() {
        let controller_did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";

        let did_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load.");

        let resolver = Resolver::<ION>::new();
        let result = resolver
            .add_controller(did_doc, &controller_did)
            .expect("Different Controller already present.");

        let expected = Document::from_json(TEST_SIDETREE_DOCUMENT_WITH_CONTROLLER)
            .expect("Document failed to load.");
        assert_eq!(result, expected);
    }
    #[test]
    fn add_controller_fail() {
        // Ad
        let controller_did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";

        let did_doc = Document::from_json(TEST_SIDETREE_DOCUMENT_WITH_CONTROLLER)
            .expect("Document failed to load.");

        let resolver = Resolver::<ION>::new();
        let result = resolver.add_controller(did_doc, &controller_did);
        let expected: Result<Document, ResolverError> =
            Err(ResolverError::ControllerAlreadyPresent);

        assert_eq!(result, expected);
    }

    #[test]
    fn remove_proof_service() {
        // Write a test for removing the proof service from an sidetree-resolved did doc
        // Test to get proof service from an sidetree-resolved did doc
        let sidetree_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load.");

        // Make resolver
        let resolver = Resolver::<ION>::new();

        // Remove proof service
        let sidetree_doc_no_proof_service = resolver.remove_proof_service(sidetree_doc);

        assert!(sidetree_doc_no_proof_service.service.is_none());
    }

    #[test]
    fn get_proof_service() {
        // Test to get proof service from an sidetree-resolved did doc
        let sidetree_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load.");
        let resolver = Resolver::<ION>::new();
        let proof_service = resolver.get_proof_service(&sidetree_doc).unwrap();
        assert_eq!(proof_service.id, "#trustchain-controller-proof");
    }

    #[test]
    fn get_proof_service_when_multiple_proof_services() {
        // Write a test to get proof service from an sidetree-resolved did doc
        // todo!()
        let sidetree_doc = Document::from_json(TEST_SIDETREE_DOCUMENT_MULTIPLE_PROOF)
            .expect("Document failed to load.");
        let resolver = Resolver::<ION>::new();
        let result = resolver.get_proof_service(&sidetree_doc);
        let expected: Result<&Service, ResolverError> =
            Err(ResolverError::MultipleTrustchainProofService);

        assert_eq!(result, expected);
    }

    #[test]
    fn get_proof_service_when_no_proof_services() {
        // Write a test to get proof service from an sidetree-resolved did doc
        let sidetree_doc =
            Document::from_json(TEST_TRUSTCHAIN_DOCUMENT).expect("Document failed to load.");
        let resolver = Resolver::<ION>::new();
        let result = resolver.get_proof_service(&sidetree_doc);

        let expected: Result<&Service, ResolverError> =
            Err(ResolverError::NoTrustchainProofService);

        assert_eq!(result, expected);
    }

    #[test]
    fn sidetree_to_trustchain_doc() {
        // Write a test to convert an sidetree-resolved did document to the trustchain resolved format
        let sidetree_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load.");
        let tc_doc =
            Document::from_json(TEST_TRUSTCHAIN_DOCUMENT).expect("Document failed to load.");

        let resolver = Resolver::<ION>::new();
        let proof_service = resolver.get_proof_service(&sidetree_doc).unwrap();
        let controller = resolver
            .get_from_proof_service(&proof_service, "controller")
            .unwrap();
        let actual = resolver.sidetree_to_trustchain_doc(&sidetree_doc, controller.as_str());

        assert_eq!(
            ION::json_canonicalization_scheme(&tc_doc).expect("Failed to canonicalize."),
            ION::json_canonicalization_scheme(&actual).expect("Failed to canonicalize.")
        );
    }

    #[test]
    fn sidetree_to_trustchain_doc_metadata() {
        // Write a test to convert sidetree-resolved did document metadata to trustchain format
        // See https://github.com/alan-turing-institute/trustchain/issues/11
        // Load test sidetree doc
        let sidetree_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load doc.");

        // Load test sidetree metadata
        let sidetree_meta: DocumentMetadata =
            serde_json::from_str(TEST_SIDETREE_DOCUMENT_METADATA).expect("Failed to load metadata");

        // Load and canoncalize the Trustchain document metadata
        let expected_tc_meta: DocumentMetadata =
            serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT_METADATA)
                .expect("Failed to load metadata");
        let expected_tc_meta = ION::json_canonicalization_scheme(&expected_tc_meta)
            .expect("Cannot add proof and canonicalize.");

        // Make new resolver
        let resolver = Resolver::<ION>::new();

        // Actual Trustchain metadata
        let actual_tc_meta = ION::json_canonicalization_scheme(
            &resolver.sidetree_to_trustchain_doc_metadata(&sidetree_doc, sidetree_meta),
        )
        .expect("Cannot add proof and canonicalize.");
        assert_eq!(expected_tc_meta, actual_tc_meta);
    }

    #[test]
    fn sidetree_to_trustchain() {
        // Test objects
        let input_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load.");
        let expected_output_doc =
            Document::from_json(TEST_TRUSTCHAIN_DOCUMENT).expect("Document failed to load.");
        let input_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_SIDETREE_DOCUMENT_METADATA)
                .expect("Document failed to load.");
        let expected_output_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT_METADATA)
                .expect("Document failed to load.");
        let input_res_meta = ResolutionMetadata {
            error: None,
            content_type: None,
            property_set: None,
        };
        let expected_output_res_meta = ResolutionMetadata {
            error: None,
            content_type: None,
            property_set: None,
        };

        // Make new resolver
        let resolver = Resolver::<ION>::new();

        // Call function and get output result type
        let output = resolver.sidetree_to_trustchain(
            input_res_meta.clone(),
            input_doc.clone(),
            input_doc_meta.clone(),
        );

        // Result should be Ok variant with returned data
        if let Ok((actual_output_res_meta, actual_output_doc, actual_output_doc_meta)) = output {
            // Check resolution metadata is equal
            assert_eq!(
                ION::json_canonicalization_scheme(&expected_output_res_meta).unwrap(),
                ION::json_canonicalization_scheme(&actual_output_res_meta).unwrap()
            );
            // Check documents are equal
            assert_eq!(expected_output_doc, actual_output_doc);
            // Check document metadata is equal
            assert_eq!(
                ION::json_canonicalization_scheme(&expected_output_doc_meta).unwrap(),
                ION::json_canonicalization_scheme(&actual_output_doc_meta).unwrap()
            );
        } else {
            // If error variant, panic
            panic!()
        }
    }

    #[test]
    fn get_from_proof_service() {
        // Write a test to extract the controller did from the service field in an sidetree-resolved DID document
        let did_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load.");

        let resolver = Resolver::<ION>::new();
        let service = resolver.get_proof_service(&did_doc).unwrap();

        let controller = resolver
            .get_from_proof_service(&service, "controller")
            .unwrap();

        assert_eq!(
            controller,
            "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
        )
    }
    #[test]
    fn add_proof() {
        // Load test sidetree doc
        let sidetree_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load doc.");

        // Load test sidetree metadata
        let sidetree_meta: DocumentMetadata =
            serde_json::from_str(TEST_SIDETREE_DOCUMENT_METADATA).expect("Failed to load metadata");

        // Load and canoncalize the Trustchain document metadata
        let expected_tc_meta: DocumentMetadata =
            serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT_METADATA)
                .expect("Failed to load metadata");
        let expected_tc_meta = ION::json_canonicalization_scheme(&expected_tc_meta)
            .expect("Cannot add proof and canonicalize.");

        // Make new resolver
        let resolver = Resolver::<ION>::new();

        // Canonicalize
        let actual_tc_meta =
            ION::json_canonicalization_scheme(&resolver.add_proof(&sidetree_doc, sidetree_meta))
                .expect("Cannot add proof and canonicalize.");
        assert_eq!(expected_tc_meta, actual_tc_meta);
    }
}

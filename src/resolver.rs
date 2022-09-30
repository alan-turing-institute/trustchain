use async_trait::async_trait;
use futures::executor::block_on;
use serde_json::Value;
use ssi::did::{DIDMethod, Document, Service, ServiceEndpoint};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, Metadata, ResolutionInputMetadata, ResolutionMetadata,
};
use ssi::one_or_many::OneOrMany;
use std::collections::HashMap;
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
    /// DID is not found.
    #[error("DID: {0} is not found.")]
    DIDNotFound(String),
}

// Newtype pattern (workaround for lack of trait upcasting coercion).
// Specifically, the DIDMethod method to_resolver() returns a reference but we want ownership.
// The workaround is to define a wrapper for DIDMethod that implements DIDResolver.
// See https://doc.rust-lang.org/book/ch19-03-advanced-traits.html#using-the-newtype-pattern-to-implement-external-traits-on-external-types.
pub struct DIDMethodWrapper<S: DIDMethod>(pub S);

impl<S: DIDMethod> DIDResolver for DIDMethodWrapper<S> {
    fn resolve<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        did: &'life1 str,
        input_metadata: &'life2 ResolutionInputMetadata,
    ) -> core::pin::Pin<
        Box<
            dyn core::future::Future<
                    Output = (
                        ResolutionMetadata,
                        Option<Document>,
                        Option<DocumentMetadata>,
                    ),
                > + core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        self.0.to_resolver().resolve(did, input_metadata)
    }
}

// DIDMethodWrapper is used only to upcast a DIDMethod to a DIDResolver,
// and resolvers do not change shared state, so we can guarantee safety
// on Sync & Send. Both are empty implementations.
unsafe impl<S: DIDMethod> Sync for DIDMethodWrapper<S> {}
unsafe impl<S: DIDMethod> Send for DIDMethodWrapper<S> {}

/// Struct for performing resolution from a sidetree server to generate
/// Trustchain DID document and DID document metadata.
pub struct Resolver<T: DIDResolver + Sync + Send> {
    /// Runtime for calling async functions.
    runtime: Runtime,
    /// Resolver for performing DID Method resolutions.
    wrapped_resolver: T,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<T: DIDResolver + Sync + Send> DIDResolver for Resolver<T> {
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        // Resolve with the wrapped DIDResolver and then transform to Trustchain format.
        self.transform(self.wrapped_resolver.resolve(did, input_metadata).await)
    }
}

impl<T: DIDResolver + Sync + Send> Resolver<T> {
    /// Constructs a Trustchain resolver.
    pub fn new(resolver: T) -> Self {
        // Make runtime
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        Self {
            runtime,
            wrapped_resolver: resolver,
        }
    }

    /// Constructs a Trustchain resolver from a DIDMethod.
    pub fn from<S: DIDMethod>(method: S) -> Resolver<DIDMethodWrapper<S>> {
        // Wrap the DIDMethod.
        Resolver::<DIDMethodWrapper<S>>::new(DIDMethodWrapper::<S>(method))
    }

    /// Transforms the result of a DID resolution into the Trustchain format.
    fn transform(
        &self,
        (res_meta, doc, doc_meta): (
            ResolutionMetadata,
            Option<Document>,
            Option<DocumentMetadata>,
        ),
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        // Transform
        // If a document and document metadata are returned, try to convert
        if let (Some(did_doc), Some(did_doc_meta)) = (doc, doc_meta) {
            // Convert to trustchain versions
            let tc_result = self.transform_as_result(res_meta, did_doc, did_doc_meta);
            match tc_result {
                // Map the tuple of non-option types to have tuple with optional document
                // document metadata
                Ok((tc_res_meta, tc_doc, tc_doc_meta)) => {
                    (tc_res_meta, Some(tc_doc), Some(tc_doc_meta))
                }
                // If cannot convert, return the relevant error
                Err(ResolverError::FailedToConvertToTrustchain) => {
                    let res_meta = ResolutionMetadata {
                        error: Some(
                            "Failed to convert to Truschain document and metadata.".to_string(),
                        ),
                        content_type: None,
                        property_set: None,
                    };
                    (res_meta, None, None)
                }
                Err(ResolverError::MultipleTrustchainProofService) => {
                    let res_meta = ResolutionMetadata {
                        error: Some(
                            "Multiple 'TrustchainProofService' entries are present.".to_string(),
                        ),
                        content_type: None,
                        property_set: None,
                    };
                    (res_meta, None, None)
                }
                // If not defined error, panic!()
                _ => panic!(),
            }
        } else {
            // If doc or doc_meta None, return sidetree resolution as is
            (res_meta, None, None)
        }
    }

    /// Sync Trustchain resolve function returning resolution metadata,
    /// DID document and DID document metadata from a passed DID as a `Result` type.
    pub fn resolve_as_result(
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
            let (did_res_meta, did_doc, did_doc_meta) =
                block_on(self.resolve(&did.to_string(), &ResolutionInputMetadata::default()));

            // Handle error cases based on string content of the resolution metadata
            if let Some(did_res_meta_error) = &did_res_meta.error {
                if did_res_meta_error
                    .starts_with("Error sending HTTP request: error sending request for url")
                {
                    return Err(ResolverError::ConnectionFailure);
                } else if did_res_meta_error == "invalidDid" {
                    return Err(ResolverError::NonExistentDID(did.to_string()));
                } else if did_res_meta_error == "notFound" {
                    return Err(ResolverError::DIDNotFound(did.to_string()));
                } else if did_res_meta_error
                    == "Failed to convert to Truschain document and metadata."
                {
                    return Err(ResolverError::FailedToConvertToTrustchain);
                } else if did_res_meta_error
                    == "Multiple 'TrustchainProofService' entries are present."
                {
                    return Err(ResolverError::MultipleTrustchainProofService);
                } else {
                    eprintln!("Unhandled error message: {}", did_res_meta_error);
                    panic!();
                }
            } else {
                return Ok((did_res_meta, did_doc, did_doc_meta));
            }
        })
    }

    /// Gets a result of an index of a single Trustchain proof service, otherwise relevant error.
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

    /// Gets a result of a reference to a single Trustchain proof service, otherwise relevant error.
    fn get_proof_service<'a>(&'a self, doc: &'a Document) -> Result<&Service, ResolverError> {
        // Extract proof service as an owned service
        let idxs = self.get_proof_idx(doc);
        match idxs {
            Ok(idx) => Ok(&doc.service.as_ref().unwrap()[idx]),
            Err(e) => Err(e),
        }
    }

    /// Removes Trustchain proof service from passed document.
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

    /// Gets the value of a key in a Trustchain proof service.
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

    /// Adds a proof from a DID Document to DocumentMetadata.
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

    /// Adds the controller property to a resolved DID document, using the
    /// value passed in the controller_did argument. This must be the DID of
    /// the subject (id property) found in the upstream DID document.
    fn add_controller(
        &self,
        mut doc: Document,
        controller_did: &str,
    ) -> Result<Document, ResolverError> {
        // Check controller is empty and if not throw error.
        if doc.controller.is_some() {
            return Err(ResolverError::ControllerAlreadyPresent);
        }

        // Add the controller property to the DID document.
        doc.controller = Some(OneOrMany::One(controller_did.to_string()));

        // Return updated DID document.
        Ok(doc)
    }

    /// Converts DID Document Metadata from a resolved DID to the Trustchain resolved format.
    pub fn transform_doc_metadata(
        &self,
        doc: &Document,
        doc_meta: DocumentMetadata,
    ) -> DocumentMetadata {
        // Add proof property to the DID Document Metadata (if it exists).
        let doc_meta = self.add_proof(doc, doc_meta);
        doc_meta
    }

    /// Converts a DID Document from a resolved DID to the Trustchain resolved format.
    pub fn transform_doc(&self, doc: &Document, controller_did: &str) -> Document {
        // Clone the passed DID document.
        let doc_clone = doc.clone();

        // Duplication?
        // // Check if the Trustchain proof service alreday exists in the document.
        // let doc_clone = self.remove_proof_service(doc_clone);

        // Add controller
        let doc_clone = self
            .add_controller(doc_clone, controller_did)
            .expect("Controller already present in document.");

        // Remove the proof service from the document.
        let doc_clone = self.remove_proof_service(doc_clone);

        doc_clone
    }

    /// Converts DID Document + Metadata to the Trustchain resolved format.
    pub fn transform_as_result(
        &self,
        sidetree_res_meta: ResolutionMetadata,
        sidetree_doc: Document,
        sidetree_doc_meta: DocumentMetadata,
    ) -> Result<(ResolutionMetadata, Document, DocumentMetadata), ResolverError> {
        // Get controller DID
        let service = self.get_proof_service(&sidetree_doc);

        // Return immediately multiple proof services present
        if let Err(ResolverError::MultipleTrustchainProofService) = service {
            return Err(ResolverError::MultipleTrustchainProofService);
        };

        if let Ok(service) = service {
            let controller_did = self.get_from_proof_service(&service, "controller");

            // Convert doc
            let doc = self.transform_doc(&sidetree_doc, controller_did.unwrap().as_str());

            // Convert metadata
            let doc_meta = self.transform_doc_metadata(&sidetree_doc, sidetree_doc_meta);

            // Convert resolution metadata
            let res_meta = sidetree_res_meta;

            // Return tuple
            Ok((res_meta, doc, doc_meta))
        } else {
            // TODO: If proof service is not present or multiple, just return Ok for now.
            Ok((sidetree_res_meta, sidetree_doc, sidetree_doc_meta))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{
        TEST_SIDETREE_DOCUMENT, TEST_SIDETREE_DOCUMENT_METADATA,
        TEST_SIDETREE_DOCUMENT_MULTIPLE_PROOF, TEST_SIDETREE_DOCUMENT_SERVICE_AND_PROOF,
        TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF, TEST_SIDETREE_DOCUMENT_WITH_CONTROLLER,
        TEST_TRUSTCHAIN_DOCUMENT, TEST_TRUSTCHAIN_DOCUMENT_METADATA,
    };

    use crate::utils::canonicalize;
    use ssi::did_resolve::HTTPDIDResolver;

    // General function for generating a HTTP resolver for tests only
    fn get_http_resolver() -> HTTPDIDResolver {
        HTTPDIDResolver::new("http://localhost:3000/")
    }

    #[test]
    fn add_controller() {
        // Test add_controller method with successful result.

        let controller_did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";

        // Load a Sidetree-resolved DID Document.
        let did_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load.");

        // Check there is no controller in the DID document.
        assert!(did_doc.controller.is_none());

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        // Call add_controller on the Resolver to get the result.
        let result = resolver
            .add_controller(did_doc, &controller_did)
            .expect("Different Controller already present.");

        // Check there *is* a controller field in the resulting DID document.
        assert!(result.controller.is_some());
        // Check the controller DID is correct.
        assert_eq!(
            result.controller,
            Some(OneOrMany::One(String::from(controller_did)))
        );

        // Construct the expected result (a DID Document) from a test fixture.
        let expected = Document::from_json(TEST_SIDETREE_DOCUMENT_WITH_CONTROLLER)
            .expect("Document failed to load.");

        // Check the resulting DID document matches the expected one.
        assert_eq!(result, expected);
    }

    #[test]
    fn add_controller_fail() {
        // Test add_controller method with failure as controller already present.

        let controller_did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";

        // Construct a DID Document that already contains a controller property.
        let did_doc = Document::from_json(TEST_SIDETREE_DOCUMENT_WITH_CONTROLLER)
            .expect("Document failed to load.");

        // Check the controller property is present.
        assert!(did_doc.controller.is_some());

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        // Attempt to add the controller.
        let result = resolver.add_controller(did_doc, &controller_did);
        let expected: Result<Document, ResolverError> =
            Err(ResolverError::ControllerAlreadyPresent);

        // Confirm error.
        assert_eq!(result, expected);
    }

    #[test]
    fn remove_proof_service() {
        // Test remove_proof_service method with successful result.

        // Load a Sidetree-resolved DID Document.
        let did_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load.");

        // Check the proof service is present.
        assert!(did_doc.service.is_some());

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        // Remove the proof service in the DID document.
        let did_doc_no_proof_service = resolver.remove_proof_service(did_doc);

        // Check the proof service has been removed.
        assert!(did_doc_no_proof_service.service.is_none());
    }

    #[test]
    fn get_proof_service() {
        // Test get_proof_service method on a sidetree-resolved DID document.

        // Load a Sidetree-resolved DID Document.
        let did_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load.");

        // Check that precisely one service is present in the DID document.
        assert_eq!((&did_doc).service.as_ref().unwrap().len(), 1 as usize);

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        // Get the service property containing the Trustchain proof.
        let proof_service = resolver.get_proof_service(&did_doc).unwrap();

        // Check the contents of the proof service property.
        assert_eq!(proof_service.id, "#trustchain-controller-proof");
        assert_eq!(
            proof_service.type_,
            OneOrMany::One(String::from("TrustchainProofService"))
        );
    }

    #[test]
    fn get_proof_service_only() {
        // Test get_proof_service method when non-proof service is present.

        // Load a Sidetree-resolved DID Document.
        let did_doc = Document::from_json(TEST_SIDETREE_DOCUMENT_SERVICE_AND_PROOF)
            .expect("Document failed to load.");

        // Check that two services are present in the DID document.
        assert_eq!((&did_doc).service.as_ref().unwrap().len(), 2 as usize);

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        // Get the service property containing the Trustchain proof.
        let proof_service = resolver.get_proof_service(&did_doc).unwrap();

        // Check the contents of the proof service property.
        assert_eq!(proof_service.id, "#trustchain-controller-proof");
        assert_eq!(
            proof_service.type_,
            OneOrMany::One(String::from("TrustchainProofService"))
        );
    }

    #[test]
    fn get_proof_service_fail_multiple_proof_services() {
        // Test get_proof_service method with failure as multiple proof services present.

        // Construct a DID Document with muliple proof services.
        let did_doc = Document::from_json(TEST_SIDETREE_DOCUMENT_MULTIPLE_PROOF)
            .expect("Document failed to load.");

        // Check that two services are present in the DID document.
        assert_eq!((&did_doc).service.as_ref().unwrap().len(), 2 as usize);

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        let result = resolver.get_proof_service(&did_doc);

        // Expect an error due to the presence of multiple proof services.
        let expected: Result<&Service, ResolverError> =
            Err(ResolverError::MultipleTrustchainProofService);

        assert_eq!(result, expected);
    }

    #[test]
    fn get_proof_service_fail_no_proof_services() {
        // Test get_proof_service method with failure as no proof services present.

        // Construct a DID Document with a service but no proof services.
        let did_doc = Document::from_json(TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF)
            .expect("Document failed to load.");

        // Check that a service is present in the DID document.
        assert!(did_doc.service.is_some());

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        let result = resolver.get_proof_service(&did_doc);

        // Expect an error due to the absence of any proof services.
        let expected: Result<&Service, ResolverError> =
            Err(ResolverError::NoTrustchainProofService);

        assert_eq!(result, expected);
    }

    #[test]
    fn get_proof_service_fail_no_services() {
        // Test get_proof_service method with failure as no services present.

        // Construct a DID Document with no proof services.
        let did_doc =
            Document::from_json(TEST_TRUSTCHAIN_DOCUMENT).expect("Document failed to load.");

        // Check that no services are present in the DID document.
        assert!(did_doc.service.is_none());

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        let result = resolver.get_proof_service(&did_doc);

        // Expect an error due to the absence of any proof services.
        let expected: Result<&Service, ResolverError> =
            Err(ResolverError::NoTrustchainProofService);

        assert_eq!(result, expected);
    }

    #[test]
    fn get_from_proof_service() {
        // Test to extract the controller DID from the service field in a sidetree-resolved DID document.

        // Load a Sidetree-resolved DID Document.
        let did_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load.");

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        // Get a reference to the proof service.
        let service = resolver.get_proof_service(&did_doc).unwrap();

        // Get the controller DID from the proof service.
        let controller = resolver
            .get_from_proof_service(&service, "controller")
            .unwrap();

        // Check the controller DID matches the expected value.
        assert_eq!(
            controller,
            "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
        )
    }

    #[test]
    fn add_proof() {
        // Test adding a proof to DID Document Metadata.

        // Load a Sidetree-resolved DID Document.
        let sidetree_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load doc.");

        // Load Sidetree-resolved DID Document Metadata.
        let sidetree_meta: DocumentMetadata =
            serde_json::from_str(TEST_SIDETREE_DOCUMENT_METADATA).expect("Failed to load metadata");

        // Load and canonicalize Trustchain document metadata.
        let expected_tc_meta: DocumentMetadata =
            serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT_METADATA)
                .expect("Failed to load metadata");
        let expected_tc_meta =
            canonicalize(&expected_tc_meta).expect("Cannot add proof and canonicalize.");

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        // Add proof to the DID Document Metadata and canonicalize the result.
        let actual_tc_meta = canonicalize(&resolver.add_proof(&sidetree_doc, sidetree_meta))
            .expect("Cannot add proof and canonicalize.");

        // Check that the result matches the expected metadata.
        assert_eq!(expected_tc_meta, actual_tc_meta);
    }

    #[test]
    fn transform_doc_metadata() {
        // Test transformation of Sidetree-resolved DID Document Metadata to Trustchain format.

        // See https://github.com/alan-turing-institute/trustchain/issues/11

        // Load a Sidetree-resolved DID Document.
        let did_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load doc.");

        // Construct Sidetree-resolved DID Document Metadata.
        let sidetree_meta: DocumentMetadata =
            serde_json::from_str(TEST_SIDETREE_DOCUMENT_METADATA).expect("Failed to load metadata");

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        // Transform the DID Document Metadata by resolving into Trustchain format.
        let actual = resolver.transform_doc_metadata(&did_doc, sidetree_meta);

        // Canonicalise the result and compare with the expected Trustchain format.
        let canon_actual_meta = canonicalize(&actual).expect("Cannot add proof and canonicalize.");

        let tc_meta: DocumentMetadata = serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT_METADATA)
            .expect("Failed to load metadata");
        let canon_tc_meta = canonicalize(&tc_meta).expect("Cannot add proof and canonicalize.");

        assert_eq!(canon_tc_meta, canon_actual_meta);
    }

    #[test]
    fn transform_doc() {
        // Test transformation of a Sidetree-resolved DID Document into Trustchain format.

        // Load a Sidetree-resolved DID Document.
        let did_doc =
            Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load.");

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        // Get the controller from the proof service property in the Sidetree-resolved DID document.
        let proof_service = resolver.get_proof_service(&did_doc).unwrap();
        let controller = resolver
            .get_from_proof_service(&proof_service, "controller")
            .unwrap();

        // Transform the DID document by resolving into Trustchain format.
        let actual = resolver.transform_doc(&did_doc, controller.as_str());

        // Canonicalise the result and compare with the expected Trustchain format.
        let canon_actual_doc = canonicalize(&actual).expect("Failed to canonicalize.");

        let tc_doc =
            Document::from_json(TEST_TRUSTCHAIN_DOCUMENT).expect("Document failed to load.");
        let canon_tc_doc = canonicalize(&tc_doc).expect("Failed to canonicalize.");

        assert_eq!(canon_tc_doc, canon_actual_doc);
    }

    #[test]
    fn transform_as_result() {
        // Test transformation of Sidetree-resolved DID Document + Metadata into Trustchain format.

        // Construct sample DID documents & metadata from test fixtures.
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

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        // Call function and get output result type
        let output = resolver.transform_as_result(
            input_res_meta.clone(),
            input_doc.clone(),
            input_doc_meta.clone(),
        );

        // Result should be Ok variant with returned data
        if let Ok((actual_output_res_meta, actual_output_doc, actual_output_doc_meta)) = output {
            // Check resolution metadata is equal
            assert_eq!(
                canonicalize(&expected_output_res_meta).unwrap(),
                canonicalize(&actual_output_res_meta).unwrap()
            );
            // Check documents are equal
            assert_eq!(expected_output_doc, actual_output_doc);
            // Check document metadata is equal
            assert_eq!(
                canonicalize(&expected_output_doc_meta).unwrap(),
                canonicalize(&actual_output_doc_meta).unwrap()
            );
        } else {
            // If error variant, panic
            panic!()
        }
    }

    #[test]
    fn transform_as_result_with_multiple_proof_services() {
        // Test that Trustchain resolution fails in the presence of multiple proof services
        // (indicating an invalid DID Document).

        // Construct sample DID document & metadata from test fixtures.
        let input_doc = Document::from_json(TEST_SIDETREE_DOCUMENT_MULTIPLE_PROOF)
            .expect("Document failed to load.");
        let input_doc_meta: DocumentMetadata =
            serde_json::from_str(TEST_SIDETREE_DOCUMENT_METADATA)
                .expect("Document failed to load.");
        let input_res_meta = ResolutionMetadata {
            error: None,
            content_type: None,
            property_set: None,
        };

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        // Call the resolve function and get output Result type.
        let output = resolver.transform_as_result(
            input_res_meta.clone(),
            input_doc.clone(),
            input_doc_meta.clone(),
        );

        // Check for the correct error.
        match output {
            Err(e) => assert_eq!(e, ResolverError::MultipleTrustchainProofService),
            _ => panic!(),
        }
    }
}

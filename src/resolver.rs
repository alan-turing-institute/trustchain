use futures::executor::block_on;
use serde_json::Value;
use ssi::did::{Document, Service, ServiceEndpoint, DIDMethod};
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
}

// Newtype pattern (workaround for lack of trait upcasting coercion).
// See https://doc.rust-lang.org/book/ch19-03-advanced-traits.html#using-the-newtype-pattern-to-implement-external-traits-on-external-types.
pub struct DIDMethodWrapper<T: DIDMethod>(pub T);

impl<T: DIDMethod> DIDResolver for DIDMethodWrapper<T> {
    fn resolve< 'life0, 'life1, 'life2, 'async_trait>(& 'life0 self,did: & 'life1 str,input_metadata: & 'life2 ResolutionInputMetadata,) ->  core::pin::Pin<Box<dyn core::future::Future<Output = (ResolutionMetadata,Option<Document> ,Option<DocumentMetadata> ,)> + core::marker::Send+ 'async_trait> >where 'life0: 'async_trait, 'life1: 'async_trait, 'life2: 'async_trait,Self: 'async_trait {
        self.0.to_resolver().resolve(did, input_metadata)
    }
}

// NOTE: Two alternative approaches to the Resolver struct are implemented.

// To switch between the alternatives, comment out the line(s) immediately following 
// one of the markers, either "APPROACH 1" or "APPROACH 2", throughout this module
// (four occurrences) and also inside the `resolve.rs` module (one occurrence).

// // APPROACH 1. (Trait object)
// /// Struct for performing resolution from a sidetree server to generate 
// /// Trustchain DID document and DID document metadata.
// pub struct Resolver {
//     /// Runtime for calling async functions.
//     runtime: Runtime,
//     /// Resolver for performing DID Method resolutions.
//     wrapped_resolver: Box<dyn DIDResolver>
// }

// APPROACH 2. (Generic type parameter)
/// Struct for performing resolution from a sidetree server to generate 
/// Trustchain DID document and DID document metadata.
pub struct Resolver<T: DIDResolver + Sync + Send> {
    /// Runtime for calling async functions.
    runtime: Runtime,
    /// Resolver for performing DID Method resolutions.
    wrapped_resolver: T
}

// // APPROACH 1.
// impl Resolver {

// APPROACH 2.
impl<T: DIDResolver + Sync + Send> Resolver<T> {

    /// Produces a new resolver.
    // // APPROACH 1.
    // pub fn new(resolver: Box<dyn DIDResolver>) -> Self {

    // APPROACH 2.
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

    /// Async function wrapping sidetree client resolution.
    async fn wrapped_resolve(
        &self,
        did_short: &str,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let (res_meta, doc, doc_meta) = self.wrapped_resolver
            .resolve(&did_short[..], &ResolutionInputMetadata::default())
            .await;

        (res_meta, doc, doc_meta)
    }

    /// Trustchain resolve function returning resolution metadata, 
    /// DID document and DID document metadata from a passed DID.
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
            let (did_res_meta, did_doc, did_doc_meta) =
                block_on(self.wrapped_resolve(&did.to_string()));

            // Handle cases when: 1. cannot connect to server; 2. Did not find DID.
            if let Some(did_res_meta_error) = &did_res_meta.error {
                if did_res_meta_error
                    .starts_with("Error sending HTTP request: error sending request for url")
                {
                    return Err(ResolverError::ConnectionFailure);
                } else if did_res_meta_error == "invalidDid" {
                    return Err(ResolverError::NonExistentDID(did.to_string()));
                } else {
                    eprintln!("Unhandled error message: {}", did_res_meta_error);
                    panic!();
                }
            }

            // If a document and document metadata are returned, try to convert
            if let (Some(did_doc), Some(did_doc_meta)) = (did_doc, did_doc_meta)
            {
                // Convert to trustchain versions
                let tc_result =
                    self.sidetree_to_trustchain(did_res_meta, did_doc, did_doc_meta);
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
                    Err(ResolverError::MultipleTrustchainProofService) => {
                        Err(ResolverError::MultipleTrustchainProofService)
                    }
                    // If not defined error, panic!()
                    _ => panic!(),
                }
            } else {
                // If doc or doc_meta None, return sidetree resolution as is
                Ok((did_res_meta, None, None))
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

    /// Converts a document from a sidetree resolved to a Trustchain resolved format.
    pub fn resolve_trustchain_doc(&self, doc: &Document, controller_did: &str) -> Document {
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

    /// Performs conversion of sidetree resolved objects to Trustchain objects.
    pub fn sidetree_to_trustchain(
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
            let doc =
                self.resolve_trustchain_doc(&sidetree_doc, controller_did.unwrap().as_str());

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

    /// Converts document metadata from a sidetree resolved to a Trustchain resolved format.
    pub fn sidetree_to_trustchain_doc_metadata(
        &self,
        doc: &Document,
        doc_meta: DocumentMetadata,
    ) -> DocumentMetadata {
        // Add proof to sidetree document metadata if it exists
        let doc_meta = self.add_proof(doc, doc_meta);

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{
        TEST_SIDETREE_DOCUMENT, 
        TEST_SIDETREE_DOCUMENT_METADATA,
        TEST_SIDETREE_DOCUMENT_SERVICE_AND_PROOF,
        TEST_SIDETREE_DOCUMENT_MULTIPLE_PROOF,
        TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF,
        TEST_SIDETREE_DOCUMENT_WITH_CONTROLLER,
        TEST_TRUSTCHAIN_DOCUMENT,
        TEST_TRUSTCHAIN_DOCUMENT_METADATA,
    };
    use ssi::did_resolve::HTTPDIDResolver;
    use did_ion::sidetree::{Sidetree};
    use did_ion::ION;

    // For testing, use a (dummy) HTTPDIDResolver.
    // // APPROACH 1.
    // fn get_http_resolver() -> Box<HTTPDIDResolver> {
    //     Box::new(HTTPDIDResolver::new("http://localhost:3000/"))
    // }

    // APPROACH 2.
    fn get_http_resolver() -> HTTPDIDResolver {
        HTTPDIDResolver::new("http://localhost:3000/")
    }
        
    #[test]
    fn add_controller() {
        // Test add_controller method with successful result.

        let controller_did = "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP";

        // Construct a Sidetree-resolved DID Document.
        let did_doc = Document::from_json(TEST_SIDETREE_DOCUMENT)
            .expect("Document failed to load.");

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
        assert_eq!(result.controller, Some(OneOrMany::One(String::from(controller_did))));

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

        // Construct a Sidetree-resolved DID Document.
        let did_doc = Document::from_json(TEST_SIDETREE_DOCUMENT)
            .expect("Document failed to load.");

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

        // Construct a Sidetree-resolved DID Document.
        let did_doc = Document::from_json(TEST_SIDETREE_DOCUMENT)
            .expect("Document failed to load.");

        // Check that precisely one service is present in the DID document.
        assert_eq!((&did_doc).service.as_ref().unwrap().len(), 1 as usize);

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        // Get the service property containing the Trustchain proof. 
        let proof_service = resolver.get_proof_service(&did_doc).unwrap();

        // Check the contents of the proof service property.
        assert_eq!(proof_service.id, "#trustchain-controller-proof");
        assert_eq!(proof_service.type_, OneOrMany::One(String::from("TrustchainProofService")));
    }

    #[test]
    fn get_proof_service_only() {
        // Test get_proof_service method when non-proof service is present.

        // Construct a Sidetree-resolved DID Document.
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
        assert_eq!(proof_service.type_, OneOrMany::One(String::from("TrustchainProofService")));
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
    fn resolve_trustchain_doc() {
        // Test resolve_trustchain_doc method to convert an Sidetree-resolved 
        // DID Document to the Trustchain-resolved format.

        // Construct Sidetree-resolved and Trustchain-resolved DID Documents.
        let did_doc = Document::from_json(TEST_SIDETREE_DOCUMENT)
            .expect("Document failed to load.");
        let tc_doc = Document::from_json(TEST_TRUSTCHAIN_DOCUMENT)
            .expect("Document failed to load.");

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        // Get the controller from the proof service in the Sidetree-resolved DID document.
        let proof_service = resolver.get_proof_service(&did_doc).unwrap();
        let controller = resolver
            .get_from_proof_service(&proof_service, "controller")
            .unwrap();

        let actual = resolver.resolve_trustchain_doc(&did_doc, controller.as_str());

        // Canonicalise the 
        let canon_tc_doc = ION::json_canonicalization_scheme(&tc_doc)
            .expect("Failed to canonicalize.");
        let canon_actual_doc = ION::json_canonicalization_scheme(&actual)
            .expect("Failed to canonicalize.");
        
        assert_eq!(canon_tc_doc, canon_actual_doc);
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

        // Construct a Resolver instance.
        let resolver = Resolver::new(get_http_resolver());

        // Actual Trustchain metadata
        let actual_tc_meta = ION::json_canonicalization_scheme(
            &resolver.sidetree_to_trustchain_doc_metadata(&sidetree_doc, sidetree_meta),
        )
        .expect("Cannot add proof and canonicalize.");
        assert_eq!(expected_tc_meta, actual_tc_meta);
    }

    // #[test]
    // fn sidetree_to_trustchain() {
    //     // Test objects
    //     let input_doc =
    //         Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load.");
    //     let expected_output_doc =
    //         Document::from_json(TEST_TRUSTCHAIN_DOCUMENT).expect("Document failed to load.");
    //     let input_doc_meta: DocumentMetadata =
    //         serde_json::from_str(TEST_SIDETREE_DOCUMENT_METADATA)
    //             .expect("Document failed to load.");
    //     let expected_output_doc_meta: DocumentMetadata =
    //         serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT_METADATA)
    //             .expect("Document failed to load.");
    //     let input_res_meta = ResolutionMetadata {
    //         error: None,
    //         content_type: None,
    //         property_set: None,
    //     };
    //     let expected_output_res_meta = ResolutionMetadata {
    //         error: None,
    //         content_type: None,
    //         property_set: None,
    //     };

    //     // Make new resolver
    //     // let resolver = Resolver::<ION>::new();
    //     let resolver = Resolver::new(get_ion_resolver());

    //     // Call function and get output result type
    //     let output = resolver.sidetree_to_trustchain(
    //         input_res_meta.clone(),
    //         input_doc.clone(),
    //         input_doc_meta.clone(),
    //     );

    //     // Result should be Ok variant with returned data
    //     if let Ok((actual_output_res_meta, actual_output_doc, actual_output_doc_meta)) = output {
    //         // Check resolution metadata is equal
    //         assert_eq!(
    //             ION::json_canonicalization_scheme(&expected_output_res_meta).unwrap(),
    //             ION::json_canonicalization_scheme(&actual_output_res_meta).unwrap()
    //         );
    //         // Check documents are equal
    //         assert_eq!(expected_output_doc, actual_output_doc);
    //         // Check document metadata is equal
    //         assert_eq!(
    //             ION::json_canonicalization_scheme(&expected_output_doc_meta).unwrap(),
    //             ION::json_canonicalization_scheme(&actual_output_doc_meta).unwrap()
    //         );
    //     } else {
    //         // If error variant, panic
    //         panic!()
    //     }
    // }
    // #[test]
    // fn sidetree_to_trustchain_with_multiple_proof_services() {
    //     // TODO: resolve fn needs to be updated to return ResolverError::MultipleTrustchainProofService
    //     // if there are multiple proof services present in the document as this is invalid.

    //     // Test objects
    //     let input_doc = Document::from_json(TEST_SIDETREE_DOCUMENT_MULTIPLE_PROOF)
    //         .expect("Document failed to load.");
    //     let input_doc_meta: DocumentMetadata =
    //         serde_json::from_str(TEST_SIDETREE_DOCUMENT_METADATA)
    //             .expect("Document failed to load.");
    //     let input_res_meta = ResolutionMetadata {
    //         error: None,
    //         content_type: None,
    //         property_set: None,
    //     };

    //     // Make new resolver
    //     // let resolver = Resolver::<ION>::new();
    //     let resolver = Resolver::new(get_ion_resolver());

    //     // Call function and get output result type
    //     let output = resolver.sidetree_to_trustchain(
    //         input_res_meta.clone(),
    //         input_doc.clone(),
    //         input_doc_meta.clone(),
    //     );

    //     // Check correct error
    //     match output {
    //         Err(e) => assert_eq!(e, ResolverError::MultipleTrustchainProofService),
    //         _ => panic!(),
    //     }
    // }

    // #[test]
    // fn get_from_proof_service() {
    //     // Write a test to extract the controller did from the service field in an sidetree-resolved DID document
    //     let did_doc =
    //         Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load.");

    //     // let resolver = Resolver::<ION>::new();
    //     let resolver = Resolver::new(get_ion_resolver());

    //     let service = resolver.get_proof_service(&did_doc).unwrap();

    //     let controller = resolver
    //         .get_from_proof_service(&service, "controller")
    //         .unwrap();

    //     assert_eq!(
    //         controller,
    //         "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
    //     )
    // }
    // #[test]
    // fn add_proof() {
    //     // Load test sidetree doc
    //     let sidetree_doc =
    //         Document::from_json(TEST_SIDETREE_DOCUMENT).expect("Document failed to load doc.");

    //     // Load test sidetree metadata
    //     let sidetree_meta: DocumentMetadata =
    //         serde_json::from_str(TEST_SIDETREE_DOCUMENT_METADATA).expect("Failed to load metadata");

    //     // Load and canoncalize the Trustchain document metadata
    //     let expected_tc_meta: DocumentMetadata =
    //         serde_json::from_str(TEST_TRUSTCHAIN_DOCUMENT_METADATA)
    //             .expect("Failed to load metadata");
    //     let expected_tc_meta = ION::json_canonicalization_scheme(&expected_tc_meta)
    //         .expect("Cannot add proof and canonicalize.");

    //     // Make new resolver
    //     // let resolver = Resolver::<ION>::new();
    //     let resolver = Resolver::new(get_ion_resolver());

    //     // Canonicalize
    //     let actual_tc_meta =
    //         ION::json_canonicalization_scheme(&resolver.add_proof(&sidetree_doc, sidetree_meta))
    //             .expect("Cannot add proof and canonicalize.");
    //     assert_eq!(expected_tc_meta, actual_tc_meta);
    // }
}

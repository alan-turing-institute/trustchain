use async_trait::async_trait;
use did_ion::{sidetree::SidetreeClient, ION};
use did_method_key::DIDKey;
use ssi::did::{DIDMethod, DIDMethods, Document, PrimaryDIDURL, Source};
use ssi::did_resolve::{
    Content, ContentMetadata, DIDResolver, DereferencingInputMetadata, DereferencingMetadata,
    DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
};
use trustchain_core::resolver::{DIDMethodWrapper, Resolver, ResolverError, ResolverResult};

use crate::config::ion_config;
use crate::IONResolver;

pub struct DIDMethodsResult<'a> {
    wrapped: DIDMethods<'a>,
}

impl<'a> DIDMethodsResult<'a> {
    pub fn insert(&mut self, method: &'a dyn DIDMethod) -> Option<&'a dyn DIDMethod> {
        self.wrapped.insert(method)
    }
    pub fn get(&self, method_name: &str) -> Option<&&'a dyn DIDMethod> {
        self.wrapped.get(method_name)
    }
    pub fn to_resolver(&self) -> &dyn DIDResolver {
        self.wrapped.to_resolver()
    }
    pub fn get_method(&self, did: &str) -> Result<&&'a dyn DIDMethod, &'static str> {
        self.wrapped.get_method(did)
    }
    pub fn generate(&self, source: &Source) -> Option<String> {
        self.wrapped.generate(source)
    }
    /// Sync Trustchain resolve function returning resolution metadata,
    /// DID document and DID document metadata from a passed DID as a `Result` type.
    pub async fn resolve_as_result(&self, did: &str) -> ResolverResult {
        // sidetree resolved resolution metadata, document and document metadata
        let (did_res_meta, did_doc, did_doc_meta) =
            self.resolve(did, &ResolutionInputMetadata::default()).await;

        // Handle error cases based on string content of the resolution metadata
        if let Some(did_res_meta_error) = &did_res_meta.error {
            if did_res_meta_error
                .starts_with("Error sending HTTP request: error sending request for url")
            {
                Err(ResolverError::ConnectionFailure)
            } else if did_res_meta_error == "invalidDid" {
                Err(ResolverError::NonExistentDID(did.to_string()))
            } else if did_res_meta_error == "notFound" {
                Err(ResolverError::DIDNotFound(did.to_string()))
            } else if did_res_meta_error == "Failed to convert to Truschain document and metadata."
            {
                Err(ResolverError::FailedToConvertToTrustchain)
            } else if did_res_meta_error == "Multiple Trustchain proof service entries are present."
            {
                Err(ResolverError::MultipleTrustchainProofService)
            } else {
                eprintln!("Unhandled error message: {}", did_res_meta_error);
                let eof_err_msg = "Error parsing resolution response: EOF while parsing a value at line 1 column 0";
                if did_res_meta_error == eof_err_msg {
                    eprintln!(
                        "HINT: If using HTTP for resolution, ensure a valid client is in use."
                    );
                }
                panic!();
            }
        } else {
            Ok((did_res_meta, did_doc, did_doc_meta))
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a> DIDResolver for DIDMethodsResult<'a> {
    /// Resolve a DID using the corresponding DID method, using the corresponding DID method in the
    /// [DIDMethods][] instance.
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let method = match self.get_method(did) {
            Ok(method) => method,
            Err(err) => return (ResolutionMetadata::from_error(err), None, None),
        };
        method.to_resolver().resolve(did, input_metadata).await
    }

    /// Resolve a DID to a DID document representation, using the corresponding DID method in the
    /// [DIDMethods][] instance.
    async fn resolve_representation(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (ResolutionMetadata, Vec<u8>, Option<DocumentMetadata>) {
        let method = match self.get_method(did) {
            Ok(method) => method,
            Err(err) => return (ResolutionMetadata::from_error(err), Vec::new(), None),
        };
        method
            .to_resolver()
            .resolve_representation(did, input_metadata)
            .await
    }

    /// Dereference a DID URL, using the corresponding DID method in the
    /// [DIDMethods][] instance.
    async fn dereference(
        &self,
        did_url: &PrimaryDIDURL,
        input_metadata: &DereferencingInputMetadata,
    ) -> Option<(DereferencingMetadata, Content, ContentMetadata)> {
        let method = match self.get_method(&did_url.did) {
            Ok(method) => method,
            Err(err) => {
                return Some((
                    DereferencingMetadata::from_error(err),
                    Content::Null,
                    ContentMetadata::default(),
                ))
            }
        };
        method
            .to_resolver()
            .dereference(did_url, input_metadata)
            .await
    }
}

/// Create a collection of DID methods that can be used as a single DID resolver
pub fn build_methods_resolver<'a>(resolvers: &'a [&dyn DIDMethod]) -> DIDMethodsResult<'a> {
    let mut did_methods = DIDMethods::default();
    did_methods.insert(&DIDKey);
    for resolver in resolvers {
        did_methods.insert(&**resolver);
    }
    DIDMethodsResult {
        wrapped: did_methods,
    }
}

lazy_static! {
    static ref TC: Resolver<DIDMethodWrapper<SidetreeClient<ION>>> = IONResolver::from(
        SidetreeClient::<ION>::new(Some(ion_config().ion_connection_string.to_owned()))
    );
    /// Static reference to a pre-built DIDMethods map using an ion_connection_string defined in
    /// TRUSTCHAIN_CONFIG
    pub static ref DID_METHODS: DIDMethodsResult<'static> = {
        let mut methods = DIDMethods::default();
        methods.insert(&DIDKey);
        methods.insert(&*TC);
        DIDMethodsResult { wrapped: methods }
    };
}

//! DID resolution and `DIDResolver` implementation.
use async_trait::async_trait;
use ipfs_api_backend_hyper::IpfsClient;
use ssi::did::{Service, ServiceEndpoint};
use ssi::did_resolve::DocumentMetadata;
use ssi::one_or_many::OneOrMany;
use ssi::{
    did::{DIDMethod, Document},
    did_resolve::{DIDResolver, ResolutionInputMetadata, ResolutionMetadata},
};
use trustchain_core::resolver::TrustchainResolver;
use trustchain_core::utils::{HasEndpoints, HasKeys};

use crate::utils::query_ipfs;
use crate::SERVICE_TYPE_IPFS_KEY;

// Newtype pattern (workaround for lack of trait upcasting coercion).
// Specifically, the DIDMethod method to_resolver() returns a reference but we want ownership.
// The workaround is to define a wrapper for DIDMethod that implements DIDResolver.
// See https://doc.rust-lang.org/book/ch19-03-advanced-traits.html#using-the-newtype-pattern-to-implement-external-traits-on-external-types.
pub struct DIDMethodWrapper<S: DIDMethod>(pub S);

#[async_trait]
impl<S: DIDMethod> DIDResolver for DIDMethodWrapper<S> {
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        self.0.to_resolver().resolve(did, input_metadata).await
    }
}

/// Struct for performing resolution from a sidetree server to generate
/// Trustchain DID document and DID document metadata.
pub struct Resolver<T: DIDResolver + Sync + Send> {
    pub wrapped_resolver: T,
    // pub ipfs_client: IpfsClient,
}

impl<T: DIDResolver + Sync + Send> Resolver<T> {
    /// Constructs a Trustchain resolver.
    pub fn new(resolver: T) -> Self {
        Self {
            wrapped_resolver: resolver,
            // ipfs_client: IpfsClient::default(),
        }
    }
    /// Constructs a Trustchain resolver from a DIDMethod.
    pub fn from<S: DIDMethod>(method: S) -> Resolver<DIDMethodWrapper<S>> {
        // Wrap the DIDMethod.
        Resolver::<DIDMethodWrapper<S>>::new(DIDMethodWrapper::<S>(method))
    }
}

#[async_trait]
impl<T> TrustchainResolver for Resolver<T>
where
    T: DIDResolver + Sync + Send,
{
    fn wrapped_resolver(&self) -> &dyn DIDResolver {
        &self.wrapped_resolver
    }

    async fn extended_transform(
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
        let ipfs_key_endpoints: Vec<String> = doc
            .unwrap()
            .service
            .unwrap()
            .iter()
            .filter(|s| s.type_.to_single().is_some())
            .filter_map(|ref s| {
                if s.type_
                    .to_single()
                    .as_deref()
                    .unwrap()
                    .eq(SERVICE_TYPE_IPFS_KEY)
                {
                    match s.service_endpoint {
                        Some(OneOrMany::One(ServiceEndpoint::URI(ref uri))) => Some(uri.to_owned()),
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .collect();

        // TODO: move to Resolver struct.
        // let ipfs_client = IpfsClient::default();
        // for endpoint in ipfs_key_endpoints {
        //     // Download the content of the corresponding CID
        //     let result = query_ipfs(cid, &ipfs_client).await.unwrap();

        //     // Check the content is a valid public key block.

        //     // Insert the public key in the list of keys inside the resolved DID document.
        // }

        // Duplication?
        // // Check if the Trustchain proof service alreday exists in the document.
        // let doc_clone = self.remove_proof_service(doc_clone);

        // TODO.
        (res_meta, None, doc_meta)
    }
}

// pub trait CASClient {
//     fn client() -> Option<fn(String) -> String> {
//         None
//     }
// }

#[async_trait]
impl<T> DIDResolver for Resolver<T>
where
    T: DIDResolver + Sync + Send,
{
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        self.trustchain_resolve(did, input_metadata).await
    }
}

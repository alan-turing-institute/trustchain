//! DID resolution and `DIDResolver` implementation.
use async_trait::async_trait;
use ssi::did_resolve::DocumentMetadata;
use ssi::{
    did::{DIDMethod, Document},
    did_resolve::{DIDResolver, ResolutionInputMetadata, ResolutionMetadata},
};
use trustchain_core::resolver::TrustchainResolver;

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
}

impl<T: DIDResolver + Sync + Send> Resolver<T> {
    /// Constructs a Trustchain resolver.
    pub fn new(resolver: T) -> Self {
        Self {
            wrapped_resolver: resolver,
        }
    }
    /// Constructs a Trustchain resolver from a DIDMethod.
    pub fn from<S: DIDMethod>(method: S) -> Resolver<DIDMethodWrapper<S>> {
        // Wrap the DIDMethod.
        Resolver::<DIDMethodWrapper<S>>::new(DIDMethodWrapper::<S>(method))
    }
}

impl<T> TrustchainResolver for Resolver<T>
where
    T: DIDResolver + Sync + Send,
{
    fn wrapped_resolver(&self) -> &dyn DIDResolver {
        &self.wrapped_resolver
    }

    // fn extended_transform() {}
}

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

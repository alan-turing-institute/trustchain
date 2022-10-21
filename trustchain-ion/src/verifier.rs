/// Struct for TrustchainVerifier
pub struct IONVerifier<T>
where
    T: Sync + Send + DIDResolver,
{
    resolver: Resolver<T>,
}

impl<T> IONVerifier<T>
where
    T: Send + Sync + DIDResolver,
{
    /// Construct a new IONVerifier.
    pub fn new(resolver: Resolver<T>) -> Self {
        Self { resolver }
    }
}

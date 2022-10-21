use ssi::did_resolve::DIDResolver;
use trustchain_core::resolver::Resolver;
use trustchain_core::verifier::Verifier;

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

impl<T> Verifier<T> for IONVerifier<T>
where
    T: Sync + Send + DIDResolver,
{
    fn verified_timestamp(&self, did: &str) -> u32 {
        todo!()
    }

    fn resolver(&self) -> &Resolver<T> {
        &self.resolver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}

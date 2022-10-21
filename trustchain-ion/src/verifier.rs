use crate::{
    MONGO_COLLECTION_OPERATIONS, MONGO_CONNECTION_STRING, MONGO_DATABASE_ION_TESTNET_CORE,
};
use futures::executor::block_on;
use mongodb::{bson::doc, options::ClientOptions, Client};
use ssi::did_resolve::DIDResolver;
use trustchain_core::resolver::Resolver;
use trustchain_core::verifier::{Verifier, VerifierError};

/// A transaction on the PoW ledger.
type Transaction = (u32, u32);

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

    /// Returns the ledger transaction representing the ION DID operation.
    fn transaction(&self, did: &str) -> Result<Transaction, VerifierError> {
        // Query the database.
        self.resolver().runtime.block_on(async {
            // sidetree resolved resolution metadata, document and document metadata
            let doc = block_on(Self::query_mongo(did));

            // let json = serde_json::from_str()?;

            // Extract the transaction data.
            // let block_height = json.get("txnTime");

            // TODO: txnNumber looks like NumberLong("2377445000003")
            // so we need to parse it, remove the block_height and then convert to a u32.
            // let transaction_index = json.get("txnNumber");
            Ok((0, 0))
        })
    }

    /// Query the ION MongoDB for a DID operation.
    async fn query_mongo(did: &str) -> mongodb::error::Result<mongodb::bson::Document> {
        // Connect to the ION Mongo DB.
        // Parse your connection string into an options struct
        let mut client_options = ClientOptions::parse(MONGO_CONNECTION_STRING).await?;

        let client = Client::with_options(client_options)?;

        let doc: mongodb::bson::Document = client
            .database(MONGO_DATABASE_ION_TESTNET_CORE)
            .collection(MONGO_COLLECTION_OPERATIONS)
            .find_one(
                doc! {
                    "didSuffix": did
                },
                None,
            )
            .await?
            .expect("Missing 'Parasite' document.");
        Ok(doc)
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
    use ssi::did_resolve::HTTPDIDResolver;

    // Helper function for generating a HTTP resolver for tests only.
    fn get_http_resolver() -> HTTPDIDResolver {
        HTTPDIDResolver::new("http://localhost:3000/")
    }

    #[test]
    fn test_transaction() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        let did = "EiCClfEdkTv_aM3UnBBh10V89L1GhpQAbfeZLFdFxVFkEg";

        let (block_height, transaction_index) = target.transaction(did).unwrap();

        assert_eq!(block_height, 2377445);
        assert_eq!(transaction_index, 3);
    }
}

use crate::{
    BITCOIN_CONNECTION_STRING, BITCOIN_RPC_PASSWORD, BITCOIN_RPC_USERNAME,
    MONGO_COLLECTION_OPERATIONS, MONGO_CONNECTION_STRING, MONGO_CREATE_OPERATION,
    MONGO_DATABASE_ION_TESTNET_CORE, MONGO_FILTER_DID_SUFFIX, MONGO_FILTER_TYPE,
};
use bitcoincore_rpc::RpcApi;
use futures::executor::block_on;
use mongodb::{bson::doc, options::ClientOptions, Client};
use ssi::did_resolve::DIDResolver;
use std::convert::TryFrom;
use trustchain_core::did_suffix;
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
        let suffix = did_suffix(did);
        self.resolver().runtime.block_on(async {
            // Query the database.
            let doc = match block_on(Self::query_mongo(suffix)) {
                Ok(x) => x,
                Err(e) => {
                    return Err(VerifierError::FailureToGetDIDOperation(
                        did.to_owned(),
                        e.to_string(),
                    ))
                }
            };

            // Extract the block height.
            let block_height: u32 = match doc.get_i32("txnTime") {
                Ok(x) => match u32::try_from(x) {
                    Ok(y) => y,
                    Err(_) => return Err(VerifierError::InvalidBlockHeight(x)),
                },
                Err(e) => {
                    return Err(VerifierError::FailureToGetDIDOperation(
                        suffix.to_owned(),
                        e.to_string(),
                    ))
                }
            };

            // Extract the index of the transaction inside the block.
            let txn_number_str = match doc.get_i64("txnNumber") {
                Ok(x) => x,
                Err(e) => {
                    return Err(VerifierError::FailureToGetDIDOperation(
                        suffix.to_owned(),
                        e.to_string(),
                    ))
                }
            }
            .to_string();

            let transaction_index = match txn_number_str.strip_prefix(&block_height.to_string()) {
                Some(x) => match str::parse::<u32>(x) {
                    Ok(y) => y,
                    Err(e) => {
                        return Err(VerifierError::FailureToGetDIDOperation(
                            suffix.to_owned(),
                            e.to_string(),
                        ))
                    }
                },
                // Includes a check that the transaction txnNumber starts with the block height.
                None => {
                    return Err(VerifierError::FailureToGetDIDOperation(
                        did.to_owned(),
                        String::from("txnNumber should start with block height."),
                    ))
                }
            };
            Ok((block_height, transaction_index))
        })
    }

    /// Query the ION MongoDB for a DID operation.
    // async fn query_mongo(did: &str) -> mongodb::error::Result<mongodb::bson::Document> {
    async fn query_mongo(did: &str) -> Result<mongodb::bson::Document, Box<dyn std::error::Error>> {
        let client_options = ClientOptions::parse(MONGO_CONNECTION_STRING).await?;
        let client = Client::with_options(client_options)?;

        // let doc: mongodb::bson::Document = client
        let query_result = client
            .database(MONGO_DATABASE_ION_TESTNET_CORE)
            .collection(MONGO_COLLECTION_OPERATIONS)
            .find_one(
                doc! {
                    MONGO_FILTER_TYPE : MONGO_CREATE_OPERATION,
                    MONGO_FILTER_DID_SUFFIX : did
                },
                None,
            )
            .await;
        match query_result {
            Ok(Some(doc)) => Ok(doc),
            Err(e) => {
                println!("{}", e);
                return Err(Box::new(VerifierError::FailureToGetDIDOperation(
                    did.to_owned(),
                    "MongoDB query failed.".to_string(),
                )));
            }
            _ => {
                return Err(Box::new(VerifierError::FailureToGetDIDOperation(
                    did.to_owned(),
                    "MongoDB query failed.".to_string(),
                )))
            }
        }
    }

    /// Gets the OP_RETURN in the Bitcoin transaction for a given DID.
    fn op_return(&self, did: &str) -> Result<&str, VerifierError> {
        let (block_height, transaction_index) = self.transaction(did)?;

        let rpc = bitcoincore_rpc::Client::new(
            BITCOIN_CONNECTION_STRING,
            bitcoincore_rpc::Auth::UserPass(
                BITCOIN_RPC_USERNAME.to_string(),
                BITCOIN_RPC_PASSWORD.to_string(),
            ),
        )
        .unwrap();

        let block_hash = rpc.get_block_hash(u64::from(block_height)).unwrap();
        let block_header = rpc.get_block_header(&block_hash).unwrap();

        println!("best block hash: {:?}", block_header);

        let op_return = "abc";

        // TODO.

        Ok(op_return)
    }
}

impl<T> Verifier<T> for IONVerifier<T>
where
    T: Sync + Send + DIDResolver,
{
    fn verified_block_height(&self, did: &str) -> Result<u32, VerifierError> {
        let (block_height, _) = self.transaction(did)?;
        Ok(block_height)
    }

    fn verified_timestamp(&self, did: &str) -> Result<u32, VerifierError> {
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
    #[ignore = "Integration test requires MongoDB"]
    fn test_transaction() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        let did = "did:ion:test:EiDYpQWYf_vkSm60EeNqWys6XTZYvg6UcWrRI9Mh12DuLQ";

        let (block_height, transaction_index) = target.transaction(did).unwrap();

        assert_eq!(block_height, 1902377);
        assert_eq!(transaction_index, 118);

        let did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
        let (block_height, transaction_index) = target.transaction(did).unwrap();

        assert_eq!(block_height, 2377445);
        assert_eq!(transaction_index, 3);

        // Invalid DID
        let invalid_did = "did:ion:test:EiCClfEdkTv_aM3UnBBh10V89L1GhpQAbfeZLFdFxVFkEg";
        let result = target.transaction(invalid_did);
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "Integration test requires MongoDB"]
    fn test_op_return() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        let did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";

        let result = target.op_return(did);
    }
}

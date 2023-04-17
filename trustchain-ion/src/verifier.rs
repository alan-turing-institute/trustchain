use crate::config::ion_config;
use crate::{
    MONGO_COLLECTION_OPERATIONS, MONGO_CREATE_OPERATION, MONGO_FILTER_DID_SUFFIX, MONGO_FILTER_TYPE,
};
use bitcoincore_rpc::RpcApi;
use futures::executor::block_on;
use mongodb::{bson::doc, options::ClientOptions, Client};
use ssi::did_resolve::DIDResolver;
use std::convert::TryFrom;
use trustchain_core::resolver::Resolver;
use trustchain_core::utils::get_did_suffix;
use trustchain_core::verifier::{Verifier, VerifierError};

/// A transaction on the PoW ledger.
type TransactionIndex = (u32, u32);

/// Trustchain Verifier for ION DID method. The generic type parameterises the wrapped DID resolver.
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
    /// Constructs a new IONVerifier.
    pub fn new(resolver: Resolver<T>) -> Self {
        Self { resolver }
    }

    /// Returns the ledger transaction representing the ION DID operation.
    fn transaction_index(&self, did: &str) -> Result<TransactionIndex, VerifierError> {
        let suffix = get_did_suffix(did);
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

    /// Queries the ION MongoDB for a DID operation.
    async fn query_mongo(did: &str) -> Result<mongodb::bson::Document, Box<dyn std::error::Error>> {
        let client_options = ClientOptions::parse(&ion_config().mongo_connection_string).await?;
        let client = Client::with_options(client_options)?;

        let query_result = client
            .database(&ion_config().mongo_database_ion_core)
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
                eprintln!("{}", e);
                Err(Box::new(VerifierError::FailureToGetDIDOperation(
                    did.to_owned(),
                    "MongoDB query failed.".to_string(),
                )))
            }
            _ => Err(Box::new(VerifierError::FailureToGetDIDOperation(
                did.to_owned(),
                "MongoDB query failed.".to_string(),
            ))),
        }
    }
}

impl<T> Verifier<T> for IONVerifier<T>
where
    T: Sync + Send + DIDResolver,
{
    fn verified_block_height(&self, did: &str) -> Result<u32, VerifierError> {
        let (block_height, _) = self.transaction_index(did)?;
        Ok(block_height)
    }

    fn verified_timestamp(&self, _did: &str) -> Result<u32, VerifierError> {
        todo!()
    }

    fn resolver(&self) -> &Resolver<T> {
        &self.resolver
    }
    fn block_height_to_unixtime(&self, block_height: u32) -> Result<u32, VerifierError> {
        let rpc = bitcoincore_rpc::Client::new(
            &ion_config().bitcoin_connection_string,
            bitcoincore_rpc::Auth::UserPass(
                ion_config().bitcoin_rpc_username.to_owned(),
                ion_config().bitcoin_rpc_password.to_owned(),
            ),
        )
        .unwrap();

        let block_hash = rpc.get_block_hash(u64::from(block_height)).unwrap();
        let block_header = rpc.get_block_header(&block_hash).unwrap();
        Ok(block_header.time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssi::did_resolve::HTTPDIDResolver;

    // Helper function for generating a placeholder HTTP resolver only for tests not querying ION.
    fn get_http_resolver() -> HTTPDIDResolver {
        HTTPDIDResolver::new("http://localhost:3000/")
    }

    #[test]
    #[ignore = "Integration test requires MongoDB"]
    fn test_transaction() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        let did = "did:ion:test:EiDYpQWYf_vkSm60EeNqWys6XTZYvg6UcWrRI9Mh12DuLQ";

        let (block_height, transaction_index) = target.transaction_index(did).unwrap();

        assert_eq!(block_height, 1902377);
        assert_eq!(transaction_index, 118);

        let did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
        let (block_height, transaction_index) = target.transaction_index(did).unwrap();

        assert_eq!(block_height, 2377445);
        assert_eq!(transaction_index, 3);

        // Invalid DID
        let invalid_did = "did:ion:test:EiCClfEdkTv_aM3UnBBh10V89L1GhpQAbfeZLFdFxVFkEg";
        let result = target.transaction_index(invalid_did);
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "Requires connection to a Bitcoin core testnet node on http://localhost:18332"]
    fn test_block_height_to_unixtime() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);
        let block_height = 2377445;
        let result = target.block_height_to_unixtime(block_height);
        assert_eq!(result.unwrap(), 1666265405u32);
        let block_height = 2378493;
        let result = target.block_height_to_unixtime(block_height);
        assert_eq!(result.unwrap(), 1666971942u32);
    }
}

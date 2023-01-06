use crate::{
    BITCOIN_CONNECTION_STRING, BITCOIN_RPC_PASSWORD, BITCOIN_RPC_USERNAME,
    MONGO_COLLECTION_OPERATIONS, MONGO_CONNECTION_STRING, MONGO_CREATE_OPERATION,
    MONGO_DATABASE_ION_TESTNET_CORE, MONGO_FILTER_DID_SUFFIX, MONGO_FILTER_TYPE,
};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoincore_rpc::bitcoin::Script;
use bitcoincore_rpc::RpcApi;
use futures::executor::block_on;
use mongodb::{bson::doc, options::ClientOptions, Client};
use ssi::did_resolve::DIDResolver;
use std::convert::TryFrom;
use std::str::FromStr;
use trustchain_core::did_suffix;
use trustchain_core::resolver::Resolver;
use trustchain_core::verifier::{Verifier, VerifierError};

/// Locator for a transaction on the PoW ledger, given by the pair:
/// (block_hash, tx_index_within_block).
type TransactionLocator = (BlockHash, u32);

/// Struct for TrustchainVerifier
pub struct IONVerifier<T>
where
    T: Sync + Send + DIDResolver,
{
    resolver: Resolver<T>,
    rpc_client: bitcoincore_rpc::Client,
}

impl<T> IONVerifier<T>
where
    T: Send + Sync + DIDResolver,
{
    /// Constructs a new IONVerifier.
    pub fn new(resolver: Resolver<T>) -> Self {
        // Construct a Bitcoin RPC client to communicate with the ION Bitcoin node.
        let rpc_client = bitcoincore_rpc::Client::new(
            BITCOIN_CONNECTION_STRING,
            bitcoincore_rpc::Auth::UserPass(
                BITCOIN_RPC_USERNAME.to_string(),
                BITCOIN_RPC_PASSWORD.to_string(),
            ),
        )
        .unwrap();
        // Safe to use unwrap() here, as Client::new can only return Err when using cookie authentication.

        Self {
            resolver,
            rpc_client,
        }
    }

    /// Returns the location on the ledger of the transaction embedding
    /// the most recent ION operation for the given DID.
    fn locate_transaction(&self, did: &str) -> Result<TransactionLocator, VerifierError> {
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
            let tx_number_str = match doc.get_i64("txnNumber") {
                Ok(x) => x,
                Err(e) => {
                    return Err(VerifierError::FailureToGetDIDOperation(
                        suffix.to_owned(),
                        e.to_string(),
                    ))
                }
            }
            .to_string();

            let tx_index = match tx_number_str.strip_prefix(&block_height.to_string()) {
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

            // Convert the block height to a block hash.
            let block_hash = match self.rpc_client.get_block_hash(u64::from(block_height)) {
                Ok(block_hash) => block_hash,
                // If a call to get_network_info succeeds, the issue is with the block_height.
                Err(e) => match self.rpc_client.get_network_info() {
                    Ok(_) => return Err(VerifierError::InvalidBlockHeight(block_height as i32)),
                    Err(e) => {
                        println!("{}", e);
                        return Err(VerifierError::LedgerClientError("getblockhash".to_string()));
                    }
                },
            };

            Ok((block_hash, tx_index))
        })
    }

    /// Queries the ION MongoDB for a DID operation.
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

    /// Gets the Bitcoin transaction at the given location.
    fn transaction(&self, tx_locator: TransactionLocator) -> Result<Transaction, VerifierError> {
        let (block_hash, transaction_index) = tx_locator;

        match self.rpc_client.get_block(&block_hash) {
            Ok(block) => Ok(block.txdata[transaction_index as usize].to_owned()),
            Err(e) => {
                println!("{}", e);
                Err(VerifierError::LedgerClientError("getblock".to_string()))
            }
        }
    }

    /// Extracts the ION OP_RETURN data from a Bitcoin transaction.
    ///
    /// ## Errors
    ///  - `VerifierError::AmbigousOpReturnData` if the transaction contains multiple ION OP_RETURN scripts
    ///  - `VerifierError::NoIonOpReturnScript` if the transaction contains no ION OP_RETURN script
    fn op_return_data(&self, tx: &Transaction) -> Result<String, VerifierError> {
        let tx_out_vec = &tx.output;
        // Get the output scripts that contain an OP_RETURN.
        let op_return_scripts: Vec<&Script> = tx_out_vec
            .iter()
            .filter_map(|x| match x.script_pubkey.is_op_return() {
                true => Some(&x.script_pubkey),
                false => None,
            })
            .collect();

        // Iterate over the OP_RETURN scripts. Extract any that contain the
        // substring 'ion:' and raise an error unless precisely one such script exists.
        let mut ret = "";
        for script in &op_return_scripts {
            match std::str::from_utf8(&script.as_ref()) {
                Ok(op_return_str) => match op_return_str.find("ion:") {
                    Some(i) => {
                        if ret.len() == 0 {
                            ret = &op_return_str[i..] // Trim any leading characters.
                        } else {
                            // Raise an error if multiple ION OP_RETURN scripts are found.
                            return Err(VerifierError::AmbigousOpReturnData(tx.txid().to_string()));
                        }
                    }
                    // Ignore the script if the 'ion:' substring is not found.
                    None => continue,
                },
                // Ignore the script if it cannot be converted to UTF-8.
                Err(_) => continue,
            }
        }
        if ret.len() == 0 {
            return Err(VerifierError::NoIonOpReturnScript(tx.txid().to_string()));
        }

        Ok(ret.to_string())
    }
}

impl<T> Verifier<T> for IONVerifier<T>
where
    T: Sync + Send + DIDResolver,
{
    fn verified_block_hash(&self, did: &str) -> Result<String, VerifierError> {
        let tx_locator = self.locate_transaction(did)?;
        let tx = self.transaction(tx_locator)?;

        // TODO: Need to perform 2 verifications:
        // 1. verify expected DID data really is committed to by the transaction
        //      See Branch 1 at https://hackmd.io/Dgoof7eZS6ysXuM6CUbCVQ#Branch-1-Verify-the-IPFS-data
        // 2. verify transaction really is in the block (via Merkle proof)
        //      See Branch 2 at https://hackmd.io/Dgoof7eZS6ysXuM6CUbCVQ#Branch-2-Verify-the-Bitcoin-transaction

        // 1. Verify that the DID Document was committed to by the Bitcoin transaction.
        // IMP NOTE: Do this by checking each pub key and service endpoint one by one, rather than
        // attempting to reconstruct the exact DID Document and hashing it.
        let op_return_data = &self.op_return_data(&tx)?;

        todo!();

        // 2. Verify that the Bitcoin transaction is in the block (via a Merkle proof).
        todo!();
    }

    fn block_hash_to_unix_time(&self, block_hash: &str) -> Result<u32, VerifierError> {
        let hash = match BlockHash::from_str(block_hash) {
            Ok(hash) => hash,
            Err(e) => {
                println!("{}", e);
                return Err(VerifierError::InvalidBlockHash(block_hash.to_owned()));
            }
        };
        let block_header = match self.rpc_client.get_block_header(&hash) {
            Ok(block_header) => block_header,
            Err(e) => {
                println!("{}", e);
                return Err(VerifierError::LedgerClientError(
                    "getblockheader".to_string(),
                ));
            }
        };
        Ok(block_header.time)
    }

    fn resolver(&self) -> &Resolver<T> {
        &self.resolver
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use bitcoin::Block;
    use ssi::did_resolve::HTTPDIDResolver;

    // Helper function for generating a HTTP resolver for tests only.
    fn get_http_resolver() -> HTTPDIDResolver {
        HTTPDIDResolver::new("http://localhost:3000/")
    }

    #[test]
    #[ignore = "Integration test requires MongoDB"]
    fn test_locate_transaction() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        let did = "did:ion:test:EiDYpQWYf_vkSm60EeNqWys6XTZYvg6UcWrRI9Mh12DuLQ";

        let (block_hash, transaction_index) = target.locate_transaction(did).unwrap();

        // Block 1902377
        let expected_block_hash =
            BlockHash::from_str("00000000e89bddeae5ad5589dfa4a7ea76ad9c83b0d711b5e6d4ee515ace6447")
                .unwrap();
        assert_eq!(block_hash, expected_block_hash);
        assert_eq!(transaction_index, 118);

        let did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
        let (block_hash, transaction_index) = target.locate_transaction(did).unwrap();

        // Block 2377445
        let expected_block_hash =
            BlockHash::from_str("000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f")
                .unwrap();
        assert_eq!(block_hash, expected_block_hash);
        assert_eq!(transaction_index, 3);

        // Invalid DID
        let invalid_did = "did:ion:test:EiCClfEdkTv_aM3UnBBh10V89L1GhpQAbfeZLFdFxVFkEg";
        let result = target.locate_transaction(invalid_did);
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "Integration test requires Bitcoin RPC"]
    fn test_transaction() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        // let did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
        let block_hash =
            BlockHash::from_str("000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f")
                .unwrap();
        let tx_locator = (block_hash, 3); // block hash & transaction index

        // The transaction can be found on-chain inside this block (indexed 3, starting from 0):
        // https://blockstream.info/testnet/block/000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f
        let txid_str = "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        let txid_hash = bitcoin::hashes::sha256d::Hash::from_str(txid_str).unwrap();
        let expected = Txid::from_hash(txid_hash);
        let result = target.transaction(tx_locator);
        assert!(result.is_ok());
        assert_eq!(expected, result.unwrap().txid());
    }

    #[test]
    #[ignore = "Integration test requires Bitcoin RPC"]
    fn test_op_return_data() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        // The transaction, including OP_RETURN data, can be found on-chain:
        // https://blockstream.info/testnet/tx/9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c
        let expected = "ion:3.QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";

        // Block 2377445
        let block_hash =
            BlockHash::from_str("000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f")
                .unwrap();
        let tx_locator = (block_hash, 3); // block hash & transaction index
        let tx = target.transaction(tx_locator).unwrap();

        let actual = target.op_return_data(&tx).unwrap();
        assert_eq!(expected, actual);
    }
}

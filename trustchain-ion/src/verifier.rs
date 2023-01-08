use crate::{
    BITCOIN_CONNECTION_STRING, BITCOIN_RPC_PASSWORD, BITCOIN_RPC_USERNAME, CHUNKS_KEY,
    CHUNK_FILE_URI_KEY, DELTAS_KEY, DID_DELIMITER, ION_METHOD, ION_OPERATION_COUNT_DELIMITER,
    MONGO_COLLECTION_OPERATIONS, MONGO_CONNECTION_STRING, MONGO_CREATE_OPERATION,
    MONGO_DATABASE_ION_TESTNET_CORE, MONGO_FILTER_DID_SUFFIX, MONGO_FILTER_TYPE,
    PROVISIONAL_INDEX_FILE_URI_KEY,
};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoincore_rpc::bitcoin::Script;
use bitcoincore_rpc::RpcApi;
use flate2::read::GzDecoder;
use futures::executor::block_on;
use futures::TryStreamExt;
use ipfs_api::IpfsApi;
use ipfs_api_backend_actix::IpfsClient;
use ipfs_hasher::IpfsHasher;
use mongodb::{bson::doc, options::ClientOptions, Client};
use serde_json::Value;
use ssi::did_resolve::DIDResolver;
use std::convert::TryFrom;
use std::io::Read;
use std::str::FromStr;
use trustchain_core::did_suffix;
use trustchain_core::resolver::Resolver;
use trustchain_core::verifier::{Verifier, VerifierError};

/// Locator for a transaction on the PoW ledger, given by the pair:
/// (block_hash, tx_index_within_block).
type TransactionLocator = (BlockHash, u32);

/// Enum to distinguish ION file types.
#[derive(Debug, PartialEq)]
enum IonFileType {
    CoreIndexFile,
    ProvisionalIndexFile,
    ChunkFile,
}

/// Struct for TrustchainVerifier
pub struct IONVerifier<T>
where
    T: Sync + Send + DIDResolver,
{
    resolver: Resolver<T>,
    rpc_client: bitcoincore_rpc::Client,
    ipfs_client: IpfsClient,
    ipfs_hasher: IpfsHasher,
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

        // TODO: this client must be configured to connect to the endpoint
        // specified as "ipfsHttpApiEndpointUri" in the ION config file
        // named "testnet-core-config.json" (or "mainnet-core-config.json").
        let ipfs_client = IpfsClient::default();
        let ipfs_hasher = IpfsHasher::default();

        Self {
            resolver,
            rpc_client,
            ipfs_client,
            ipfs_hasher,
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
                    eprintln!("Error querying MongoDB: {}", e);
                    return Err(VerifierError::FailureToGetDIDOperation(did.to_owned()));
                }
            };

            // Extract the block height.
            let block_height: u32 = match doc.get_i32("txnTime") {
                Ok(x) => match u32::try_from(x) {
                    Ok(y) => y,
                    Err(_) => return Err(VerifierError::InvalidBlockHeight(x)),
                },
                Err(e) => {
                    eprintln!("Failed to access txnTime: {}", e);
                    return Err(VerifierError::FailureToGetDIDOperation(suffix.to_owned()));
                }
            };

            // Extract the index of the transaction inside the block.
            let tx_number_str = match doc.get_i64("txnNumber") {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("Failed to access txnNumber: {}", e);
                    return Err(VerifierError::FailureToGetDIDOperation(suffix.to_owned()));
                }
            }
            .to_string();

            let tx_index = match tx_number_str.strip_prefix(&block_height.to_string()) {
                Some(x) => match str::parse::<u32>(x) {
                    Ok(y) => y,
                    Err(e) => {
                        eprintln!("Failed to parse transaction index: {}", e);
                        return Err(VerifierError::FailureToGetDIDOperation(suffix.to_owned()));
                    }
                },
                // Includes a check that the transaction txnNumber starts with the block height.
                None => {
                    eprintln!(
                        "Error: txnNumber {} should start with block height",
                        tx_number_str
                    );
                    return Err(VerifierError::FailureToGetDIDOperation(did.to_owned()));
                }
            };

            // Convert the block height to a block hash.
            let block_hash = match self.rpc_client.get_block_hash(u64::from(block_height)) {
                Ok(block_hash) => block_hash,
                // If a call to get_network_info succeeds, the issue is with the block_height.
                Err(e) => match self.rpc_client.get_network_info() {
                    Ok(_) => return Err(VerifierError::InvalidBlockHeight(block_height as i32)),
                    Err(e) => {
                        eprintln!("Error getting Bitcoin block hash: {}", e);
                        return Err(VerifierError::LedgerClientError("getblockhash".to_string()));
                    }
                },
            };

            Ok((block_hash, tx_index))
        })
    }

    // TODO: try making this a method and re-using the same client (struct member) each time.
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
                eprintln!("Error querying MongoDB: {}", e);
                return Err(Box::new(VerifierError::FailureToGetDIDOperation(
                    did.to_owned(),
                )));
            }
            _ => {
                return Err(Box::new(VerifierError::FailureToGetDIDOperation(
                    did.to_owned(),
                )))
            }
        }
    }

    /// Queries IPFS for the given content identifier (CID) to retrieve the content
    /// (as bytes), hashes the content and checks that the hash matches the CID,
    /// decompresses the content, converts it to a UTF-8 string and then to JSON.
    ///
    /// By checking that the hash of the content is identical to the CID, this method
    /// verifies that the content itself must have been used to originally construct the CID.
    ///
    /// ## Errors
    ///  - `VerifierError::FailureToGetDIDContent` if the IPFS query fails, or the decoding or JSON serialisation fails
    ///  - `VerifierError::FailedContentHashVerification` if the content hash is not identical to the CID
    #[actix_rt::main]
    async fn query_ipfs(&self, cid: &str) -> Result<Value, VerifierError> {
        let ipfs_file = match self
            .ipfs_client
            .cat(cid)
            .map_ok(|chunk| chunk.to_vec())
            .try_concat()
            .await
        {
            Ok(res) => res,
            Err(e) => {
                eprintln!("Error querying IPFS: {}", e);
                return Err(VerifierError::FailureToGetDIDContent(cid.to_string()));
            }
        };

        // Verify the content hash. This verifies that the content returned by this
        // method must have been used to construct the content identifier (CID).
        let ipfs_hash = self.ipfs_hasher.compute(&ipfs_file);
        if ipfs_hash.ne(cid) {
            return Err(VerifierError::FailedContentHashVerification(
                ipfs_hash,
                cid.to_string(),
            ));
        }

        // Decompress the content and deserialise to JSON.
        let mut decoder = GzDecoder::new(&ipfs_file[..]);
        let mut ipfs_content_str = String::new();
        match decoder.read_to_string(&mut ipfs_content_str) {
            Ok(_) => {
                match serde_json::from_str(&ipfs_content_str) {
                    Ok(value) => return Ok(value),
                    Err(e) => {
                        eprintln!("Error deserialising IPFS content to JSON: {}", e);
                        return Err(VerifierError::FailureToGetDIDContent(cid.to_string()));
                    }
                };
            }
            Err(e) => {
                eprintln!("Error decoding IPFS content: {}", e);
                return Err(VerifierError::FailureToGetDIDContent(cid.to_string()));
            }
        }
    }

    /// Gets the Bitcoin transaction at the given location.
    fn transaction(&self, tx_locator: TransactionLocator) -> Result<Transaction, VerifierError> {
        let (block_hash, transaction_index) = tx_locator;

        match self.rpc_client.get_block(&block_hash) {
            Ok(block) => Ok(block.txdata[transaction_index as usize].to_owned()),
            Err(e) => {
                eprintln!("Error getting Bitcoin block: {}", e);
                Err(VerifierError::LedgerClientError("getblock".to_string()))
            }
        }
    }

    /// Extracts the ION OP_RETURN data from a Bitcoin transaction.
    ///
    /// ## Errors
    ///  - `VerifierError::MultipleDIDContentIdentifiers` if the transaction contains multiple ION OP_RETURN scripts
    ///  - `VerifierError::NoDIDContentIdentifier` if the transaction contains no ION OP_RETURN script
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
        let ion_substr = format!("{}{}", ION_METHOD, DID_DELIMITER);
        for script in &op_return_scripts {
            match std::str::from_utf8(&script.as_ref()) {
                Ok(op_return_str) => match op_return_str.find(&ion_substr) {
                    Some(i) => {
                        if ret.len() == 0 {
                            ret = &op_return_str[i..] // Trim any leading characters.
                        } else {
                            // Raise an error if multiple ION OP_RETURN scripts are found.
                            return Err(VerifierError::MultipleDIDContentIdentifiers(
                                tx.txid().to_string(),
                            ));
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
            return Err(VerifierError::NoDIDContentIdentifier(tx.txid().to_string()));
        }

        Ok(ret.to_string())
    }

    /// Extracts the IPFS content identifier from the ION OP_RETURN data
    /// inside a Bitcoin transaction.
    fn op_return_cid(&self, tx: &Transaction) -> Result<String, VerifierError> {
        let op_return_data = self.op_return_data(tx)?;
        let (_, operation_count_plus_cid) = op_return_data.rsplit_once(DID_DELIMITER).unwrap();
        let (_, cid) = operation_count_plus_cid
            .rsplit_once(ION_OPERATION_COUNT_DELIMITER)
            .unwrap();
        return Ok(cid.to_string());
    }

    /// Gets DID Document content from IPFS and verifies that the given
    /// transacton contains a commitment to the content.
    fn verified_content(&self, tx: &Transaction) -> Result<Value, VerifierError> {
        let ipfs_cid = &self.op_return_cid(&tx)?;
        return self.unwrap_ion_content(ipfs_cid);
    }

    /// Unwraps the ION DID content associated with an IPFS content identifier.
    fn unwrap_ion_content(&self, cid: &str) -> Result<Value, VerifierError> {
        let ipfs_json = match self.query_ipfs(cid) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Error querying IPFS: {}", e);
                return Err(VerifierError::FailureToGetDIDContent(cid.to_string()));
            }
        };

        if let Some(file_type) = self.ion_file_type(&ipfs_json) {
            match file_type {
                IonFileType::CoreIndexFile => {
                    // get the provisionalIndexFileUri (CID) & recursively call on that.
                    let prov_index_file_uri = ipfs_json
                        .get(PROVISIONAL_INDEX_FILE_URI_KEY)
                        .unwrap()
                        .as_str()
                        .unwrap();
                    return self.unwrap_ion_content(prov_index_file_uri);
                }
                IonFileType::ProvisionalIndexFile => {
                    // Get the chunkFileUri (CID) & recursively call on that.
                    let chunks = ipfs_json.get(CHUNKS_KEY).unwrap();
                    let chunk_file_uri =
                        chunks[0].get(CHUNK_FILE_URI_KEY).unwrap().as_str().unwrap();
                    return self.unwrap_ion_content(chunk_file_uri);
                }
                IonFileType::ChunkFile => return Ok(ipfs_json),
            }
        } else {
            return Err(VerifierError::UnrecognisedDidContent(cid.to_string()));
        }
    }

    /// Determines the type of ION file found in a given JSON object.
    fn ion_file_type(&self, json: &Value) -> Option<IonFileType> {
        println!("{}", json.to_string());

        if let Some(_) = json.get(PROVISIONAL_INDEX_FILE_URI_KEY) {
            return Some(IonFileType::CoreIndexFile);
        } else if let Some(chunks_array) = json.get(CHUNKS_KEY) {
            if let Some(_) = chunks_array[0].get(CHUNK_FILE_URI_KEY) {
                return Some(IonFileType::ProvisionalIndexFile);
            } else {
                return None;
            }
        } else if let Some(_) = json.get(DELTAS_KEY) {
            return Some(IonFileType::ChunkFile);
        } else {
            return None;
        }
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
        // 1. verify that the transaction commits to the expected DID data
        //      See Branch 1 at https://hackmd.io/Dgoof7eZS6ysXuM6CUbCVQ#Branch-1-Verify-the-IPFS-data
        // 2. verify that the transaction really is in the block (via Merkle proof)
        //      See Branch 2 at https://hackmd.io/Dgoof7eZS6ysXuM6CUbCVQ#Branch-2-Verify-the-Bitcoin-transaction

        // 1. Verify that the DID Document was committed to by the Bitcoin transaction.
        // IMP NOTE: Do this by checking each pub key and service endpoint one by one, rather than
        // attempting to reconstruct the exact DID Document and hashing it.

        // Query_ipfs to get the ION chunkFile content (containing public keys & endpoints).
        let verified_content = &self.verified_content(&tx);

        todo!();

        // Handle the chunkFile (i.e. extract the public keys - "publicKeyJwk" elements -
        // and API endpoints - "serviceEndpoint" elements).

        // Query ION to get the DID Document content.

        // Extract the public keys & service endpoints from the DID Document. These are the expected values.

        // Iterate over the set of expected public keys and check that each is actually found in the chunk file.
        // Repeat for the service endpoints.

        // If they do, this branch of verification is complete.

        // 2. Verify that the Bitcoin transaction is in the block (via a Merkle proof).
    }

    fn block_hash_to_unix_time(&self, block_hash: &str) -> Result<u32, VerifierError> {
        let hash = match BlockHash::from_str(block_hash) {
            Ok(hash) => hash,
            Err(e) => {
                eprintln!("Error converting string to BlockHash: {}", e);
                return Err(VerifierError::InvalidBlockHash(block_hash.to_owned()));
            }
        };
        let block_header = match self.rpc_client.get_block_header(&hash) {
            Ok(block_header) => block_header,
            Err(e) => {
                eprintln!("Error getting Bitcoin block header: {}", e);
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

    #[test]
    #[ignore = "Integration test requires Bitcoin RPC"]
    fn test_op_return_cid() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        // The transaction, including OP_RETURN data, can be found on-chain:
        // https://blockstream.info/testnet/tx/9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c
        let expected = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";

        // Block 2377445
        let block_hash =
            BlockHash::from_str("000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f")
                .unwrap();
        let tx_locator = (block_hash, 3); // block hash & transaction index
        let tx = target.transaction(tx_locator).unwrap();

        let actual = target.op_return_cid(&tx).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    #[ignore = "Integration test requires IPFS"]
    fn test_query_ipfs() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        let cid = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";

        let actual = match target.query_ipfs(cid) {
            Ok(x) => x,
            Err(e) => panic!(),
        };

        // The CID is the address of a core index file, so the JSON result
        // contains the key "provisionalIndexFileUri".
        assert!(actual.get(PROVISIONAL_INDEX_FILE_URI_KEY).is_some());
    }

    #[test]
    fn test_ion_file_type() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        let json_str_core_index = r#"{"operations":{"create":[{"suffixData":{"deltaHash":"EiC6lxYLAjrwBjEz_uNT2ht5WCmt2fo2EZqxUvGBic-7OQ","recoveryCommitment":"EiA2PI72Nx4NncDCIXSQhX8eMJF-1JSiqk2Z9aOcfn3Y3w"}}]},"provisionalIndexFileUri":"QmPPTCygrc9fdtdbHWvKvvR8nVmfHa8KJ7BCd1mdMKC2WK"}"#;
        let json_str_prov_index =
            r#"{"chunks":[{"chunkFileUri":"QmS7wMGjVW7hQ3SUpQyD8oqV7XFdupYgZ5W9UWFbPGHNXK"}]}"#;
        let json_str_chunks = r#"{"deltas":[{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"signing-key","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"xbbKX8W-JFrigm9aHHIadDAPBqbwRpNb2iYybNRLyfg","y":"3HDnnvYF62CmrJ-i6D9G7XsVyFiFyvj6sVy-A7hdncg"},"type":"EcdsaSecp256k1VerificationKey2019"}]}}],"updateCommitment":"EiAo0UWyp7lSGoQYDMgYz5P9TvLhKGVzjCARpaANhj-fBQ"}]}"#;

        let json_core_index: Value = serde_json::from_str(json_str_core_index).unwrap();
        let json_prov_index: Value = serde_json::from_str(json_str_prov_index).unwrap();
        let json_chunks: Value = serde_json::from_str(json_str_chunks).unwrap();

        assert_eq!(
            target.ion_file_type(&json_core_index).unwrap(),
            IonFileType::CoreIndexFile
        );
        assert_eq!(
            target.ion_file_type(&json_prov_index).unwrap(),
            IonFileType::ProvisionalIndexFile
        );
        assert_eq!(
            target.ion_file_type(&json_chunks).unwrap(),
            IonFileType::ChunkFile
        );

        // Test negative results with bad JSON data.
        let bad_json_str_core_index = r#"{"operations":{"create":[{"suffixData":{"deltaHash":"EiC6lxYLAjrwBjEz_uNT2ht5WCmt2fo2EZqxUvGBic-7OQ","recoveryCommitment":"EiA2PI72Nx4NncDCIXSQhX8eMJF-1JSiqk2Z9aOcfn3Y3w"}}]},"other":"QmPPTCygrc9fdtdbHWvKvvR8nVmfHa8KJ7BCd1mdMKC2WK"}"#;
        let bad_json_str_prov_index =
            r#"{"chunks":[{"other":"QmS7wMGjVW7hQ3SUpQyD8oqV7XFdupYgZ5W9UWFbPGHNXK"}]}"#;
        let bad_json_str_chunks = r#"{"other":[{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"signing-key","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"xbbKX8W-JFrigm9aHHIadDAPBqbwRpNb2iYybNRLyfg","y":"3HDnnvYF62CmrJ-i6D9G7XsVyFiFyvj6sVy-A7hdncg"},"type":"EcdsaSecp256k1VerificationKey2019"}]}}],"updateCommitment":"EiAo0UWyp7lSGoQYDMgYz5P9TvLhKGVzjCARpaANhj-fBQ"}]}"#;

        let bad_json_core_index: Value = serde_json::from_str(bad_json_str_core_index).unwrap();
        let bad_json_prov_index: Value = serde_json::from_str(bad_json_str_prov_index).unwrap();
        let bad_json_chunks: Value = serde_json::from_str(bad_json_str_chunks).unwrap();

        assert!(target.ion_file_type(&bad_json_core_index).is_none());
        assert!(target.ion_file_type(&bad_json_prov_index).is_none());
        assert!(target.ion_file_type(&bad_json_chunks).is_none());
    }

    #[test]
    #[ignore = "Integration test requires Bitcoin RPC"]
    fn test_verified_content() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        // Block 2377445
        let block_hash =
            BlockHash::from_str("000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f")
                .unwrap();
        let tx_locator = (block_hash, 3); // block hash & transaction index
        let tx = target.transaction(tx_locator).unwrap();

        let actual = target.verified_content(&tx).unwrap();

        // Check that the content is the chunk file JSON (with top-level key "deltas").
        assert!(actual.get(DELTAS_KEY).is_some());

        // The "deltas" element contains an array of "patches".
        assert!(actual.get(DELTAS_KEY).unwrap().is_array());
        assert!(actual.get(DELTAS_KEY).unwrap()[0].get("patches").is_some());

        // Each patch contains (in this case) a single "action".
        assert!(actual.get(DELTAS_KEY).unwrap()[0]
            .get("patches")
            .unwrap()
            .is_array());
        assert!(
            actual.get(DELTAS_KEY).unwrap()[0].get("patches").unwrap()[0]
                .get("action")
                .is_some()
        );

        // And each patch also contains a "document" which contains public keys.
        assert!(
            actual.get(DELTAS_KEY).unwrap()[0].get("patches").unwrap()[0]
                .get("document")
                .is_some()
        );
        let doc = actual.get(DELTAS_KEY).unwrap()[0].get("patches").unwrap()[0]
            .get("document")
            .unwrap();
        assert!(doc.get("publicKeys").is_some());
    }
}

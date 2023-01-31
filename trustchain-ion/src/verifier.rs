use crate::commitment::IONCommitment;
use crate::utils::{
    block_header, decode_block_header, decode_ipfs_content, query_ipfs, query_mongodb,
    reverse_endianness,
};
use crate::{
    BITCOIN_CONNECTION_STRING, BITCOIN_RPC_PASSWORD, BITCOIN_RPC_USERNAME, BITS_KEY, CHUNKS_KEY,
    CHUNK_FILE_URI_KEY, DELTAS_KEY, DID_DELIMITER, HASH_PREV_BLOCK_KEY, ION_METHOD,
    ION_OPERATION_COUNT_DELIMITER, MERKLE_ROOT_KEY, METHOD_KEY, MONGO_COLLECTION_OPERATIONS,
    MONGO_CONNECTION_STRING, MONGO_CREATE_OPERATION, MONGO_DATABASE_ION_TESTNET_CORE,
    MONGO_FILTER_DID_SUFFIX, MONGO_FILTER_TYPE, NONCE_KEY, PROVISIONAL_INDEX_FILE_URI_KEY,
    TIMESTAMP_KEY, UPDATE_COMMITMENT_KEY, VERSION_KEY,
};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hash_types::BlockHash;
use bitcoin::{BlockHeader, MerkleBlock};
use bitcoincore_rpc::bitcoin::Script;
use bitcoincore_rpc::RpcApi;
use did_ion::sidetree::{Delta, DocumentState, PublicKeyEntry, ServiceEndpointEntry};
use flate2::read::GzDecoder;
use futures::executor::block_on;
use futures::TryStreamExt;
use ipfs_api::IpfsApi;
use ipfs_api_backend_actix::IpfsClient;
use ipfs_hasher::IpfsHasher;
use mongodb::{bson::doc, options::ClientOptions, Client};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi::did::Document;
use ssi::did_resolve::{DIDResolver, DocumentMetadata, Metadata};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::io::Read;
use std::str::FromStr;
use trustchain_core::commitment::{Commitment, CommitmentError, DIDCommitment};
use trustchain_core::did_suffix;
use trustchain_core::resolver::Resolver;
use trustchain_core::verifier::{Verifier, VerifierError};

// /// Locator for a transaction on the PoW ledger, given by the pair:
// /// (block_hash, tx_index_within_block).
type TransactionLocator = (BlockHash, u32);

/// Enum to distinguish ION file types.
#[derive(Debug, PartialEq)]
enum IonFileType {
    CoreIndexFile,
    ProvisionalIndexFile,
    ChunkFile,
}

/// Data bundle for DID timestamp verification.
#[derive(Serialize, Deserialize)]
pub struct VerificationBundle {
    did_doc: Document,               // DID Document
    did_doc_meta: DocumentMetadata,  // DID Document Metadata
    chunk_file: Vec<u8>,             // ION chunkFile
    provisional_index_file: Vec<u8>, // ION provisionalIndexFile
    core_index_file: Vec<u8>,        // ION coreIndexFile
    transaction: Vec<u8>, // Bitcoin Transaction (the one that anchors the DID operation in the blockchain)
    merkle_block: Vec<u8>, // MerkleBlock (containing a PartialMerkleTree and the BlockHeader)
    block_header: Vec<u8>, // Bitcoin block header
}

impl VerificationBundle {
    pub fn new(
        did_doc: Document,
        did_doc_meta: DocumentMetadata,
        chunk_file: Vec<u8>,
        provisional_index_file: Vec<u8>,
        core_index_file: Vec<u8>,
        transaction: Vec<u8>,
        merkle_block: Vec<u8>,
        block_header: Vec<u8>,
    ) -> Self {
        Self {
            did_doc,
            did_doc_meta,
            chunk_file,
            provisional_index_file,
            core_index_file,
            transaction,
            merkle_block,
            block_header,
        }
    }
}

/// Struct for Trustchain Verifier implementation via the ION DID method.
pub struct IONVerifier<T>
where
    T: Sync + Send + DIDResolver,
{
    resolver: Resolver<T>,
    rpc_client: bitcoincore_rpc::Client,
    ipfs_client: IpfsClient,
    ipfs_hasher: IpfsHasher,
    bundles: HashMap<String, VerificationBundle>,
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
        // Similar for the MongoDB client.
        let ipfs_client = IpfsClient::default();
        let ipfs_hasher = IpfsHasher::default();
        let bundles = HashMap::new();
        Self {
            resolver,
            rpc_client,
            ipfs_client,
            ipfs_hasher,
            bundles,
        }
    }

    pub fn bundles(&self) -> &HashMap<String, VerificationBundle> {
        &self.bundles
    }

    /// Returns a DID verification bundle.
    pub fn verification_bundle(&mut self, did: &str) -> Result<&VerificationBundle, VerifierError> {
        // Fetch (and store) the bundle if it isn't already avaialable.
        if !self.bundles.contains_key(did) {
            self.fetch_bundle(did)?;
        }
        Ok(self.bundles.get(did).unwrap())
    }

    /// Fetches the data needed to verify the DID's timestamp and stores it as a verification bundle.
    pub fn fetch_bundle(&mut self, did: &str) -> Result<(), VerifierError> {
        // TODO: if running on a Trustchain light client, make an API call to a full node to request the bundle.

        let (did_doc, did_doc_meta) = self.resolve_did(did)?;
        let (block_hash, tx_index) = self.locate_transaction(did)?;
        let tx = self.fetch_transaction(&block_hash, tx_index)?;
        let transaction = bitcoin::util::psbt::serialize::Serialize::serialize(&tx);
        let cid = self.op_return_cid(&tx)?;
        let core_index_file = self.fetch_core_index_file(&cid)?;
        let provisional_index_file = self.fetch_prov_index_file(&core_index_file)?;
        let chunk_file = self.fetch_chunk_file(&provisional_index_file, &did_doc_meta)?;
        let merkle_block = self.fetch_merkle_block(&block_hash, &tx)?;
        let block_header = self.fetch_block_header(&block_hash)?;
        // TODO: Consider extracting the block header (bytes) from the MerkleBlock to avoid one RPC call.

        let bundle = VerificationBundle::new(
            did_doc,
            did_doc_meta,
            chunk_file,
            provisional_index_file,
            core_index_file,
            transaction,
            merkle_block,
            block_header,
        );
        // Insert the bundle into the HashMap of bundles, keyed by the DID.
        let _ = &self.bundles.insert(did.to_string(), bundle);
        Ok(())
    }

    fn fetch_transaction(
        &self,
        block_hash: &BlockHash,
        tx_index: u32,
    ) -> Result<Transaction, VerifierError> {
        match transaction(block_hash, tx_index, Some(&self.rpc_client)) {
            Ok(x) => Ok(x),
            Err(e) => {
                eprintln!("Failed to fetch transaction: {}", e);
                return Err(VerifierError::FailureToFetchVerificationMaterial);
            }
        }
    }

    fn fetch_core_index_file(&self, cid: &str) -> Result<Vec<u8>, VerifierError> {
        match query_ipfs(cid, &self.ipfs_client) {
            Ok(x) => Ok(x),
            Err(e) => {
                eprintln!("Failed to fetch ION core index file: {}", e);
                return Err(VerifierError::FailureToFetchVerificationMaterial);
            }
        }
    }

    fn fetch_prov_index_file(&self, core_index_file: &Vec<u8>) -> Result<Vec<u8>, VerifierError> {
        let content = match decode_ipfs_content(core_index_file) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Failed to decode ION core index file: {}", e);
                return Err(VerifierError::FailureToFetchVerificationMaterial);
            }
        };
        let cid = match content.get(PROVISIONAL_INDEX_FILE_URI_KEY) {
            Some(value) => value.as_str().unwrap(),
            None => {
                eprintln!(
                    "Failed to find key {} in ION index file content.",
                    PROVISIONAL_INDEX_FILE_URI_KEY
                );
                return Err(VerifierError::FailureToFetchVerificationMaterial);
            }
        };
        match query_ipfs(cid, &self.ipfs_client) {
            Ok(x) => Ok(x),
            Err(e) => {
                eprintln!("Failed to fetch ION provisional index file: {}", e);
                return Err(VerifierError::FailureToFetchVerificationMaterial);
            }
        }
    }

    fn fetch_chunk_file(
        &self,
        prov_index_file: &Vec<u8>,
        did_doc_meta: &DocumentMetadata,
    ) -> Result<Vec<u8>, VerifierError> {
        // TODO: use the update commitment (from the doc metadata) to identify the right chunk deltas.
        let content = match decode_ipfs_content(prov_index_file) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Failed to decode ION provisional index file: {}", e);
                return Err(VerifierError::FailureToFetchVerificationMaterial);
            }
        };
        // Look inside the "chunks" element.
        let content = match content.get(CHUNKS_KEY) {
            Some(x) => x,
            None => {
                eprintln!(
                    "Expected key {} not found in ION provisional index file.",
                    CHUNKS_KEY
                );
                return Err(VerifierError::FailureToFetchVerificationMaterial);
            }
        };

        // In the current version of the Sidetree protocol, a single chunk
        // entry must be present in the chunks array (see
        // https://identity.foundation/sidetree/spec/#provisional-index-file).
        // So here we only need to consider the first entry in the content.
        // This may need to be updated in future to accommodate changes to the Sidetre protocol.
        let cid = match content[0].get(CHUNK_FILE_URI_KEY) {
            Some(value) => value.as_str().unwrap(),
            None => {
                eprintln!(
                    "Expected key {} not found in ION provisional index file.",
                    CHUNK_FILE_URI_KEY
                );
                return Err(VerifierError::FailureToFetchVerificationMaterial);
            }
        };
        match query_ipfs(cid, &self.ipfs_client) {
            Ok(x) => Ok(x),
            Err(e) => {
                eprintln!("Failed to fetch ION provisional index file: {}", e);
                return Err(VerifierError::FailureToFetchVerificationMaterial);
            }
        }
    }

    /// Fetches a Merkle proof directly from a Bitcoin node.
    fn fetch_merkle_block(
        &self,
        block_hash: &BlockHash,
        tx: &Transaction,
    ) -> Result<Vec<u8>, VerifierError> {
        match self
            .rpc_client
            .get_tx_out_proof(&[tx.txid()], Some(block_hash))
        {
            Ok(x) => Ok(x),
            Err(e) => {
                eprintln!("Failed to fetch Merkle proof via RPC: {}", e);
                return Err(VerifierError::FailureToFetchVerificationMaterial);
            }
        }
    }

    fn fetch_block_header(&self, block_hash: &BlockHash) -> Result<Vec<u8>, VerifierError> {
        let block_header = match block_header(block_hash, Some(&self.rpc_client)) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Failed to fetch Bitcoin block header via RPC: {}", e);
                return Err(VerifierError::FailureToFetchVerificationMaterial);
            }
        };
        Ok(bitcoin::consensus::serialize(&block_header))
    }

    /// Returns the location on the ledger of the transaction embedding
    /// the most recent ION operation for the given DID.
    fn locate_transaction(&self, did: &str) -> Result<TransactionLocator, VerifierError> {
        let suffix = did_suffix(did);
        self.resolver().runtime.block_on(async {
            // Query the database for a bson::Document.
            // let doc = match block_on(Self::query_mongo(suffix)) {
            let doc = match block_on(query_mongodb(suffix, None)) {
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

    /// Unwraps the ION DID content associated with an IPFS content identifier.
    fn unwrap_ion_content(
        &self,
        cid: &str,
        ipfs_client: &IpfsClient,
    ) -> Result<Value, VerifierError> {
        let ipfs_file = match query_ipfs(cid, ipfs_client) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Error querying IPFS for CID {}: {}", cid, e);
                return Err(VerifierError::FailureToGetDIDContent(cid.to_string()));
            }
        };
        let ipfs_json = match decode_ipfs_content(&ipfs_file) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Error decoding IPFS data for CID {}: {}", cid, e);
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
                    return self.unwrap_ion_content(prov_index_file_uri, ipfs_client);
                }
                IonFileType::ProvisionalIndexFile => {
                    // Get the chunkFileUri (CID) & recursively call on that.
                    let chunks = ipfs_json.get(CHUNKS_KEY).unwrap();
                    let chunk_file_uri =
                        chunks[0].get(CHUNK_FILE_URI_KEY).unwrap().as_str().unwrap();
                    return self.unwrap_ion_content(chunk_file_uri, ipfs_client);
                }
                IonFileType::ChunkFile => return Ok(ipfs_json),
            }
        } else {
            return Err(VerifierError::UnrecognisedDIDContent(cid.to_string()));
        }
    }

    /// Determines the type of ION file found in a given JSON object.
    fn ion_file_type(&self, json: &Value) -> Option<IonFileType> {
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

    /// Gets DID Document content from IPFS committed to by the given transaction and update commitment.
    fn verified_content(
        &self,
        tx: &Transaction,
        update_commitment: &str,
        ipfs_client: &IpfsClient,
    ) -> Result<DocumentState, VerifierError> {
        let ipfs_cid = &self.op_return_cid(&tx)?;
        let content_json = &self.unwrap_ion_content(ipfs_cid, ipfs_client)?;
        let deltas = content_deltas(content_json)?;
        return extract_doc_state(deltas, update_commitment);
    }

    /// Resolves the given DID to obtain the DID Document and Document Metadata.
    fn resolve_did(&self, did: &str) -> Result<(Document, DocumentMetadata), VerifierError> {
        match self.resolver.resolve_as_result(did) {
            Ok((x, y, z)) => {
                if let (_, Some(doc), Some(doc_meta)) = (x, y, z) {
                    Ok((doc, doc_meta))
                } else {
                    eprintln!("Missing Document and/or DocumentMetadata for DID: {}", did);
                    return Err(VerifierError::DIDResolutionError(did.to_string()));
                }
            }
            Err(e) => {
                eprintln!("Failed to resolve DID: {}", e);
                return Err(VerifierError::DIDResolutionError(did.to_string()));
            }
        }
    }

    // /// Resolves the given DID to obtain the DID Document and Update Commitment.
    // fn resolve_did(&self, did: &str) -> Result<(Document, DocumentMetadata, String), VerifierError> {
    //     let (doc, doc_meta) = match self.resolver.resolve_as_result(did) {
    //         Ok((x, y, z)) => {
    //             if let (_, Some(doc), Some(doc_meta)) = (x, y, z) {
    //                 (doc, doc_meta)
    //             } else {
    //                 eprintln!("Missing Document and/or DocumentMetadata for DID: {}", did);
    //                 return Err(VerifierError::DIDResolutionError(did.to_string()));
    //             }
    //         }
    //         Err(e) => {
    //             eprintln!("Failed to resolve DID: {}", e);
    //             return Err(VerifierError::DIDResolutionError(did.to_string()));
    //         }
    //     };

    //     // Extract the Update Commitment from the DID Document Metadata.
    //     if let Some(property_set) = doc_meta.property_set {
    //         // if let Some(metadata) = property_set.get(UPDATE_COMMITMENT_KEY) {
    //         if let Some(method_metadata) = property_set.get(METHOD_KEY) {
    //             let method_map = match method_metadata {
    //                 Metadata::Map(x) => x,
    //                 _ => {
    //                     eprintln!("Unhandled Metadata variant. Expected Map.");
    //                     return Err(VerifierError::DIDResolutionError(did.to_string()));
    //                 }
    //             };
    //             if let Some(uc_metadata) = method_map.get(UPDATE_COMMITMENT_KEY) {
    //                 match uc_metadata {
    //                     Metadata::String(uc) => return Ok((doc, doc_meta, uc.to_string())),
    //                     _ => {
    //                         eprintln!("Unhandled Metadata variant. Expected String.");
    //                         return Err(VerifierError::DIDResolutionError(did.to_string()));
    //                     }
    //                 }
    //             } else {
    //                 eprintln!(
    //                     "Missing '{}' key in DocumentMetadata {} value for DID: {}",
    //                     UPDATE_COMMITMENT_KEY, METHOD_KEY, did
    //                 );
    //                 return Err(VerifierError::DIDResolutionError(did.to_string()));
    //             }
    //         } else {
    //             eprintln!(
    //                 "Missing '{}' key in DocumentMetadata for DID: {}",
    //                 METHOD_KEY, did
    //             );
    //             return Err(VerifierError::DIDResolutionError(did.to_string()));
    //         }
    //     } else {
    //         eprintln!("Missing property set in DocumentMetadata for DID: {}", did);
    //         return Err(VerifierError::DIDResolutionError(did.to_string()));
    //     }
    // }

    // TODO: make this a free function.
    /// Extract the Update Commitment from DID Document Metadata.
    fn extract_update_commitment(
        &self,
        did_doc_meta: &DocumentMetadata,
    ) -> Result<String, VerifierError> {
        if let Some(property_set) = &did_doc_meta.property_set {
            // if let Some(metadata) = property_set.get(UPDATE_COMMITMENT_KEY) {
            if let Some(method_metadata) = property_set.get(METHOD_KEY) {
                let method_map = match method_metadata {
                    Metadata::Map(x) => x,
                    _ => {
                        eprintln!("Unhandled Metadata variant. Expected Map.");
                        return Err(VerifierError::DIDMetadataError);
                    }
                };
                if let Some(uc_metadata) = method_map.get(UPDATE_COMMITMENT_KEY) {
                    match uc_metadata {
                        Metadata::String(uc) => return Ok(uc.to_string()),
                        _ => {
                            eprintln!("Unhandled Metadata variant. Expected String.");
                            return Err(VerifierError::DIDMetadataError);
                        }
                    }
                } else {
                    eprintln!(
                        "Missing '{}' key in Document Metadata {} value.",
                        UPDATE_COMMITMENT_KEY, METHOD_KEY
                    );
                    return Err(VerifierError::DIDMetadataError);
                }
            } else {
                eprintln!("Missing '{}' key in DID Document Metadata.", METHOD_KEY);
                return Err(VerifierError::DIDMetadataError);
            }
        } else {
            eprintln!("Missing property set in DID Document Metadata.");
            return Err(VerifierError::DIDMetadataError);
        }
    }
}

// TODO: move some/all of these free functions to utils.

/// Converts a VerificationBundle into an IONCommitment.
pub fn construct_commitment(bundle: &VerificationBundle) -> Result<IONCommitment, CommitmentError> {
    IONCommitment::new(
        bundle.did_doc.clone(),
        bundle.chunk_file.clone(),
        bundle.provisional_index_file.clone(),
        bundle.core_index_file.clone(),
        bundle.transaction.clone(),
        bundle.merkle_block.clone(),
        bundle.block_header.clone(),
    )
}

/// Gets a Bitcoin RPC client instance.
pub fn rpc_client() -> bitcoincore_rpc::Client {
    // TODO: check where these config parameters (username & password)
    // are configured in ION and use the same config file.
    bitcoincore_rpc::Client::new(
        BITCOIN_CONNECTION_STRING,
        bitcoincore_rpc::Auth::UserPass(
            BITCOIN_RPC_USERNAME.to_string(),
            BITCOIN_RPC_PASSWORD.to_string(),
        ),
    )
    .unwrap()
    // Safe to use unwrap() here, as Client::new can only return Err when using cookie authentication.
}

/// Gets the Bitcoin transaction at the given location via the RPC API.
pub fn transaction(
    block_hash: &BlockHash,
    tx_index: u32,
    client: Option<&bitcoincore_rpc::Client>,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    // If necessary, construct a Bitcoin RPC client to communicate with the ION Bitcoin node.
    if client.is_none() {
        let rpc_client = crate::verifier::rpc_client();
        return transaction(block_hash, tx_index, Some(&rpc_client));
    }
    match client.unwrap().get_block(&block_hash) {
        Ok(block) => Ok(block.txdata[tx_index as usize].to_owned()),
        Err(e) => {
            eprintln!("Error getting Bitcoin block via RPC: {}", e);
            Err(Box::new(e))
        }
    }
}

/// Gets a Merkle proof for the given transaction via the RPC API.
pub fn merkle_proof(
    tx: &Transaction,
    block_hash: &BlockHash,
    client: Option<&bitcoincore_rpc::Client>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // If necessary, construct a Bitcoin RPC client to communicate with the ION Bitcoin node.
    if client.is_none() {
        let rpc_client = crate::verifier::rpc_client();
        return merkle_proof(tx, block_hash, Some(&rpc_client));
    }
    match client
        .unwrap()
        .get_tx_out_proof(&[tx.txid()], Some(&block_hash))
    {
        Ok(x) => Ok(x),
        Err(e) => {
            eprintln!("Error getting Merkle proof via RPC: {}", e);
            Err(Box::new(e))
        }
    }
}

/// Converts DID content from a chunk file into a vector of Delta objects.
pub fn content_deltas(chunk_file_json: &Value) -> Result<Vec<Delta>, VerifierError> {
    if let Some(deltas_json_array) = chunk_file_json.get(DELTAS_KEY) {
        let deltas: Vec<Delta> = match deltas_json_array {
            Value::Array(vec) => vec
                .iter()
                .filter_map(
                    |value| match serde_json::from_value::<Delta>(value.to_owned()) {
                        Ok(x) => Some(x),
                        Err(e) => {
                            eprintln!("Failed to read DocumentState from chunk file JSON: {}", e);
                            None
                        }
                    },
                )
                .collect(),
            _ => {
                eprintln!("Chunk file content 'deltas' not Value::Array type.");
                return Err(VerifierError::FailureToParseDIDContent());
            }
        };
        return Ok(deltas);
    } else {
        eprintln!("Key '{}' not found in chunk file content.", DELTAS_KEY);
        return Err(VerifierError::FailureToParseDIDContent());
    }
}

// TODO: Move this logic into the `decode_candidate_data` method inside TrivialIpfsCommitment.
/// Extracts public keys and endpoints from "deltas" with matching update commitment.
pub fn extract_doc_state(
    deltas: Vec<Delta>,
    update_commitment: &str,
) -> Result<DocumentState, VerifierError> {
    let mut pub_key_entries = Vec::<PublicKeyEntry>::new();
    let mut service_endpoints = Vec::<ServiceEndpointEntry>::new();

    // Include a check that there is at most one matching update commitment in the "deltas".
    // This catches an edge case where the same update commitment could (technically)
    // be reused across different DID operations. This would be bad practice, but is
    // possible. Currently we return an error in this (unlikely) case. A better fix
    // would be to handle the edge case by deriving the DID itself by hashing the delta
    // to find the "deltaHash" recorded in the coreIndexFile, then hashing the corresponding
    // "suffixData", to obtain the DID itself.
    let mut matched_update_commitment = false;
    for delta in deltas {
        // Ignore deltas whose update commitment does not match.
        if delta.update_commitment != update_commitment {
            continue;
        }
        // Check that at most one matching update commitment is found in the "deltas".
        if matched_update_commitment {
            eprintln!("Unexpected error: duplicate update commitments found in chunk file deltas.");
            return Err(VerifierError::DuplicateDIDUpdateCommitments(
                update_commitment.to_string(),
            ));
        }
        matched_update_commitment = true;
        for patch in delta.patches {
            match patch {
                did_ion::sidetree::DIDStatePatch::Replace { document } => {
                    if let Some(mut pub_keys) = document.public_keys {
                        pub_key_entries.append(&mut pub_keys);
                    }
                    if let Some(mut services) = document.services {
                        service_endpoints.append(&mut services);
                    }
                }
                _ => return Err(VerifierError::UnhandledDIDContent(format!("{:?}", patch))),
            }
        }
    }
    let public_keys = match pub_key_entries.is_empty() {
        true => None,
        false => Some(pub_key_entries),
    };
    let services = match service_endpoints.is_empty() {
        true => None,
        false => Some(service_endpoints),
    };
    return Ok(DocumentState {
        public_keys,
        services,
    });
}

impl<T> Verifier<T> for IONVerifier<T>
where
    T: Sync + Send + DIDResolver,
{
    /// Queries a local proof-of-work node to get the expected timestamp for a given proof-of-work hash.
    fn expected_timestamp(&self, hash: &str) -> Result<u64, VerifierError> {
        let block_hash = match BlockHash::from_str(hash) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Failed to convert hash string to BlockHash: {}", e);
                return Err(VerifierError::InvalidProofOfWorkHash(hash.to_string()));
            }
        };
        let block_header = match block_header(&block_hash, Some(&self.rpc_client)) {
            Ok(x) => x,
            Err(_) => {
                todo!()
            }
        };
        Ok(block_header.time as u64)
    }

    /// Gets a block hash (proof-of-work) Commitment for the given DID.
    /// The mutable reference to self enables a newly-fetched Commitment
    /// to be stored locally for faster subsequent retrieval.
    fn did_commitment(&mut self, did: &str) -> Result<Box<dyn DIDCommitment>, VerifierError> {
        let _ = self.fetch_did_commitment(did);
        if !self.bundles.contains_key(did) {
            eprintln!("Commitment not yet fetched for DID: {}", did);
            return Err(VerifierError::VerificationMaterialNotYetFetched(
                did.to_string(),
            ));
        }
        let bundle = self.bundles.get(did).unwrap();
        match construct_commitment(bundle) {
            Ok(x) => Ok(Box::new(x)),
            Err(e) => {
                eprintln!("Failed to obtain proof of work Commitment: {}", e);
                Err(VerifierError::TimestampVerificationError(did.to_string()))
            }
        }
    }

    fn fetch_did_commitment(&mut self, did: &str) -> Result<(), VerifierError> {
        // TODO: handle the possibility that the DID has been updated since previously fetched.

        // If the corresponding VerificationBundle is already available, do nothing.
        if self.bundles.contains_key(did) {
            return Ok(());
        };
        let _ = self.verification_bundle(did)?;
        Ok(())
    }

    fn resolver(&self) -> &Resolver<T> {
        &self.resolver
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::str::FromStr;

    use super::*;
    use crate::{
        data::{
            TEST_CHUNK_FILE_CONTENT, TEST_CHUNK_FILE_HEX, TEST_CORE_INDEX_FILE_CONTENT,
            TEST_MERKLE_BLOCK_HEX, TEST_PROVISIONAL_INDEX_FILE_CONTENT,
            TEST_PROVISIONAL_INDEX_FILE_HEX, TEST_TRANSACTION_HEX,
        },
        IONResolver,
    };
    use did_ion::{
        sidetree::{PublicKey, SidetreeClient},
        ION,
    };
    use ssi::{did::ServiceEndpoint, did_resolve::HTTPDIDResolver, jwk::Params, jwk::JWK};
    use trustchain_core::commitment::{
        ChainedCommitment, Commitment, CommitmentChain, TrivialCommitment,
    };
    use trustchain_core::data::TEST_ROOT_DOCUMENT_METADATA;

    // Helper function for generating a placeholder HTTP resolver for tests only.
    // Note that this resolver will *not* succeed at resolving DIDs. For that, a
    // SidetreeClient is needed.
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

        let did = "did:ion:test:EiBP_RYTKG2trW1_SN-e26Uo94I70a8wB4ETdHy48mFfMQ";
        let (block_hash, transaction_index) = target.locate_transaction(did).unwrap();
        // Block 2377339
        let expected_block_hash =
            BlockHash::from_str("000000000000003fadd15bdd2b55994371b832c6251781aa733a2a9e8865162b")
                .unwrap();
        assert_eq!(block_hash, expected_block_hash);
        assert_eq!(transaction_index, 10);

        // Invalid DID
        let invalid_did = "did:ion:test:EiCClfEdkTv_aM3UnBBh10V89L1GhpQAbfeZLFdFxVFkEg";
        let result = target.locate_transaction(invalid_did);
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "Integration test requires Bitcoin"]
    fn test_transaction() {
        // The transaction can be found on-chain inside this block (indexed 3, starting from 0):
        // https://blockstream.info/testnet/block/000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f
        let block_hash =
            BlockHash::from_str("000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f")
                .unwrap();
        let tx_index = 3;
        let result = transaction(&block_hash, tx_index, None);

        assert!(result.is_ok());
        let tx = result.unwrap();

        // Expected transaction ID:
        let expected = "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        assert_eq!(tx.txid().to_string(), expected);

        // Expect a different transaction ID to fail.
        let not_expected = "8dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        assert_ne!(tx.txid().to_string(), not_expected);
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
    fn test_ion_file_type() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        let json_core_index: Value = serde_json::from_str(TEST_CORE_INDEX_FILE_CONTENT).unwrap();
        let json_prov_index: Value =
            serde_json::from_str(TEST_PROVISIONAL_INDEX_FILE_CONTENT).unwrap();
        let json_chunks: Value = serde_json::from_str(TEST_CHUNK_FILE_CONTENT).unwrap();

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
        // Test with different sample files.
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
    #[ignore = "Integration test requires IPFS"]
    fn test_unwrap_ion_content() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        let cid = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";

        let ipfs_client = IpfsClient::default();
        let actual = target.unwrap_ion_content(cid, &ipfs_client).unwrap();

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

    #[test]
    fn test_extract_doc_state() {
        let chunk_file_json: Value = serde_json::from_str(TEST_CHUNK_FILE_CONTENT).unwrap();
        let deltas = content_deltas(&chunk_file_json).unwrap();
        let update_commitment = "EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg";
        let result = extract_doc_state(deltas, update_commitment).unwrap();

        // Expect one public key and one service endpoint (for the given
        // update_commitment - there are three in the chunk file JSON).
        let public_keys = result.public_keys.unwrap();
        let services = result.services.unwrap();
        assert_eq!(public_keys.len(), 1);
        assert_eq!(services.len(), 1);

        // Check the public key entry in the content.
        assert!(matches!(
            public_keys.first().unwrap().public_key,
            PublicKey::PublicKeyJwk { .. }
        ));
        let pub_key_jwk = match &public_keys.first().unwrap().public_key {
            PublicKey::PublicKeyJwk(x) => x,
            _ => panic!(), // Unreachable.
        };
        let jwk = JWK::try_from(pub_key_jwk.to_owned()).unwrap();
        assert!(matches!(&jwk.params, Params::EC { .. }));

        let ec_params = match jwk.params {
            Params::EC(x) => x,
            _ => panic!(), // Unreachable.
        };
        assert!(ec_params.x_coordinate.is_some());
        assert!(ec_params.y_coordinate.is_some());
        if let (Some(x), Some(y)) = (&ec_params.x_coordinate, &ec_params.y_coordinate) {
            assert_eq!(
                serde_json::to_string(x).unwrap(),
                "\"7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso\""
            );
            assert_eq!(
                serde_json::to_string(y).unwrap(),
                "\"kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE\""
            );
        };

        // Check the service endpoint entry in the content.
        assert!(matches!(
            services.first().unwrap().service_endpoint,
            ServiceEndpoint::URI { .. }
        ));
        let uri = match &services.first().unwrap().service_endpoint {
            ServiceEndpoint::URI(x) => x,
            _ => panic!(), // Unreachable.
        };
        // Check the URI.
        assert_eq!(uri, "https://identity.foundation/ion/trustchain-root");
    }

    #[test]
    #[ignore = "Integration test requires ION"]
    fn test_resolve_did() {
        // Use a SidetreeClient for the resolver in this case, as we need to resolve a DID.
        let resolver = IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(
            "http://localhost:3000/",
        ))));
        let target = IONVerifier::new(resolver);

        let did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
        let result = target.resolve_did(did);

        assert!(result.is_ok());
        let (doc, doc_meta) = result.unwrap();

        // Also testing the extract_update_commitment method.
        // TODO: split this into a separate test.
        let update_commitment = target.extract_update_commitment(&doc_meta);
        assert!(update_commitment.is_ok());
        let update_commitment = update_commitment.unwrap();
        assert_eq!(
            update_commitment,
            "EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg"
        );
    }

    #[test]
    #[ignore = "Integration test requires Bitcoin RPC & IPFS"]
    fn test_verified_content() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        // Test with the transaction committing to DID:
        // did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg

        // Block 2377445
        let block_hash =
            BlockHash::from_str("000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f")
                .unwrap();
        let tx_locator = (block_hash, 3); // block hash & transaction index
        let tx = target.transaction(tx_locator).unwrap();
        let update_commitment = "EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg";

        let ipfs_client = IpfsClient::default();
        let result = target
            .verified_content(&tx, update_commitment, &ipfs_client)
            .unwrap();

        // Expect one public key and one service endpoint.
        assert_eq!(result.public_keys.as_ref().unwrap().len(), 1);
        assert_eq!(result.services.as_ref().unwrap().len(), 1);

        // Check the endpoint (pub_key checked in test_extract_doc_state).
        if let ServiceEndpoint::URI(uri) =
            &result.services.unwrap().first().unwrap().service_endpoint
        {
            assert_eq!(uri, "https://identity.foundation/ion/trustchain-root");
        } else {
            panic!();
        }
    }

    #[test]
    #[ignore = "Integration test requires IPFS"]
    fn test_fetch_chunk_file() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        let prov_index_file = hex::decode(TEST_PROVISIONAL_INDEX_FILE_HEX).unwrap();
        let did_doc_meta = serde_json::from_str(TEST_ROOT_DOCUMENT_METADATA).unwrap();

        let result = target.fetch_chunk_file(&prov_index_file, &did_doc_meta);
        assert!(result.is_ok());
        let chunk_file_bytes = result.unwrap();

        let mut decoder = GzDecoder::new(&*chunk_file_bytes);
        let mut ipfs_content_str = String::new();
        let value: serde_json::Value = match decoder.read_to_string(&mut ipfs_content_str) {
            Ok(_) => serde_json::from_str(&ipfs_content_str).unwrap(),
            Err(_) => panic!(),
        };
        assert!(value.is_object());
        assert!(value.as_object().unwrap().contains_key("deltas"));
    }

    #[test]
    #[ignore = "Integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    fn test_fetch_bundle() {
        // Use a SidetreeClient for the resolver in this case, as we need to resolve a DID.
        let resolver = IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(
            "http://localhost:3000/",
        ))));
        let mut target = IONVerifier::new(resolver);

        assert!(target.bundles().is_empty());
        let did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
        target.fetch_bundle(&did);

        assert!(!target.bundles().is_empty());
        assert_eq!(target.bundles().len(), 1);
        assert!(target.bundles().contains_key(did));
    }

    #[test]
    #[ignore = "Integration test requires ION, MongoDB, IPFS and Bitcoin RPC"]
    fn test_commitment() {
        // Use a SidetreeClient for the resolver in this case, as we need to resolve a DID.
        let resolver = IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(
            "http://localhost:3000/",
        ))));
        let mut target = IONVerifier::new(resolver);

        let did = "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";

        assert!(target.bundles().is_empty());
        let result = target.did_commitment(did).unwrap();

        // Check that the verification bundle for the commitment is now stored in the Verifier.
        assert!(!target.bundles().is_empty());
        assert_eq!(target.bundles().len(), 1);
        let bundle = target.bundles.get(did).unwrap();
        let commitment = construct_commitment(bundle).unwrap();
        assert_eq!(result.hash(), commitment.hash());
    }

    // #[test]
    // fn test_verification_bundle_serialize() {
    //     // let verification_bundle = VerificationBundle();
    //     // Tests: 1. is valid json
    //     todo!();
    // }

    // #[test]
    // fn test_verification_bundle_deserialize() {
    //     // Tests: assert individual elements of struct
    //     todo!();
    // }

    #[test]
    fn test_chunk_file_deserialize() {
        let bytes = hex::decode(TEST_CHUNK_FILE_HEX).unwrap();
        let mut decoder = GzDecoder::new(&*bytes);
        let mut ipfs_content_str = String::new();
        let value: serde_json::Value = match decoder.read_to_string(&mut ipfs_content_str) {
            Ok(_) => serde_json::from_str(&ipfs_content_str).unwrap(),
            Err(_) => panic!(),
        };
        assert!(value.is_object());
        assert!(value.as_object().unwrap().contains_key("deltas"));
    }

    #[test]
    fn test_prov_index_file_deserialize() {
        let bytes = hex::decode(TEST_PROVISIONAL_INDEX_FILE_HEX).unwrap();
        let mut decoder = GzDecoder::new(&*bytes);
        let mut ipfs_content_str = String::new();
        let value: serde_json::Value = match decoder.read_to_string(&mut ipfs_content_str) {
            Ok(_) => serde_json::from_str(&ipfs_content_str).unwrap(),
            Err(_) => panic!(),
        };
        assert!(value.is_object());
        assert!(value.as_object().unwrap().contains_key("chunks"));
    }

    // #[test]
    // fn test_core_index_file_deserialize() {
    //     todo!()
    // }

    #[test]
    fn test_tx_deserialize() {
        let bytes = hex::decode(TEST_TRANSACTION_HEX).unwrap();
        let tx: Transaction =
            bitcoin::util::psbt::serialize::Deserialize::deserialize(&bytes).unwrap();
        let expected_txid = "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        assert_eq!(tx.txid().to_string(), expected_txid);
    }

    #[test]
    fn test_merkle_block_deserialize() {
        let bytes = hex::decode(TEST_MERKLE_BLOCK_HEX).unwrap();
        let merkle_block: MerkleBlock = bitcoin::consensus::deserialize(&bytes).unwrap();
        let header = merkle_block.header;
        let expected_merkle_root =
            "7dce795209d4b5051da3f5f5293ac97c2ec677687098062044654111529cad69";
        assert_eq!(header.merkle_root.to_string(), expected_merkle_root);
    }

    // #[test]
    // fn test_block_header_deserialize() {
    //     todo!()
    // }
}

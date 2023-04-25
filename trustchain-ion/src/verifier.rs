use crate::commitment::IONCommitment;
use crate::config::ion_config;
use crate::sidetree::{ChunkFile, ChunkFileUri, CoreIndexFile, ProvisionalIndexFile};
use crate::utils::{
    block_header, decode_ipfs_content, query_ipfs, query_mongodb, transaction, tx_to_op_return_cid,
};
use crate::URL;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hash_types::BlockHash;
use bitcoincore_rpc::RpcApi;
use did_ion::sidetree::Delta;
use futures::executor::block_on;
use futures::TryFutureExt;
use ipfs_api_backend_actix::IpfsClient;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi::did::Document;
use ssi::did_resolve::{DIDResolver, DocumentMetadata};
use std::collections::HashMap;
use std::convert::TryInto;
use std::str::FromStr;
use trustchain_core::commitment::{CommitmentError, DIDCommitment};
use trustchain_core::resolver::{Resolver, ResolverError};
use trustchain_core::utils::get_did_suffix;
use trustchain_core::verifier::{Timestamp, Verifier, VerifierError};

/// Locator for a transaction on the PoW ledger, given by the pair:
/// (block_hash, tx_index_within_block).
type TransactionLocator = (BlockHash, u32);

/// Data bundle for DID timestamp verification.
#[derive(Serialize, Deserialize)]
pub struct VerificationBundle {
    /// DID Document.
    did_doc: Document,
    /// DID Document Metadata.
    did_doc_meta: DocumentMetadata,
    /// ION chunk file.
    chunk_file: Vec<u8>,
    /// ION provisional index file.
    provisional_index_file: Vec<u8>,
    /// ION core index file.
    core_index_file: Vec<u8>,
    /// Bitcoin Transaction (the one that anchors the DID operation in the blockchain).
    transaction: Vec<u8>,
    /// MerkleBlock (containing a PartialMerkleTree and the BlockHeader).
    merkle_block: Vec<u8>,
    /// Bitcoin block header.
    block_header: Vec<u8>,
}

impl VerificationBundle {
    #[allow(clippy::too_many_arguments)]
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
            &ion_config().bitcoin_connection_string,
            bitcoincore_rpc::Auth::UserPass(
                ion_config().bitcoin_rpc_username.clone(),
                ion_config().bitcoin_rpc_password.clone(),
            ),
        )
        // Safe to use unwrap() here, as Client::new can only return Err when using cookie authentication.
        .unwrap();

        // This client must be configured to connect to the endpoint
        // specified as "ipfsHttpApiEndpointUri" in the ION config file
        // named "testnet-core-config.json" (or "mainnet-core-config.json").
        // Similar for the MongoDB client.
        // TODO: add customisable endpoint configuration to `trustchain_config.toml`
        let ipfs_client = IpfsClient::default();
        let bundles = HashMap::new();
        Self {
            resolver,
            rpc_client,
            ipfs_client,
            bundles,
        }
    }

    /// Fetches the DID commitment.
    fn fetch_did_commitment(&mut self, did: &str) -> Result<(), VerifierError> {
        // TODO: handle the possibility that the DID has been updated since previously fetched.

        // If the corresponding VerificationBundle is already available, do nothing.
        if !self.bundles.contains_key(did) {
            self.verification_bundle(did)?;
        };
        Ok(())
    }
    /// Returns the cached bundles.
    pub fn bundles(&self) -> &HashMap<String, VerificationBundle> {
        &self.bundles
    }

    /// Returns a DID verification bundle.
    pub fn verification_bundle(&mut self, did: &str) -> Result<&VerificationBundle, VerifierError> {
        // Fetch (and store) the bundle if it isn't already avaialable.
        if !self.bundles.contains_key(did) {
            self.fetch_bundle(did, None)?;
        }
        Ok(self.bundles.get(did).unwrap())
    }

    /// Fetches the data needed to verify the DID's timestamp and stores it as a verification bundle.
    pub fn fetch_bundle(&mut self, did: &str, endpoint: Option<URL>) -> Result<(), VerifierError> {
        let bundle: Result<VerificationBundle, VerifierError> = match endpoint.as_ref() {
            // If running on a Trustchain light client, make an API call to a full node to
            // request the bundle.
            Some(endpoint) => self.resolver.runtime.block_on(async {
                Ok(serde_json::from_str(
                    &reqwest::get(endpoint)
                        .await
                        .map_err(|e| {
                            VerifierError::ErrorFetchingVerificationMaterial(
                                format!("Error requesting bundle from endpoint: {endpoint}"),
                                e.into(),
                            )
                        })?
                        .text()
                        .map_err(|e| {
                            VerifierError::ErrorFetchingVerificationMaterial(
                                format!("Error extracting bundle response body from endpoint: {endpoint}"),
                                e.into(),
                            )
                        })
                        .await?,
                )?)
            }),
            _ => {
                let (did_doc, did_doc_meta) = self.resolve_did(did)?;
                let (block_hash, tx_index) = self.locate_transaction(did)?;
                let tx = self.fetch_transaction(&block_hash, tx_index)?;
                let transaction = bitcoin::util::psbt::serialize::Serialize::serialize(&tx);
                let cid = self.op_return_cid(&tx)?;
                let core_index_file = self.fetch_core_index_file(&cid)?;
                let provisional_index_file = self.fetch_prov_index_file(&core_index_file)?;
                let chunk_file = self.fetch_chunk_file(&provisional_index_file)?;
                let merkle_block = self.fetch_merkle_block(&block_hash, &tx)?;
                let block_header = self.fetch_block_header(&block_hash)?;
                // TODO: Consider extracting the block header (bytes) from the MerkleBlock to avoid one RPC call.
                Ok(VerificationBundle::new(
                    did_doc,
                    did_doc_meta,
                    chunk_file,
                    provisional_index_file,
                    core_index_file,
                    transaction,
                    merkle_block,
                    block_header,
                ))
            }
        };
        // Insert the bundle into the HashMap of bundles, keyed by the DID.
        self.bundles.insert(did.to_string(), bundle?);
        Ok(())
    }

    /// Resolves the given DID to obtain the DID Document and Document Metadata.
    fn resolve_did(&self, did: &str) -> Result<(Document, DocumentMetadata), VerifierError> {
        let (res_meta, doc, doc_meta) = self.resolver.resolve_as_result(did)?;
        if let (Some(doc), Some(doc_meta)) = (doc, doc_meta) {
            Ok((doc, doc_meta))
        } else {
            Err(VerifierError::DIDResolutionError(
                format!("Missing Document and/or DocumentMetadata for DID: {}", did),
                ResolverError::FailureWithMetadata(res_meta).into(),
            ))
        }
    }

    fn fetch_transaction(
        &self,
        block_hash: &BlockHash,
        tx_index: u32,
    ) -> Result<Transaction, VerifierError> {
        transaction(block_hash, tx_index, Some(&self.rpc_client)).map_err(|e| {
            VerifierError::ErrorFetchingVerificationMaterial(
                "Failed to fetch transaction.".to_string(),
                e.into(),
            )
        })
    }

    fn fetch_core_index_file(&self, cid: &str) -> Result<Vec<u8>, VerifierError> {
        query_ipfs(cid, &self.ipfs_client).map_err(|e| {
            VerifierError::ErrorFetchingVerificationMaterial(
                "Failed to fetch core index file".to_string(),
                e.into(),
            )
        })
    }

    fn fetch_prov_index_file(&self, core_index_file: &[u8]) -> Result<Vec<u8>, VerifierError> {
        let content = decode_ipfs_content(core_index_file).map_err(|e| {
            VerifierError::FailureToFetchVerificationMaterial(format!(
                "Failed to decode ION core index file: {}",
                e
            ))
        })?;
        let provisional_index_file_uri = serde_json::from_value::<CoreIndexFile>(content.clone())?
            .provisional_index_file_uri
            .ok_or(VerifierError::FailureToFetchVerificationMaterial(format!(
                "Missing provisional index file URI in core index file: {content}."
            )))?;
        query_ipfs(&provisional_index_file_uri, &self.ipfs_client).map_err(|e| {
            VerifierError::ErrorFetchingVerificationMaterial(
                "Failed to fetch ION provisional index file.".to_string(),
                e.into(),
            )
        })
    }

    fn fetch_chunk_file(&self, prov_index_file: &[u8]) -> Result<Vec<u8>, VerifierError> {
        let content = decode_ipfs_content(prov_index_file).map_err(|err| {
            VerifierError::ErrorFetchingVerificationMaterial(
                "Failed to decode ION provisional index file".to_string(),
                err.into(),
            )
        })?;

        // // Look inside the "chunks" element.
        let prov_index_file: ProvisionalIndexFile =
            serde_json::from_value(content).map_err(|err| {
                VerifierError::ErrorFetchingVerificationMaterial(
                    "Failed to parse ION provisional index file.".to_string(),
                    err.into(),
                )
            })?;

        // In the current version of the Sidetree protocol, a single chunk entry must be present in
        // the chunks array (see https://identity.foundation/sidetree/spec/#provisional-index-file).
        // So here we only need to consider the first entry in the content. This may need to be
        // updated in future to accommodate changes to the Sidetre protocol.
        let chunk_file_uri = match prov_index_file.chunks.as_deref() {
            Some([ChunkFileUri { chunk_file_uri }]) => chunk_file_uri,
            _ => return Err(VerifierError::FailureToGetDIDContent("".to_string())),
        };

        // Get Chunk File
        query_ipfs(chunk_file_uri, &self.ipfs_client).map_err(|err| {
            VerifierError::ErrorFetchingVerificationMaterial(
                "Failed to fetch ION provisional index file.".to_string(),
                err.into(),
            )
        })
    }

    /// Fetches a Merkle proof directly from a Bitcoin node.
    fn fetch_merkle_block(
        &self,
        block_hash: &BlockHash,
        tx: &Transaction,
    ) -> Result<Vec<u8>, VerifierError> {
        self.rpc_client
            .get_tx_out_proof(&[tx.txid()], Some(block_hash))
            .map_err(|e| {
                VerifierError::ErrorFetchingVerificationMaterial(
                    "Failed to fetch Merkle proof via RPC.".to_string(),
                    e.into(),
                )
            })
    }

    fn fetch_block_header(&self, block_hash: &BlockHash) -> Result<Vec<u8>, VerifierError> {
        block_header(block_hash, Some(&self.rpc_client))
            .map_err(|e| {
                VerifierError::ErrorFetchingVerificationMaterial(
                    "Failed to fetch Bitcoin block header via RPC.".to_string(),
                    e.into(),
                )
            })
            .map(|block_header| bitcoin::consensus::serialize(&block_header))
    }

    /// Returns the location on the ledger of the transaction embedding
    /// the most recent ION operation for the given DID.
    fn locate_transaction(&self, did: &str) -> Result<TransactionLocator, VerifierError> {
        let suffix = get_did_suffix(did);
        self.resolver().runtime.block_on(async {
            // Query the database for a bson::Document.
            let doc = block_on(query_mongodb(suffix, None)).map_err(|e| {
                VerifierError::ErrorFetchingVerificationMaterial(
                    "Error querying MongoDB".to_string(),
                    e.into(),
                )
            })?;

            // Extract the block height.
            let block_height: i64 = doc
                .get_i32("txnTime")
                .map_err(|_| VerifierError::FailureToGetDIDOperation(suffix.to_owned()))?
                .into();

            // Convert to block height u32
            let block_height: u32 = block_height
                .try_into()
                .map_err(|_| VerifierError::InvalidBlockHeight(block_height))?;

            // Extract the index of the transaction inside the block.
            let tx_index = doc
                .get_i64("txnNumber")
                .map_err(|_| VerifierError::FailureToGetDIDOperation(suffix.to_owned()))?
                .to_string()
                .strip_prefix(&block_height.to_string())
                .ok_or(VerifierError::FailureToGetDIDOperation(did.to_owned()))?
                .parse::<u32>()
                .map_err(|_| VerifierError::FailureToGetDIDOperation(suffix.to_owned()))?;

            // If call to get_network_info fails, return error
            self.rpc_client
                .get_network_info()
                .map_err(|_| VerifierError::LedgerClientError("getblockhash".to_string()))?;

            // Convert the block height to a block hash.
            let block_hash = self
                .rpc_client
                .get_block_hash(u64::from(block_height))
                .map_err(|_| VerifierError::InvalidBlockHeight(block_height.into()))?;

            Ok((block_hash, tx_index))
        })
    }

    /// Extracts the IPFS content identifier from the ION OP_RETURN data inside a Bitcoin transaction.
    fn op_return_cid(&self, tx: &Transaction) -> Result<String, VerifierError> {
        tx_to_op_return_cid(tx)
    }
}

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

/// Converts DID content from a chunk file into a vector of Delta objects.
pub fn content_deltas(chunk_file_json: &Value) -> Result<Vec<Delta>, VerifierError> {
    let chunk_file: ChunkFile =
        serde_json::from_value(chunk_file_json.to_owned()).map_err(|_| {
            VerifierError::FailureToParseDIDContent(format!(
                "Failed to parse chunk file: {}",
                chunk_file_json
            ))
        })?;
    Ok(chunk_file.deltas)
}

impl<T> Verifier<T> for IONVerifier<T>
where
    T: Sync + Send + DIDResolver,
{
    fn expected_timestamp(&self, hash: &str) -> Result<Timestamp, VerifierError> {
        let block_hash = BlockHash::from_str(hash)
            .map_err(|_| VerifierError::InvalidProofOfWorkHash(hash.to_string()))?;
        let block_header = block_header(&block_hash, Some(&self.rpc_client))
            .map_err(|_| VerifierError::FailureToGetBlockHeader(hash.to_string()))?;
        Ok(block_header.time)
    }

    fn did_commitment(&mut self, did: &str) -> Result<Box<dyn DIDCommitment>, VerifierError> {
        self.fetch_did_commitment(did)?;
        let bundle =
            self.bundles
                .get(did)
                .ok_or(VerifierError::VerificationMaterialNotYetFetched(
                    did.to_string(),
                ))?;
        Ok(construct_commitment(bundle).map(Box::new)?)
    }

    fn resolver(&self) -> &Resolver<T> {
        &self.resolver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        data::{
            TEST_BLOCK_HEADER_HEX, TEST_CHUNK_FILE_HEX, TEST_CORE_INDEX_FILE_HEX,
            TEST_MERKLE_BLOCK_HEX, TEST_PROVISIONAL_INDEX_FILE_HEX, TEST_TRANSACTION_HEX,
        },
        IONResolver,
    };
    use bitcoin::{BlockHeader, MerkleBlock};
    use did_ion::{sidetree::SidetreeClient, ION};
    use flate2::read::GzDecoder;
    use ssi::did_resolve::HTTPDIDResolver;
    use std::{io::Read, str::FromStr};
    use trustchain_core::commitment::TrivialCommitment;

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
    #[ignore = "Integration test requires Bitcoin RPC"]
    fn test_op_return_cid() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        // The transaction, including OP_RETURN data, can be found on-chain:
        // https://blockstream.info/testnet/tx/9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c
        let expected = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";

        // Block 2377445.
        let block_hash =
            BlockHash::from_str("000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f")
                .unwrap();
        let tx_index = 3;
        let tx = transaction(&block_hash, tx_index, Some(&target.rpc_client)).unwrap();

        let actual = target.op_return_cid(&tx).unwrap();
        assert_eq!(expected, actual);
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
    }

    #[test]
    #[ignore = "Integration test requires IPFS"]
    fn test_fetch_chunk_file() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        let prov_index_file = hex::decode(TEST_PROVISIONAL_INDEX_FILE_HEX).unwrap();

        let result = target.fetch_chunk_file(&prov_index_file);
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
    #[ignore = "Integration test requires IPFS"]
    fn test_fetch_core_index_file() {
        let resolver = Resolver::new(get_http_resolver());
        let target = IONVerifier::new(resolver);

        let cid = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        let result = target.fetch_core_index_file(cid);
        assert!(result.is_ok());
        let core_index_file_bytes = result.unwrap();

        let mut decoder = GzDecoder::new(&*core_index_file_bytes);
        let mut ipfs_content_str = String::new();
        let value: serde_json::Value = match decoder.read_to_string(&mut ipfs_content_str) {
            Ok(_) => serde_json::from_str(&ipfs_content_str).unwrap(),
            Err(_) => panic!(),
        };
        assert!(value.is_object());
        assert!(value
            .as_object()
            .unwrap()
            .contains_key("provisionalIndexFileUri"));
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
        target.fetch_bundle(did, None).unwrap();

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
        assert_eq!(result.hash().unwrap(), commitment.hash().unwrap());
    }

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

    #[test]
    fn test_core_index_file_deserialize() {
        let bytes = hex::decode(TEST_CORE_INDEX_FILE_HEX).unwrap();
        let mut decoder = GzDecoder::new(&*bytes);
        let mut ipfs_content_str = String::new();
        let value: serde_json::Value = match decoder.read_to_string(&mut ipfs_content_str) {
            Ok(_) => serde_json::from_str(&ipfs_content_str).unwrap(),
            Err(_) => panic!(),
        };
        assert!(value.is_object());
        assert!(value
            .as_object()
            .unwrap()
            .contains_key("provisionalIndexFileUri"));
    }

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

    #[test]
    fn test_block_header_deserialize() {
        let bytes = hex::decode(TEST_BLOCK_HEADER_HEX).unwrap();
        let header: BlockHeader = bitcoin::consensus::deserialize(&bytes).unwrap();
        let expected_merkle_root =
            "7dce795209d4b5051da3f5f5293ac97c2ec677687098062044654111529cad69";
        assert_eq!(header.merkle_root.to_string(), expected_merkle_root);
    }
}

//! Utils module.
use bitcoin::{BlockHash, Transaction};
use bitcoincore_rpc::RpcApi;
use did_ion::sidetree::{DocumentState, PublicKey, PublicKeyEntry, ServiceEndpointEntry};
use flate2::read::GzDecoder;
use futures::TryStreamExt;
use ipfs_api::IpfsApi;
use ipfs_api_backend_actix::IpfsClient;
use mongodb::{bson::doc, options::ClientOptions, Client};
use ssi::did::{Document, ServiceEndpoint, VerificationMethod, VerificationMethodMap};
use ssi::jwk::JWK;
use std::convert::TryFrom;
use std::error::Error;
use std::io::Read;
use trustchain_core::verifier::VerifierError;

use crate::{
    TrustchainIpfsError, TrustchainMongodbError, BITCOIN_CONNECTION_STRING, BITCOIN_RPC_PASSWORD,
    BITCOIN_RPC_USERNAME, MONGO_COLLECTION_OPERATIONS, MONGO_CONNECTION_STRING,
    MONGO_CREATE_OPERATION, MONGO_DATABASE_ION_TESTNET_CORE, MONGO_FILTER_DID_SUFFIX,
    MONGO_FILTER_TYPE,
};

pub trait HasKeys {
    fn get_keys(&self) -> Option<Vec<JWK>>;
}

pub trait HasEndpoints {
    fn get_endpoints(&self) -> Option<Vec<ServiceEndpoint>>;
}

impl HasKeys for Document {
    fn get_keys(&self) -> Option<Vec<JWK>> {
        let verification_methods = match &self.verification_method {
            Some(x) => x,
            None => return None,
        };

        let verification_method_maps: Vec<&VerificationMethodMap> = verification_methods
            .iter()
            .filter_map(|verification_method| match verification_method {
                VerificationMethod::Map(x) => Some(x),
                _ => {
                    eprintln!("Unhandled VerificationMethod variant. Expected Map.");
                    return None;
                }
            })
            .collect();

        if verification_method_maps.len() == 0 {
            return None;
        }

        let keys: Vec<JWK> = verification_method_maps
            .iter()
            .filter_map(|verification_method_map| verification_method_map.public_key_jwk.to_owned())
            .collect();

        if keys.len() == 0 {
            return None;
        }
        Some(keys)
    }
}

impl HasKeys for DocumentState {
    fn get_keys(&self) -> Option<Vec<JWK>> {
        let public_key_entries: Vec<PublicKeyEntry> = match &self.public_keys {
            Some(x) => x.to_vec(),
            None => return None,
        };
        let public_keys: Vec<JWK> = public_key_entries
            .iter()
            .filter_map(|entry| {
                match &entry.public_key {
                    PublicKey::PublicKeyJwk(pub_key_jwk) => {
                        // Return the JWK
                        match JWK::try_from(pub_key_jwk.to_owned()) {
                            Ok(jwk) => return Some(jwk),
                            Err(e) => {
                                eprintln!("Failed to convert PublicKeyJwk to JWK: {}", e);
                                return None;
                            }
                        }
                    }
                    PublicKey::PublicKeyMultibase(_) => {
                        eprintln!("Unhandled PublicKey variant. Expected PublicKeyJwk.");
                        return None;
                    }
                }
            })
            .collect();
        if public_keys.len() == 0 {
            return None;
        }
        return Some(public_keys);
    }
}

impl HasEndpoints for Document {
    fn get_endpoints(&self) -> Option<Vec<ServiceEndpoint>> {
        let services = match &self.service {
            Some(x) => x,
            None => return None,
        };
        let service_endpoints: Vec<ServiceEndpoint> = services
            .iter()
            .flat_map(|service| match service.to_owned().service_endpoint {
                Some(endpoints) => return endpoints.into_iter(),
                None => return Vec::<ServiceEndpoint>::new().into_iter(),
            })
            .collect();
        if service_endpoints.len() == 0 {
            return None;
        }
        Some(service_endpoints)
    }
}

impl HasEndpoints for DocumentState {
    fn get_endpoints(&self) -> Option<Vec<ServiceEndpoint>> {
        let service_endpoint_entries: Vec<ServiceEndpointEntry> = match &self.services {
            Some(x) => x.to_vec(),
            None => return None,
        };
        let service_endpoints: Vec<ServiceEndpoint> = service_endpoint_entries
            .iter()
            .map(|entry| entry.service_endpoint.to_owned())
            .collect();
        return Some(service_endpoints);
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
pub async fn query_ipfs(
    cid: &str,
    client: Option<IpfsClient>,
) -> Result<Vec<u8>, Box<ipfs_api_backend_actix::Error>> {
    // TODO: this client must be configured to connect to the endpoint
    // specified as "ipfsHttpApiEndpointUri" in the ION config file
    // named "testnet-core-config.json" (or "mainnet-core-config.json").
    let client = match client {
        Some(x) => x,
        None => IpfsClient::default(),
    };
    match client
        .cat(cid)
        .map_ok(|chunk| chunk.to_vec())
        .try_concat()
        .await
    {
        Ok(res) => Ok(res),
        Err(e) => {
            eprintln!("Error querying IPFS: {}", e);
            return Err(Box::new(e));
        }
    }
}

/// Decodes an IPFS file.
pub fn decode_ipfs_content(ipfs_file: Vec<u8>) -> Result<serde_json::Value, TrustchainIpfsError> {
    // Decompress the content and deserialise to JSON.
    let mut decoder = GzDecoder::new(&ipfs_file[..]);
    let mut ipfs_content_str = String::new();
    match decoder.read_to_string(&mut ipfs_content_str) {
        Ok(_) => {
            match serde_json::from_str(&ipfs_content_str) {
                Ok(value) => return Ok(value),
                Err(e) => {
                    eprintln!("Error deserialising IPFS content to JSON: {}", e);
                    return Err(TrustchainIpfsError::DataDecodingError);
                }
            };
        }
        Err(e) => {
            eprintln!("Error decoding IPFS content: {}", e);
            return Err(TrustchainIpfsError::DataDecodingError);
        }
    }
}

/// Queries the ION MongoDB for a DID operation.
pub async fn query_mongodb(
    did: &str,
    client: Option<mongodb::Client>,
) -> Result<mongodb::bson::Document, Box<dyn std::error::Error>> {
    // TODO: this client must be configured to connect to the endpoint
    // specified as "TODO!" in the ION config file
    // named "testnet-core-config.json" (or "mainnet-core-config.json").
    let client = match client {
        Some(x) => x,
        None => {
            let client_options = ClientOptions::parse(MONGO_CONNECTION_STRING).await?;
            mongodb::Client::with_options(client_options)?
        }
    };

    // MOST IMP TODO: try other queries (different to .find_one()) to see whether
    // a fuller collection of DID operations can be obtained (e.g. both create and updates).
    let query_result: Result<std::option::Option<mongodb::bson::Document>, mongodb::error::Error> =
        client
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
        Ok(None) => {
            eprintln!("Error querying MongoDB. None returned");
            Err(Box::new(TrustchainMongodbError::QueryReturnedNone))
        }
        Err(e) => {
            eprintln!("Error querying MongoDB: {}", e);
            Err(Box::new(TrustchainMongodbError::QueryReturnedError(
                e.to_string(),
            )))
        }
    }
}

pub fn reverse_endianness(hex: &str) -> Result<String, hex::FromHexError> {
    let mut bytes = hex::decode(hex)?;
    bytes.reverse();
    Ok(hex::encode(bytes))
}

pub fn int_to_little_endian_hex(int: &u32) -> String {
    let hex = format!("{:x}", int);
    reverse_endianness(&hex).unwrap()
}

#[cfg(test)]
mod tests {
    use core::panic;
    use std::io::Read;
    use std::str::FromStr;

    use super::*;
    use crate::data::{
        TEST_CHUNK_FILE_CONTENT_MULTIPLE_KEYS, TEST_CHUNK_FILE_CONTENT_MULTIPLE_SERVICES,
    };
    use crate::verifier::extract_doc_state;
    use crate::PROVISIONAL_INDEX_FILE_URI_KEY;
    use crate::{data::TEST_CHUNK_FILE_CONTENT, verifier::content_deltas};
    use flate2::read::GzDecoder;
    use futures::executor::block_on;
    use serde_json::Value;
    use ssi::jwk::Params;
    use trustchain_core::data::{
        TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS, TEST_SIDETREE_DOCUMENT_SERVICE_AND_PROOF,
        TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF,
    };
    use trustchain_core::did_suffix;

    #[test]
    fn test_get_keys_from_document() {
        let doc_json = serde_json::from_str(TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF).unwrap();
        let doc = Document::from(doc_json);

        let result = doc.get_keys();
        assert!(result.as_ref().is_some());
        assert_eq!(result.as_ref().unwrap().len(), 1);

        // Check the values of the key's x & y coordinates.
        if let Params::EC(ec_params) = &result.unwrap().first().unwrap().params {
            assert!(ec_params.x_coordinate.is_some());
            assert!(ec_params.y_coordinate.is_some());
            if let (Some(x), Some(y)) = (&ec_params.x_coordinate, &ec_params.y_coordinate) {
                assert_eq!(
                    serde_json::to_string(x).unwrap(),
                    "\"RbIj1Y4jeqkn0cizEfxHZidD-GQouFmAtE6YCpxFjpg\""
                );
                assert_eq!(
                    serde_json::to_string(y).unwrap(),
                    "\"ZcbgNp3hrfp3cujZFKqgFS0uFGOn2Rk16Y9nOv0h15s\""
                );
            };
        } else {
            panic!();
        }

        // Now test with a Document containing two keys.
        let doc_json = serde_json::from_str(TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS).unwrap();
        let doc = Document::from(doc_json);

        let result = doc.get_keys();
        assert!(result.as_ref().is_some());
        assert_eq!(result.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_get_keys_from_document_state() {
        let chunk_file_json: Value = serde_json::from_str(TEST_CHUNK_FILE_CONTENT).unwrap();
        let deltas = content_deltas(&chunk_file_json).unwrap();
        // Note: this is the update commitment for the *second* delta in TEST_CHUNK_FILE_CONTENT.
        let update_commitment = "EiC0EdwzQcqMYNX_3aqoZNUau4AKOL3gXQ5Pz3ATi1q_iA";
        let doc_state = extract_doc_state(deltas, update_commitment).unwrap();

        let result = doc_state.get_keys();
        assert!(result.as_ref().is_some());
        assert_eq!(result.as_ref().unwrap().len(), 1);

        // Check the values of the key's x & y coordinates.
        if let Params::EC(ec_params) = &result.unwrap().first().unwrap().params {
            assert!(ec_params.x_coordinate.is_some());
            assert!(ec_params.y_coordinate.is_some());
            if let (Some(x), Some(y)) = (&ec_params.x_coordinate, &ec_params.y_coordinate) {
                assert_eq!(
                    serde_json::to_string(x).unwrap(),
                    "\"aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU\""
                );
                assert_eq!(
                    serde_json::to_string(y).unwrap(),
                    "\"dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0\""
                );
            };
        } else {
            panic!();
        }

        // Now test with a DocumentState containing two keys.
        let chunk_file_json: Value =
            serde_json::from_str(TEST_CHUNK_FILE_CONTENT_MULTIPLE_KEYS).unwrap();
        let deltas = content_deltas(&chunk_file_json).unwrap();
        // Note: this is the update commitment for the *second* delta in TEST_CHUNK_FILE_CONTENT.
        let update_commitment = "EiC0EdwzQcqMYNX_3aqoZNUau4AKOL3gXQ5Pz3ATi1q_iA";
        let doc_state = extract_doc_state(deltas, update_commitment).unwrap();

        let result = doc_state.get_keys();
        assert!(result.as_ref().is_some());
        assert_eq!(result.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_get_endpoints_from_document() {
        let doc_json = serde_json::from_str(TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF).unwrap();
        let doc = Document::from(doc_json);

        let result = doc.get_endpoints();
        assert!(&result.is_some());
        let result = result.unwrap();
        assert_eq!(&result.len(), &1);
        let uri = match result.first().unwrap() {
            ServiceEndpoint::URI(x) => x,
            _ => panic!(),
        };
        assert_eq!(uri, "https://bar.example.com");

        // Now test with a DID document containing two ServiceEndpoints:
        let doc_json = serde_json::from_str(TEST_SIDETREE_DOCUMENT_SERVICE_AND_PROOF).unwrap();
        let doc = Document::from(doc_json);

        let result = doc.get_endpoints();
        assert!(&result.is_some());
        let result = result.unwrap();

        // Expect two ServiceEndpoints. The first a Map and the second a URI.
        assert_eq!(&result.len(), &2);
        assert!(matches!(&result[0], ServiceEndpoint::Map { .. }));
        assert!(matches!(&result[1], ServiceEndpoint::URI { .. }));
        let uri = match &result[1] {
            ServiceEndpoint::URI(x) => x,
            _ => panic!(),
        };
        assert_eq!(uri, "https://bar.example.com");
    }

    #[test]
    fn test_get_endpoints_from_document_state() {
        let chunk_file_json: Value = serde_json::from_str(TEST_CHUNK_FILE_CONTENT).unwrap();
        let deltas = content_deltas(&chunk_file_json).unwrap();
        let update_commitment = "EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg";
        let doc_state = extract_doc_state(deltas, update_commitment).unwrap();

        let result = doc_state.get_endpoints();
        assert!(&result.is_some());
        let result = result.unwrap();
        assert_eq!(&result.len(), &1);
        let uri = match result.first().unwrap() {
            ServiceEndpoint::URI(x) => x,
            _ => panic!(),
        };

        assert_eq!(uri, "https://identity.foundation/ion/trustchain-root");

        // Now test with DocumentState containing two service endpoints.
        let chunk_file_json: Value =
            serde_json::from_str(TEST_CHUNK_FILE_CONTENT_MULTIPLE_SERVICES).unwrap();
        let deltas = content_deltas(&chunk_file_json).unwrap();
        let update_commitment = "EiC0EdwzQcqMYNX_3aqoZNUau4AKOL3gXQ5Pz3ATi1q_iA";
        let doc_state = extract_doc_state(deltas, update_commitment).unwrap();

        let result = doc_state.get_endpoints();
        assert!(&result.is_some());
        let result = result.unwrap();
        assert_eq!(&result.len(), &2);
    }

    #[test]
    #[ignore = "Integration test requires IPFS"]
    fn test_query_ipfs() {
        let cid = "QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";

        let result = match query_ipfs(cid, None) {
            Ok(x) => x,
            Err(e) => panic!(),
        };

        // Decompress the content and deserialise to JSON.
        let mut decoder = GzDecoder::new(&result[..]);
        let mut ipfs_content_str = String::new();
        let actual: serde_json::Value = match decoder.read_to_string(&mut ipfs_content_str) {
            Ok(_) => match serde_json::from_str(&ipfs_content_str) {
                Ok(value) => value,
                Err(e) => {
                    panic!()
                }
            },
            Err(e) => {
                panic!()
            }
        };

        // The CID is the address of a core index file, so the JSON result
        // contains the key "provisionalIndexFileUri".
        assert!(actual.get(PROVISIONAL_INDEX_FILE_URI_KEY).is_some());

        // Expect an invalid CID to fail.
        let cid = "PmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97";
        assert!(query_ipfs(cid, None).is_err());
    }

    #[test]
    #[ignore = "Integration test requires MongoDB"]
    fn test_query_mongodb() {
        let did = "EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg";
        let suffix = did_suffix(did);
        // Make runtime
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let doc = block_on(query_mongodb(suffix, None)).unwrap();

            let block_height: i32 = doc.get_i32("txnTime").unwrap();
            assert_eq!(block_height, 2377445);
        });
    }
}
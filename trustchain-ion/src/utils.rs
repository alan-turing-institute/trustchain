//! Utils module.
use bitcoin::{BlockHash, Transaction};
use bitcoincore_rpc::RpcApi;
use did_ion::sidetree::{DocumentState, PublicKey, PublicKeyEntry, ServiceEndpointEntry};
use futures::TryStreamExt;
use ipfs_api::IpfsApi;
use ipfs_api_backend_actix::IpfsClient;
use ssi::did::{Document, ServiceEndpoint, VerificationMethod, VerificationMethodMap};
use ssi::jwk::JWK;
use std::convert::TryFrom;

use crate::{BITCOIN_CONNECTION_STRING, BITCOIN_RPC_PASSWORD, BITCOIN_RPC_USERNAME};

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

/// Gets the Bitcoin transaction at the given location via an RPC client.
pub fn transaction(
    block_hash: &BlockHash,
    tx_index: u32,
    rpc_client: Option<bitcoincore_rpc::Client>,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    // If necessary, construct a Bitcoin RPC client to communicate with the ION Bitcoin node.
    let client = match rpc_client {
        Some(x) => x,
        None => {
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
    };
    match client.get_block(&block_hash) {
        Ok(block) => Ok(block.txdata[tx_index as usize].to_owned()),
        Err(e) => {
            eprintln!("Error getting Bitcoin block: {}", e);
            Err(Box::new(e))
        }
    }
}

#[actix_rt::main]
pub async fn query_ipfs(
    cid: &str,
    client: Option<IpfsClient>,
) -> Result<Vec<u8>, Box<ipfs_api_backend_actix::Error>> {
    // Result<Vec<u8>, Box<dyn std::error::Error>> {
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
    use serde_json::Value;
    use ssi::jwk::Params;
    use trustchain_core::data::{
        TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS, TEST_SIDETREE_DOCUMENT_SERVICE_AND_PROOF,
        TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF,
    };

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
    #[ignore = "Integration test requires Bitcoin"]
    fn test_transaction() {
        // Get the Bitcoin transaction.
        let block_hash =
            BlockHash::from_str("000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f")
                .unwrap();
        let result = transaction(&block_hash, 3, None);

        assert!(result.is_ok());
        let tx = result.unwrap();

        let expected = "9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        assert_eq!(tx.txid().to_string(), expected);

        // Expect a different transaction ID to fail.
        let not_expected = "8dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c";
        assert_ne!(tx.txid().to_string(), not_expected);
    }
}

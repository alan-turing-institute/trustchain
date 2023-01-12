//! Utils module.
use std::convert::TryFrom;

use did_ion::sidetree::{DocumentState, PublicKey, PublicKeyEntry, ServiceEndpointEntry};
use ssi::did::{Document, ServiceEndpoint};
use ssi::jwk::JWK;

pub trait HasKeys {
    fn get_keys(&self) -> Option<Vec<JWK>>;
}

pub trait HasEndpoints {
    fn get_endpoints(&self) -> Option<Vec<ServiceEndpoint>>;
}

impl HasKeys for Document {
    fn get_keys(&self) -> Option<Vec<JWK>> {
        todo!()
    }
}

impl HasKeys for DocumentState {
    fn get_keys(&self) -> Option<Vec<JWK>> {
        let public_key_entries: Vec<PublicKeyEntry> = match &self.public_keys {
            Some(x) => x.to_vec(),
            None => {
                eprintln!("No public keys found in DocumentState.");
                return None;
            }
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
                        eprintln!("PublicKey::PublicKeyMultibase not handled.");
                        return None;
                    }
                }
            })
            .collect();
        return Some(public_keys);
    }
}

impl HasEndpoints for Document {
    fn get_endpoints(&self) -> Option<Vec<ServiceEndpoint>> {
        todo!()
    }
}

impl HasEndpoints for DocumentState {
    fn get_endpoints(&self) -> Option<Vec<ServiceEndpoint>> {
        let service_endpoint_entries: Vec<ServiceEndpointEntry> = match &self.services {
            Some(x) => x.to_vec(),
            None => {
                eprintln!("No service endpoints found in DocumentState.");
                return None;
            }
        };
        let service_endpoints: Vec<ServiceEndpoint> = service_endpoint_entries
            .iter()
            .filter_map(|entry| {
                if let ServiceEndpoint::URI(_) = entry.service_endpoint {
                    return Some(entry.service_endpoint.to_owned());
                } else {
                    eprintln!("ServiceEndpoint::Map not handled.");
                    return None;
                }
            })
            .collect();
        return Some(service_endpoints);
    }
}

#[cfg(test)]
mod tests {
    use core::panic;

    use super::*;
    use crate::verifier::extract_doc_state;
    use crate::{data::TEST_CHUNK_FILE_CONTENT, verifier::content_deltas};
    use serde_json::Value;
    use ssi::jwk::Params;
    use trustchain_core::data::TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF;

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
    }

    #[test]
    fn test_get_endpoints_from_document_state() {
        let chunk_file_json: Value = serde_json::from_str(TEST_CHUNK_FILE_CONTENT).unwrap();
        let deltas = &content_deltas(&chunk_file_json).unwrap();
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
    }
}

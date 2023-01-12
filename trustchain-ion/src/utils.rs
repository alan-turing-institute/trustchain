//! Utils module.
use std::convert::TryFrom;
use std::iter;
use std::vec::IntoIter;

use did_ion::sidetree::{DocumentState, PublicKey, PublicKeyEntry, ServiceEndpointEntry};
use ssi::did::{Document, ServiceEndpoint, VerificationMethod, VerificationMethodMap};
use ssi::jwk::JWK;
use ssi::one_or_many::OneOrMany;

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

#[cfg(test)]
mod tests {
    use core::panic;

    use super::*;
    use crate::data::{
        TEST_CHUNK_FILE_CONTENT_MULTIPLE_KEYS, TEST_CHUNK_FILE_CONTENT_MULTIPLE_SERVICES,
    };
    use crate::verifier::extract_doc_state;
    use crate::{data::TEST_CHUNK_FILE_CONTENT, verifier::content_deltas};
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
}

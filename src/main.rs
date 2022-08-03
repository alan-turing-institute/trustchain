use did_ion::{
    sidetree::{is_secp256k1, PublicKeyEntry, Sidetree, SidetreeError},
    ION,
};
use serde_json::json;

use anyhow::{anyhow, bail, ensure, Context, Error as AError, Result as AResult};
use async_trait::async_trait;
use core::fmt::Debug;
use json_patch::Patch;
use lazy_static::lazy_static;
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use ssi::did::{
    DIDCreate, DIDDeactivate, DIDDocumentOperation, DIDMethod, DIDMethodError,
    DIDMethodTransaction, DIDRecover, DIDUpdate, Document, Service, ServiceEndpoint,
    VerificationRelationship,
};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, HTTPDIDResolver, ResolutionInputMetadata, ResolutionMetadata,
    ERROR_INVALID_DID,
};
use ssi::jwk::{Algorithm, Base64urlUInt, JWK};
use ssi::jws::Header;
use ssi::one_or_many::OneOrMany;
use std::convert::TryFrom;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;
use thiserror::Error as ThisError;

struct Example;

impl Sidetree for Example {
    fn generate_key() -> Result<JWK, SidetreeError> {
        let key = JWK::generate_secp256k1().context("Generate secp256k1 key")?;
        Ok(key)
    }
    fn validate_key(key: &JWK) -> Result<(), SidetreeError> {
        if !is_secp256k1(key) {
            return Err(anyhow!("Key must be Secp256k1").into());
        }
        Ok(())
    }
    const SIGNATURE_ALGORITHM: Algorithm = Algorithm::ES256K;
    const METHOD: &'static str = "sidetree";
}

/// <https://identity.foundation/sidetree/spec/v1.0.0/#did>
static LONGFORM_DID: &str = "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ";
static SHORTFORM_DID: &str = "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg";

lazy_static::lazy_static! {

    /// <https://identity.foundation/sidetree/spec/v1.0.0/#create-2>
    static ref CREATE_OPERATION: Operation = serde_json::from_value(json!({
      "type": "create",
      "suffixData": {
        "deltaHash": "EiCfDWRnYlcD9EGA3d_5Z1AHu-iYqMbJ9nfiqdz5S8VDbg",
        "recoveryCommitment": "EiBfOZdMtU6OBw8Pk879QtZ-2J-9FbbjSZyoaA_bqD4zhA"
      },
      "delta": {
        "updateCommitment": "EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA",
        "patches": [
          {
            "action": "replace",
            "document": {
              "publicKeys": [
                {
                  "id": "publicKeyModel1Id",
                  "type": "EcdsaSecp256k1VerificationKey2019",
                  "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "secp256k1",
                    "x": "tXSKB_rubXS7sCjXqupVJEzTcW3MsjmEvq1YpXn96Zg",
                    "y": "dOicXqbjFxoGJ-K0-GJ1kHYJqic_D_OMuUwkQ7Ol6nk"
                  },
                  "purposes": [
                    "authentication",
                    "keyAgreement"
                  ]
                }
              ],
              "services": [
                {
                  "id": "service1Id",
                  "type": "service1Type",
                  "serviceEndpoint": "http://www.service1.com"
                }
              ]
            }
          }
        ]
      }
    })).unwrap();

    /// <https://identity.foundation/sidetree/spec/v1.0.0/#update-2>
    static ref UPDATE_OPERATION: Operation = serde_json::from_value(json!({
      "type": "update",
      "didSuffix": "EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
      "revealValue": "EiBkRSeixqX-PhOij6PIpuGfPld5Nif5MxcrgtGCw-t6LA",
      "delta": {
        "patches": [
          {
            "action": "add-public-keys",
            "publicKeys": [
              {
                "id": "additional-key",
                "type": "EcdsaSecp256k1VerificationKey2019",
                "publicKeyJwk": {
                  "kty": "EC",
                  "crv": "secp256k1",
                  "x": "aN75CTjy3VCgGAJDNJHbcb55hO8CobEKzgCNrUeOwAY",
                  "y": "K9FhCEpa_jG09pB6qriXrgSvKzXm6xtxBvZzIoXXWm4"
                },
                "purposes": [
                  "authentication",
                  "assertionMethod",
                  "capabilityInvocation",
                  "capabilityDelegation",
                  "keyAgreement"
                ]
              }
            ]
          }
        ],
        "updateCommitment": "EiDOrcmPtfMHuwIWN6YoihdeIPxOKDHy3D6sdMXu_7CN0w"
      },
      "signedData": "eyJhbGciOiJFUzI1NksifQ.eyJ1cGRhdGVLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4Ijoid2Z3UUNKM09ScVZkbkhYa1Q4UC1MZ19HdHhCRWhYM3R5OU5VbnduSHJtdyIsInkiOiJ1aWU4cUxfVnVBblJEZHVwaFp1eExPNnFUOWtQcDNLUkdFSVJsVHBXcmZVIn0sImRlbHRhSGFzaCI6IkVpQ3BqTjQ3ZjBNcTZ4RE5VS240aFNlZ01FcW9EU19ycFEyOVd5MVY3M1ZEYncifQ.RwZK1DG5zcr4EsrRImzStb0VX5j2ZqApXZnuoAkA3IoRdErUscNG8RuxNZ0FjlJtjMJ0a-kn-_MdtR0wwvWVgg"
    })).unwrap();

    /// <https://identity.foundation/sidetree/spec/v1.0.0/#recover-2>
    static ref RECOVER_OPERATION: Operation = serde_json::from_value(json!({
      "type": "recover",
      "didSuffix": "EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
      "revealValue": "EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ",
      "signedData": "eyJhbGciOiJFUzI1NksifQ.eyJkZWx0YUhhc2giOiJFaUNTem1ZSk0yWGpaWE00a1Q0bGpKcEVGTjVmVkM1QVNWZ3hSekVtMEF2OWp3IiwicmVjb3ZlcnlLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn0sInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ3NBN1NHTE5lZGE1SW5sb3Fub2tVY0pGejZ2S1Q0SFM1ZGNLcm1ubEpocEEifQ.lxWnrg5jaeCAhYuz1fPhidKw6Z2cScNlEc6SWcs15DtJbrHZFxl5IezGJ3cWdOSS2DlzDl4M1ZF8dDE9kRwFeQ",
      "delta": {
        "patches": [
          {
            "action": "replace",
            "document": {
              "publicKeys": [
                {
                  "id": "newKey",
                  "type": "EcdsaSecp256k1VerificationKey2019",
                  "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "secp256k1",
                    "x": "JUWp0pAMGevNLhqq_Qmd48izuLYfO5XWpjSmy5btkjc",
                    "y": "QYaSu1NHYnxR4qfk-RkXb4NQnQf1X3XQCpDYuibvlNc"
                  },
                  "purposes": [
                    "authentication",
                    "assertionMethod",
                    "capabilityInvocation",
                    "capabilityDelegation",
                    "keyAgreement"
                  ]
                }
              ],
              "services": [
                {
                  "id": "serviceId123",
                  "type": "someType",
                  "serviceEndpoint": "https://www.url.com"
                }
              ]
            }
          }
        ],
        "updateCommitment": "EiD6_csybTfxELBoMgkE9O2BTCmhScG_RW_qaZQkIkJ_aQ"
      }
    })).unwrap();

    /// <https://identity.foundation/sidetree/spec/v1.0.0/#deactivate-2>
    static ref DEACTIVATE_OPERATION: Operation = serde_json::from_value(json!({
      "type": "deactivate",
      "didSuffix": "EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
      "revealValue": "EiB-dib5oumdaDGH47TB17Qg1nHza036bTIGibQOKFUY2A",
      "signedData": "eyJhbGciOiJFUzI1NksifQ.eyJkaWRTdWZmaXgiOiJFaUR5T1FiYlpBYTNhaVJ6ZUNrVjdMT3gzU0VSampIOTNFWG9JTTNVb040b1dnIiwicmVjb3ZlcnlLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoiSk1ucF9KOW5BSGFkTGpJNmJfNVU3M1VwSEZqSEZTVHdtc1ZUUG9FTTVsMCIsInkiOiJ3c1QxLXN0UWJvSldPeEJyUnVINHQwVV9zX1lSQy14WXQyRkFEVUNHR2M4In19.ARTZrvupKdShOFNAJ4EWnsuaONKBgXUiwY5Ct10a9IXIp1uFsg0UyDnZGZtJT2v2bgtmYsQBmT6L9kKaaDcvUQ"
    })).unwrap();
}

fn main() {
    // println!("Hello, world!");

    // let ion = sidetree::CreateOperation();

    // let key = Sidetree::generate_key();

    let key = ION::generate_key().unwrap();

    println!("{:?}", key);

    let validate = ION::validate_key(&key);

    println!("{:?}", validate);

    PublicKeyEntry::try_from(key);
}

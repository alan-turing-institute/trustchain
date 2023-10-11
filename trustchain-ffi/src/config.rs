use anyhow::anyhow;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use ssi::vc::LinkedDataProofOptions;
use std::{fs, str::FromStr};
use trustchain_core::{verifier::Timestamp, TRUSTCHAIN_CONFIG};
use trustchain_ion::{Endpoint, URL};

use crate::mobile::FFIMobileError;

lazy_static! {
    /// Lazy static reference to ION configuration loaded from `trustchain_config.toml`.
    pub static ref FFI_CONFIG: FFIConfig = parse_toml(
        &fs::read_to_string(std::env::var(TRUSTCHAIN_CONFIG).unwrap().as_str())
        .expect("Error reading trustchain_config.toml"));
}

/// Parses and maps ION subfields to a new type.
pub(crate) fn parse_toml(toml_str: &str) -> FFIConfig {
    toml::from_str::<Config>(toml_str)
        .expect("Error parsing trustchain_config.toml")
        .ffi
}

/// Gets `trustchain-ffi` configuration variables.
pub fn ffi_config() -> &'static FFI_CONFIG {
    &FFI_CONFIG
}

/// Wrapper struct for parsing the `ffi` table.
#[derive(Serialize, Deserialize, Debug)]
struct Config {
    /// FFI configuration data.
    ffi: FFIConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EndpointOptions {
    pub ion_endpoint: Endpoint,
    pub trustchain_endpoint: Option<Endpoint>,
}

impl EndpointOptions {
    pub fn ion_endpoint(&self) -> &Endpoint {
        &self.ion_endpoint
    }
    pub fn trustchain_endpoint(&self) -> anyhow::Result<&Endpoint> {
        self.trustchain_endpoint
            .as_ref()
            .ok_or_else(|| anyhow!("Expected trustchain endpoint."))
    }
}

impl Default for EndpointOptions {
    fn default() -> Self {
        Self {
            ion_endpoint: Endpoint::new(URL::from("http://127.0.0.1"), 3000),
            trustchain_endpoint: Some(Endpoint::new(URL::from("http://127.0.0.1"), 8081)),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustchainOptions {
    pub signature_only: bool,
    pub root_event_time: Timestamp,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FFIConfig {
    pub endpoint_options: Option<EndpointOptions>,
    pub trustchain_options: Option<TrustchainOptions>,
    pub linked_data_proof_options: Option<LinkedDataProofOptions>,
}

impl FFIConfig {
    pub fn endpoint(&self) -> anyhow::Result<&EndpointOptions> {
        Ok(self
            .endpoint_options
            .as_ref()
            .ok_or(anyhow!("Expected endpoint options."))
            .map_err(FFIMobileError::NoConfig)?)
    }
    pub fn trustchain(&self) -> anyhow::Result<&TrustchainOptions> {
        Ok(self
            .trustchain_options
            .as_ref()
            .ok_or(anyhow!("Expected trustchain options."))
            .map_err(FFIMobileError::NoConfig)?)
    }
    pub fn linked_data_proof(&self) -> anyhow::Result<&LinkedDataProofOptions> {
        Ok(self
            .linked_data_proof_options
            .as_ref()
            .ok_or(anyhow!("Expected linked data proof options."))
            .map_err(FFIMobileError::NoConfig)?)
    }
}

impl FromStr for FFIConfig {
    type Err = FFIMobileError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map_err(FFIMobileError::FailedToDeserialize)
    }
}

#[cfg(test)]
mod tests {
    use ssi::vc::ProofPurpose;

    use super::*;

    const TEST_ENDPOINT_OPTIONS: &str = r#"
        {
            "ionEndpoint": {
                "host": "http://127.0.0.1",
                "port": 3000
            },
            "trustchainEndpoint": {
                "host": "http://127.0.0.1",
                "port": 8081
            }
        }
    "#;

    const TEST_TRUSTCHAIN_OPTIONS: &str = r#"
        {
            "signatureOnly": false,
            "rootEventTime": 1666971942
        }
    "#;

    const TEST_LINKED_DATA_PROOF_OPTIONS: &str = r#"
        {
            "proofPurpose": "assertionMethod",
            "created": "2023-07-18T08:42:50Z"
        }
    "#;

    const TEST_FFI_OPTIONS: &str = r#"
    [ffi.endpointOptions.ionEndpoint]
    host="http://127.0.0.1"
    port=3000
    [ffi.endpointOptions.trustchainEndpoint]
    host="http://127.0.0.1"
    port=8081

    [ffi.trustchainOptions]
    "signatureOnly"= false
    "rootEventTime"= 1666971942

    [ffi.linkedDataProofOptions]
    proofPurpose="assertionMethod"
    created="2023-07-18T08:42:50Z"

    "#;

    #[test]
    fn test_endpoint_options() {
        serde_json::from_str::<EndpointOptions>(TEST_ENDPOINT_OPTIONS).unwrap();
    }
    #[test]
    fn test_trustchain_options() {
        serde_json::from_str::<TrustchainOptions>(TEST_TRUSTCHAIN_OPTIONS).unwrap();
    }
    #[test]
    fn test_proof_options() {
        serde_json::from_str::<LinkedDataProofOptions>(TEST_LINKED_DATA_PROOF_OPTIONS).unwrap();
    }
    #[test]
    fn test_ffi_options() {
        let test_mobile_options: String = format!(
            r#"
            {{
                "endpointOptions": {TEST_ENDPOINT_OPTIONS},
                "trustchainOptions": {TEST_TRUSTCHAIN_OPTIONS},
                "linkedDataProofOptions": {TEST_LINKED_DATA_PROOF_OPTIONS}
            }}
        "#,
        );
        serde_json::from_str::<FFIConfig>(&test_mobile_options).unwrap();
    }
    #[test]
    fn test_ffi_options_from_toml() {
        println!("{:?}", parse_toml(TEST_FFI_OPTIONS));
        assert_eq!(
            parse_toml(TEST_FFI_OPTIONS)
                .endpoint()
                .unwrap()
                .trustchain_endpoint()
                .unwrap()
                .port,
            8081
        );
        assert_eq!(
            parse_toml(TEST_FFI_OPTIONS)
                .linked_data_proof()
                .unwrap()
                .proof_purpose
                .as_ref()
                .unwrap(),
            &ProofPurpose::AssertionMethod
        );
    }
}

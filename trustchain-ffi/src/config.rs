use anyhow::anyhow;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use ssi::vc::LinkedDataProofOptions;
use std::fs;
use trustchain_core::TRUSTCHAIN_CONFIG;
use trustchain_ion::URL;

lazy_static! {
    /// Lazy static reference to ION configuration loaded from `trustchain_config.toml`.
    pub static ref FFI_CONFIG: FFIConfig = parse_toml(
        &fs::read_to_string(std::env::var(TRUSTCHAIN_CONFIG).unwrap().as_str())
        .expect("Error reading trustchain_config.toml"));
}

/// Parses and maps ION subfields to a new type.
fn parse_toml(toml_str: &str) -> FFIConfig {
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
pub struct Endpoint {
    pub url: URL,
    pub port: u16,
}

impl Endpoint {
    pub fn new(url: URL, port: u16) -> Self {
        Self { url, port }
    }
    pub fn to_address(&self) -> URL {
        format!("{}:{}/", self.url, self.port)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EndpointOptions {
    pub resolver_endpoint: Endpoint,
    pub bundle_endpoint: Endpoint,
}

impl Default for EndpointOptions {
    fn default() -> Self {
        Self {
            resolver_endpoint: Endpoint::new(URL::from("http://127.0.0.1"), 3000),
            bundle_endpoint: Endpoint::new(URL::from("http://127.0.0.1"), 8081),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustchainOptions {
    pub signature_only: bool,
    pub root_event_time: u32,
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
        self.endpoint_options
            .as_ref()
            .ok_or_else(|| anyhow!("Expected endpoint options."))
    }
    pub fn trustchain(&self) -> anyhow::Result<&TrustchainOptions> {
        self.trustchain_options
            .as_ref()
            .ok_or_else(|| anyhow!("Expected trustchain options."))
    }
    pub fn linked_data_proof(&self) -> anyhow::Result<&LinkedDataProofOptions> {
        self.linked_data_proof_options
            .as_ref()
            .ok_or_else(|| anyhow!("Expected linked data proof options."))
    }
}

#[cfg(test)]
mod tests {
    use ssi::vc::ProofPurpose;

    use super::*;

    const TEST_ENDPOINT_OPTIONS: &str = r#"
        {
            "resolverEndpoint": {
                "url": "http://127.0.0.1",
                "port": 3000
            },
            "bundleEndpoint": {
                "url": "http://127.0.0.1",
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
    [ffi.endpointOptions.resolverEndpoint]
    url="http://127.0.0.1"
    port=3000
    [ffi.endpointOptions.bundleEndpoint]
    url="http://127.0.0.1"
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
                "endpointOptions": {},
                "trustchainOptions": {},
                "linkedDataProofOptions": {}
            }}
        "#,
            TEST_ENDPOINT_OPTIONS, TEST_TRUSTCHAIN_OPTIONS, TEST_LINKED_DATA_PROOF_OPTIONS
        );
        serde_json::from_str::<FFIConfig>(&test_mobile_options).unwrap();
    }
    #[test]
    fn test_ffi_options_from_toml() {
        println!("{:?}", parse_toml(&TEST_FFI_OPTIONS));
        assert_eq!(
            parse_toml(&TEST_FFI_OPTIONS)
                .endpoint_options
                .unwrap()
                .resolver_endpoint
                .port,
            3000
        );
        assert_eq!(
            parse_toml(&TEST_FFI_OPTIONS)
                .linked_data_proof_options
                .unwrap()
                .proof_purpose
                .unwrap(),
            ProofPurpose::AssertionMethod
        );
    }
}

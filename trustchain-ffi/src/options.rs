use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use ssi::vc::LinkedDataProofOptions;
use trustchain_ion::URL;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct MobileOptions {
    pub endpoint_options: Option<EndpointOptions>,
    pub trustchain_options: Option<TrustchainOptions>,
    pub linked_data_proof_options: Option<LinkedDataProofOptions>,
}

impl MobileOptions {
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
    fn test_mobile_options() {
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
        serde_json::from_str::<MobileOptions>(&test_mobile_options).unwrap();
    }
}

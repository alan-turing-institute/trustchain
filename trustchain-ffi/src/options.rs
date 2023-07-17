use serde::{Deserialize, Serialize};
use trustchain_ion::URL;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Endpoint {
    pub url: URL,
    pub port: u16,
}

impl Endpoint {
    pub fn new(url: URL, port: u16) -> Self {
        Self { url, port }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EndpointOptions {
    resolver_endpoint: Endpoint,
    bundle_endpoint: Endpoint,
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
struct ProofOptions {
    signature_only: bool,
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

    const TEST_PROOF_OPTIONS: &str = r#"
        {
            "signatureOnly": false
        }
    "#;

    #[test]
    fn test_endpoint_options() {
        serde_json::from_str::<EndpointOptions>(TEST_ENDPOINT_OPTIONS).unwrap();
    }
    #[test]
    fn test_proof_options() {
        serde_json::from_str::<ProofOptions>(TEST_PROOF_OPTIONS).unwrap();
    }
}

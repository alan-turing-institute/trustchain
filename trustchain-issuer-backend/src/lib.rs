pub mod handlers;
pub mod qrcode;

/// Server localhost address
pub const HOST: &str = "http://127.0.0.1:8081";

/// Android server localhost address
// const HOST: &str = "http://10.0.2.2:8081";

/// Example VP request used by demo.spruceid.com
pub const EXAMPLE_VP_REQUEST: &str = r#"{ "type": "VerifiablePresentationRequest", "query": [ { "type": "QueryByExample", "credentialQuery": { "reason": "Sign in", "example": { "@context": [ "https:\/\/www.w3.org\/2018\/credentials\/v1" ], "type": "VerifiableCredential" } } } ], "challenge": "4f34494e-43d4-4e08-8b72-d634650daf44", "domain": "demo.spruceid.com" }"#;

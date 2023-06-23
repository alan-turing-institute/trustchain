pub mod config;
pub mod errors;
pub mod issuer;
pub mod middleware;
pub mod qrcode;
pub mod resolver;
pub mod server;
pub mod state;
pub mod static_handlers;
pub mod verifier;

/// Example VP request used by demo.spruceid.com
pub const EXAMPLE_VP_REQUEST: &str = r#"{ "type": "VerifiablePresentationRequest", "query": [ { "type": "QueryByExample", "credentialQuery": { "reason": "Request credential", "example": { "@context": [ "https://www.w3.org/2018/credentials/v1" ], "type": "VerifiableCredential" } } } ], "challenge": "a877fb0a-11dd-11ee-9df7-9be7abdeee2d", "domain": "https://alan-turing-institute.github.io/trustchain" }"#;

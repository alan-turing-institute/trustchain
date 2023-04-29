use did_ion::{sidetree::SidetreeClient, ION};
use trustchain_core::resolver::DIDMethodWrapper;
use trustchain_ion::verifier::IONVerifier;

pub mod config;
pub mod data;
pub mod errors;
pub mod handlers;
pub mod issuer;
pub mod qrcode;
pub mod resolver;
pub mod state;
pub mod vc;
pub mod verifier;

/// Issuer DID
pub const ISSUER_DID: &str = "did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA";

/// Example VP request used by demo.spruceid.com
pub const EXAMPLE_VP_REQUEST: &str = r#"{ "type": "VerifiablePresentationRequest", "query": [ { "type": "QueryByExample", "credentialQuery": { "reason": "Sign in", "example": { "@context": [ "https:\/\/www.w3.org\/2018\/credentials\/v1" ], "type": "VerifiableCredential" } } } ], "challenge": "4f34494e-43d4-4e08-8b72-d634650daf44", "domain": "demo.spruceid.com" }"#;

/// Verifier type for trustchain-http
pub(crate) type HTTPVerifier = IONVerifier<DIDMethodWrapper<SidetreeClient<ION>>>;
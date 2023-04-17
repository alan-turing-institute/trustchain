//! Trustchain library.
pub mod attestor;
pub mod chain;
pub mod config;
pub mod controller;
pub mod data;
pub mod display;
pub mod graph;
pub mod issuer;
pub mod key_manager;
pub mod resolver;
pub mod subject;
pub mod utils;
pub mod verifier;

// WASM
use wasm_bindgen::prelude::*;

/// Environment variable name for Trustchain data.
pub const TRUSTCHAIN_DATA: &str = "TRUSTCHAIN_DATA";

/// Environment variable name for Trustchain config file.
pub const TRUSTCHAIN_CONFIG: &str = "TRUSTCHAIN_CONFIG";

/// The value used in a DID document to identify the default Trustchain service endpoint.
pub const TRUSTCHAIN_SERVICE_ID_VALUE: &str = "TrustchainID";

/// The value used for identifying a service containing a Trustchain controller proof within a DID document.
pub const TRUSTCHAIN_PROOF_SERVICE_ID_VALUE: &str = "trustchain-controller-proof";

/// The value of the type for the service containing a Trustchain controller proof within a DID document.
pub const TRUSTCHAIN_PROOF_SERVICE_TYPE_VALUE: &str = "TrustchainProofService";

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, trustchain!");
}

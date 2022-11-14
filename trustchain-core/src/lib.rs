//! Trustchain library.
pub mod attestor;
pub mod chain;
pub mod controller;
pub mod data;
pub mod graph;
pub mod key_manager;
pub mod resolver;
pub mod utils;
pub mod verifier;

/// A DID Subject.
pub trait Subject {
    fn did(&self) -> &str;
    fn did_suffix(&self) -> &str;
}

/// Returns the suffix of a short-form DID.
pub fn get_did_suffix(did: &str) -> &str {
    did.split(':').last().unwrap()
}

// WASM
use wasm_bindgen::prelude::*;

/// Rust variable for Trustchain data environment variable
pub const TRUSTCHAIN_DATA: &str = "TRUSTCHAIN_DATA";

/// Root event time hardcoded into binary
// pub const ROOT_EVENT_TIME: u32 = 2377445;
// pub const ROOT_EVENT_TIME_2378493: u32 = 2378493;
pub const ROOT_EVENT_TIME: u32 = 1666265405;
pub const ROOT_EVENT_TIME_2378493: u32 = 1666971942;

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

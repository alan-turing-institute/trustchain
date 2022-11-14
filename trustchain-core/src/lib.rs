//! Trustchain library.
pub mod attestor;
pub mod controller;
pub mod data;
pub mod key_manager;
pub mod resolver;
pub mod utils;

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

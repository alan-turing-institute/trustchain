//! Trustchain library.
pub mod controller;
mod data;
mod key_manager;
pub mod resolver;
pub mod subject;
mod utils;

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

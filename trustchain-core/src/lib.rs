//! Trustchain library.
pub mod attestor;
pub mod chain;
pub mod controller;
pub mod data;
pub mod key_manager;
pub mod graph;
pub mod resolver;
pub mod verifier;
mod utils;

// use std::io::Read;
use std::path::Path;
use std::sync::Once;
use tempfile;

/// A DID Subject.
pub trait Subject {
    fn did(&self) -> &str;
}

// Set-up tempdir and use as env var for TRUSTCHAIN_DATA
// https://stackoverflow.com/questions/58006033/how-to-run-setup-code-before-any-tests-run-in-rust
static INIT: Once = Once::new();
pub fn init() {
    INIT.call_once(|| {
        // initialization code here
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var(TRUSTCHAIN_DATA, Path::new(tempdir.as_ref().as_os_str()));
    });
}

// WASM
use wasm_bindgen::prelude::*;

/// Rust variable for Trustchain data environment variable
pub const TRUSTCHAIN_DATA: &str = "TRUSTCHAIN_DATA";

/// Root event time hardcoded into binary
pub const ROOT_EVENT_TIME: u64 = 42;

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

//! Trustchain library.
mod data;
pub mod resolver;
mod utils;
use did_ion::{sidetree::SidetreeClient, ION};
use resolver::{Resolver, DIDMethodWrapper};

// Type aliases 
pub type IONResolver = Resolver::<DIDMethodWrapper<SidetreeClient::<ION>>>;

pub fn test_resolver(endpoint: &str) -> IONResolver {
    IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(endpoint))))
}

// WASM
use wasm_bindgen::prelude::*;

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


//! Trustchain HTTP server functionality.
pub mod config;
#[cfg(test)]
pub(crate) mod data;
pub mod errors;
pub mod ion;
pub mod issuer;
pub mod middleware;
pub mod qrcode;
pub mod resolver;
pub mod root;
pub mod server;
pub mod state;
pub mod static_handlers;
pub mod store;
pub mod verifier;

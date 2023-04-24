#![allow(
    non_camel_case_types,
    unused,
    clippy::redundant_closure,
    clippy::useless_conversion,
    clippy::unit_arg,
    clippy::double_parens,
    non_snake_case,
    clippy::too_many_arguments
)]
// AUTO GENERATED FILE, DO NOT EDIT.
// Generated by `flutter_rust_bridge`@ 1.64.0.

use crate::gui::*;
use core::panic::UnwindSafe;
use flutter_rust_bridge::*;
use std::ffi::c_void;
use std::sync::Arc;

// Section: imports

// Section: wire functions

fn wire_create_impl(
    port_: MessagePort,
    doc_state: impl Wire2Api<Option<String>> + UnwindSafe,
    verbose: impl Wire2Api<bool> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "create",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_doc_state = doc_state.wire2api();
            let api_verbose = verbose.wire2api();
            move |task_callback| create(api_doc_state, api_verbose)
        },
    )
}
fn wire_attest_impl(
    port_: MessagePort,
    did: impl Wire2Api<String> + UnwindSafe,
    controlled_did: impl Wire2Api<String> + UnwindSafe,
    verbose: impl Wire2Api<bool> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "attest",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_did = did.wire2api();
            let api_controlled_did = controlled_did.wire2api();
            let api_verbose = verbose.wire2api();
            move |task_callback| attest(api_did, api_controlled_did, api_verbose)
        },
    )
}
fn wire_resolve_impl(port_: MessagePort, did: impl Wire2Api<String> + UnwindSafe) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "resolve",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_did = did.wire2api();
            move |task_callback| resolve(api_did)
        },
    )
}
fn wire_verify_impl(
    port_: MessagePort,
    did: impl Wire2Api<String> + UnwindSafe,
    verbose: impl Wire2Api<bool> + UnwindSafe,
) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "verify",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_did = did.wire2api();
            let api_verbose = verbose.wire2api();
            move |task_callback| verify(api_did, api_verbose)
        },
    )
}
// Section: wrapper structs

// Section: static checks

// Section: allocate functions

// Section: related functions

// Section: impl Wire2Api

pub trait Wire2Api<T> {
    fn wire2api(self) -> T;
}

impl<T, S> Wire2Api<Option<T>> for *mut S
where
    *mut S: Wire2Api<T>,
{
    fn wire2api(self) -> Option<T> {
        (!self.is_null()).then(|| self.wire2api())
    }
}

impl Wire2Api<bool> for bool {
    fn wire2api(self) -> bool {
        self
    }
}

impl Wire2Api<u8> for u8 {
    fn wire2api(self) -> u8 {
        self
    }
}

// Section: impl IntoDart

// Section: executor

support::lazy_static! {
    pub static ref FLUTTER_RUST_BRIDGE_HANDLER: support::DefaultHandler = Default::default();
}

#[cfg(not(target_family = "wasm"))]
#[path = "bridge_generated.io.rs"]
mod io;
#[cfg(not(target_family = "wasm"))]
pub use io::*;

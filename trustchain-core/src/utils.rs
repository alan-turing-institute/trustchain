//! Utils module.
use serde::Serialize;

// use std::io::Read;
use crate::TRUSTCHAIN_DATA;
use std::path::Path;
use std::sync::Once;
use tempfile;

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

/// [`JSON_CANONICALIZATION_SCHEME`](https://identity.foundation/sidetree/spec/v1.0.0/#json-canonicalization-scheme)
#[allow(dead_code)]
pub fn canonicalize<T: Serialize + ?Sized>(value: &T) -> Result<String, serde_json::Error> {
    serde_jcs::to_string(value)
}

#[allow(dead_code)]
pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

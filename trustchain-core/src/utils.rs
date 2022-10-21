//! Utils module.
use serde::Serialize;
use sha2::{Digest, Sha256};
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

/// From did-ion: https://docs.rs/did-ion/0.1.0/src/did_ion/sidetree.rs.html
const MULTIHASH_SHA2_256_PREFIX: &[u8] = &[0x12];
const MULTIHASH_SHA2_256_SIZE: &[u8] = &[0x20];
/// From did-ion: https://docs.rs/did-ion/0.1.0/src/did_ion/sidetree.rs.html#107-209
/// Combination of [hash_protocol] and [hash_algorithm]
///
/// Returns multihash prefix and hash.
///
/// Default implementation: SHA-256 (`sha2-256`)
///
/// [hash_protocol] and [hash_algorithm] must correspond, and their default implementations
/// call this function ([hash_protocol_algorithm]). Implementers are therefore encouraged to
/// overwrite this function ([hash_protocol_algorithm]) rather than those ([hash_protocol] and
/// [hash_algorithm]).
///
/// [hash_protocol]: Self::hash_protocol
/// [hash_algorithm]: Self::hash_algorithm
/// [hash_protocol_algorithm]: Self::hash_protocol_algorithm
fn hash_protocol_algorithm(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize().to_vec();
    (
        [MULTIHASH_SHA2_256_PREFIX, MULTIHASH_SHA2_256_SIZE].concat(),
        hash,
    )
}

/// [`DATA_ENCODING_SCHEME`](https://identity.foundation/sidetree/spec/v1.0.0/#data-encoding-scheme)
fn data_encoding_scheme(data: &[u8]) -> String {
    base64::encode_config(data, base64::URL_SAFE_NO_PAD)
}

/// [`JSON_CANONICALIZATION_SCHEME`](https://identity.foundation/sidetree/spec/v1.0.0/#json-canonicalization-scheme)
pub fn canonicalize<T: Serialize + ?Sized>(value: &T) -> Result<String, serde_json::Error> {
    serde_jcs::to_string(value)
}

/// [`HASH_PROTOCOL`](https://identity.foundation/sidetree/spec/v1.0.0/#hash-protocol)
///
/// This should be implemented using [hash_algorithm].
///
/// Default implementation calls [hash_protocol_algorithm] and returns the concatenation of the
/// prefix and hash.
///
/// This function must correspond with [hash_algorithm]. To ensure that correspondence,
/// implementers may want to override [hash_protocol_algorithm] instead of this function.
///
/// [hash_algorithm]: Self::hash_algorithm
/// [hash_protocol_algorithm]: Self::hash_protocol_algorithm
fn hash_protocol(data: &[u8]) -> Vec<u8> {
    let (prefix, hash) = hash_protocol_algorithm(data);
    [prefix, hash].concat()
}

/// Hash and encode data
///
/// [Sidetree §6.1 Hashing Process](https://identity.foundation/sidetree/spec/#hashing-process)
pub fn hash(data: &str) -> String {
    let hash = hash_protocol(data.as_bytes());
    data_encoding_scheme(&hash)
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

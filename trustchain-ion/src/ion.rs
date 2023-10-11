use anyhow::{anyhow, Context, Result};
use did_ion::sidetree::{is_secp256k1, Sidetree, SidetreeClient, SidetreeError};
use ssi::jwk::{Algorithm, JWK};

pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// Type for ION test network given [did-ion-0.2.0](https://github.com/spruceid/ssi/blob/79ad4a679933d1b4f6af93193408cd0a24e68f74/did-ion/src/lib.rs)
/// now uses main network.
#[derive(Clone)]
pub struct IONTest;

/// did:ion:test Method
pub type DIDIONTest = SidetreeClient<IONTest>;

impl Sidetree for IONTest {
    fn generate_key() -> Result<JWK, SidetreeError> {
        let key = JWK::generate_secp256k1().context("Generate secp256k1 key")?;
        Ok(key)
    }

    fn validate_key(key: &JWK) -> Result<(), SidetreeError> {
        if !is_secp256k1(key) {
            return Err(anyhow!("Key must be Secp256k1").into());
        }
        Ok(())
    }

    const SIGNATURE_ALGORITHM: Algorithm = Algorithm::ES256K;
    const METHOD: &'static str = "ion";
    // Specify "test" network.
    const NETWORK: Option<&'static str> = Some("test");
}

use crate::ion::IONTest as ION;
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use did_ion::sidetree::Sidetree;
use ed25519_dalek_bip32::derivation_path::DerivationPath as Ed25519DerivationPath;
use ed25519_dalek_bip32::derivation_path::DerivationPathParseError;
use ed25519_dalek_bip32::ExtendedSigningKey;
use ssi::jwk::{Base64urlUInt, ECParams, OctetParams, Params, JWK};
use std::str::FromStr;
use thiserror::Error;

use crate::{
    RECOVERY_KEY_DERIVATION_PATH, SIGNING_KEY_DERIVATION_PATH, UPDATE_KEY_DERIVATION_PATH,
};

/// An error relating to key generation from a mnemonic.
#[derive(Error, Debug)]
pub enum MnemonicError {
    /// Invalid BIP32 derivation path.
    #[error("Invalid BIP32 derivation path: {0}")]
    InvalidDerivationPath(bitcoin::bip32::Error),
    /// Invalid BIP32 derivation path.
    #[error("Wrapped ed25519_dalek_bip32 error: {0}")]
    Ed25519DalekBip32Error(ed25519_dalek_bip32::Error),
    /// Invalid ed25519 BIP32 derivation path.
    #[error("Invalid ed25519 BIP32 derivation path: {0}")]
    InvalidDerivationPathEd25519(DerivationPathParseError),
    /// Failed to deserialize private scalar.
    #[error("Failed to deserialize private scalar bytes: {0}")]
    FailedToDeserializeScalar(k256::elliptic_curve::Error),
    /// Failed to convert elliptic curve parameters.
    #[error("Failed to convert elliptic curve parameters.")]
    FailedToConvertECParams,
}

impl From<bitcoin::bip32::Error> for MnemonicError {
    fn from(err: bitcoin::bip32::Error) -> Self {
        MnemonicError::InvalidDerivationPath(err)
    }
}

impl From<k256::elliptic_curve::Error> for MnemonicError {
    fn from(err: k256::elliptic_curve::Error) -> Self {
        MnemonicError::FailedToDeserializeScalar(err)
    }
}

impl From<DerivationPathParseError> for MnemonicError {
    fn from(err: DerivationPathParseError) -> Self {
        MnemonicError::InvalidDerivationPathEd25519(err)
    }
}

impl From<ed25519_dalek_bip32::Error> for MnemonicError {
    fn from(err: ed25519_dalek_bip32::Error) -> Self {
        MnemonicError::Ed25519DalekBip32Error(err)
    }
}

/// Generates a signing key on the ed25519 elliptic curve from a mnemonic.
fn generate_ed25519_signing_key(
    mnemonic: &Mnemonic,
    index: Option<u32>,
) -> Result<JWK, MnemonicError> {
    let seed = mnemonic.to_seed("");
    let extended_secret_key = ExtendedSigningKey::from_seed(&seed)?;
    let derivation_path = ed25519_derivation_path(SIGNING_KEY_DERIVATION_PATH, index)?;
    let private_key = extended_secret_key.derive(&derivation_path)?;
    let public_key = private_key.verifying_key().to_bytes();
    // Make a JWK from bytes: https://docs.rs/ssi/0.4.0/src/ssi/jwk.rs.html#251-265
    Ok(JWK::from(Params::OKP(OctetParams {
        curve: "Ed25519".to_string(),
        public_key: Base64urlUInt(public_key.to_vec()),
        private_key: Some(Base64urlUInt(private_key.signing_key.to_bytes().to_vec())),
    })))
}

/// Generates a key on the secp256k1 elliptic curve from a mnemonic.
fn generate_secp256k1_key(
    mnemonic: &Mnemonic,
    path: &str,
    index: Option<u32>,
) -> Result<JWK, MnemonicError> {
    let seed = mnemonic.to_seed("");
    let m = Xpriv::new_master(bitcoin::Network::Bitcoin, &seed)?;
    let secp = Secp256k1::new();
    let derivation_path = secp256k1_derivation_path(path, index)?;
    let xpriv = m.derive_priv(&secp, &derivation_path)?;
    let private_key = xpriv.to_priv();

    // Now convert the bitcoin::bip32::Xpriv into a JWK.
    let k256_secret_key = k256::SecretKey::from_slice(&private_key.to_bytes())?;
    let k256_public_key = k256_secret_key.public_key();
    let mut ec_params = match ECParams::try_from(&k256_public_key) {
        Ok(params) => params,
        Err(_) => return Err(MnemonicError::FailedToConvertECParams),
    };
    ec_params.ecc_private_key = Some(Base64urlUInt(private_key.to_bytes().to_vec()));
    Ok(JWK::from(Params::EC(ec_params)))
}

/// Generates derivation path.
fn derivation_path(path: &str, index: Option<u32>) -> Result<String, MnemonicError> {
    let index = index.unwrap_or(0);
    // Handle case index > 2^31 - 1.
    if index > 2u32.pow(31) - 1 {
        return Err(MnemonicError::InvalidDerivationPath(
            bitcoin::bip32::Error::InvalidChildNumber(index),
        ));
    }
    Ok(format!("{}/{index}'", path.replace('h', "'")))
}

/// Generates derivation path.
fn secp256k1_derivation_path(
    path: &str,
    index: Option<u32>,
) -> Result<DerivationPath, MnemonicError> {
    Ok(DerivationPath::from_str(&derivation_path(path, index)?)?)
}

/// Generates an ed25519_dalek_bip32 derivation path.
fn ed25519_derivation_path(
    path: &str,
    index: Option<u32>,
) -> Result<Ed25519DerivationPath, MnemonicError> {
    Ok(Ed25519DerivationPath::from_str(&derivation_path(
        path, index,
    )?)?)
}

/// Generates a DID update key on the secp256k1 elliptic curve from a mnemonic.
fn generate_secp256k1_update_key(
    mnemonic: &Mnemonic,
    index: Option<u32>,
) -> Result<JWK, MnemonicError> {
    generate_secp256k1_key(mnemonic, UPDATE_KEY_DERIVATION_PATH, index)
}

/// Generates a DID recovery key on the secp256k1 elliptic curve from a mnemonic.
fn generate_secp256k1_recovery_key(
    mnemonic: &Mnemonic,
    index: Option<u32>,
) -> Result<JWK, MnemonicError> {
    generate_secp256k1_key(mnemonic, RECOVERY_KEY_DERIVATION_PATH, index)
}
/// A type for the set of JWK required for an ION create operation.
pub struct IONKeys {
    pub signing_key: JWK,
    pub update_key: JWK,
    pub recovery_key: JWK,
}

/// Generates a set of signing, update and recovery keys from a mnemonic and child index.
pub fn generate_keys(mnemonic: &Mnemonic, index: Option<u32>) -> Result<IONKeys, MnemonicError> {
    let signing_key = generate_ed25519_signing_key(mnemonic, index)?;
    let update_key = generate_secp256k1_update_key(mnemonic, index)?;
    let recovery_key = generate_secp256k1_recovery_key(mnemonic, index)?;
    ION::validate_key(&update_key).unwrap();
    ION::validate_key(&recovery_key).unwrap();
    Ok(IONKeys {
        signing_key,
        update_key,
        recovery_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::bip32::{DerivationPath, Xpriv};
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::Address;
    use ssi::jwk::ECParams;
    use ssi::jwk::JWK;
    use std::str::FromStr;

    fn get_test_mnemonic() -> Mnemonic {
        Mnemonic::parse(
            "state draft moral repeat knife trend animal pretty delay collect fall adjust",
        )
        .unwrap()
    }

    #[test]
    fn test_secp256k1_derivation_path() {
        let path = "m/1h";
        let expected = DerivationPath::from_str("m/1'/0'").unwrap();
        assert_eq!(expected, secp256k1_derivation_path(path, None).unwrap());

        let path = "m/1h";
        let index: u32 = 0;
        let expected = DerivationPath::from_str("m/1h/0h").unwrap();
        assert_eq!(
            expected,
            secp256k1_derivation_path(path, Some(index)).unwrap()
        );

        let path = "m/2h";
        let index: u32 = 2147483647;
        let expected = DerivationPath::from_str("m/2h/2147483647h").unwrap();
        assert_eq!(
            expected,
            secp256k1_derivation_path(path, Some(index)).unwrap()
        );

        let path = "m/2h";
        let index: u32 = 2147483647;
        let expected = DerivationPath::from_str("m/1h/2147483647h").unwrap();
        assert_ne!(
            expected,
            secp256k1_derivation_path(path, Some(index)).unwrap()
        );

        let path = "m/1'";
        let index: u32 = 0;
        let expected = DerivationPath::from_str("m/1h/0h").unwrap();
        assert_eq!(
            expected,
            secp256k1_derivation_path(path, Some(index)).unwrap()
        );

        let path = "m/0'";
        let index: u32 = 0;
        let expected = DerivationPath::from_str("m/1h/0h").unwrap();
        assert_ne!(
            expected,
            secp256k1_derivation_path(path, Some(index)).unwrap()
        );

        // Note: the fmt::Display implementation for DerivationPath changed in
        // rust-bitcoin version 0.32.0-rc1 to omit the leading "m" character.
        let derivation_path = DerivationPath::from_str("m/1h/0h").unwrap();
        let expected = "1'/0'";
        assert_eq!(expected, derivation_path.to_string());

        let derivation_path = DerivationPath::from_str("m/1'/0'").unwrap();
        let expected = "1'/0'";
        assert_eq!(expected, derivation_path.to_string());

        // Test the round-trip.
        let derivation_path = DerivationPath::from_str("1h/0'").unwrap();
        let expected = "1'/0'";
        assert_eq!(expected, derivation_path.to_string());
        let actual = DerivationPath::from_str(&derivation_path.to_string()).unwrap();
        assert_eq!(derivation_path, actual);
    }

    #[test]
    fn test_ed25519_derivation_path() {
        let path = "m/1h";
        let expected = Ed25519DerivationPath::from_str("m/1'/0'").unwrap();
        assert_eq!(expected, ed25519_derivation_path(path, None).unwrap());

        let path = "m/1h";
        let index: u32 = 0;
        let expected = Ed25519DerivationPath::from_str("m/1'/0'").unwrap();
        assert_eq!(
            expected,
            ed25519_derivation_path(path, Some(index)).unwrap()
        );

        let path = "m/2h";
        let index: u32 = 2147483647;
        let expected = Ed25519DerivationPath::from_str("m/2'/2147483647'").unwrap();
        assert_eq!(
            expected,
            ed25519_derivation_path(path, Some(index)).unwrap()
        );

        let path = "m/2h";
        let index: u32 = 2147483647;
        let expected = Ed25519DerivationPath::from_str("m/1'/2147483647'").unwrap();
        assert_ne!(
            expected,
            ed25519_derivation_path(path, Some(index)).unwrap()
        );

        let path = "m/1'";
        let index: u32 = 0;
        let expected = Ed25519DerivationPath::from_str("m/1'/0'").unwrap();
        assert_eq!(
            expected,
            ed25519_derivation_path(path, Some(index)).unwrap()
        );

        let path = "m/0'";
        let index: u32 = 0;
        let expected = Ed25519DerivationPath::from_str("m/1'/0'").unwrap();
        assert_ne!(
            expected,
            ed25519_derivation_path(path, Some(index)).unwrap()
        );

        let derivation_path = Ed25519DerivationPath::from_str("m/1'/0'").unwrap();
        let expected = "m/1'/0'";
        assert_eq!(expected, derivation_path.to_string());

        let derivation_path = Ed25519DerivationPath::from_str("m/1'/0'").unwrap();
        let expected = "m/1'/0'";
        assert_eq!(expected, derivation_path.to_string());
    }

    #[test]
    fn test_generate_ed25519_signing_key() -> Result<(), Box<dyn std::error::Error>> {
        let mnemonic = get_test_mnemonic();
        let result = generate_ed25519_signing_key(&mnemonic, Some(0))?;
        let expected = r#"
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "jil0ZZqW_cldlxq2a0Ezw59IgEIULSj9E3NOD6YQCHo",
            "d": "wHwSUdy4a00qTxAhnuOHeWpai4ERjdZGslaou-Lig5g"
        }"#;
        assert_eq!(result, serde_json::from_str::<JWK>(expected)?);
        Ok(())
    }

    #[test]
    fn test_generate_secp256k1_update_key() -> Result<(), Box<dyn std::error::Error>> {
        let mnemonic = get_test_mnemonic();
        let result = generate_secp256k1_update_key(&mnemonic, None)?;
        let expected = r#"
        {
            "kty": "EC",
            "crv": "secp256k1",
            "x": "pALnEGubf31SDdZQsbjSXqqDRivTSQXteERlggq3vYI",
            "y": "sWjJLyW3dDbqXnYNNPnyeuQGBkBmBH2K_XV3LVCDCDQ",
            "d": "LxQYTvQ2naxEl-XsTWxekhMroP4LtkTW5mdOXuoyS0E"
        }"#;
        assert_eq!(result, serde_json::from_str::<JWK>(expected)?);
        Ok(())
    }

    #[test]
    fn test_generate_secp256k1_recovery_key() -> Result<(), Box<dyn std::error::Error>> {
        let mnemonic = get_test_mnemonic();
        let result = generate_secp256k1_recovery_key(&mnemonic, Some(2))?;
        let expected = r#"
        {
            "kty": "EC",
            "crv": "secp256k1",
            "x": "3SKbKH_8zBKfWi-5_xgsiVlOmnWIOCHcP27VpndhDp8",
            "y": "aTNRpMlDjVglXVb4G8PqqAd0Akf95aCyVqPzN636fA8",
            "d": "0fJzxc3TJ5T1xx8ZnY90uLJT99QN8Y4pn57i2n0SZH8"
        }"#;
        assert_eq!(result, serde_json::from_str::<JWK>(expected)?);
        Ok(())
    }

    #[test]
    fn test_mnemonic_secp256k1() -> Result<(), Box<dyn std::error::Error>> {
        let mnemonic = get_test_mnemonic();
        let seed = mnemonic.to_seed("");
        let path = "m/0'/0'";

        // Using rust bitcoin crate:
        let m = Xpriv::new_master(bitcoin::Network::Bitcoin, &seed)?;
        let secp = Secp256k1::new();
        let derivation_path = DerivationPath::from_str(path)?;
        let xpriv = m.derive_priv(&secp, &derivation_path)?;

        let private_key = xpriv.to_priv();
        let public_key: bitcoin::key::PublicKey = private_key.public_key(&secp);
        let address = Address::p2pkh(&public_key, bitcoin::Network::Bitcoin);

        // This matches the address generated at https://learnmeabitcoin.com/technical/derivation-paths
        let expected_address = "1KtK31vM2RaK9vKkV8e16yBfBGEKF8tNb4";
        assert_eq!(address.to_string(), expected_address);

        // Now convert the bitcoin::bip32::Xpriv into a JWK.
        let k256_secret_key = k256::SecretKey::from_slice(&private_key.to_bytes())?;
        let k256_public_key = k256_secret_key.public_key();

        let mut ec_params = ECParams::try_from(&k256_public_key)?;
        ec_params.ecc_private_key = Some(Base64urlUInt(private_key.to_bytes().to_vec()));
        let jwk = JWK::from(Params::EC(ec_params));
        let expected_jwk = r#"{
            "kty": "EC",
            "crv": "secp256k1",
            "x": "czAsjE4ifEsU-QO-nkz4WNWxlEWBqBIqg2Wn1hxJ7bg",
            "y": "lnBcn6tVS9_O2PHR5Lr1Qim0gDryEHyErTaRx4to8-k",
            "d": "8dJUi9adMsRYkVDVJR49kr38cSKLeMYahdNYsZalTns"
          }"#;
        assert_eq!(jwk, serde_json::from_str::<JWK>(expected_jwk)?);

        Ok(())
    }

    #[test]
    fn test_ed25519_signing_key_signature() {
        let key = generate_ed25519_signing_key(&get_test_mnemonic(), None).unwrap();
        let algorithm = key.get_algorithm().unwrap();
        let payload = "payload";
        let signed = ssi::jws::encode_sign(algorithm, payload, &key).unwrap();
        let verified = ssi::jws::decode_verify(&signed, &key.to_public());
        assert!(verified.is_ok());
        assert_eq!(payload, String::from_utf8(verified.unwrap().1).unwrap());
    }
}

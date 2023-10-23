use bip39::Mnemonic;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use did_ion::sidetree::Sidetree;
use did_ion::ION;
use ed25519_dalek_bip32::derivation_path::DerivationPath as Ed25519DerivationPath;
use ed25519_dalek_bip32::derivation_path::DerivationPathParseError;
use ed25519_dalek_bip32::ExtendedSigningKey;
use ssi::jwk::{Base64urlUInt, ECParams, OctetParams, Params, JWK};
use std::str::FromStr;
use thiserror::Error;

use crate::{
    RECOVERY_KEY_DERIVATION_PATH, SIGNING_KEY_DERIVATION_PATH, UPDATE_KEY_DERIVATION_PATH,
};

/// An error relating to key generation from a mnemonic seed phrase.
#[derive(Error, Debug)]
pub enum MnemonicError {
    /// Invalid BIP32 derivation path.
    #[error("Invalid BIP32 derivation path: {0}")]
    InvalidDerivationPath(bitcoin::util::bip32::Error),
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

impl From<bitcoin::util::bip32::Error> for MnemonicError {
    fn from(err: bitcoin::util::bip32::Error) -> Self {
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

// See: https://github.com/alepop/dart-ed25519-hd-key/blob/f785c73b1248037df58f8d582e6f71c480e49d39/lib/src/hd_key.dart#L45-L56
fn with_zero_byte(public_key: [u8; 32]) -> [u8; 33] {
    let mut new_public_key = [0u8; 33];
    new_public_key[1..33].copy_from_slice(public_key.as_slice());
    new_public_key
}

/// Generates a signing key on the ed25519 elliptic curve from a mnemonic seed phrase.
fn generate_ed25519_signing_key(
    mnemonic: &Mnemonic,
    index: Option<u32>,
) -> Result<JWK, MnemonicError> {
    let seed = mnemonic.to_seed("");
    let extended_secret_key = ExtendedSigningKey::from_seed(&seed)?;
    let derivation_path = ed25519_derivation_path(SIGNING_KEY_DERIVATION_PATH, index)?;
    let private_key = extended_secret_key.derive(&derivation_path)?;
    let public_key = private_key.verifying_key().to_bytes();
    // For some reason zero byte is required despite the false arg here:
    // https://github.com/alan-turing-institute/trustchain-mobile/blob/1b735645fd140b94bf1360bd5546643214c423b6/lib/app/shared/key_generation.dart#L12
    let public_key = with_zero_byte(public_key);
    // Make a JWK from bytes: https://docs.rs/ssi/0.4.0/src/ssi/jwk.rs.html#251-265
    Ok(JWK::from(Params::OKP(OctetParams {
        curve: "Ed25519".to_string(),
        public_key: Base64urlUInt(public_key.to_vec()),
        private_key: Some(Base64urlUInt(private_key.signing_key.to_bytes().to_vec())),
    })))
}

/// Generates a key on the secp256k1 elliptic curve from a mnemonic seed phrase.
fn generate_secp256k1_key(
    mnemonic: &Mnemonic,
    path: &str,
    index: Option<u32>,
) -> Result<JWK, MnemonicError> {
    let seed = mnemonic.to_seed("");
    let m = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &seed)?;
    let secp = Secp256k1::new();
    let derivation_path = secp256k1_derivation_path(path, index)?;
    let xpriv = m.derive_priv(&secp, &derivation_path)?;
    let private_key = xpriv.to_priv();
    // let public_key: bitcoin::util::key::PublicKey = private_key.public_key(&secp);

    // Now convert the bitcoin::util::bip32::ExtendedPrivKey into a JWK.

    let k256_secret_key = k256::SecretKey::from_slice(&private_key.to_bytes())?;
    let k256_public_key = k256_secret_key.public_key();
    let mut ec_params = match ECParams::try_from(&k256_public_key) {
        Ok(params) => params,
        Err(_) => return Err(MnemonicError::FailedToConvertECParams),
    };
    ec_params.ecc_private_key = Some(Base64urlUInt(private_key.to_bytes().to_vec()));
    Ok(JWK::from(Params::EC(ec_params)))
}

fn derivation_path(path: &str, index: Option<u32>) -> Result<String, bitcoin::util::bip32::Error> {
    let index = index.unwrap_or(0);
    // Handle case index > 2^31 - 1.
    if index > 2u32.pow(31) - 1 {
        return Err(bitcoin::util::bip32::Error::InvalidChildNumber(index));
    }
    Ok(format!("{}/{index}'", path.replace('h', "'")))
}

fn secp256k1_derivation_path(
    path: &str,
    index: Option<u32>,
) -> Result<DerivationPath, bitcoin::util::bip32::Error> {
    DerivationPath::from_str(&derivation_path(path, index)?)
}

fn ed25519_derivation_path(
    path: &str,
    index: Option<u32>,
) -> Result<Ed25519DerivationPath, MnemonicError> {
    Ok(Ed25519DerivationPath::from_str(&derivation_path(
        path, index,
    )?)?)
}

/// Generates a DID update key on the secp256k1 elliptic curve from a mnemonic seed phrase.
fn generate_secp256k1_update_key(
    mnemonic: &Mnemonic,
    index: Option<u32>,
) -> Result<JWK, MnemonicError> {
    generate_secp256k1_key(mnemonic, UPDATE_KEY_DERIVATION_PATH, index)
}

/// Generates a DID recovery key on the secp256k1 elliptic curve from a mnemonic seed phrase.
fn generate_secp256k1_recovery_key(
    mnemonic: &Mnemonic,
    index: Option<u32>,
) -> Result<JWK, MnemonicError> {
    generate_secp256k1_key(mnemonic, RECOVERY_KEY_DERIVATION_PATH, index)
}
pub struct IONKeys {
    pub signing_key: JWK,
    pub update_key: JWK,
    pub recovery_key: JWK,
}

/// Generates a set of signing, update and recovery keys from a mnemonic phrase and child index.
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

    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
    use bitcoin::Address;
    use ssi::jwk::ECParams;
    use ssi::jwk::JWK;
    use std::str::FromStr;

    fn get_test_mnemonic() -> Mnemonic {
        let phrase = "state draft moral repeat knife trend animal pretty delay collect fall adjust";
        Mnemonic::parse(phrase).unwrap()
    }

    #[test]
    fn test_secp256k1_derivation_path() {
        let path = "m/1h";
        let expected = DerivationPath::from_str("m/1'/0'");
        assert_eq!(expected, secp256k1_derivation_path(path, None));

        let path = "m/1h";
        let index: u32 = 0;
        let expected = DerivationPath::from_str("m/1h/0h");
        assert_eq!(expected, secp256k1_derivation_path(path, Some(index)));

        let path = "m/2h";
        let index: u32 = 2147483647;
        let expected = DerivationPath::from_str("m/2h/2147483647h");
        assert_eq!(expected, secp256k1_derivation_path(path, Some(index)));

        let path = "m/2h";
        let index: u32 = 2147483647;
        let expected = DerivationPath::from_str("m/1h/2147483647h");
        assert_ne!(expected, secp256k1_derivation_path(path, Some(index)));

        let path = "m/1'";
        let index: u32 = 0;
        let expected = DerivationPath::from_str("m/1h/0h");
        assert_eq!(expected, secp256k1_derivation_path(path, Some(index)));

        let path = "m/0'";
        let index: u32 = 0;
        let expected = DerivationPath::from_str("m/1h/0h");
        assert_ne!(expected, secp256k1_derivation_path(path, Some(index)));

        let derivation_path = DerivationPath::from_str("m/1h/0h").unwrap();
        let expected = "m/1'/0'";
        assert_eq!(expected, derivation_path.to_string());

        let derivation_path = DerivationPath::from_str("m/1'/0'").unwrap();
        let expected = "m/1'/0'";
        assert_eq!(expected, derivation_path.to_string());
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
        let result = generate_ed25519_signing_key(&mnemonic, Some(22))?;
        let expected = r#"
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "AFPB4OPrkVLsxAxppQ2QrqcX1vK_dLP1pJfNuwUA8WGA",
            "d": "065j_kBmgaYT5JCMbIebOSRkkneHJ83JKkjVrogSamI"
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
        let phrase = "state draft moral repeat knife trend animal pretty delay collect fall adjust";
        let mnemonic = Mnemonic::parse(phrase).unwrap();
        let seed = mnemonic.to_seed("");
        let path = "m/0'/0'";

        // Using rust bitcoin crate:
        let m = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &seed)?;
        let secp = Secp256k1::new();
        let derivation_path = DerivationPath::from_str(path)?;
        let xpriv = m.derive_priv(&secp, &derivation_path)?;

        let private_key = xpriv.to_priv();
        let public_key: bitcoin::util::key::PublicKey = private_key.public_key(&secp);
        let address = Address::p2pkh(&public_key, bitcoin::Network::Bitcoin);

        // This matches the address generated at https://learnmeabitcoin.com/technical/derivation-paths
        let expected_address = "1KtK31vM2RaK9vKkV8e16yBfBGEKF8tNb4";
        assert_eq!(address.to_string(), expected_address);

        // Now convert the bitcoin::util::bip32::ExtendedPrivKey into a JWK.
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

    // #[test]
    // fn test_mnemonic_ed22519() {
    //     // Test case:
    //     // https://github.com/alan-turing-institute/trustchain-mobile/blob/1b735645fd140b94bf1360bd5546643214c423b6/test/app/key_tests.dart
    //     let phrase = "state draft moral repeat knife trend animal pretty delay collect fall adjust";
    //     let mnemonic = Mnemonic::parse(phrase).unwrap();
    //     let seed = mnemonic.to_seed("");
    //     let path = "m/0'/0'";
    //     let (private_key, _chain_code) = ed25519_hd_key::derive_from_path(path, &seed);
    //     let public_key = ed25519_hd_key::get_public_key(&private_key);
    //     // For some reason zero byte is required despite the false arg here:
    //     // https://github.com/alan-turing-institute/trustchain-mobile/blob/1b735645fd140b94bf1360bd5546643214c423b6/lib/app/shared/key_generation.dart#L12
    //     let public_key = with_zero_byte(public_key);

    //     // Compare to test case JWK:
    //     let expected = r#"{"kty":"OKP","crv":"Ed25519","d":"wHwSUdy4a00qTxAhnuOHeWpai4ERjdZGslaou-Lig5g=","x":"AI4pdGWalv3JXZcatmtBM8OfSIBCFC0o_RNzTg-mEAh6"}"#;
    //     let expected_jwk: JWK = serde_json::from_str(expected).unwrap();

    //     // Make a JWK from bytes: https://docs.rs/ssi/0.4.0/src/ssi/jwk.rs.html#251-265
    //     let jwk = JWK::from(Params::OKP(OctetParams {
    //         curve: "Ed25519".to_string(),
    //         public_key: Base64urlUInt(public_key.to_vec()),
    //         private_key: Some(Base64urlUInt(private_key.to_vec())),
    //     }));
    //     // println!("{}", serde_json::to_string_pretty(&jwk).unwrap());
    //     // println!("{}", serde_json::to_string_pretty(&expected_jwk).unwrap());
    //     assert_eq!(jwk, expected_jwk);
    // }
}

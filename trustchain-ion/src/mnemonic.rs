use bip39::Mnemonic;
use ed25519_hd_key;
use ssi::jwk::{Base64urlUInt, OctetParams, Params, JWK};

// See: https://github.com/alepop/dart-ed25519-hd-key/blob/f785c73b1248037df58f8d582e6f71c480e49d39/lib/src/hd_key.dart#L45-L56
fn with_zero_byte(public_key: [u8; 32]) -> [u8; 33] {
    let mut new_public_key = [0u8; 33];
    new_public_key[1..33].copy_from_slice(public_key.as_slice());
    new_public_key
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
        let k256_secret_key = k256::SecretKey::from_bytes(private_key.to_bytes())?;
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
    fn test_mnemonic_ed22519() {
        // Test case:
        // https://github.com/alan-turing-institute/trustchain-mobile/blob/1b735645fd140b94bf1360bd5546643214c423b6/test/app/key_tests.dart
        let phrase = "state draft moral repeat knife trend animal pretty delay collect fall adjust";
        let mnemonic = Mnemonic::parse(phrase).unwrap();
        let seed = mnemonic.to_seed("");
        let path = "m/0'/0'";
        let (private_key, _chain_code) = ed25519_hd_key::derive_from_path(path, &seed);
        let public_key = ed25519_hd_key::get_public_key(&private_key);
        // For some reason zero byte is required despite the false arg here:
        // https://github.com/alan-turing-institute/trustchain-mobile/blob/1b735645fd140b94bf1360bd5546643214c423b6/lib/app/shared/key_generation.dart#L12
        let public_key = with_zero_byte(public_key);

        // Compare to test case JWK:
        let expected = r#"{"kty":"OKP","crv":"Ed25519","d":"wHwSUdy4a00qTxAhnuOHeWpai4ERjdZGslaou-Lig5g=","x":"AI4pdGWalv3JXZcatmtBM8OfSIBCFC0o_RNzTg-mEAh6"}"#;
        let expected_jwk: JWK = serde_json::from_str(expected).unwrap();

        // Make a JWK from bytes: https://docs.rs/ssi/0.4.0/src/ssi/jwk.rs.html#251-265
        let jwk = JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(public_key.to_vec()),
            private_key: Some(Base64urlUInt(private_key.to_vec())),
        }));
        println!("{}", serde_json::to_string_pretty(&jwk).unwrap());
        println!("{}", serde_json::to_string_pretty(&expected_jwk).unwrap());
        assert_eq!(jwk, expected_jwk);
    }
}

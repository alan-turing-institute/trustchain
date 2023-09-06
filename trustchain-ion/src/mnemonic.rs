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
    use bip32::{DerivationPath, Prefix, PrivateKey, XPrv};
    use bitcoin::Address;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    // use lazy_static::__Deref;
    use ssi::jwk::ECParams;

    #[test]
    fn test_mnemonic_secp256k1() -> Result<(), Box<dyn std::error::Error>> {
        let phrase = "state draft moral repeat knife trend animal pretty delay collect fall adjust";
        let mnemonic = Mnemonic::parse(phrase).unwrap();
        let seed = mnemonic.to_seed("");
        // Update key is 1/0
        let path = "m/0'/0'";

        // Derive the root `XPrv` from the `seed` value
        // let root_xprv = XPrv::new(seed)?;
        let path: DerivationPath = path.parse()?;
        let root_xprv = XPrv::derive_from_path(seed, &path)?;
        let private_key = root_xprv.private_key();
        let mut private_key_32_bytes: [u8; 32] = [0; 32];
        private_key_32_bytes.copy_from_slice(&private_key.to_bytes());

        let secret_key = k256::SecretKey::from_bytes(private_key_32_bytes)?;
        // Copied from SSI try_from conversion but leads to identical bytes to removing.
        // let sk_bytes: &[u8] = secret_key.as_scalar_bytes().as_ref();
        // assert_eq!(sk_bytes, private_key_32_bytes);

        let public_key = secret_key.public_key();
        let mut ec_params = ECParams::try_from(&public_key)?;
        ec_params.ecc_private_key = Some(Base64urlUInt(private_key_32_bytes.to_vec()));
        let jwk = JWK::from(Params::EC(ec_params));
        println!("{}", serde_json::to_string_pretty(&jwk).unwrap());

        let public_key_bytes = public_key.to_encoded_point(false).as_bytes();
        // let hash = sha2::digest(public_key_bytes);
        // let bitcoin_pk = bitcoin::PublicKey::new_uncompressed();

        // use secp256k1::{PublicKey, Secp256k1, SecretKey};
        // let secp = Secp256k1::new();
        // // let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        // let secret_key =
        //     SecretKey::from_slice(&private_key_32_bytes).expect("32 bytes, within curve order");
        // let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        // Address::p2pkh(&public_key_bytes, bitcoin::Network::Bitcoin);

        // Test cases: https://learnmeabitcoin.com/technical/derivation-paths
        // With above phrase
        // m/0h/0h: 1KtK31vM2RaK9vKkV8e16yBfBGEKF8tNb4

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

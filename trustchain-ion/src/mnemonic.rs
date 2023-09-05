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
    use bip32::{Prefix, XPrv};
    use ssi::jwk::ECParams;

    use super::*;

    #[test]
    fn test_mnemonic_secp256k1() -> Result<(), Box<dyn std::error::Error>> {
        let phrase = "state draft moral repeat knife trend animal pretty delay collect fall adjust";
        let mnemonic = Mnemonic::parse(phrase).unwrap();
        let seed = mnemonic.to_seed("");
        // Update key is 1/0
        let path = "m/1'/0'";
        // Derive the root `XPrv` from the `seed` value
        let root_xprv = XPrv::new(&seed)?;
        let private_key = root_xprv.private_key().to_bytes();
        let public_key = root_xprv.public_key().to_bytes();
        println!("{:?}", private_key);
        println!("{:?}", public_key);
        println!("{:?}", root_xprv.to_string(Prefix::XPRV));
        // TODO: how to convert into EC params?
        // let jwk = JWK::from(Params::EC(ECParams {
        //     curve: "secp256k1".to_string(),
        //     public_key: Base64urlUInt(public_key.to_vec()),
        //     private_key: Some(Base64urlUInt(private_key.to_vec())),
        // }));
        // println!("{}", serde_json::to_string_pretty(&jwk).unwrap());
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

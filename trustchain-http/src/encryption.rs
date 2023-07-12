use josekit::{
    jwe::ECDH_ES,
    jwe::{alg::ecdh_es::EcdhEsJweAlgorithm::EcdhEs, Dir, JweHeader},
    jwk::Jwk,
    jwt::{self, JwtPayload},
    JoseError,
};
use serde_json::Value;

const temp_private_key: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JokHTNHd1lIw2EXUTV1RJL3wvWMgoIRHPaWxTHcyH9U","y":"z737jJY7kxW_lpE1eZur-9n9_HUEGFyBGsTdChzI4Kg","d":"CfdUwQ-CcBQkWpIDPjhSJAq2SCg6hAGdcvLmCj0aA-c"}"#;
const temp_pub_key: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JokHTNHd1lIw2EXUTV1RJL3wvWMgoIRHPaWxTHcyH9U","y":"z737jJY7kxW_lpE1eZur-9n9_HUEGFyBGsTdChzI4Kg"}"#;

// const temp_private_key: &str = r#"{"crv":"secp256k1","x":"JokHTNHd1lIw2EXUTV1RJL3wvWMgoIRHPaWxTHcyH9U","y":"z737jJY7kxW_lpE1eZur-9n9_HUEGFyBGsTdChzI4Kg","d":"CfdUwQ-CcBQkWpIDPjhSJAq2SCg6hAGdcvLmCj0aA-c"}"#;
// const temp_pub_key: &str = r#"{"crv":"secp256k1","x":"JokHTNHd1lIw2EXUTV1RJL3wvWMgoIRHPaWxTHcyH9U","y":"z737jJY7kxW_lpE1eZur-9n9_HUEGFyBGsTdChzI4Kg"}"#;

fn example() -> Result<(), JoseError> {
    let mut header = JweHeader::new();
    header.set_token_type("JWT");
    // header.set_content_encryption("A128CBC-HS256");
    header.set_content_encryption("A256GCM");

    let mut payload = JwtPayload::new();
    payload.set_subject("subject");
    payload.set_claim("Name of claim", Some(Value::String("my_claim".to_string())))?;

    // let key = b"0123456789ABCDEF0123456789ABCDEF";

    // Encrypting JWT
    let temp_pub_key_jwk: Jwk = serde_json::from_str(&temp_pub_key).unwrap();
    // let temp_pub_key_jwk = Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::Secp256k1).unwrap();
    let encrypter_from_jwk = ECDH_ES.encrypter_from_jwk(&temp_pub_key_jwk)?;
    // let encrypter = Dir.encrypter_from_bytes(key)?;
    let jwt = jwt::encode_with_encrypter(&payload, &header, &encrypter_from_jwk)?;
    println!("JWT: {}", jwt);

    // Decrypting JWT
    let temp_private_key_jwk: Jwk = serde_json::from_str(&temp_private_key).unwrap();
    let decrypter_from_jwk = ECDH_ES.decrypter_from_jwk(&temp_private_key_jwk)?;
    // let decrypter = Dir.decrypter_from_bytes(key)?;
    let (payload, header) = jwt::decode_with_decrypter(&jwt, &decrypter_from_jwk)?;
    println!("Header: {}", header);
    println!("Payload: {}", payload);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_example() {
        example().unwrap();
    }

    #[test]
    fn test_ec_key() {
        let key = Jwk::generate_ec_key(josekit::jwk::alg::ec::EcCurve::Secp256k1).unwrap();
        println!("{}", serde_json::to_string_pretty(&key).unwrap());
    }
}

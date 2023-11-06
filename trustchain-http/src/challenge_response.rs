#[cfg(test)]
mod tests {

    // use ssi::vc::URI;
    use tempfile::tempdir;

    use std::str;

    use crate::data::{
        TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS, TEST_SIGNING_KEY_1, TEST_SIGNING_KEY_2,
        TEST_TEMP_KEY, TEST_UPDATE_KEY, TEST_UPSTREAM_KEY,
    };

    use super::*;

    #[test]
    fn test_identity_challenge_response() {
        // ==========| UE - generate challenge | ==============
        let upstream_s_key: Jwk = serde_json::from_str(TEST_UPSTREAM_KEY).unwrap();
        let update_key: Jwk = serde_json::from_str(TEST_UPDATE_KEY).unwrap();
        let temp_s_key: Jwk = serde_json::from_str(TEST_TEMP_KEY).unwrap();
        let temp_p_key = temp_s_key.to_public_key().unwrap();

        // generate challenge
        let request_initiation = IdentityCRInitiation {
            temp_p_key: Some(temp_p_key.clone()),
            requester_details: Some(RequesterDetails {
                requester_org: String::from("My Org"),
                operator_name: String::from("John Doe"),
            }),
        };

        let mut upstream_identity_challenge_response = CRIdentityChallenge {
            update_p_key: Some(update_key.clone()),
            identity_nonce: Some(Nonce::new()),
            identity_challenge_signature: None,
            identity_response_signature: None,
        };

        // sign and encrypt
        let upstream_entity = Entity {};

        let payload = JwtPayload::try_from(&upstream_identity_challenge_response).unwrap();
        let signed_encrypted_challenge = upstream_entity
            .sign_and_encrypt_claim(
                &payload,
                &upstream_s_key,
                &request_initiation.temp_p_key.unwrap(),
            )
            .unwrap();

        upstream_identity_challenge_response.identity_challenge_signature =
            Some(signed_encrypted_challenge);

        // ==========| DE - generate response | ==============

        // decrypt and verify
        let downstream_entity = Entity {};
        let upstream_p_key = upstream_s_key.to_public_key().unwrap();
        let signed_encrypted_challenge = upstream_identity_challenge_response
            .identity_challenge_signature
            .clone()
            .unwrap();

        let decrypted_verified_challenge = downstream_entity
            .decrypt_and_verify(signed_encrypted_challenge, &temp_s_key, &upstream_p_key)
            .unwrap();
        let downstream_identity_challenge =
            CRIdentityChallenge::try_from(&decrypted_verified_challenge).unwrap();

        // generate response
        let mut payload = JwtPayload::new();
        payload
            .set_claim(
                "identity_nonce",
                Some(Value::from(
                    downstream_identity_challenge
                        .identity_nonce
                        .as_ref()
                        .unwrap()
                        .to_string(),
                )),
            )
            .unwrap();
        let signed_encrypted_response = downstream_entity
            .sign_and_encrypt_claim(&payload, &temp_s_key, &upstream_p_key)
            .unwrap();

        // ==========| UE - verify response | ==============

        // decrypt and verify signature
        let decrypted_verified_response = upstream_entity
            .decrypt_and_verify(signed_encrypted_response, &upstream_s_key, &temp_p_key)
            .unwrap();

        let nonce = decrypted_verified_response
            .claim("identity_nonce")
            .unwrap()
            .as_str()
            .unwrap();

        let expected_nonce = upstream_identity_challenge_response
            .identity_nonce
            .unwrap()
            .to_string();
        assert_eq!(nonce, expected_nonce);
    }

    #[test]
    fn test_content_challenge_response() {
        // ==========| UE - generate challenge | ==============
        let upstream_entity = Entity {};
        let upstream_s_key: Jwk = serde_json::from_str(TEST_UPSTREAM_KEY).unwrap();
        let temp_s_key: Jwk = serde_json::from_str(TEST_TEMP_KEY).unwrap();
        let temp_p_key = temp_s_key.to_public_key().unwrap();
        // get signing keys for DE from did document
        let doc: Document = serde_json::from_str(TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS).unwrap();
        let test_keys_map = extract_key_ids_and_jwk(&doc).unwrap();

        // generate map with unencrypted nonces so UE can store them for later verification
        let nonces: HashMap<String, Nonce> =
            test_keys_map
                .iter()
                .fold(HashMap::new(), |mut acc, (key_id, _)| {
                    acc.insert(String::from(key_id), Nonce::new());
                    acc
                });

        for (_, val) in &nonces {
            println!("{:?}", val);
        }

        // turn nonces into challenges by encrypting them with the public keys of UE
        let challenges = nonces
            .iter()
            .fold(HashMap::new(), |mut acc, (key_id, nonce)| {
                acc.insert(
                    String::from(key_id),
                    upstream_entity
                        .encrypt(
                            &JwtPayload::try_from(nonce).unwrap(),
                            &test_keys_map.get(key_id).unwrap(),
                        )
                        .unwrap(),
                );
                acc
            });

        // sign (UE private key) and encrypt (DE temp public key) entire challenge
        let value: serde_json::Value = serde_json::to_value(challenges).unwrap();
        let mut payload = JwtPayload::new();
        payload.set_claim("challenges", Some(value)).unwrap();
        let signed_encrypted_challenges = upstream_entity
            .sign_and_encrypt_claim(&payload, &upstream_s_key, &temp_p_key)
            .unwrap();

        // ==========| DE - generate response | ==============
        let downstream_entity = Entity {};
        let upstream_p_key = upstream_s_key.to_public_key().unwrap();

        // decrypt and verify signature on challenges
        let decrypted_verified_challenges = downstream_entity
            .decrypt_and_verify(signed_encrypted_challenges, &temp_s_key, &upstream_p_key)
            .unwrap();

        // decrypt nonces from challenges
        let challenges_map: HashMap<String, String> = serde_json::from_value(
            decrypted_verified_challenges
                .claim("challenges")
                .unwrap()
                .clone(),
        )
        .unwrap();

        let downstream_s_key_1: Jwk = serde_json::from_str(TEST_SIGNING_KEY_1).unwrap();
        let downstream_s_key_2: Jwk = serde_json::from_str(TEST_SIGNING_KEY_2).unwrap();
        let downstream_key_id_1 = josekit_to_ssi_jwk(&downstream_s_key_1)
            .unwrap()
            .thumbprint()
            .unwrap();
        let downstream_key_id_2 = josekit_to_ssi_jwk(&downstream_s_key_2)
            .unwrap()
            .thumbprint()
            .unwrap();

        let mut downstream_s_keys_map: HashMap<String, Jwk> = HashMap::new();
        downstream_s_keys_map.insert(downstream_key_id_1, downstream_s_key_1);
        downstream_s_keys_map.insert(downstream_key_id_2, downstream_s_key_2);

        let decrypted_nonces: HashMap<String, String> =
            challenges_map
                .iter()
                .fold(HashMap::new(), |mut acc, (key_id, nonce)| {
                    acc.insert(
                        String::from(key_id),
                        downstream_entity
                            .decrypt(
                                &Some(Value::from(nonce.clone())).unwrap(),
                                downstream_s_keys_map.get(key_id).unwrap(),
                            )
                            .unwrap()
                            .claim("nonce")
                            .unwrap()
                            .as_str()
                            .unwrap()
                            .to_string(),
                    );

                    acc
                });
        // sign and encrypt response
        let value: serde_json::Value = serde_json::to_value(decrypted_nonces).unwrap();
        let mut payload = JwtPayload::new();
        payload.set_claim("nonces", Some(value)).unwrap();
        let signed_encrypted_response = downstream_entity
            .sign_and_encrypt_claim(&payload, &temp_s_key, &upstream_p_key)
            .unwrap();

        // ==========| UE - verify response | ==============
        let decrypted_verified_response = upstream_entity
            .decrypt_and_verify(signed_encrypted_response, &upstream_s_key, &temp_p_key)
            .unwrap();
        println!(
            "Decrypted and verified response: {:?}",
            decrypted_verified_response
        );
        let verified_response_map: HashMap<String, Nonce> =
            serde_json::from_value(decrypted_verified_response.claim("nonces").unwrap().clone())
                .unwrap();
        println!("Verified response map: {:?}", verified_response_map);
        assert_eq!(verified_response_map, nonces);
    }
}

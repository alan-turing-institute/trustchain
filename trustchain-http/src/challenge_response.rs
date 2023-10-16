use josekit::jwe::{JweHeader, ECDH_ES};
use josekit::jwk::Jwk;
use josekit::jws::{JwsHeader, ES256K};
use josekit::jwt::{self, JwtPayload};
use josekit::JoseError;
use rand::thread_rng;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use serde_json::{to_string_pretty as to_json, Value};
use serde_with::skip_serializing_none;
use ssi::did::{Document, VerificationMethod};
use ssi::jwk::JWK;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{BufWriter, Write};

use is_empty::IsEmpty;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TrustchainCRError {
    /// Serde JSON error.
    #[error("Wrapped serialization error: {0}")]
    Serde(serde_json::Error),
    /// Wrapped jose error.
    #[error("Wrapped jose error: {0}")]
    Jose(JoseError),
    /// Missing JWK from verification method.
    #[error("Missing JWK from verification method of a DID document.")]
    MissingJWK,
    /// Key not found in hashmap.
    #[error("Key id not found.")]
    KeyNotFound,
    /// Claim not found in JWTPayload.
    #[error("Claim not found in JWTPayload.")]
    ClaimNotFound,
    /// Nonce type invalid.
    #[error("Invalid nonce type.")]
    InvalidNonceType,
    /// Failed to open file.
    #[error("Failed to open file.")]
    FailedToOpen,
    /// Failed to save to file.
    #[error("Failed to save to file.")]
    FailedToSave,
    /// Failed to set permissions on file.
    #[error("Failed to set permissions on file.")]
    FailedToSetPermissions,
    /// Failed deserialize from file.
    #[error("Failed to deserialize.")]
    FailedToDeserialize,
    /// Failed to check CR status.
    #[error("Failed to determine CR status.")]
    FailedStatusCheck,
    /// Path for CR does not exist.
    #[error("Path does not exist. No challenge-response record for this temporary key id.")]
    CRPathNotFound,
}

#[derive(Debug, PartialEq)]
enum CurrentCRState {
    NotStarted,
    IdentityCRInitiated,
    IdentityChallengeComplete,
    IdentityResponseComplete,
    ContentCRInitiated,
    ContentChallengeComplete,
    ContentResponseComplete,
}

fn get_status_message(current_state: &CurrentCRState) -> String {
    match current_state {
        CurrentCRState::NotStarted => {
            return String::from("No records found for this challenge-response identifier. \nThe challenge-response process has not been initiated yet.");
        }
        CurrentCRState::IdentityCRInitiated => {
            return String::from("Identity challenge-response initiated. Await response.");
        }
        CurrentCRState::IdentityChallengeComplete => {
            return String::from("Identity challenge has been presented. Await response.");
        }
        CurrentCRState::IdentityResponseComplete => {
            return String::from("Identity challenge-response complete.");
        }
        CurrentCRState::ContentCRInitiated => {
            return String::from("Content challenge-response initiated. Await response.");
        }
        CurrentCRState::ContentChallengeComplete => {
            return String::from("Content challenge has been presented. Await response.");
        }
        CurrentCRState::ContentResponseComplete => {
            return String::from("Challenge-response complete.");
        }
    }
}

impl From<JoseError> for TrustchainCRError {
    fn from(err: JoseError) -> Self {
        Self::Jose(err)
    }
}

/// Interface for serializing and deserializing each field of structs to/from files.
trait ElementwiseSerializeDeserialize
where
    Self: Serialize,
{
    fn elementwise_serialize(&self, path: &PathBuf) -> Result<(), TrustchainCRError> {
        let serialized =
            serde_json::to_value(&self).map_err(|_| TrustchainCRError::FailedToSave)?;
        if let Value::Object(fields) = serialized {
            for (field_name, field_value) in fields {
                if !field_value.is_null() {
                    let json_filename = format!("{}.json", field_name);
                    let file_path = path.join(json_filename);

                    self.save_to_file(&file_path, &to_json(&field_value).unwrap())?;
                }
            }
        }
        Ok(())
    }

    fn elementwise_deserialize(self, path: &PathBuf) -> Result<Option<Self>, TrustchainCRError>
    where
        Self: Sized;

    fn save_to_file(&self, path: &PathBuf, data: &str) -> Result<(), TrustchainCRError> {
        if path.exists() {
            println!("File already exists: {:?}", path);
            return Ok(());
        }

        // Open the new file if it doesn't exist yet
        let new_file = OpenOptions::new().create(true).write(true).open(path);

        // Write key to file
        match new_file {
            Ok(file) => {
                let mut writer = BufWriter::new(file);
                match writer.write_all(data.as_bytes()) {
                    Ok(_) => {
                        // Set file permissions to read-only (user, group, and others)
                        let mut permissions = fs::metadata(path)
                            .map_err(|_| TrustchainCRError::FailedToSetPermissions)?
                            .permissions();
                        permissions.set_readonly(true);
                        fs::set_permissions(path, permissions)
                            .map_err(|_| TrustchainCRError::FailedToSetPermissions)?;
                        Ok(())
                    }
                    Err(_) => Err(TrustchainCRError::FailedToSave),
                }
            }

            Err(_) => Err(TrustchainCRError::FailedToSave),
        }
    }
}

/// Interface for signing and then encrypting data.
pub trait SignEncrypt {
    fn sign(&self, payload: &JwtPayload, secret_key: &Jwk) -> Result<String, TrustchainCRError> {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        let signer = ES256K.signer_from_jwk(&secret_key)?;
        let signed_jwt = jwt::encode_with_signer(payload, &header, &signer)?;
        Ok(signed_jwt)
    }
    /// `JWTPayload` is a wrapped [`Map`](https://docs.rs/serde_json/1.0.79/serde_json/struct.Map.html)
    /// of claims.
    fn encrypt(&self, payload: &JwtPayload, public_key: &Jwk) -> Result<String, TrustchainCRError> {
        let mut header = JweHeader::new();
        header.set_token_type("JWT");
        header.set_content_encryption("A128CBC-HS256");
        header.set_content_encryption("A256GCM");

        let encrypter = ECDH_ES.encrypter_from_jwk(&public_key)?;
        let encrypted_jwt = jwt::encode_with_encrypter(payload, &header, &encrypter)?;
        Ok(encrypted_jwt)
    }
    /// Combined sign and encryption
    fn sign_and_encrypt_claim(
        &self,
        payload: &JwtPayload,
        secret_key: &Jwk,
        public_key: &Jwk,
    ) -> Result<String, TrustchainCRError> {
        let signed_encoded_payload = self.sign(payload, secret_key)?;
        let mut claims = JwtPayload::new();
        claims.set_claim("claim", Some(Value::from(signed_encoded_payload)))?;
        self.encrypt(&claims, &public_key)
    }
}
/// Interface for decrypting and then verifying data.
trait DecryptVerify {
    fn decrypt(&self, value: &Value, secret_key: &Jwk) -> Result<JwtPayload, TrustchainCRError> {
        let decrypter = ECDH_ES.decrypter_from_jwk(&secret_key)?;
        let (payload, _) = jwt::decode_with_decrypter(value.as_str().unwrap(), &decrypter)?;
        Ok(payload)
    }
    fn decrypt_and_verify(
        &self,
        input: String,
        secret_key: &Jwk,
        public_key: &Jwk,
    ) -> Result<JwtPayload, TrustchainCRError> {
        let decrypter = ECDH_ES.decrypter_from_jwk(secret_key)?;
        let (payload, _) = jwt::decode_with_decrypter(input, &decrypter)?;

        let verifier = ES256K.verifier_from_jwk(public_key)?;
        let (payload, _) = jwt::decode_with_verifier(
            &payload.claim("claim").unwrap().as_str().unwrap(),
            &verifier,
        )?;
        Ok(payload)
    }
}

struct Entity {}

impl SignEncrypt for Entity {}

impl DecryptVerify for Entity {}

// pub struct Nonce<const N: usize>([u8; N]);
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Nonce(String);

impl Nonce {
    pub fn new() -> Self {
        Self(
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect(),
        )
    }
}

impl AsRef<str> for Nonce {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl ToString for Nonce {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl From<String> for Nonce {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, IsEmpty)]
struct CRState {
    identity_cr_initiation: Option<IdentityCRInitiation>,
    identity_challenge_response: Option<CRIdentityChallenge>,
    content_cr_initiation: Option<ContentCRInitiation>,
    content_challenge_response: Option<CRContentChallenge>,
}

impl CRState {
    fn new() -> Self {
        Self {
            identity_cr_initiation: None,
            identity_challenge_response: None,
            content_cr_initiation: None,
            content_challenge_response: None,
        }
    }

    fn is_complete(&self) -> bool {
        if self.identity_cr_initiation.is_some()
            && self.identity_challenge_response.is_some()
            && self.content_cr_initiation.is_some()
            && self.content_challenge_response.is_some()
        {
            return true;
        }
        return false;
    }

    fn check_cr_status(&self) -> Result<CurrentCRState, TrustchainCRError> {
        println!("Checking current challenge-response status...");
        println!(" ");
        let mut current_state = CurrentCRState::NotStarted;
        if self.is_empty() {
            println!("{}", get_status_message(&current_state));
            return Ok(current_state);
        }

        // CR complete
        if self.is_complete() {
            current_state = CurrentCRState::ContentResponseComplete;
            println!("{}", get_status_message(&current_state));
            return Ok(current_state);
        }

        // Identity CR initation
        if self.identity_cr_initiation.is_none()
            || !self.identity_cr_initiation.as_ref().unwrap().is_complete()
        {
            println!("{}", get_status_message(&current_state));
            return Ok(current_state);
        }
        current_state = CurrentCRState::IdentityCRInitiated;
        println!("{}", get_status_message(&current_state));

        // Identity challenge
        if self.identity_challenge_response.is_none()
            || !self
                .identity_challenge_response
                .as_ref()
                .unwrap()
                .challenge_complete()
        {
            return Ok(current_state);
        }
        current_state = CurrentCRState::IdentityChallengeComplete;
        println!("{}", get_status_message(&current_state));

        // Identity response
        if !self
            .identity_challenge_response
            .as_ref()
            .unwrap()
            .response_complete()
        {
            return Ok(current_state);
        }
        current_state = CurrentCRState::IdentityResponseComplete;

        // Content CR initation
        if self.content_cr_initiation.is_none()
            || !self.content_cr_initiation.as_ref().unwrap().is_complete()
        {
            return Ok(current_state);
        }
        current_state = CurrentCRState::ContentCRInitiated;

        // Content challenge
        if self.content_challenge_response.is_none()
            || !self
                .content_challenge_response
                .as_ref()
                .unwrap()
                .challenge_complete()
        {
            return Ok(current_state);
        }
        current_state = CurrentCRState::ContentChallengeComplete;

        // Content response
        if !self
            .content_challenge_response
            .as_ref()
            .unwrap()
            .response_complete()
        {
            return Ok(current_state);
        }

        return Ok(current_state);
    }
}

impl ElementwiseSerializeDeserialize for CRState {
    fn elementwise_serialize(&self, path: &PathBuf) -> Result<(), TrustchainCRError> {
        if let Some(identity_initiation) = &self.identity_cr_initiation {
            identity_initiation.elementwise_serialize(path)?;
        }
        if let Some(identity_challenge_response) = &self.identity_challenge_response {
            identity_challenge_response.elementwise_serialize(path)?;
        }
        if let Some(content_cr_initiation) = &self.content_cr_initiation {
            content_cr_initiation.elementwise_serialize(path)?;
        }
        if let Some(content_challenge_response) = &self.content_challenge_response {
            content_challenge_response.elementwise_serialize(path)?;
        }
        Ok(())
    }
    fn elementwise_deserialize(
        mut self,
        path: &PathBuf,
    ) -> Result<Option<CRState>, TrustchainCRError> {
        self.identity_cr_initiation = IdentityCRInitiation::new().elementwise_deserialize(path)?;
        self.identity_challenge_response =
            CRIdentityChallenge::new().elementwise_deserialize(path)?;
        self.content_cr_initiation = ContentCRInitiation::new().elementwise_deserialize(path)?;
        self.content_challenge_response =
            CRContentChallenge::new().elementwise_deserialize(path)?;
        Ok(Some(self))
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
struct RequesterDetails {
    requester_org: String,
    operator_name: String,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, IsEmpty)]
struct IdentityCRInitiation {
    temp_p_key: Option<Jwk>,
    requester_details: Option<RequesterDetails>,
}

impl IdentityCRInitiation {
    fn new() -> Self {
        Self {
            temp_p_key: None,
            requester_details: None,
        }
    }

    fn is_complete(&self) -> bool {
        return self.temp_p_key.is_some() && self.requester_details.is_some();
    }
}

impl ElementwiseSerializeDeserialize for IdentityCRInitiation {
    // fn elementwise_serialize(&self, path: &PathBuf) -> Result<(), TrustchainCRError> {
    //     // let file_path = path.join("temp_p_key.json");
    //     // let data: &str = &to_json(&self.temp_p_key).unwrap();
    //     // if !file_path.exists() {
    //     //     self.save_to_file(&file_path, data);
    //     // }

    //     // let file_path = path.join("requester_details.json");
    //     // let data: &str = &to_json(&self.requester_details).unwrap();
    //     // if !file_path.exists() {
    //     //     self.save_to_file(&file_path, data);
    //     // }

    //     // =======| new version |===========
    //     let serialized = serde_json::to_value(&self).expect("Serialization failed");

    //     if let Value::Object(fields) = serialized {
    //         for (field_name, field_value) in fields {
    //             if !field_value.is_null() {
    //                 let json_filename = format!("{}.json", field_name);
    //                 let file_path = path.join(json_filename);

    //                 self.save_to_file(&file_path, &to_json(&field_value).unwrap());
    //             }
    //         }
    //     }

    //     Ok(())
    // }
    fn elementwise_deserialize(
        mut self,
        path: &PathBuf,
    ) -> Result<Option<IdentityCRInitiation>, TrustchainCRError> {
        let temp_p_key_path = path.join("temp_p_key.json");
        self.temp_p_key = match File::open(&temp_p_key_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                let deserialized = serde_json::from_reader(reader)
                    .map_err(|_| TrustchainCRError::FailedToDeserialize)?;
                Some(deserialized)
            }
            Err(_) => None,
        };

        let requester_details_path = path.join("requester_details.json");
        self.requester_details = match File::open(&requester_details_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                let deserialized = serde_json::from_reader(reader)
                    .map_err(|_| TrustchainCRError::FailedToDeserialize)?;
                Some(deserialized)
            }
            Err(_) => None,
        };

        if self.temp_p_key.is_none() && self.requester_details.is_none() {
            return Ok(None);
        }

        Ok(Some(self))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, IsEmpty)]
struct ContentCRInitiation {
    temp_p_key: Option<Jwk>,
    requester_did: Option<String>,
}

impl ContentCRInitiation {
    fn new() -> Self {
        Self {
            temp_p_key: None,
            requester_did: None,
        }
    }

    fn is_complete(&self) -> bool {
        return self.temp_p_key.is_some() && self.requester_did.is_some();
    }
}

impl ElementwiseSerializeDeserialize for ContentCRInitiation {
    fn elementwise_deserialize(
        mut self,
        path: &PathBuf,
    ) -> Result<Option<ContentCRInitiation>, TrustchainCRError> {
        let temp_p_key_path = path.join("temp_p_key.json");
        self.temp_p_key = match File::open(&temp_p_key_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                let deserialized = serde_json::from_reader(reader)
                    .map_err(|_| TrustchainCRError::FailedToDeserialize)?;
                Some(deserialized)
            }
            Err(_) => None,
        };

        let requester_details_path = path.join("requester_did.json");
        self.requester_did = match File::open(&requester_details_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                let deserialized = serde_json::from_reader(reader)
                    .map_err(|_| TrustchainCRError::FailedToDeserialize)?;
                Some(deserialized)
            }
            Err(_) => None,
        };

        if self.temp_p_key.is_none() && self.requester_did.is_none() {
            return Ok(None);
        }

        Ok(Some(self))
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, IsEmpty)]
struct CRIdentityChallenge {
    update_p_key: Option<Jwk>,
    identity_nonce: Option<Nonce>, // make own Nonce type
    identity_challenge_signature: Option<String>,
    identity_response_signature: Option<String>,
}

impl CRIdentityChallenge {
    fn new() -> Self {
        Self {
            update_p_key: None,
            identity_nonce: None,
            identity_challenge_signature: None,
            identity_response_signature: None,
        }
    }

    fn challenge_complete(&self) -> bool {
        return self.update_p_key.is_some()
            && self.identity_nonce.is_some()
            && self.identity_challenge_signature.is_some();
    }

    fn response_complete(&self) -> bool {
        return self.challenge_complete() && self.identity_response_signature.is_some();
    }
}

impl ElementwiseSerializeDeserialize for CRIdentityChallenge {
    fn elementwise_deserialize(
        mut self,
        path: &PathBuf,
    ) -> Result<Option<CRIdentityChallenge>, TrustchainCRError> {
        // update public key
        let mut full_path = path.join("update_p_key.json");
        self.update_p_key = match File::open(&full_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                let deserialized = serde_json::from_reader(reader)
                    .map_err(|_| TrustchainCRError::FailedToDeserialize)?;
                Some(deserialized)
            }
            Err(_) => None,
        };
        // identity nonce
        full_path = path.join("identity_nonce.json");
        self.identity_nonce = match File::open(&full_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                let deserialized = serde_json::from_reader(reader)
                    .map_err(|_| TrustchainCRError::FailedToDeserialize)?;
                Some(deserialized)
            }
            Err(_) => None,
        };
        // identity challenge signature
        full_path = path.join("identity_challenge_signature.json");
        self.identity_challenge_signature = match File::open(&full_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                let deserialized = serde_json::from_reader(reader)
                    .map_err(|_| TrustchainCRError::FailedToDeserialize)?;
                Some(deserialized)
            }
            Err(_) => None,
        };
        // identity response signature
        full_path = path.join("identity_response_signature.json");
        self.identity_response_signature = match File::open(&full_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                let deserialized = serde_json::from_reader(reader)
                    .map_err(|_| TrustchainCRError::FailedToDeserialize)?;
                Some(deserialized)
            }
            Err(_) => None,
        };

        if self.update_p_key.is_none()
            && self.identity_nonce.is_none()
            && self.identity_challenge_signature.is_none()
            && self.identity_response_signature.is_none()
        {
            return Ok(None);
        }

        Ok(Some(self))
    }
}

impl TryFrom<&JwtPayload> for CRIdentityChallenge {
    type Error = TrustchainCRError;
    fn try_from(value: &JwtPayload) -> Result<Self, Self::Error> {
        let mut challenge = CRIdentityChallenge {
            update_p_key: None,
            identity_nonce: None,
            identity_challenge_signature: None,
            identity_response_signature: None,
        };
        challenge.update_p_key = Some(
            serde_json::from_str(value.claim("update_p_key").unwrap().as_str().unwrap()).unwrap(),
        );
        challenge.identity_nonce = Some(Nonce::from(
            value
                .claim("identity_nonce")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string(),
        ));
        Ok(challenge)
    }
}

#[derive(Debug, Serialize, Deserialize, IsEmpty)]
struct CRContentChallenge {
    content_nonce: Option<HashMap<String, Nonce>>,
    content_challenge_signature: Option<String>,
    content_response_signature: Option<String>,
}

impl CRContentChallenge {
    fn new() -> Self {
        Self {
            content_nonce: None,
            content_challenge_signature: None,
            content_response_signature: None,
        }
    }

    fn challenge_complete(&self) -> bool {
        return self.content_nonce.is_some() && self.content_challenge_signature.is_some();
    }

    fn response_complete(&self) -> bool {
        return self.challenge_complete() && self.content_response_signature.is_some();
    }
}

impl ElementwiseSerializeDeserialize for CRContentChallenge {
    // fn elementwise_serialize(&self, path: &PathBuf) -> Result<(), TrustchainCRError> {
    //     if let Some(content_nonce) = &self.content_nonce {
    //         let file_path = path.join("content_nonce.json");
    //         let data: &str = &to_json(content_nonce).unwrap();
    //         if !file_path.exists() {
    //             self.save_to_file(&file_path, data);
    //         }
    //     }
    //     if let Some(content_challenge_signature) = &self.content_challenge_signature {
    //         let file_path = path.join("content_challenge_signature.json");
    //         let data: &str = &to_json(content_challenge_signature).unwrap();
    //         if !file_path.exists() {
    //             self.save_to_file(&file_path, data);
    //         }
    //     }
    //     if let Some(content_response_signature) = &self.content_response_signature {
    //         let file_path = path.join("content_response_signature.json");
    //         let data: &str = &to_json(content_response_signature).unwrap();
    //         if !file_path.exists() {
    //             self.save_to_file(&file_path, data);
    //         }
    //     }
    //     Ok(())
    // }
    fn elementwise_deserialize(
        mut self,
        path: &PathBuf,
    ) -> Result<Option<CRContentChallenge>, TrustchainCRError> {
        // content nonce(s)
        let mut full_path = path.join("content_nonce.json");
        self.content_nonce = match File::open(&full_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                let deserialized = serde_json::from_reader(reader)
                    .map_err(|_| TrustchainCRError::FailedToDeserialize)?;
                Some(deserialized)
            }
            Err(_) => None,
        };

        // content challenge signature
        full_path = path.join("content_challenge_signature.json");
        self.content_challenge_signature = match File::open(&full_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                let deserialized = serde_json::from_reader(reader)
                    .map_err(|_| TrustchainCRError::FailedToDeserialize)?;
                Some(deserialized)
            }
            Err(_) => None,
        };
        // content response signature
        full_path = path.join("content_response_signature.json");
        self.content_response_signature = match File::open(&full_path) {
            Ok(file) => {
                let reader = std::io::BufReader::new(file);
                let deserialized = serde_json::from_reader(reader)
                    .map_err(|_| TrustchainCRError::FailedToDeserialize)?;
                Some(deserialized)
            }
            Err(_) => None,
        };

        if self.content_nonce.is_none()
            && self.content_challenge_signature.is_none()
            && self.content_response_signature.is_none()
        {
            return Ok(None);
        }

        Ok(Some(self))
    }
}

impl TryFrom<&CRIdentityChallenge> for JwtPayload {
    type Error = TrustchainCRError;
    fn try_from(value: &CRIdentityChallenge) -> Result<Self, Self::Error> {
        let mut payload = JwtPayload::new();
        payload.set_claim(
            "identity_nonce",
            Some(Value::from(
                value.identity_nonce.as_ref().unwrap().to_string(),
            )),
        )?;
        payload.set_claim(
            "update_p_key",
            Some(Value::from(
                value.update_p_key.as_ref().unwrap().to_string(),
            )),
        )?;
        Ok(payload)
    }
}

impl TryFrom<&Nonce> for JwtPayload {
    type Error = TrustchainCRError;
    fn try_from(value: &Nonce) -> Result<Self, Self::Error> {
        let mut payload = JwtPayload::new();
        payload.set_claim("nonce", Some(Value::from(value.to_string())))?;
        Ok(payload)
    }
}

// make a try_from instead
fn josekit_to_ssi_jwk(key: &Jwk) -> Result<JWK, serde_json::Error> {
    let key_as_str: &str = &serde_json::to_string(&key).unwrap();
    let ssi_key: JWK = serde_json::from_str(key_as_str).unwrap();
    Ok(ssi_key)
}

fn ssi_to_josekit_jwk(key: &JWK) -> Result<Jwk, serde_json::Error> {
    let key_as_str: &str = &serde_json::to_string(&key).unwrap();
    let ssi_key: Jwk = serde_json::from_str(key_as_str).unwrap();
    Ok(ssi_key)
}

fn extract_key_ids_and_jwk(document: &Document) -> Result<HashMap<String, Jwk>, TrustchainCRError> {
    let mut my_map = HashMap::<String, Jwk>::new();
    if let Some(vms) = &document.verification_method {
        // TODO: leave the commented code
        // vms.iter().for_each(|vm| match vm {
        //     VerificationMethod::Map(vm_map) => {
        //         let id = vm_map.id;
        //         let key = vm_map.get_jwk().unwrap();
        //         let key_jose = ssi_to_josekit_jwk(&key).unwrap();
        //         my_map.insert(id, key_jose);
        //     }
        //     _ => (),
        // });
        // TODO: consider rewriting functional with filter, partition, fold over returned error
        // variants.
        for vm in vms {
            match vm {
                VerificationMethod::Map(vm_map) => {
                    let key = vm_map
                        .get_jwk()
                        .map_err(|_| TrustchainCRError::MissingJWK)?;
                    let id = key
                        .thumbprint()
                        .map_err(|_| TrustchainCRError::MissingJWK)?;
                    let key_jose =
                        ssi_to_josekit_jwk(&key).map_err(|err| TrustchainCRError::Serde(err))?;
                    my_map.insert(id, key_jose);
                }
                _ => (),
            }
        }
    }
    Ok(my_map)
}

#[cfg(test)]
mod tests {

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
    #[test]
    fn test_elementwise_serialize() {
        // ==========| Identity CR | ==============
        let temp_s_key: Jwk = serde_json::from_str(TEST_TEMP_KEY).unwrap();
        let initiation = IdentityCRInitiation {
            temp_p_key: Some(temp_s_key.to_public_key().unwrap()),
            requester_details: Some(RequesterDetails {
                requester_org: String::from("My Org"),
                operator_name: String::from("John Doe"),
            }),
        };

        // identity challenge
        let identity_challenge = CRIdentityChallenge {
            update_p_key: serde_json::from_str(TEST_UPDATE_KEY).unwrap(),
            identity_nonce: Some(Nonce::new()),
            identity_challenge_signature: Some(String::from("some challenge signature string")),
            identity_response_signature: Some(String::from("some response signature string")),
        };

        // ==========| Content CR | ==============
        let content_initiation = ContentCRInitiation {
            temp_p_key: Some(temp_s_key.to_public_key().unwrap()),
            requester_did: Some("did:example:123456789abcdefghi".to_string()),
        };
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
        let content_challenge_response = CRContentChallenge {
            content_nonce: Some(nonces),
            content_challenge_signature: Some(String::from(
                "some content challenge signature string",
            )),
            content_response_signature: Some(String::from(
                "some content response signature string",
            )),
        };

        // ==========| CR state | ==============
        let cr_state = CRState {
            identity_cr_initiation: Some(initiation),
            identity_challenge_response: Some(identity_challenge),
            content_cr_initiation: Some(content_initiation),
            content_challenge_response: Some(content_challenge_response),
        };
        // write to file
        let path = tempdir().unwrap().into_path();
        let result = cr_state.elementwise_serialize(&path);
        assert_eq!(result.is_ok(), true);

        // try to write to file again
        let result = cr_state.elementwise_serialize(&path);
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn test_deserialize_challenge_state() {
        let path = tempdir().unwrap().into_path();
        let challenge_state = CRState::new();

        // Test case 1: some files exist and can be deserialised
        let identity_initiatiation = IdentityCRInitiation {
            temp_p_key: Some(serde_json::from_str(TEST_TEMP_KEY).unwrap()),
            requester_details: Some(RequesterDetails {
                requester_org: String::from("My Org"),
                operator_name: String::from("John Doe"),
            }),
        };
        let _ = identity_initiatiation.elementwise_serialize(&path);
        let identity_challenge = CRIdentityChallenge {
            update_p_key: Some(serde_json::from_str(TEST_UPDATE_KEY).unwrap()),
            identity_nonce: Some(Nonce::new()),
            identity_challenge_signature: Some(String::from("some challenge signature string")),
            identity_response_signature: Some(String::from("some response signature string")),
        };
        let _ = identity_challenge.elementwise_serialize(&path);

        let content_cr_initiation = ContentCRInitiation {
            temp_p_key: Some(serde_json::from_str(TEST_TEMP_KEY).unwrap()),
            requester_did: Some("did:example:123456789abcdefghi".to_string()),
        };
        let _ = content_cr_initiation.elementwise_serialize(&path);

        let result = challenge_state.elementwise_deserialize(&path);
        assert!(result.is_ok());
        let challenge_state = result.unwrap().unwrap();
        println!(
            "Challenge state deserialized from files: {:?}",
            challenge_state
        );
        assert!(challenge_state.identity_cr_initiation.is_some());
        assert!(challenge_state.identity_challenge_response.is_some());
        assert!(challenge_state.content_cr_initiation.is_some());
        assert!(challenge_state.content_challenge_response.is_none());

        // Test case 2: one file cannot be deserialized
        let identity_nonce_path = path.join("content_nonce.json");
        let identity_nonce_file = File::create(&identity_nonce_path).unwrap();
        serde_json::to_writer(identity_nonce_file, &42).unwrap();
        let challenge_state = CRState::new().elementwise_deserialize(&path);
        assert!(challenge_state.is_err());
    }

    #[test]
    fn test_elementwise_deserialize_initiation() {
        let cr_initiation = IdentityCRInitiation::new();
        let temp_path = tempdir().unwrap().into_path();

        // Test case 1: None of the json files exist
        let result = cr_initiation.elementwise_deserialize(&temp_path);
        assert!(result.is_ok());
        let initiation = result.unwrap();
        assert!(initiation.is_none());

        // Test case 2: Only one json file exists and can be deserialized
        let cr_initiation = IdentityCRInitiation::new();
        let temp_p_key_path = temp_path.join("temp_p_key.json");
        let temp_p_key_file = File::create(&temp_p_key_path).unwrap();
        let temp_p_key: Jwk = serde_json::from_str(TEST_TEMP_KEY).unwrap();
        serde_json::to_writer(temp_p_key_file, &temp_p_key).unwrap();

        let result = cr_initiation.elementwise_deserialize(&temp_path);
        assert!(result.is_ok());
        let initiation = result.unwrap().unwrap();
        assert!(initiation.temp_p_key.is_some());
        assert!(initiation.requester_details.is_none());

        // Test case 3: Both json files exist and can be deserialized
        let cr_initiation = IdentityCRInitiation::new();
        let requester_details_path = temp_path.join("requester_details.json");
        let requester_details_file = File::create(&requester_details_path).unwrap();
        let requester_details = RequesterDetails {
            requester_org: String::from("My Org"),
            operator_name: String::from("John Doe"),
        };
        serde_json::to_writer(requester_details_file, &requester_details).unwrap();
        let result = cr_initiation.elementwise_deserialize(&temp_path);
        assert!(result.is_ok());
        let initiation = result.unwrap().unwrap();
        assert!(initiation.temp_p_key.is_some());
        assert!(initiation.requester_details.is_some());

        // Test case 4: Both json files exist but one is invalid json and cannot be
        // deserialized
        let cr_initiation = IdentityCRInitiation::new();
        // override temp key with invalid key
        let temp_p_key_file = File::create(&temp_p_key_path).unwrap();
        serde_json::to_writer(temp_p_key_file, "this is not valid json").unwrap();
        let result = cr_initiation.elementwise_deserialize(&temp_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_elementwise_deserialize_identity_challenge() {
        let identity_challenge = CRIdentityChallenge::new();
        let temp_path = tempdir().unwrap().into_path();

        // Test case 1: None of the json files exist
        let result = identity_challenge.elementwise_deserialize(&temp_path);
        assert!(result.is_ok());
        let identity_challenge = result.unwrap();
        assert!(identity_challenge.is_none());

        // Test case 2: Only one json file exists and can be deserialized
        let update_p_key_path = temp_path.join("update_p_key.json");
        let update_p_key_file = File::create(&update_p_key_path).unwrap();
        let update_p_key: Jwk = serde_json::from_str(TEST_UPDATE_KEY).unwrap();
        serde_json::to_writer(update_p_key_file, &update_p_key).unwrap();
        let identity_challenge = CRIdentityChallenge::new();
        let result = identity_challenge.elementwise_deserialize(&temp_path);
        assert!(result.is_ok());
        let identity_challenge = result.unwrap().unwrap();
        assert_eq!(identity_challenge.update_p_key, Some(update_p_key));
        assert!(identity_challenge.identity_nonce.is_none());
        assert!(identity_challenge.identity_challenge_signature.is_none());
        assert!(identity_challenge.identity_response_signature.is_none());

        // Test case 3: One file exists but cannot be deserialized
        let identity_nonce_path = temp_path.join("identity_nonce.json");
        let identity_nonce_file = File::create(&identity_nonce_path).unwrap();
        serde_json::to_writer(identity_nonce_file, &42).unwrap();
        let identity_challenge = CRIdentityChallenge::new();
        let result = identity_challenge.elementwise_deserialize(&temp_path);
        assert!(result.is_err());
        println!("Error: {:?}", result.unwrap_err());
    }

    #[test]
    fn test_elementwise_deserialize_content_challenge() {
        let content_challenge = CRContentChallenge::new();
        let temp_path = tempdir().unwrap().into_path();

        // Test case 1: None of the json files exist
        let result = content_challenge.elementwise_deserialize(&temp_path);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Test case 2: Only one json file exists and can be deserialized
        let content_challenge = CRContentChallenge::new();
        let content_nonce_path = temp_path.join("content_nonce.json");
        let content_nonce_file = File::create(&content_nonce_path).unwrap();
        let mut nonces_map: HashMap<&str, Nonce> = HashMap::new();
        nonces_map.insert("test_id", Nonce::new());
        serde_json::to_writer(content_nonce_file, &nonces_map).unwrap();
        let result = content_challenge.elementwise_deserialize(&temp_path);
        assert!(result.is_ok());
        let content_challenge = result.unwrap().unwrap();
        assert!(content_challenge.content_nonce.is_some());
        assert!(content_challenge.content_challenge_signature.is_none());
        assert!(content_challenge.content_response_signature.is_none());

        // Test case 3: One file exists but cannot be deserialized
        let content_nonce_file = File::create(&content_nonce_path).unwrap();
        serde_json::to_writer(content_nonce_file, "thisisinvalid").unwrap();
        let result = content_challenge.elementwise_deserialize(&temp_path);
        print!("Result: {:?}", result);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_cr_status() {
        let mut cr_state = CRState::new();
        // Test case 1: CR State is empty
        let result = cr_state.check_cr_status().unwrap();
        assert_eq!(result, CurrentCRState::NotStarted);

        // Test case 2: some, but not all, initation information exists
        cr_state.identity_cr_initiation = Some(IdentityCRInitiation {
            temp_p_key: Some(serde_json::from_str(TEST_TEMP_KEY).unwrap()),
            requester_details: None,
        });
        let result = cr_state.check_cr_status();
        assert_eq!(result.unwrap(), CurrentCRState::NotStarted);

        // Test case 3: identity initiation completed, identity challenge presented
        cr_state.identity_cr_initiation = Some(IdentityCRInitiation {
            temp_p_key: Some(serde_json::from_str(TEST_TEMP_KEY).unwrap()),
            requester_details: Some(RequesterDetails {
                requester_org: String::from("My Org"),
                operator_name: String::from("John Doe"),
            }),
        });
        cr_state.identity_challenge_response = Some(CRIdentityChallenge {
            update_p_key: Some(serde_json::from_str(TEST_UPDATE_KEY).unwrap()),
            identity_nonce: Some(Nonce::new()),
            identity_challenge_signature: Some(String::from("some challenge signature string")),
            identity_response_signature: None,
        });
        let result = cr_state.check_cr_status();
        assert_eq!(result.unwrap(), CurrentCRState::IdentityChallengeComplete);

        // Test case 4: Identity challenge response complete, content challenge initiated
        cr_state.identity_challenge_response = Some(CRIdentityChallenge {
            update_p_key: Some(serde_json::from_str(TEST_UPDATE_KEY).unwrap()),
            identity_nonce: Some(Nonce::new()),
            identity_challenge_signature: Some(String::from("some challenge signature string")),
            identity_response_signature: Some(String::from("some response signature string")),
        });
        cr_state.content_cr_initiation = {
            Some(ContentCRInitiation {
                temp_p_key: Some(serde_json::from_str(TEST_TEMP_KEY).unwrap()),
                requester_did: Some("did:example:123456789abcdefghi".to_string()),
            })
        };
        let result = cr_state.check_cr_status();
        assert_eq!(result.unwrap(), CurrentCRState::ContentCRInitiated);

        // Test case 5: Content challenge-response complete
        cr_state.content_challenge_response = Some(CRContentChallenge {
            content_nonce: Some(HashMap::new()),
            content_challenge_signature: Some(String::from(
                "some content challenge signature string",
            )),
            content_response_signature: Some(String::from(
                "some content response signature string",
            )),
        });
        let result = cr_state.check_cr_status();
        assert_eq!(result.unwrap(), CurrentCRState::ContentResponseComplete);
    }
    #[test]
    fn test_check_cr_status_inconsistent_order() {
        let mut cr_state = CRState::new();
        cr_state.identity_challenge_response = Some(CRIdentityChallenge {
            update_p_key: Some(serde_json::from_str(TEST_UPDATE_KEY).unwrap()),
            identity_nonce: Some(Nonce::new()),
            identity_challenge_signature: Some(String::from("some challenge signature string")),
            identity_response_signature: Some(String::from("some response signature string")),
        });
        let result = cr_state.check_cr_status();
        assert_eq!(result.unwrap(), CurrentCRState::NotStarted);
    }
}

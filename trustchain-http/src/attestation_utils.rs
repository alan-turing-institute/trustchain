use std::{
    collections::HashMap,
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

// use axum::response::Response;
use is_empty::IsEmpty;
use josekit::JoseError;
use josekit::{jwk::Jwk, jwt::JwtPayload};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::{to_string_pretty as to_json, Value};
use serde_with::skip_serializing_none;
use ssi::{did::Service, jwk::JWK};
use ssi::{did::ServiceEndpoint, one_or_many::OneOrMany};
use std::fs::OpenOptions;
use thiserror::Error;
use trustchain_core::TRUSTCHAIN_DATA;

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
    /// Failed to generate key.
    #[error("Failed to generate key.")]
    FailedToGenerateKey,
    /// Reqwest error.
    #[error("Network request failed.")]
    Reqwest(reqwest::Error),
    /// Invalid service endpoint.
    #[error("Invalid service endpoint.")]
    InvalidServiceEndpoint,
    /// CR initiation failed
    #[error("Failed to initiate challenge-response.")]
    FailedToInitiateCR,
    /// Failed attestation request
    #[error("Failed attestation request.")]
    FailedAttestationRequest,
    /// Field of struct not found
    #[error("Field not found.")]
    FieldNotFound,
    /// Field to respond
    #[error("Response to challenge failed.")]
    FailedToRespond(reqwest::Response),
    // Failed to verify nonce
    #[error("Failed to verify nonce.")]
    FailedToVerifyNonce,
}

impl From<JoseError> for TrustchainCRError {
    fn from(err: JoseError) -> Self {
        Self::Jose(err)
    }
}

#[derive(Serialize, Deserialize)]
pub struct CustomResponse {
    pub message: String,
    pub data: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum CurrentCRState {
    NotStarted,
    IdentityCRInitiated,
    IdentityChallengeComplete,
    IdentityResponseComplete,
    ContentCRInitiated,
    ContentChallengeComplete,
    ContentResponseComplete,
}

// TODO: Impose additional constraints on the nonce type.
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

impl TryFrom<&Nonce> for JwtPayload {
    type Error = TrustchainCRError;
    fn try_from(value: &Nonce) -> Result<Self, Self::Error> {
        let mut payload = JwtPayload::new();
        payload.set_claim("nonce", Some(Value::from(value.to_string())))?;
        Ok(payload)
    }
}

/// Interface for serializing and deserializing each field of structs to/from files.
pub trait ElementwiseSerializeDeserialize
where
    Self: Serialize,
{
    /// Serialize each field of the struct to a file.
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
    /// Deserializes each field of the struct from a file.
    fn elementwise_deserialize(self, path: &PathBuf) -> Result<Option<Self>, TrustchainCRError>
    where
        Self: Sized;
    /// Save data to file. If file already exists, do nothing.
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

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RequesterDetails {
    pub requester_org: String,
    pub operator_name: String,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, IsEmpty, Clone)]
pub struct IdentityCRInitiation {
    pub temp_p_key: Option<Jwk>,
    pub temp_s_key: Option<Jwk>,
    pub requester_details: Option<RequesterDetails>,
}

impl IdentityCRInitiation {
    pub fn new() -> Self {
        Self {
            temp_p_key: None,
            temp_s_key: None,
            requester_details: None,
        }
    }

    fn is_complete(&self) -> bool {
        return self.temp_p_key.is_some() && self.requester_details.is_some();
    }
}

impl ElementwiseSerializeDeserialize for IdentityCRInitiation {
    /// Deserialize each field of the struct from a file. Fields are optional. If no files are found, return None.
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

        let temp_s_key_path = path.join("temp_s_key.json");
        self.temp_s_key = match File::open(&temp_s_key_path) {
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

        if self.temp_p_key.is_none()
            && self.temp_s_key.is_none()
            && self.requester_details.is_none()
        {
            return Ok(None);
        }

        Ok(Some(self))
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, IsEmpty)]
pub struct IdentityCRChallenge {
    pub update_p_key: Option<Jwk>,
    pub update_s_key: Option<Jwk>,
    pub identity_nonce: Option<Nonce>, // make own Nonce type
    /// Encrypted identity challenge, signed by the attestor.
    pub identity_challenge_signature: Option<String>,
    pub identity_response_signature: Option<String>,
}

impl IdentityCRChallenge {
    pub fn new() -> Self {
        Self {
            update_p_key: None,
            update_s_key: None,
            identity_nonce: None,
            identity_challenge_signature: None,
            identity_response_signature: None,
        }
    }
    /// Returns true if all fields required for the challenge have a non-null value.
    fn challenge_complete(&self) -> bool {
        return self.update_p_key.is_some()
            && self.identity_nonce.is_some()
            && self.identity_challenge_signature.is_some();
    }
    /// Returns true if all fields of the challenge-response have a non-null value.
    fn response_complete(&self) -> bool {
        return self.challenge_complete() && self.identity_response_signature.is_some();
    }
}

impl ElementwiseSerializeDeserialize for IdentityCRChallenge {
    /// Deserialize each field of the struct from a file. Fields are optional. If no files are found, return None.
    fn elementwise_deserialize(
        mut self,
        path: &PathBuf,
    ) -> Result<Option<IdentityCRChallenge>, TrustchainCRError> {
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

impl TryFrom<&IdentityCRChallenge> for JwtPayload {
    type Error = TrustchainCRError;
    fn try_from(value: &IdentityCRChallenge) -> Result<Self, Self::Error> {
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

impl TryFrom<&JwtPayload> for IdentityCRChallenge {
    type Error = TrustchainCRError;
    fn try_from(value: &JwtPayload) -> Result<Self, Self::Error> {
        let mut challenge = IdentityCRChallenge {
            update_p_key: None,
            update_s_key: None,
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

#[derive(Debug, Serialize, Deserialize, Clone, IsEmpty)]
pub struct ContentCRInitiation {
    pub requester_did: Option<String>,
}

impl ContentCRInitiation {
    pub fn new() -> Self {
        Self {
            requester_did: None,
        }
    }

    fn is_complete(&self) -> bool {
        return self.requester_did.is_some();
    }
}

impl ElementwiseSerializeDeserialize for ContentCRInitiation {
    /// Deserialize each field of the struct from a file. Fields are optional. If no files are found, return None.
    fn elementwise_deserialize(
        mut self,
        path: &PathBuf,
    ) -> Result<Option<ContentCRInitiation>, TrustchainCRError> {
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

        // if self.temp_p_key.is_none() && self.requester_did.is_none() {
        //     return Ok(None);
        // }
        if self.requester_did.is_none() {
            return Ok(None);
        }

        Ok(Some(self))
    }
}

#[derive(Debug, Serialize, Deserialize, IsEmpty)]
pub struct ContentCRChallenge {
    pub content_nonce: Option<HashMap<String, Nonce>>,
    pub content_challenge_signature: Option<String>,
    pub content_response_signature: Option<String>,
}

impl ContentCRChallenge {
    pub fn new() -> Self {
        Self {
            content_nonce: None,
            content_challenge_signature: None,
            content_response_signature: None,
        }
    }
    /// Returns true if all fields required for the challenge have a non-null value.
    fn challenge_complete(&self) -> bool {
        return self.content_nonce.is_some() && self.content_challenge_signature.is_some();
    }
    /// Returns true if all fields required for the challenge-response have a non-null value.
    fn response_complete(&self) -> bool {
        return self.challenge_complete() && self.content_response_signature.is_some();
    }
}

impl ElementwiseSerializeDeserialize for ContentCRChallenge {
    /// Deserialize each field of the struct from a file. Fields are optional. If no files are found, return None.
    fn elementwise_deserialize(
        mut self,
        path: &PathBuf,
    ) -> Result<Option<ContentCRChallenge>, TrustchainCRError> {
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

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, IsEmpty)]
pub struct CRState {
    pub identity_cr_initiation: Option<IdentityCRInitiation>,
    pub identity_challenge_response: Option<IdentityCRChallenge>,
    pub content_cr_initiation: Option<ContentCRInitiation>,
    pub content_challenge_response: Option<ContentCRChallenge>,
}

impl CRState {
    pub fn new() -> Self {
        Self {
            identity_cr_initiation: None,
            identity_challenge_response: None,
            content_cr_initiation: None,
            content_challenge_response: None,
        }
    }
    /// Returns true if all fields have a non-null value.
    pub fn is_complete(&self) -> bool {
        if self.identity_cr_initiation.is_some()
            && self.identity_challenge_response.is_some()
            && self.content_cr_initiation.is_some()
            && self.content_challenge_response.is_some()
        {
            return true;
        }
        return false;
    }
    /// Determines current status of the challenge response process and accordingly prints messages to the console.
    pub fn check_cr_status(&self) -> Result<CurrentCRState, TrustchainCRError> {
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
    /// Serialize each field of the struct to a file. Fields with null values are ignored.
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
    /// Deserialize each field of the struct from a file. All fields are optional.
    fn elementwise_deserialize(
        mut self,
        path: &PathBuf,
    ) -> Result<Option<CRState>, TrustchainCRError> {
        self.identity_cr_initiation = IdentityCRInitiation::new().elementwise_deserialize(path)?;
        self.identity_challenge_response =
            IdentityCRChallenge::new().elementwise_deserialize(path)?;
        self.content_cr_initiation = ContentCRInitiation::new().elementwise_deserialize(path)?;
        self.content_challenge_response =
            ContentCRChallenge::new().elementwise_deserialize(path)?;
        Ok(Some(self))
    }
}

/// Returns message that corresponds to the current state of the challenge-response process.
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

/// Returns endpoint that contains the given fragment from the given list of service endpoints.
/// Throws error if no or more than one matching endpoint is found.
pub fn matching_endpoint(
    services: &[Service],
    fragment: &str,
) -> Result<String, TrustchainCRError> {
    let mut endpoints = Vec::new();
    for service in services {
        println!("service id: {}", service.id);
        if service.id.eq(fragment) {
            match &service.service_endpoint {
                Some(OneOrMany::One(ServiceEndpoint::URI(uri))) => {
                    endpoints.push(uri.to_string());
                }

                _ => return Err(TrustchainCRError::InvalidServiceEndpoint),
            }
        }
    }
    if endpoints.len() != 1 {
        return Err(TrustchainCRError::InvalidServiceEndpoint);
    }
    return Ok(endpoints[0].clone());
}

/// Returns unique path name for a specific attestation request derived from public key for the interaction.
pub fn attestation_request_path(key: &JWK) -> Result<PathBuf, TrustchainCRError> {
    // Root path in TRUSTCHAIN_DATA
    let path: String =
        std::env::var(TRUSTCHAIN_DATA).map_err(|_| TrustchainCRError::FailedAttestationRequest)?;
    let key_id = key
        .thumbprint()
        .map_err(|_| TrustchainCRError::MissingJWK)?; // Use hash of temp_pub_key
    Ok(Path::new(path.as_str())
        .join("attestation_requests")
        .join(key_id))
}

#[cfg(test)]
mod tests {
    use crate::attestation_encryption_utils::extract_key_ids_and_jwk;
    use crate::data::{TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS, TEST_TEMP_KEY, TEST_UPDATE_KEY};
    use ssi::did::Document;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_elementwise_serialize() {
        // ==========| Identity CR | ==============
        let temp_s_key: Jwk = serde_json::from_str(TEST_TEMP_KEY).unwrap();
        let initiation = IdentityCRInitiation {
            temp_p_key: None,
            temp_s_key: Some(temp_s_key.to_public_key().unwrap()),
            requester_details: Some(RequesterDetails {
                requester_org: String::from("My Org"),
                operator_name: String::from("John Doe"),
            }),
        };

        // identity challenge
        let identity_challenge = IdentityCRChallenge {
            update_p_key: serde_json::from_str(TEST_UPDATE_KEY).unwrap(),
            update_s_key: None,
            identity_nonce: Some(Nonce::new()),
            identity_challenge_signature: Some(String::from("some challenge signature string")),
            identity_response_signature: Some(String::from("some response signature string")),
        };

        // ==========| Content CR | ==============
        let content_initiation = ContentCRInitiation {
            // temp_p_key: Some(temp_s_key.to_public_key().unwrap()),
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
        let content_challenge_response = ContentCRChallenge {
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
        assert!(initiation.temp_s_key.is_none());
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
        let identity_challenge = IdentityCRChallenge::new();
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
        let identity_challenge = IdentityCRChallenge::new();
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
        let identity_challenge = IdentityCRChallenge::new();
        let result = identity_challenge.elementwise_deserialize(&temp_path);
        assert!(result.is_err());
        println!("Error: {:?}", result.unwrap_err());
    }

    #[test]
    fn test_elementwise_deserialize_content_challenge() {
        let content_challenge = ContentCRChallenge::new();
        let temp_path = tempdir().unwrap().into_path();

        // Test case 1: None of the json files exist
        let result = content_challenge.elementwise_deserialize(&temp_path);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Test case 2: Only one json file exists and can be deserialized
        let content_challenge = ContentCRChallenge::new();
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
    fn test_deserialize_challenge_state() {
        let path = tempdir().unwrap().into_path();
        let challenge_state = CRState::new();

        // Test case 1: some files exist and can be deserialised
        let identity_initiatiation = IdentityCRInitiation {
            temp_s_key: Some(serde_json::from_str(TEST_TEMP_KEY).unwrap()),
            temp_p_key: None,
            requester_details: Some(RequesterDetails {
                requester_org: String::from("My Org"),
                operator_name: String::from("John Doe"),
            }),
        };
        let _ = identity_initiatiation.elementwise_serialize(&path);
        let identity_challenge = IdentityCRChallenge {
            update_p_key: Some(serde_json::from_str(TEST_UPDATE_KEY).unwrap()),
            update_s_key: Some(serde_json::from_str(TEST_UPDATE_KEY).unwrap()),
            identity_nonce: Some(Nonce::new()),
            identity_challenge_signature: Some(String::from("some challenge signature string")),
            identity_response_signature: Some(String::from("some response signature string")),
        };
        let _ = identity_challenge.elementwise_serialize(&path);

        let content_cr_initiation = ContentCRInitiation {
            // temp_p_key: Some(serde_json::from_str(TEST_TEMP_KEY).unwrap()),
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
    fn test_matching_endpoint() {
        let services = vec![
            Service {
                id: String::from("did:example:123456789abcdefghi#service-1"),
                service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(String::from(
                    "https://example.com/endpoint-1",
                )))),
                type_: ssi::one_or_many::OneOrMany::One("Service1".to_string()),
                property_set: None,
            },
            Service {
                id: String::from("did:example:123456789abcdefghi#service-2"),
                service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(String::from(
                    "https://example.com/endpoint-2",
                )))),
                type_: ssi::one_or_many::OneOrMany::One("Service2".to_string()),
                property_set: None,
            },
        ];
        let result = matching_endpoint(&services, "service-1");
        assert_eq!(result.unwrap(), "https://example.com/endpoint-1");
    }

    #[test]
    fn test_matching_endpoint_multiple_endpoints_found() {
        let services = vec![
            Service {
                id: String::from("did:example:123456789abcdefghi#service-1"),
                service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(String::from(
                    "https://example.com/endpoint-1",
                )))),
                type_: ssi::one_or_many::OneOrMany::One("Service1".to_string()),
                property_set: None,
            },
            Service {
                id: String::from("did:example:123456789abcdefghi#service-1"),
                service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(String::from(
                    "https://example.com/endpoint-2",
                )))),
                type_: ssi::one_or_many::OneOrMany::One("Service1".to_string()),
                property_set: None,
            },
        ];
        let result = matching_endpoint(&services, "service-1");
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
            // Same key used here for testing purposes
            temp_p_key: Some(serde_json::from_str(TEST_TEMP_KEY).unwrap()),
            temp_s_key: None,
            requester_details: None,
        });
        let result = cr_state.check_cr_status();
        assert_eq!(result.unwrap(), CurrentCRState::NotStarted);

        // Test case 3: identity initiation completed, identity challenge presented
        cr_state.identity_cr_initiation = Some(IdentityCRInitiation {
            // Same key used here for testing purposes
            temp_p_key: Some(serde_json::from_str(TEST_TEMP_KEY).unwrap()),
            temp_s_key: None,
            requester_details: Some(RequesterDetails {
                requester_org: String::from("My Org"),
                operator_name: String::from("John Doe"),
            }),
        });
        cr_state.identity_challenge_response = Some(IdentityCRChallenge {
            update_p_key: Some(serde_json::from_str(TEST_UPDATE_KEY).unwrap()),
            update_s_key: None,
            identity_nonce: Some(Nonce::new()),
            identity_challenge_signature: Some(String::from("some challenge signature string")),
            identity_response_signature: None,
        });
        let result = cr_state.check_cr_status();
        assert_eq!(result.unwrap(), CurrentCRState::IdentityChallengeComplete);

        // Test case 4: Identity challenge response complete, content challenge initiated
        cr_state.identity_challenge_response = Some(IdentityCRChallenge {
            // Same key used here for testing purposes
            update_p_key: Some(serde_json::from_str(TEST_UPDATE_KEY).unwrap()),
            update_s_key: None,
            identity_nonce: Some(Nonce::new()),
            identity_challenge_signature: Some(String::from("some challenge signature string")),
            identity_response_signature: Some(String::from("some response signature string")),
        });
        cr_state.content_cr_initiation = {
            Some(ContentCRInitiation {
                requester_did: Some("did:example:123456789abcdefghi".to_string()),
            })
        };
        let result = cr_state.check_cr_status();
        assert_eq!(result.unwrap(), CurrentCRState::ContentCRInitiated);

        // Test case 5: Content challenge-response complete
        cr_state.content_challenge_response = Some(ContentCRChallenge {
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
        cr_state.identity_challenge_response = Some(IdentityCRChallenge {
            update_s_key: None,
            update_p_key: Some(serde_json::from_str(TEST_UPDATE_KEY).unwrap()),
            identity_nonce: Some(Nonce::new()),
            identity_challenge_signature: Some(String::from("some challenge signature string")),
            identity_response_signature: Some(String::from("some response signature string")),
        });
        let result = cr_state.check_cr_status();
        assert_eq!(result.unwrap(), CurrentCRState::NotStarted);
    }
}

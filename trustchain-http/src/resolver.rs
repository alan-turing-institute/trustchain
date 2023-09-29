use crate::errors::TrustchainHTTPError;
use crate::state::AppState;
use async_trait::async_trait;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use log::debug;
use serde::{Deserialize, Serialize};
use ssi::did_resolve::DIDResolver;
use ssi::{
    did::Document,
    did_resolve::{DocumentMetadata, ResolutionResult},
};
use std::sync::Arc;
use trustchain_core::chain::{Chain, DIDChain};
use trustchain_core::resolver::Resolver;
use trustchain_core::verifier::{Timestamp, Verifier, VerifierError};
use trustchain_ion::verifier::{IONVerifier, VerificationBundle};

/// A HTTP API for resolving DID documents, chains, and verification bundles.
#[async_trait]
pub trait TrustchainHTTP {
    /// Resolves a DID document.
    async fn resolve_did<T: DIDResolver + Send + Sync>(
        did: &str,
        resolver: &Resolver<T>,
    ) -> Result<ResolutionResult, TrustchainHTTPError>;

    /// Resolves a DID chain.
    async fn resolve_chain<T: DIDResolver + Send + Sync>(
        did: &str,
        verifier: &IONVerifier<T>,
        root_event_time: Timestamp,
    ) -> Result<DIDChainResolutionResult, TrustchainHTTPError>;

    /// Resolves a DID verification bundle.
    async fn resolve_bundle<T: DIDResolver + Send + Sync>(
        did: &str,
        verifier: &IONVerifier<T>,
    ) -> Result<VerificationBundle, TrustchainHTTPError>;
}

/// Type for implementing handlers for resolution of DID documents, chains, and bundles.
pub struct TrustchainHTTPHandler {}

#[async_trait]
impl TrustchainHTTP for TrustchainHTTPHandler {
    async fn resolve_did<T: DIDResolver + Send + Sync>(
        did: &str,
        resolver: &Resolver<T>,
    ) -> Result<ResolutionResult, TrustchainHTTPError> {
        debug!("Resolving...");
        let result = resolver.resolve_as_result(did).await?;

        debug!("Resolved result: {:?}", result);
        match result {
            (_, Some(doc), Some(doc_meta)) => Ok(Self::to_resolution_result(doc, doc_meta)),
            // TODO: convert to (unknown) resolver error
            _ => Err(TrustchainHTTPError::InternalError),
        }
    }

    async fn resolve_chain<T: DIDResolver + Send + Sync>(
        did: &str,
        verifier: &IONVerifier<T>,
        root_event_time: Timestamp,
    ) -> Result<DIDChainResolutionResult, TrustchainHTTPError> {
        debug!("Verifying...");
        let chain = verifier
            .verify(did, root_event_time)
            .await
            // Any commitment error implies invalid root
            .map_err(|err| match err {
                err @ VerifierError::CommitmentFailure(_) => VerifierError::InvalidRoot(err.into()),
                err => err,
            })?;
        debug!("Verified did...");
        Ok(DIDChainResolutionResult::new(&chain))
    }

    async fn resolve_bundle<T: DIDResolver + Send + Sync>(
        did: &str,
        verifier: &IONVerifier<T>,
    ) -> Result<VerificationBundle, TrustchainHTTPError> {
        let bundle = verifier.verification_bundle(did).await?;
        Ok((*bundle).clone())
    }
}

#[derive(Deserialize, Serialize, Debug)]
/// Struct for deserializing `root_event_time` from handler's query param.
pub struct RootEventTime {
    pub root_event_time: Timestamp,
}

impl TrustchainHTTPHandler {
    /// Handles get request for DID resolve API.
    pub async fn get_did_resolution(
        Path(did): Path<String>,
        State(app_state): State<Arc<AppState>>,
    ) -> impl IntoResponse {
        debug!("Received DID to resolve: {}", did.as_str());
        TrustchainHTTPHandler::resolve_did(did.as_str(), app_state.verifier.resolver())
            .await
            .map(|resolved_json| (StatusCode::OK, Json(resolved_json)))
    }

    /// Handles get request for DID chain resolution.
    pub async fn get_chain_resolution(
        Path(did): Path<String>,
        Query(root_event_time): Query<RootEventTime>,
        State(app_state): State<Arc<AppState>>,
    ) -> impl IntoResponse {
        debug!("Received DID to get trustchain: {}", did.as_str());
        // let mut verifier = .write().await;
        TrustchainHTTPHandler::resolve_chain(
            &did,
            &app_state.verifier,
            root_event_time.root_event_time,
        )
        .await
        .map(|chain| (StatusCode::OK, Json(chain)))
    }
    /// Handles get request for DID verification bundle resolution
    pub async fn get_verification_bundle(
        Path(did): Path<String>,
        State(app_state): State<Arc<AppState>>,
    ) -> impl IntoResponse {
        debug!("Received DID to get verification bundle: {}", did.as_str());
        TrustchainHTTPHandler::resolve_bundle(&did, &app_state.verifier)
            .await
            .map(|bundle| (StatusCode::OK, Json(bundle)))
    }
    /// Converts a DID document and metadata to a `ResolutionResult` type.
    pub fn to_resolution_result(doc: Document, doc_meta: DocumentMetadata) -> ResolutionResult {
        ResolutionResult {
            context: Some(serde_json::Value::String(
                "https://w3id.org/did-resolution/v1".to_string(),
            )),
            did_document: Some(doc),
            did_resolution_metadata: None,
            did_document_metadata: Some(doc_meta),
            property_set: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Type for converting a `DIDChain` to a chain of DID documents with [W3C](https://w3c-ccg.github.io/did-resolution/#did-resolution-result)
/// data structure.
pub struct DIDChainResolutionResult {
    did_chain: Vec<ResolutionResult>,
}

impl DIDChainResolutionResult {
    pub fn new(did_chain: &DIDChain) -> Self {
        Self {
            did_chain: did_chain
                .to_vec()
                .into_iter()
                .map(|(doc, doc_meta)| TrustchainHTTPHandler::to_resolution_result(doc, doc_meta))
                .collect::<Vec<_>>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::HTTPConfig, server::TrustchainRouter};
    use axum_test_helper::TestClient;
    use hyper::Server;
    use std::net::TcpListener;
    use tower::make::Shared;
    use trustchain_core::utils::canonicalize_str;
    use trustchain_ion::get_ion_resolver;
    const TEST_ROOT_PLUS_2_RESOLVED: &str = r##"{"@context":"https://w3id.org/did-resolution/v1","didDocument":{"@context":["https://www.w3.org/ns/did/v1",{"@base":"did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"}],"assertionMethod":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"authentication":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"capabilityDelegation":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"capabilityInvocation":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"controller":"did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A","id":"did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q","keyAgreement":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"service":[{"id":"#TrustchainID","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-2","type":"Identity"}],"verificationMethod":[{"controller":"did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q","id":"#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"0nnR-pz2EZGfb7E1qfuHhnDR824HhBioxz4E-EBMnM4","y":"rWqDVJ3h16RT1N-Us7H7xRxvbC0UlMMQQgxmXOXd4bY"},"type":"JsonWebSignature2020"}]},"didDocumentMetadata":{"canonicalId":"did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q","method":{"published":true,"recoveryCommitment":"EiCy4pW16uB7H-ijA6V6jO6ddWfGCwqNcDSJpdv_USzoRA","updateCommitment":"EiAsmJrz7BysD9na9SMGyZ9RjpKIVweh_AFG_2Bs-2Okkg"},"proof":{"id":"did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A","proofValue":"eyJhbGciOiJFUzI1NksifQ.IkVpQTNtT25QRklDbTdyc2ljVjRIaFMtNjhrT21xMndqa2tlMEtkRnkzQWlWZlEi.Fxlbm8osH2O5KOQ9sS21bypT_WoWxVD8toCU4baBnLk_gOxiOy_n3cMFMVANJ8usPrKAfRFeC27ATTkWBYZzuw","type":"JsonWebSignature2020"}}}"##;
    const TEST_ROOT_PLUS_2_CHAIN: &str = r##"{"didChain":[{"@context":"https://w3id.org/did-resolution/v1","didDocument":{"@context":["https://www.w3.org/ns/did/v1",{"@base":"did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"}],"id":"did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg","verificationMethod":[{"id":"#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es","type":"JsonWebSignature2020","controller":"did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg","publicKeyJwk":{"kty":"EC","crv":"secp256k1","x":"7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso","y":"kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"}}],"authentication":["#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"],"assertionMethod":["#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"],"keyAgreement":["#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"],"capabilityInvocation":["#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"],"capabilityDelegation":["#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"],"service":[{"id":"#TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root"}]},"didDocumentMetadata":{"method":{"published":true,"recoveryCommitment":"EiCymv17OGBAs7eLmm4BIXDCQBVhdOUAX5QdpIrN4SDE5w","updateCommitment":"EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg"},"canonicalId":"did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"}},{"@context":"https://w3id.org/did-resolution/v1","didDocument":{"@context":["https://www.w3.org/ns/did/v1",{"@base":"did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A"}],"id":"did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A","controller":"did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg","verificationMethod":[{"id":"#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ","type":"JsonWebSignature2020","controller":"did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A","publicKeyJwk":{"kty":"EC","crv":"secp256k1","x":"aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU","y":"dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0"}}],"authentication":["#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"],"assertionMethod":["#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"],"keyAgreement":["#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"],"capabilityInvocation":["#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"],"capabilityDelegation":["#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"],"service":[{"id":"#TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-1"}]},"didDocumentMetadata":{"method":{"updateCommitment":"EiA0-GpdeoAa4v0-K4YCHoNTjAPsoroDy7pleDIc4a3_QQ","recoveryCommitment":"EiClOaWycGv1m-QejUjB0L18G6DVFVeTQCZCuTRrmzCBQg","published":true},"canonicalId":"did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A","proof":{"id":"did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg","type":"JsonWebSignature2020","proofValue":"eyJhbGciOiJFUzI1NksifQ.IkVpQXM5dkx2SmdaNkFHMk5XbUFmTnBrbl9EMlNSSUFSa2tCWE9kajZpMk84Umci.awNd-_O1N1ycZ6i_BxeLGV14ok51Ii2x9f1FBBCflyAWw773sqiHvQRGHIMBebKMnzbxVybFu2qUEPWUuRAC9g"}}},{"@context":"https://w3id.org/did-resolution/v1","didDocument":{"@context":["https://www.w3.org/ns/did/v1",{"@base":"did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"}],"id":"did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q","controller":"did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A","verificationMethod":[{"id":"#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI","type":"JsonWebSignature2020","controller":"did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q","publicKeyJwk":{"kty":"EC","crv":"secp256k1","x":"0nnR-pz2EZGfb7E1qfuHhnDR824HhBioxz4E-EBMnM4","y":"rWqDVJ3h16RT1N-Us7H7xRxvbC0UlMMQQgxmXOXd4bY"}}],"authentication":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"assertionMethod":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"keyAgreement":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"capabilityInvocation":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"capabilityDelegation":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"service":[{"id":"#TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-2"}]},"didDocumentMetadata":{"proof":{"proofValue":"eyJhbGciOiJFUzI1NksifQ.IkVpQTNtT25QRklDbTdyc2ljVjRIaFMtNjhrT21xMndqa2tlMEtkRnkzQWlWZlEi.Fxlbm8osH2O5KOQ9sS21bypT_WoWxVD8toCU4baBnLk_gOxiOy_n3cMFMVANJ8usPrKAfRFeC27ATTkWBYZzuw","type":"JsonWebSignature2020","id":"did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A"},"method":{"updateCommitment":"EiAsmJrz7BysD9na9SMGyZ9RjpKIVweh_AFG_2Bs-2Okkg","recoveryCommitment":"EiCy4pW16uB7H-ijA6V6jO6ddWfGCwqNcDSJpdv_USzoRA","published":true},"canonicalId":"did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"}}]}"##;
    const TEST_ROOT_PLUS_2_BUNDLE: &str = r##"{"did_doc":{"@context":["https://www.w3.org/ns/did/v1",{"@base":"did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"}],"id":"did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q","controller":"did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A","verificationMethod":[{"id":"#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI","type":"JsonWebSignature2020","controller":"did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q","publicKeyJwk":{"kty":"EC","crv":"secp256k1","x":"0nnR-pz2EZGfb7E1qfuHhnDR824HhBioxz4E-EBMnM4","y":"rWqDVJ3h16RT1N-Us7H7xRxvbC0UlMMQQgxmXOXd4bY"}}],"authentication":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"assertionMethod":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"keyAgreement":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"capabilityInvocation":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"capabilityDelegation":["#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"],"service":[{"id":"#TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-2"}]},"did_doc_meta":{"method":{"published":true,"updateCommitment":"EiAsmJrz7BysD9na9SMGyZ9RjpKIVweh_AFG_2Bs-2Okkg","recoveryCommitment":"EiCy4pW16uB7H-ijA6V6jO6ddWfGCwqNcDSJpdv_USzoRA"},"canonicalId":"did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q","proof":{"proofValue":"eyJhbGciOiJFUzI1NksifQ.IkVpQTNtT25QRklDbTdyc2ljVjRIaFMtNjhrT21xMndqa2tlMEtkRnkzQWlWZlEi.Fxlbm8osH2O5KOQ9sS21bypT_WoWxVD8toCU4baBnLk_gOxiOy_n3cMFMVANJ8usPrKAfRFeC27ATTkWBYZzuw","id":"did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A","type":"JsonWebSignature2020"}},"chunk_file":[31,139,8,0,0,0,0,0,0,3,229,147,79,115,162,76,16,198,191,11,231,240,70,197,8,230,38,50,138,18,64,16,212,184,149,178,6,152,0,242,103,6,102,64,97,43,223,125,199,36,149,125,79,123,217,220,246,48,85,93,205,211,221,195,211,191,249,41,68,40,103,144,10,143,63,126,10,4,178,48,65,31,49,12,89,138,75,225,81,168,17,201,97,136,132,59,33,194,97,83,160,146,9,143,92,218,4,121,26,26,168,251,80,167,17,87,78,231,166,231,74,81,187,108,47,197,196,176,59,120,0,96,101,27,10,176,61,134,50,177,148,213,221,116,187,83,235,17,160,188,27,235,8,226,69,107,138,203,61,10,182,105,92,66,214,212,104,52,24,13,248,215,175,254,235,75,118,155,23,214,45,23,83,20,146,209,195,36,27,114,69,198,58,158,1,115,30,94,121,32,187,200,209,245,142,46,175,65,215,24,192,41,40,113,236,243,147,140,29,191,210,188,60,242,244,38,156,238,36,177,163,152,87,220,74,179,125,91,108,229,163,221,106,126,178,80,104,103,15,148,141,218,3,2,50,73,61,154,77,147,101,45,88,219,198,246,92,1,225,237,118,163,154,96,250,238,142,0,41,69,245,205,31,19,177,4,71,188,33,108,88,194,173,73,67,248,110,27,191,30,234,102,113,141,208,187,97,119,66,8,9,12,210,60,101,221,170,108,241,151,234,119,90,67,57,138,63,210,47,111,47,119,252,87,235,54,13,209,255,236,245,234,134,242,253,192,180,92,105,191,253,91,69,183,177,220,139,175,18,80,70,4,167,183,53,9,9,99,132,62,222,223,167,159,162,255,94,113,83,70,239,83,238,111,135,125,181,20,107,140,153,240,246,242,118,155,221,16,174,65,115,92,20,41,251,88,184,0,82,109,231,2,175,61,106,211,116,235,151,184,17,117,127,214,63,60,23,217,105,33,49,210,245,177,188,88,14,207,145,187,20,143,110,204,253,250,107,154,178,115,85,215,210,220,203,138,188,95,31,119,120,192,55,114,181,168,210,214,198,131,13,104,118,178,67,172,218,227,45,50,157,239,167,9,206,136,129,131,141,173,232,202,197,110,69,188,244,20,67,178,160,168,228,162,58,156,1,169,81,143,245,126,233,77,22,107,255,147,166,136,18,80,229,108,198,114,207,88,203,225,206,221,156,98,211,204,202,78,219,84,254,69,92,235,57,185,108,71,197,162,73,6,255,8,77,34,201,27,42,14,255,8,213,124,0,162,75,239,132,149,249,108,29,78,18,172,240,209,242,97,51,158,25,246,147,20,31,156,135,77,47,205,188,116,88,157,210,217,119,64,133,54,221,129,66,171,135,74,208,236,39,177,117,128,120,121,28,200,79,166,119,141,159,230,83,67,14,3,184,58,175,210,222,91,125,63,84,131,178,116,69,210,143,192,113,249,26,200,96,88,189,54,122,82,106,174,50,26,235,137,154,226,107,63,6,34,80,205,210,28,127,66,85,239,43,109,183,150,146,225,196,245,134,150,232,83,89,151,175,238,181,13,230,3,63,55,77,199,137,175,197,193,62,68,227,224,249,159,130,106,244,71,168,84,237,149,26,173,10,183,179,103,254,128,137,44,163,205,212,210,109,226,239,93,51,9,125,203,92,91,186,167,237,29,235,50,186,220,26,253,2,202,202,18,61,4,7,0,0],"provisional_index_file":[31,139,8,0,0,0,0,0,0,3,171,86,74,206,40,205,203,46,86,178,138,174,134,48,221,50,115,82,67,139,50,149,172,148,2,115,195,83,189,77,3,146,188,29,131,43,253,178,92,35,189,189,204,140,44,243,204,42,74,203,115,19,139,162,66,34,205,10,138,82,12,45,29,253,10,74,204,10,43,253,148,106,99,107,1,80,57,150,45,78,0,0,0],"core_index_file":[31,139,8,0,0,0,0,0,0,3,133,144,221,142,162,48,0,70,223,165,215,67,34,136,69,189,107,65,20,196,65,228,71,119,55,27,211,129,162,229,183,219,34,35,24,223,125,221,125,128,153,235,47,57,231,228,123,0,46,218,158,73,214,54,164,114,154,140,222,109,86,209,88,48,176,4,65,157,159,16,209,118,114,35,121,26,133,131,184,233,173,250,81,236,131,149,231,49,168,73,161,113,180,101,163,45,59,114,15,37,120,3,45,167,130,116,47,148,4,203,7,72,5,37,29,5,203,95,15,32,111,121,206,238,22,233,200,191,33,163,85,71,54,68,94,95,142,21,195,37,58,45,6,37,146,103,201,118,99,52,150,57,26,247,219,189,227,124,224,201,116,186,175,236,201,161,234,237,133,49,100,238,229,229,16,52,109,123,42,6,179,173,107,214,213,180,233,254,83,204,161,238,85,195,95,99,36,13,234,213,181,142,157,147,101,6,56,185,102,126,140,78,179,32,227,142,120,215,67,107,53,251,4,207,231,219,55,77,184,236,39,197,108,110,96,43,140,10,183,115,122,205,114,109,223,223,148,16,106,205,34,110,175,106,223,97,242,99,234,110,209,23,77,149,79,142,67,186,238,213,90,9,104,17,23,120,226,169,243,53,180,18,59,161,81,96,254,52,111,209,65,212,163,137,131,203,247,77,86,68,108,228,159,9,133,83,87,247,118,136,163,157,178,72,80,59,111,46,179,121,20,113,109,171,104,66,109,104,9,171,224,171,159,116,126,84,225,13,27,27,133,21,8,38,176,240,97,150,29,243,181,249,249,231,61,181,66,151,103,253,57,14,199,246,128,94,77,191,159,207,191,142,167,192,117,34,2,0,0],"transaction":[2,0,0,0,1,113,221,4,189,16,26,231,2,48,224,28,93,57,7,140,195,149,161,45,117,110,230,205,103,61,52,184,254,125,243,83,89,1,0,0,0,106,71,48,68,2,32,33,204,63,234,205,220,221,165,43,15,131,19,214,231,83,195,252,217,246,170,251,83,229,47,78,58,174,92,91,222,243,186,2,32,71,116,233,174,111,54,233,197,138,99,93,100,175,153,165,194,166,101,203,26,217,146,169,131,208,230,247,254,171,12,5,2,1,33,3,210,138,101,166,212,146,135,234,245,80,56,11,62,159,113,207,113,16,105,102,75,44,32,130,109,119,241,154,12,3,85,7,255,255,255,255,2,0,0,0,0,0,0,0,0,54,106,52,105,111,110,58,51,46,81,109,82,118,103,90,109,52,74,51,74,83,120,102,107,52,119,82,106,69,50,117,50,72,105,50,85,55,86,109,111,98,89,110,112,113,104,113,72,53,81,80,54,74,57,55,109,76,238,0,0,0,0,0,25,118,169,20,199,246,99,10,196,245,226,169,38,84,22,59,206,40,9,49,99,20,24,221,136,172,0,0,0,0],"merkle_block":[0,224,228,44,50,91,136,90,53,184,101,89,134,219,136,40,143,2,100,212,246,127,92,201,14,109,13,17,39,0,0,0,0,0,0,0,105,173,156,82,17,65,101,68,32,6,152,112,104,119,198,46,124,201,58,41,245,245,163,29,5,181,212,9,82,121,206,125,61,49,81,99,192,255,63,25,113,234,45,246,29,0,0,0,6,3,211,202,105,163,97,74,203,69,161,73,102,200,18,205,158,224,52,199,5,242,15,172,61,175,143,121,108,153,244,216,5,165,253,142,118,26,226,235,158,11,14,77,98,209,149,153,88,111,185,142,138,123,230,252,113,19,68,30,85,111,179,31,248,44,156,234,132,87,199,197,126,65,242,234,243,46,166,97,119,197,11,227,194,64,83,68,66,52,146,13,149,202,60,196,157,0,163,31,110,109,24,100,1,127,156,249,212,139,81,39,72,113,196,112,14,112,145,223,239,20,175,156,146,197,52,2,21,183,216,140,200,32,33,136,227,131,123,23,29,186,20,255,237,232,241,69,178,200,124,29,188,54,66,102,153,48,81,121,88,251,117,66,156,69,172,170,81,196,22,178,131,96,77,81,95,128,249,93,219,79,97,14,141,219,120,118,152,87,19,135,118,2,175,0],"block_header":[0,224,228,44,50,91,136,90,53,184,101,89,134,219,136,40,143,2,100,212,246,127,92,201,14,109,13,17,39,0,0,0,0,0,0,0,105,173,156,82,17,65,101,68,32,6,152,112,104,119,198,46,124,201,58,41,245,245,163,29,5,181,212,9,82,121,206,125,61,49,81,99,192,255,63,25,113,234,45,246]}"##;

    #[tokio::test]
    #[ignore = "requires TRUSTCHAIN_DATA and TRUSTCHAIN_CONFIG environment variables"]
    async fn test_not_found() {
        let app = TrustchainRouter::from(HTTPConfig::default()).into_router();
        let uri = "/nonexistent-path".to_string();
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), 404);
    }

    #[tokio::test]
    #[ignore = "requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_resolve_did() {
        let app = TrustchainRouter::from(HTTPConfig::default()).into_router();
        let uri = "/did/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string();
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            canonicalize_str::<ResolutionResult>(&response.text().await).unwrap(),
            canonicalize_str::<ResolutionResult>(TEST_ROOT_PLUS_2_RESOLVED).unwrap()
        );
        let invalid_uri =
            "/did/did:ion:test:invalid_did__AsM3tgCut3OiBY4ekHTf__invalid_did".to_string();
        let response = client.get(&invalid_uri).send().await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        assert_eq!(
            response.text().await,
            r#"{"error":"Trustchain Resolver error: DID: did:ion:test:invalid_did__AsM3tgCut3OiBY4ekHTf__invalid_did does not exist."}"#
        )
    }

    #[tokio::test]
    #[ignore = "requires ION, MongoDB, IPFS and Bitcoin RPC"]
    async fn test_resolve_chain() {
        let app = TrustchainRouter::from(HTTPConfig::default()).into_router();
        let root_event_time = 1666265405;
        let uri = format!("/did/chain/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q?root_event_time={root_event_time}");
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            canonicalize_str::<DIDChainResolutionResult>(&response.text().await).unwrap(),
            canonicalize_str::<DIDChainResolutionResult>(TEST_ROOT_PLUS_2_CHAIN).unwrap()
        );

        // Test for case where incorrect root_event_time for the root of the given DID, expected to
        // return Ok but with a JSON containing the wrapped Trustchain error.
        let incorrect_root_event_time = 1234500;
        let uri_incorrect_root = format!(
            "/did/chain/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q?root_event_time={incorrect_root_event_time}"
        )
        .to_string();
        let response = client.get(&uri_incorrect_root).send().await;
        assert_eq!(response.status(), StatusCode::OK);
        // A wrapped CommitmentError is now returned here mapped to VerifierError::InvalidRoot
        // println!("{}", response.text().await);
        assert!(response
            .text()
            .await
            .starts_with(r#"{"error":"Trustchain Verifier error: Invalid root DID error:"#),)
    }

    #[tokio::test]
    #[ignore = "requires ION, MongoDB, IPFS and Bitcoin RPC"]
    // Test of the bundle endpoint by using the verifier `fetch_bundle()` method to get from the endpoint
    async fn test_get_bundle() {
        let app = TrustchainRouter::from(HTTPConfig::default()).into_router();
        let uri =
            "/did/bundle/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q".to_string();
        let client = TestClient::new(app);
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            canonicalize_str::<VerificationBundle>(&response.text().await).unwrap(),
            canonicalize_str::<VerificationBundle>(TEST_ROOT_PLUS_2_BUNDLE).unwrap()
        );
        // Failing test for non-existent DID
        let uri =
            "/did/bundle/did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65A".to_string();
        let response = client.get(&uri).send().await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.text().await,
            r#"{"error":"Trustchain Verifier error: A resolver error during verification."}"#
                .to_string()
        );
    }

    #[tokio::test]
    #[ignore = "requires ION, MongoDB, IPFS and Bitcoin RPC"]
    // Test of the bundle endpoint by using the verifier `fetch_bundle()` method to get from the endpoint
    async fn test_fetch_bundle() {
        // Using internals of the `TestClient` to make address available in test
        let listener = TcpListener::bind("127.0.0.1:0").expect("Could not bind ephemeral socket");
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        let http_config = HTTPConfig {
            port,
            ..Default::default()
        };
        assert_eq!(http_config.host.to_string(), addr.ip().to_string());

        // Run server
        tokio::spawn(async move {
            let server = Server::from_tcp(listener).unwrap().serve(Shared::new(
                TrustchainRouter::from(http_config).into_router(),
            ));
            server.await.expect("server error");
        });

        // Make a verifier instance and fetch bundle from server bundle endpoint
        let verifier = IONVerifier::with_endpoint(
            get_ion_resolver("http://localhost:3000/"),
            format!("http://127.0.0.1:{}/", port),
        );
        let did = "did:ion:test:EiBcLZcELCKKtmun_CUImSlb2wcxK5eM8YXSq3MrqNe5wA";
        // Check verification
        let root_event_time = 1666971942;
        verifier.verify(did, root_event_time).await.unwrap();
        // Check verification for another root
        let root_event_time = 1666265405;
        verifier
            .verify(
                "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
                root_event_time,
            )
            .await
            .unwrap();
    }
}

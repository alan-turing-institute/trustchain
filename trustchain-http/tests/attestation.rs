/// Integration test for attestation challenge-response process.
use trustchain_core::verifier::Verifier;
use trustchain_core::TRUSTCHAIN_DATA;
use trustchain_http::attestation_encryption_utils::ssi_to_josekit_jwk;
use trustchain_http::attestation_utils::{ElementwiseSerializeDeserialize, IdentityCRInitiation};
use trustchain_http::attestor::present_identity_challenge;
use trustchain_http::requester::{
    identity_response, initiate_content_challenge, initiate_identity_challenge,
};

use trustchain_ion::{trustchain_resolver, verifier::TrustchainVerifier};

// The root event time of DID documents used in integration test below.
const ROOT_EVENT_TIME_1: u64 = 1666265405;

use hyper::Server;
use mockall::automock;
use std::fs;
use std::{net::TcpListener, path::PathBuf};
use tower::make::Shared;
use trustchain_core::utils::{extract_keys, init};
use trustchain_http::{config::HTTPConfig, server::TrustchainRouter};

#[automock]
pub trait AttestationUtils {
    fn attestation_request_path(&self) -> String;
}
// TODO: fix so can be used for all HTTP tests
/// Init for HTTP crate
// static INIT_HTTP: Once = Once::new();
// lazy_static! {
//     static ref HANDLE =
// }
use tokio::task::JoinHandle;
async fn start_server() -> JoinHandle<()> {
    let listener = TcpListener::bind("127.0.0.1:8081").expect("Could not bind ephemeral socket");
    let addr = listener.local_addr().unwrap();
    let port = addr.port();
    let http_config = HTTPConfig {
        port,
        server_did: Some("did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A".to_string()),
        root_event_time: Some(ROOT_EVENT_TIME_1),
        ..Default::default()
    };
    // Run server
    tokio::spawn(async move {
        let server = Server::from_tcp(listener).unwrap().serve(Shared::new(
            TrustchainRouter::from(http_config).into_router(),
        ));
        server.await.expect("server error");
    })
}
// use lazy_static::lazy_static;
// use std::future::Future;
// lazy_static! {
//     pub static ref HANDLE: impl Future<Output = JoinHandle<()>> = start_server();
// }

#[tokio::test]
#[ignore]
async fn attestation_challenge_response() {
    // Set-up: init test paths, get upstream info
    // init_http();
    init();
    start_server().await;
    // |--------------------------------------------------------------|
    // |------------| Part 1: identity challenge-response |------------|
    // |--------------------------------------------------------------|

    // |------------| requester |------------|
    // Use ROOT_PLUS_1 as attestor. Run server on localhost:8081.
    let attestor_did = "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A";
    let resolver = trustchain_resolver("http://localhost:8081/");
    let verifier = TrustchainVerifier::new(resolver);
    let resolver = verifier.resolver();
    // Verify the attestor did to make sure we can trust the endpoint.
    let result = verifier.verify(attestor_did, ROOT_EVENT_TIME_1).await;
    assert!(result.is_ok());
    // Resolve did document.
    let result = resolver.resolve_as_result(attestor_did).await;
    assert!(result.is_ok());
    // Get services from did document.
    let (_, attestor_doc, _) = result.unwrap();
    let attestor_doc = attestor_doc.as_ref().unwrap();
    let services = attestor_doc.service.as_ref().unwrap();

    // Part 1.1: The requester initiates the attestation request (identity initiation).
    // The requester generates a temporary key pair and sends the public key to the attestor via
    // a POST request, together with the organization name and operator name.
    let expected_org_name = String::from("My Org");
    let expected_operator_name = String::from("Some Operator");

    let result =
        initiate_identity_challenge(&expected_org_name, &expected_operator_name, &services).await;
    assert!(result.is_ok());

    // |------------| attestor |------------|
    // Part 1.2: check the serialized data matches that received in 1.1. In deployment, this step is
    // done manually using `trustchain-cli`, where the attestor has to confirm that they recognize
    // the requester and that they want to proceed with challenge-response process
    // for attestation.
    let path = std::env::var(TRUSTCHAIN_DATA).unwrap();
    let attestation_requests_path = PathBuf::from(path).join("attestation_requests");

    // For the test, there should be only one attestation request (subdirectory).
    let paths = fs::read_dir(attestation_requests_path).unwrap();
    let request_path: PathBuf = paths.map(|path| path.unwrap().path()).collect();

    // Deserialized received information and check that it is correct.
    let identity_initiation = IdentityCRInitiation::new()
        .elementwise_deserialize(&request_path)
        .unwrap()
        .unwrap();
    let org_name = identity_initiation
        .requester_details
        .clone()
        .unwrap()
        .requester_org;
    let operator_name = identity_initiation
        .requester_details
        .clone()
        .unwrap()
        .operator_name;
    assert_eq!(expected_org_name, org_name);
    assert_eq!(expected_operator_name, operator_name);
    // If data matches, proceed with presenting signed and encrypted identity challenge payload.
    let temp_p_key = identity_initiation.clone().temp_p_key.unwrap();
    let identity_challenge_attestor =
        present_identity_challenge(&attestor_did, &temp_p_key).unwrap();
    let payload = identity_challenge_attestor
        .identity_challenge_signature
        .as_ref()
        .unwrap();

    // Write payload as requester (this step would done manually or by GUI, since in deployment
    // challenge payload is sent via alternative channel) for use in subsequent response.
    // However, as nonce for verifying response is required in part 1.3, serialise
    // full struct instead.
    identity_challenge_attestor
        .elementwise_serialize(&request_path)
        .unwrap();

    // Part 1.3: Requester responds to challenge. The received challenge is first decrypted and
    // verified, before the requester signs the challenge nonce and encrypts it with the attestor's
    // public key. This response is sent to attestor via a POST request.
    // Upon receiving the request, the attestor decrypts the response and verifies the signature,
    // before comparing the nonce from the response with the nonce from the challenge.
    // |------------| requester |------------|
    let public_keys = extract_keys(&attestor_doc);
    let attestor_public_key_ssi = public_keys.first().unwrap();
    let attestor_public_key = ssi_to_josekit_jwk(attestor_public_key_ssi).unwrap();

    // Check nonce component is captured with the response being Ok
    let result = identity_response(&request_path, &services, &attestor_public_key).await;
    assert!(result.is_ok());

    // |--------------------------------------------------------------|
    // |------------| Part 2: content challenge-response |------------|
    // |--------------------------------------------------------------|
    //
    // |------------| requester |------------|
    // After publishing a candidate DID (dDID) to be attested to (not covered in this test),
    // the requester initiates the content challenge-response process by a POST with the dDID to the
    // attestor's endpoint.
    // Upon receiving the POST request the attestor resolves dDID, extracts the signing keys from it
    // and returns to the requester a signed and encrypted challenge payload with a hashmap that
    // contains an encrypted nonce per signing key.
    // The requester decrypts the challenge payload and verifies the signature. It then decrypts
    // each nonce with the corresponding signing key and collects them in a hashmap. This
    // hashmap is signed and encrypted and sent back to the attestor via POST request.
    // The attestor decrypts the response and verifies the signature. It then compares the received
    // hashmap of nonces with the one sent to requester.
    // The entire process is automated and is kicked off with the content CR initiation request.
    let requester_did = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q";
    // let requester_did = "did:ion:test:EiCDmY0qxsde9AdIwMf2tUKOiMo4aHnoWaPBRCeGt7iMHA";
    let result = initiate_content_challenge(
        &request_path,
        requester_did,
        &services,
        &attestor_public_key,
    )
    .await;
    // Check nonces is captured with the response being Ok
    assert!(result.is_ok());
}

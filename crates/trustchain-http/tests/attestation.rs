//! Integration test for attestation challenge-response process.
use port_check::is_port_reachable;
use tokio::runtime::Runtime;
use trustchain_core::verifier::Verifier;
use trustchain_http::attestation_encryption_utils::{josekit_to_ssi_jwk, ssi_to_josekit_jwk};
use trustchain_http::attestation_utils::{
    attestation_request_path, CRState, ElementwiseSerializeDeserialize, IdentityCRChallenge,
    IdentityCRInitiation,
};
use trustchain_http::attestor::present_identity_challenge;
use trustchain_http::config::HTTPConfig;
use trustchain_http::requester::{
    identity_response, initiate_content_challenge, initiate_identity_challenge,
};

use trustchain_ion::{trustchain_resolver, verifier::TrustchainVerifier};

// The root event time of DID documents used in integration test below.
const ROOT_EVENT_TIME_1: u64 = 1666265405;

use mockall::automock;
use trustchain_core::utils::extract_keys;
use trustchain_ion::utils::init;

#[automock]
pub trait AttestationUtils {
    fn attestation_request_path(&self) -> String;
}

fn init_http() {
    init();
    assert!(
        !is_port_reachable("127.0.0.1:8081"),
        "Port 8081 is required for Challenge-Response integration test but 8081 is already in use."
    );
    let http_config = HTTPConfig {
        host: "127.0.0.1".parse().unwrap(),
        port: 8081,
        server_did: Some("did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A".to_owned()),
        root_event_time: Some(1666265405),
        ..Default::default()
    };

    // Run test server in own thread
    std::thread::spawn(|| {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            trustchain_http::server::http_server(http_config)
                .await
                .unwrap();
        });
    });
}

#[tokio::test]
#[ignore]
async fn attestation_challenge_response() {
    // Set-up: init test paths, get upstream info
    init_http();

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
        initiate_identity_challenge(&expected_org_name, &expected_operator_name, services).await;
    // Make sure initiation was successful and information is complete before serializing.
    assert!(result.is_ok());
    let (identity_initiation_requester, requester_path) = result.unwrap();
    let result = identity_initiation_requester.elementwise_serialize(&requester_path);
    assert!(result.is_ok());

    // |------------| attestor |------------|
    // Part 1.2: check the serialized data matches that received in 1.1. In deployment, this step is
    // done manually using `trustchain-cli`, where the attestor has to confirm that they recognize
    // the requester and that they want to proceed with challenge-response process
    // for attestation.
    let temp_p_key =
        josekit_to_ssi_jwk(&identity_initiation_requester.clone().temp_p_key.unwrap()).unwrap();
    let attestor_path = attestation_request_path(&temp_p_key, "attestor").unwrap();

    // Deserialized received information and check that it is correct.
    let identity_initiation_attestor = IdentityCRInitiation::new()
        .elementwise_deserialize(&attestor_path)
        .unwrap()
        .unwrap();
    // Make sure that attestor has all required information about initiation (but not secret key).
    assert!(identity_initiation_attestor.is_complete());
    assert!(identity_initiation_attestor.temp_s_key.is_none());
    let org_name = identity_initiation_attestor
        .requester_details
        .clone()
        .unwrap()
        .requester_org;
    let operator_name = identity_initiation_attestor
        .requester_details
        .clone()
        .unwrap()
        .operator_name;
    assert_eq!(expected_org_name, org_name);
    assert_eq!(expected_operator_name, operator_name);

    // If data matches, proceed with presenting signed and encrypted identity challenge payload.
    let temp_p_key = identity_initiation_attestor.clone().temp_p_key.unwrap();
    let result = present_identity_challenge(attestor_did, &temp_p_key);
    assert!(result.is_ok());
    let identity_challenge_attestor = result.unwrap();
    let _ = identity_challenge_attestor.elementwise_serialize(&attestor_path);

    // |------------| requester |------------|
    // Write signed and encrypted challenge to file to requester path (this step would done manually
    // or by GUI, since in deployment
    // challenge is sent via alternative channel) for use in subsequent response.
    let identity_challenge_requester = IdentityCRChallenge {
        update_p_key: None,
        update_s_key: None,
        identity_challenge_signature: identity_challenge_attestor.identity_challenge_signature,
        identity_nonce: None,
        identity_response_signature: None,
    };
    identity_challenge_requester
        .elementwise_serialize(&requester_path)
        .unwrap();

    // Part 1.3: Requester responds to challenge. The received challenge is first decrypted and
    // verified, before the requester signs the challenge nonce and encrypts it with the attestor's
    // public key. This response is sent to attestor via a POST request.
    // Upon receiving the request, the attestor decrypts the response and verifies the signature,
    // before comparing the nonce from the response with the nonce from the challenge.

    let public_keys = extract_keys(attestor_doc);
    let attestor_public_key_ssi = public_keys.first().unwrap();
    let attestor_public_key = ssi_to_josekit_jwk(attestor_public_key_ssi).unwrap();

    // Check nonce component is captured with the response being Ok
    let result = identity_response(&requester_path, services, &attestor_public_key).await;
    assert!(result.is_ok());
    let identity_challenge_requester = result.unwrap();
    identity_challenge_requester
        .elementwise_serialize(&requester_path)
        .unwrap();

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
    // contains an encrypted nonce pecurr signing key.
    // The requester decrypts the challenge payload and verifies the signature. It then decrypts
    // each nonce with the corresponding signing key and collects them in a hashmap. This
    // hashmap is signed and encrypted and sent back to the attestor via POST request.
    // The attestor decrypts the response and verifies the signature. It then compares the received
    // hashmap of nonces with the one sent to requester.
    // The entire process is automated and is kicked off with the content CR initiation request.
    // let requester_did = "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q";
    let requester_did = "did:ion:test:EiCDmY0qxsde9AdIwMf2tUKOiMo4aHnoWaPBRCeGt7iMHA";
    let result = initiate_content_challenge(
        &requester_path,
        requester_did,
        services,
        &attestor_public_key,
    )
    .await;
    // Check nonces is captured with the response being Ok
    assert!(result.is_ok());
    let (content_cr_initiation, content_cr_challenge) = result.unwrap();
    content_cr_initiation
        .elementwise_serialize(&requester_path)
        .unwrap();
    content_cr_challenge
        .elementwise_serialize(&requester_path)
        .unwrap();

    // Check that requester has all attestation challenge-response information it should have.
    let cr_state_requester = CRState::new()
        .elementwise_deserialize(&requester_path)
        .unwrap()
        .unwrap();
    let result = cr_state_requester.is_complete();
    assert!(result);

    // Check that requester has temp_s_key but not update_s_key.
    assert!(cr_state_requester
        .identity_cr_initiation
        .unwrap()
        .temp_s_key
        .is_some());
    assert!(cr_state_requester
        .identity_challenge_response
        .unwrap()
        .update_s_key
        .is_none());

    // |------------| attestor |------------|
    // Check that attestor has all attestation challenge-response information it should have.
    let cr_state_attestor = CRState::new()
        .elementwise_deserialize(&attestor_path)
        .unwrap()
        .unwrap();
    let result = cr_state_attestor.is_complete();
    assert!(result);
    // Check that attestor does not have temp_s_key but update_s_key.
    assert!(cr_state_attestor
        .identity_cr_initiation
        .unwrap()
        .temp_s_key
        .is_none());
    assert!(cr_state_attestor
        .identity_challenge_response
        .unwrap()
        .update_s_key
        .is_some());
}

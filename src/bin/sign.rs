use clap::{arg, command, Arg, ArgAction};
// use serde_json::{to_string_pretty as to_json}
use serde_json::{Map, Value};
use std::convert::TryFrom;

use did_ion::sidetree::DIDStatePatch;
use did_ion::sidetree::PublicKeyJwk;
use did_ion::sidetree::{DIDSuffix, Operation, ServiceEndpointEntry, Sidetree};
use did_ion::{sidetree::SidetreeClient, ION};

use ssi::did::{Document, ServiceEndpoint};
use ssi::jwk::JWK;

use trustchain::controller::{Controller, TrustchainController};
use trustchain::resolver::{DIDMethodWrapper, Resolver};
use trustchain::subject::{SubjectError, TrustchainSubject};

// Type aliases
pub type IONResolver = Resolver<DIDMethodWrapper<SidetreeClient<ION>>>;

// Check resolver implementation, get the proof service ID if single proof service present,
// Otherwise return nothing/error
fn get_proof_service_id(doc: &Document) -> Option<String> {
    todo!()
}

// Function to get private key with a given key id
fn get_key(tc_subject: &TrustchainSubject, key_id: usize) -> Result<&JWK, SubjectError> {
    todo!()
}

/// Function to return a patch for adding a proof service
fn add_proof_service(did: &str, proof: &str) -> DIDStatePatch {
    let mut obj: Map<String, Value> = Map::new();
    obj.insert("controller".to_string(), Value::from(did));
    obj.insert("proofValue".to_string(), Value::from(proof.to_owned()));
    DIDStatePatch::AddServices {
        services: vec![ServiceEndpointEntry {
            id: "trustchain-controller-proof".to_string(),
            r#type: "TrustchainProofService".to_string(),
            service_endpoint: ServiceEndpoint::Map(serde_json::Value::Object(obj.clone())),
        }],
    }
}

// Binary to resolve a controlled DID, attest to its contents and perform an update
// operation on the controlled DID to add the attestation proof within a service endpoint.
fn main() {
    // CLI pass: verbose, did, controlled_did
    let matches = command!()
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!(-d --did <DID>)
                .default_value("did:ion:test:EiA8yZGuDKbcnmPRs9ywaCsoE2FT9HMuyD9WmOiQasxBBg")
                .required(false),
        )
        .arg(
            arg!(-c --controlled_did <CONTROLLED_DID>)
                .default_value("did:ion:test:EiA8yZGuDKbcnmPRs9ywaCsoE2FT9HMuyD9WmOiQasxBBg")
                .required(false),
        )
        .get_matches();

    // 1.0. Get the did to sign and controller to sign it
    let did = matches.get_one::<String>("did").unwrap();
    let controlled_did = matches.get_one::<String>("controlled_did").unwrap();

    // 1.1. Load controller from passed controlled_did to be signed and controller DID
    let controller = match TrustchainController::new(&did, &controlled_did) {
        Ok(x) => x,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    // 1.2. Resolve controlled_did document with Trustchain resolver
    // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
    let resolver = IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(
        "http://localhost:3000/",
    ))));

    // Extract resolution items
    let (res, doc, doc_meta) = match resolver.resolve_as_result(&controlled_did) {
        Ok((res, Some(doc), Some(doc_meta))) => (res, doc, doc_meta),
        Err(e) => {
            println!("{}", e);
            return;
        }
        _ => return,
    };

    // 2: Make required patches
    let mut patches: Vec<DIDStatePatch> = Vec::<DIDStatePatch>::new();

    // 2.1 If Trustchain proof already present, add RemoveService patch, and remove
    //     this service from Doc to be signed
    // TODO: use fn from resolver (e.g. make it pub),
    if let Some(proof_service_id) = get_proof_service_id(&doc) {
        patches.push(DIDStatePatch::RemoveServices {
            ids: vec![proof_service_id],
        });
    }

    // 2.2. Controller performs attestation to Document to generate proof data
    // TODO: write fn get_key() to extract key_id
    let key_id = 0;
    let key = match get_key(&controller.to_subject(), key_id) {
        Ok(key) => key,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };
    let proof_result = controller.attest(&doc, key);

    // 2.3. Proof service is constructed from the proof data and make an AddService patch
    if let Ok(proof) = proof_result {
        patches.push(add_proof_service(&did, &proof))
    }

    // TODO: handle the unwraps in 2.4 and 2.5
    // 2.4  Generate new update key
    controller.generate_next_update_key();
    let next_update_pk = controller.next_update_key().to_public();

    // 2.4. Create update operation including all patches constructed
    let update_operation = ION::update(
        DIDSuffix(controlled_did.to_owned()),
        &controller.update_key(),
        &PublicKeyJwk::try_from(next_update_pk).unwrap(),
        patches,
    );

    // 3. Either publish the update operation using the publisher or write to JSON file
    //    and publish with `curl`.
    let operation = Operation::Update(update_operation.unwrap().clone());

    // TODO: perform publish with publisher

    // 4. Once the operation is no longer queued (or wait until published?) commit the new_update_key to replace the previous
    // TODO
}

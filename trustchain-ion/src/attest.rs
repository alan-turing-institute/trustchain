use did_ion::sidetree::DIDStatePatch;
use did_ion::sidetree::PublicKeyJwk;
use did_ion::sidetree::{DIDSuffix, Operation, Sidetree};
use did_ion::ION;
use serde_json::to_string_pretty as to_json;
use std::convert::TryFrom;
use trustchain_core::controller::Controller;
use trustchain_core::key_manager::{ControllerKeyManager, KeyType};
use trustchain_core::subject::Subject;
use trustchain_core::utils::get_operations_path;

use crate::controller::IONController;
use crate::test_resolver;

// Binary to resolve a controlled DID, attest to its contents and perform an update
// operation on the controlled DID to add the attestation proof within a service endpoint.
pub fn main_attest(
    did: &str,
    controlled_did: &str,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1.1. Load controller from passed controlled_did to be signed and controller DID
    let controller = match IONController::new(did, controlled_did) {
        Ok(x) => x,
        Err(e) => {
            println!("{}", e);
            return Err(e);
        }
    };

    if verbose {
        println!("DID: {}", controller.did());
        println!("Controlled DID: {}", controller.controlled_did());
    }

    // 1.2. Resolve controlled_did document with Trustchain resolver
    // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
    let resolver = test_resolver("http://localhost:3000/");

    // Extract resolution items
    let (_, doc, doc_meta) = match resolver.resolve_as_result(controlled_did) {
        Ok((res, Some(doc), Some(doc_meta))) => (res, doc, doc_meta),
        Err(e) => {
            println!("{}", e);
            return Err(Box::new(e));
        }
        _ => panic!(),
    };

    // 1.3 Check whether a present `next_update_key` matches the update commitment
    // TODO: This step should be refactored into a general library functionality for
    // recovery keys too and use in other update processes.
    if let Ok(Some(key)) = controller.next_update_key() {
        // Check whether the key matches the update commitment
        if controller.is_commitment_key(&doc_meta, &key, KeyType::NextUpdateKey) {
            // Set update_key as next_update_key (save to file, delete next_update_key)
            controller.apply_next_update_key(controller.controlled_did_suffix(), &key)?;
        } else {
            panic!("'update_commitment' value is not compatible with 'next_update_key'.");
        }
    }

    // 2: Make required patches
    let mut patches: Vec<DIDStatePatch> = Vec::<DIDStatePatch>::new();

    // 2.1: Add RemoveService patch if Trustchain proof already present
    if controller.is_proof_in_doc_meta(&doc_meta) {
        patches.push(DIDStatePatch::RemoveServices {
            ids: vec!["trustchain-controller-proof".to_string()],
        });
    }

    // 2.2. Controller performs attestation to Document to generate proof data
    // Sign the document from the controller using the "Attestor" trait method
    let proof = controller.to_attestor().attest(&doc, None)?;

    // 2.3. Proof service is constructed from the proof data and make an AddService patch
    patches.push(controller.add_proof_service(controller.did(), &proof));

    // 2.4  Generate new update key
    controller.generate_next_update_key()?;

    // Store update key
    let update_key = controller.update_key();
    let next_update_pk = match controller.next_update_key() {
        Ok(Some(key)) => key.to_public(),
        _ => panic!(),
    };

    // 2.4. Create update operation including all patches constructed
    // DIDSuffix gives the hased suffix data only from full string.
    let update_operation = ION::update(
        DIDSuffix(controller.controlled_did_suffix().to_string()),
        &update_key.unwrap(),
        &PublicKeyJwk::try_from(next_update_pk).unwrap(),
        patches,
    )?;

    // 3. Construct operation and save to file in operations path
    // 3.1: Construct operation
    let operation = Operation::Update(update_operation);

    // 3.2: Save operation
    let path = get_operations_path()?;
    let path = path.join(format!(
        "attest_operation_{}.json",
        controller.controlled_did_suffix()
    ));
    std::fs::write(path, to_json(&operation).unwrap())?;

    Ok(())
}

use did_ion::sidetree::DIDStatePatch;
use did_ion::sidetree::PublicKeyJwk;
use did_ion::sidetree::{DIDSuffix, Operation, Sidetree};
use did_ion::{sidetree::SidetreeClient, ION};
use serde_json::to_string_pretty as to_json;
use std::convert::TryFrom;
use std::path::Path;
use trustchain_core::controller::Controller;
use trustchain_core::key_manager::{ControllerKeyManager, KeyType};
use trustchain_core::Subject;
use trustchain_core::TRUSTCHAIN_DATA;

use crate::controller::IONController;
use trustchain_core::resolver::{DIDMethodWrapper, Resolver};

/// Type aliases
pub type IONResolver = Resolver<DIDMethodWrapper<SidetreeClient<ION>>>;

/// Check resolver implementation, get the proof service ID if single proof service present,
/// Otherwise return nothing/error
// fn get_proof_service_id(doc: &Document) -> Option<String> {
// todo!()
// }

// {
//    "canonicalId" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
//    "method" : {
//       "published" : true,
//       "recoveryCommitment" : "EiBKWQyomumgZvqiRVZnqwA2-7RVZ6Xr-cwDRmeXJT_k9g",
//       "updateCommitment" : "EiCe3q-ZByJnzI6CwGIDj-M67W-Yv78L3ejxcuEDxnWzMg"
//    },
//    "proof" : {
//       "id" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
//       "type" : "JsonWebSignature2020",
//       "proofValue" : "eyJhbGciOiJFUzI1NksifQ.IkVpQmNiTkRRcjZZNHNzZGc5QXo4eC1qNy1yS1FuNWk5T2Q2S3BjZ2c0RU1KOXci.Nii8p38DtzyurmPHO9sV2JLSH7-Pv-dCKQ0Y-H34rplwhhwca2nSra4ZofcUsHCG6u1oKJ0x4AmMUD2_3UIhRA"
//   }
// }

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

    // TODO: testing print
    // println!("===============");
    // println!("{}", controller.did());
    // println!("{}", controller.controlled_did());
    // println!("{}", did);
    // println!("{}", controlled_did);
    // println!("{}", did_suffix);
    // println!("{}", controlled_did_suffix);
    // println!("===============");

    // 1.2. Resolve controlled_did document with Trustchain resolver
    // Construct a Trustchain Resolver from a Sidetree (ION) DIDMethod.
    let resolver = IONResolver::from(SidetreeClient::<ION>::new(Some(String::from(
        "http://localhost:3000/",
    ))));

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
    // TODO: check next_update_key() returns an option
    if let Ok(Some(key)) = controller.next_update_key() {
        // Check whether the key matches the update commitment
        if controller.is_commitment_key(&doc_meta, &key, KeyType::NextUpdateKey) {
            // Set update_key as next_update_key (save to file, delete next_update_key)
            // TODO: compelete; consider adding functionality directly to key_manager
            // controller.apply_next_update_key()
            controller
                .apply_next_update_key(controller.controlled_did_suffix(), &key)
                .unwrap();
        } else {
            // update_commitment value is not related to next_update_key, don't continue
            panic!();
        }
    }

    // 2: Make required patches
    let mut patches: Vec<DIDStatePatch> = Vec::<DIDStatePatch>::new();

    // 2.1 If Trustchain proof already present, add RemoveService patch, and remove
    //     this service from Doc to be signed
    // TODO: use fn from resolver (e.g. make it pub),

    // TODO: this should not be in the sign, a proof should be removed when a content
    // update is performed
    // Check if proof in document metadata
    if controller.is_proof_in_doc_meta(&doc_meta) {
        patches.push(DIDStatePatch::RemoveServices {
            ids: vec!["trustchain-controller-proof".to_string()],
        });
    }

    // 2.2. Controller performs attestation to Document to generate proof data
    // Sign the document from the controller using the "Attestor" trait method
    let proof_result = controller.to_attestor().attest(&doc, None);

    // 2.3. Proof service is constructed from the proof data and make an AddService patch
    if let Ok(proof) = proof_result {
        patches.push(controller.add_proof_service(controller.did(), &proof));
    } else {
        return Err(Box::new(proof_result.err().unwrap()));
    }

    // TODO: handle the unwraps in 2.4 and 2.5
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
    );

    // 3. Either publish the update operation using the publisher or write to JSON file
    //    and publish with `curl`.
    let operation = Operation::Update(update_operation.unwrap());

    // TODO: perform publish with publisher

    // 4. Once the operation is no longer queued (or wait until published?) commit the new_update_key to replace the previous
    // TODO

    // 4.1 Save operation to file
    // Get environment for TRUSTCHAIN_DATA
    let path: String = match std::env::var(TRUSTCHAIN_DATA) {
        Ok(val) => val,
        Err(_) => panic!(),
    };

    // Make directory name
    let path = Path::new(path.as_str()).join("operations").join(format!(
        "attest_operation_{}.json",
        controller.controlled_did_suffix()
    ));
    std::fs::write(path, to_json(&operation).unwrap())?;

    Ok(())
}

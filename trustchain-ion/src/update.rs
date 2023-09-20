//! ION operation for DID update.
use crate::controller::IONController;
use did_ion::sidetree::PublicKeyJwk;
use did_ion::sidetree::{DIDStatePatch, DIDSuffix};
use did_ion::sidetree::{Operation, Sidetree, SidetreeOperation};
use did_ion::ION;
use ssi::did_resolve::DIDResolver;
use std::convert::TryFrom;
use trustchain_core::controller::Controller;
use trustchain_core::key_manager::KeyManagerError;
use trustchain_core::utils::get_operations_path;

/// Makes a new DID subject to be controlled with correspondong create operation written to file.
pub async fn update_operation(
    patches: Vec<DIDStatePatch>,
    did: &str,
    controlled_did: &str,
    resolver: &dyn DIDResolver,
    verbose: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let controller = IONController::new(did, controlled_did)?;
    // Check and apply current next_update_key given current resolution of controlled DID
    controller.check_and_apply_next_update_key(resolver).await?;
    // Generate a new next_update_key (does not overwrite by default). TODO: add API to overwrite.
    controller.generate_next_update_key()?;
    let update_key = controller.update_key();
    let next_update_pk = controller
        .next_update_key()?
        .ok_or(KeyManagerError::FailedToLoadKey)?
        .to_public();

    // Create update operation
    let operation = Operation::Update(ION::update(
        DIDSuffix(controller.controlled_did_suffix().to_string()),
        &update_key.unwrap(),
        &PublicKeyJwk::try_from(next_update_pk).unwrap(),
        patches,
    )?);
    // Partial verify
    operation.clone().partial_verify::<ION>()?;

    // TODO: Refactor into OperationManager trait (#48)
    let path = get_operations_path()?;
    let path = path.join(format!(
        "update_operation_{}.json",
        controller.controlled_did_suffix()
    ));
    std::fs::write(
        path.clone(),
        serde_json::to_string_pretty(&operation).unwrap(),
    )?;
    if verbose {
        println!(
            "Update operation:\n{}",
            serde_json::to_string_pretty(&operation).unwrap()
        );
        println!("Path: {:?}", path);
    }
    Ok(path.to_string_lossy().to_string())
}

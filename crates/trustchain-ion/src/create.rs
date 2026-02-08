//! ION operation for DID creation.
use crate::attestor::{AttestorData, IONAttestor};
use crate::controller::{ControllerData, IONController};
use crate::ion::IONTest as ION;
use crate::mnemonic::IONKeys;
use crate::CREATE_OPERATION_FILENAME_PREFIX;
use bip39::Mnemonic;
use did_ion::sidetree::{CreateOperation, DIDStatePatch};
use did_ion::sidetree::{DocumentState, PublicKeyEntry, PublicKeyJwk};
use did_ion::sidetree::{Operation, Sidetree, SidetreeDID, SidetreeOperation};
use serde_json::to_string_pretty as to_json;
use ssi::jwk::JWK;
use ssi::one_or_many::OneOrMany;
use std::convert::TryFrom;
use trustchain_core::controller::Controller;
use trustchain_core::utils::{generate_key, get_operations_path};
use trustchain_core::JSON_FILE_EXTENSION;

/// Collection of methods to return DID information from an operation.
pub trait OperationDID {
    /// Associated type for DID method specification such as `ION` for `Sidetree<T>`.
    type T;
    /// Returns the DID suffix.
    fn to_did_suffix(&self) -> String;
    /// Returns the short-form DID.
    fn to_did(&self) -> String;
    /// Returns the long-form DID.
    fn to_did_long(&self) -> String;
}

impl OperationDID for CreateOperation {
    type T = ION;
    fn to_did_suffix(&self) -> String {
        Self::T::serialize_suffix_data(&self.suffix_data)
            .unwrap()
            .to_string()
    }
    fn to_did(&self) -> String {
        self.to_did_long().rsplit_once(':').unwrap().0.to_string()
    }
    fn to_did_long(&self) -> String {
        SidetreeDID::<Self::T>::from_create_operation(self)
            .unwrap()
            .to_string()
    }
}

/// Writes attestor, controller and create operation.
fn write_create_operation(
    create_operation: CreateOperation,
    signing_key: Option<JWK>,
    update_key: JWK,
    recovery_key: JWK,
) -> Result<String, Box<dyn std::error::Error>> {
    // Get DID
    let controlled_did = create_operation.to_did();

    // Make attestor
    if let Some(signing_key) = signing_key {
        IONAttestor::try_from(AttestorData::new(
            controlled_did.to_string(),
            OneOrMany::One(signing_key),
        ))?;
    }

    // Write controller data: DID is arbitrarily set to contolled_did in creation
    let controller = IONController::try_from(ControllerData::new(
        controlled_did.to_string(),
        controlled_did.to_string(),
        update_key,
        recovery_key,
    ))
    .unwrap();

    // Write create operation to push to ION server
    let path = get_operations_path().unwrap();
    let filename = format!(
        "{}{}{}",
        CREATE_OPERATION_FILENAME_PREFIX,
        controller.controlled_did_suffix(),
        JSON_FILE_EXTENSION
    );
    std::fs::write(
        path.join(&filename),
        to_json(&Operation::Create(create_operation)).unwrap(),
    )?;
    Ok(filename)
}

/// Makes a new DID given public signing, update and recovery keys.
fn create_operation_from_keys(
    signing_public_key: &PublicKeyEntry,
    update_public_key: &PublicKeyJwk,
    recovery_public_key: &PublicKeyJwk,
) -> Result<CreateOperation, Box<dyn std::error::Error>> {
    // Create operation: Make the create patch from scratch or passed file
    let document_state = DocumentState {
        public_keys: Some(vec![signing_public_key.to_owned()]),
        services: None,
    };
    let patches = vec![DIDStatePatch::Replace {
        document: document_state,
    }];
    // Make the create operation from patches
    let operation = ION::create_existing(update_public_key, recovery_public_key, patches).unwrap();
    // Verify operation
    operation.clone().partial_verify::<ION>()?;
    let create_operation = match operation.clone() {
        Operation::Create(x) => x,
        _ => panic!(),
    };
    Ok(create_operation)
}

/// Makes a new DID subject to be controlled with corresponding create operation written to file.
pub fn create_operation(
    document_state: Option<DocumentState>,
    verbose: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    // Generate random keys
    let update_key = generate_key();
    let recovery_key = generate_key();
    ION::validate_key(&update_key).unwrap();
    ION::validate_key(&recovery_key).unwrap();
    let update_pk = PublicKeyJwk::try_from(update_key.to_public()).unwrap();
    let recovery_pk = PublicKeyJwk::try_from(recovery_key.to_public()).unwrap();

    // Create operation: Make the create patch from scratch or passed file
    let (document_state, generated_signing_key) = if let Some(mut document_state) = document_state {
        // If no keys loaded, generate a key
        let generated_signing_key: Option<JWK> = if document_state.public_keys.is_none() {
            let generated_signing_key = Some(generate_key());
            let public_key_entry = PublicKeyEntry::try_from(generated_signing_key.clone().unwrap());
            document_state.public_keys = Some(vec![public_key_entry.unwrap()]);
            generated_signing_key
        } else {
            None
        };
        (document_state, generated_signing_key)
    } else {
        // If no document passed, generate key and empty document
        let generated_signing_key = Some(generate_key());
        let public_key_entry = PublicKeyEntry::try_from(generated_signing_key.clone().unwrap());
        (
            DocumentState {
                public_keys: Some(vec![public_key_entry.unwrap()]),
                services: None,
            },
            generated_signing_key,
        )
    };

    // Construct patches
    let patches = vec![DIDStatePatch::Replace {
        document: document_state,
    }];

    // Make the create operation from patches
    let operation = ION::create_existing(&update_pk, &recovery_pk, patches)?;

    // Partially verify operation
    operation.clone().partial_verify::<ION>()?;

    // Extract data from operation
    let create_operation = match operation {
        Operation::Create(x) => x,
        _ => panic!("Operation is not expected 'Create' type."),
    };

    // Get DID information
    let controlled_did_suffix = create_operation.to_did_suffix();
    let controlled_did_long = create_operation.to_did_long();
    let controlled_did = create_operation.to_did();

    // Verbose output
    if verbose {
        println!("Create operation:");
        println!("{}", to_json(&create_operation).unwrap());
        println!("Controlled DID suffix: {:?}", controlled_did_suffix);
        println!("Controlled DID (short-form): {:?}", controlled_did);
        println!("Controlled DID (long-form) : {:?}", controlled_did_long);
    }
    // Write operation and keys
    write_create_operation(
        create_operation,
        generated_signing_key,
        update_key,
        recovery_key,
    )
}

/// Generates a create operation and corresponding keys from a mnemonic.
pub fn mnemonic_to_create_and_keys(
    mnemonic: &str,
    index: Option<u32>,
) -> Result<(CreateOperation, IONKeys), Box<dyn std::error::Error>> {
    let ion_keys = crate::mnemonic::generate_keys(&Mnemonic::parse(mnemonic)?, index)?;
    let signing_public_key = PublicKeyEntry::try_from(ion_keys.signing_key.clone())?;
    let update_public_key = PublicKeyJwk::try_from(ion_keys.update_key.to_public())?;
    let recovery_public_key = PublicKeyJwk::try_from(ion_keys.recovery_key.to_public())?;

    // Construct create operation
    let create_operation = create_operation_from_keys(
        &signing_public_key,
        &update_public_key,
        &recovery_public_key,
    )
    .map_err(|err| err.to_string())?;
    Ok((create_operation, ion_keys))
}

/// Makes a new DID subject to be controlled with corresponding create operation written to file
/// from a mnemonic.
pub fn create_operation_mnemonic(
    mnemonic: &str,
    index: Option<u32>,
) -> Result<String, Box<dyn std::error::Error>> {
    // Generate operation and keys
    let (create_operation, ion_keys) = mnemonic_to_create_and_keys(mnemonic, index)?;

    // Write create operation
    write_create_operation(
        create_operation,
        Some(ion_keys.signing_key),
        ion_keys.update_key,
        ion_keys.recovery_key,
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::init;
    use glob::glob;

    // Test document state for making a create operation from
    const TEST_DOC_STATE: &str = r#"{
        "publicKeys": [
        {
            "id": "Mz94EfSCueClM5qv62SXxtLWRj4Ti7rR2wLWmW37aCs",
            "type": "JsonWebSignature2020",
            "publicKeyJwk": {
            "crv": "secp256k1",
            "kty": "EC",
            "x": "7VKmPezI_VEnMjOPfAeUnpQxhS1sLjAKfd0s7xrmx9A",
            "y": "gWZ5Bo197eZuMh3Se-3rqWCQjZWbuDpOYAaw8yC-yaQ"
            },
            "purposes": [
            "assertionMethod",
            "authentication",
            "keyAgreement",
            "capabilityInvocation",
            "capabilityDelegation"
            ]
        }
        ],
        "services": [
        {
            "id": "trustchain-controller-proof",
            "type": "TrustchainProofService",
            "serviceEndpoint": {
            "controller": "did:ion:test:EiA8yZGuDKbcnmPRs9ywaCsoE2FT9HMuyD9WmOiQasxBBg",
            "proofValue": "dummy_string"
            }
        }
        ]
    }"#;

    #[test]
    fn test_create() -> Result<(), Box<dyn std::error::Error>> {
        init();

        // 1. Run create with no document state passed
        create_operation(None, false)?;

        // 2. Run create with a document state passed
        let doc_state: DocumentState = serde_json::from_reader(TEST_DOC_STATE.as_bytes())?;
        create_operation(Some(doc_state), false)?;

        // Try to read outputted create operations and check they deserialize
        let path = get_operations_path()?;
        let pattern = path.join(format!(
            "{}*{}",
            CREATE_OPERATION_FILENAME_PREFIX, JSON_FILE_EXTENSION
        ));
        let pattern = pattern.into_os_string().into_string().unwrap();
        let paths = glob(pattern.as_str())?;

        let mut operation_count = 0;
        for path in paths {
            if let Ok(path_buf) = path {
                let operation_string = std::fs::read_to_string(path_buf)?;
                let _operation: Operation = serde_json::from_str(&operation_string)?;
                operation_count += 1;
            } else {
                panic!("No path present.");
            }
        }
        // Check two create operations exist.
        assert!(operation_count == 2);
        Ok(())
    }
}

# Usage

This page contains instructions for using the Trustchain command line interface (CLI).

Depending on your role within the network of Trustchain users you may need to perform some or all of the operations described below. For more information, see the [User Roles](roles.md) page.

!!! info "Prerequisites"

    To use the Trustchain CLI, first make sure that you have followed the installation and configuration instructions on the [Getting Started](getting-started.md) page.

    Also, your ION node will need to be up and running. Instructions for restarting ION can be found [here](ion.md#restarting-ion).

## Trustchain CLI

To invoke the Trustchain CLI, open a Terminal and run this command:
``` bash
trustchain-cli
```
You should see a list of available commands and some usage hints.

If instead you get an error that `trustchain-cli` command is not found, make sure you have followed all of the installation steps on the [Getting Started](getting-started.md) page.

The CLI is organised into a set of subcommands for different types of operation:

| Subcommand    | Description       |
| ------------- | ----------------- |
| `did`         | DID functionality: create, attest, resolve, verify.   |
| `vc`          | Verifiable credential functionality: sign and verify. |
| `data`        | Data provenance functionality: sign and verify.       |

To get help with a particular subcommand, use the `--help` flag (or `-h` for short). For example, to get help with the CLI commands relating to DIDs:
``` bash
trustchain-cli did --help
```

## DID Resolution

DID Resolution is a process defined in the [W3C standard](https://www.w3.org/TR/did-core/#did-resolution) for Decentralised Identifiers (DIDs).

It takes as input a DID (string identifier) and returns the corresponding DID document, containing the public keys and service endpoints (URLs) that belong to the legal entity referred to by the DID.

To resolve a DID using the Trustchain CLI, execute this command replacing `<DID>` with the DID of interest:
```
trustchain-cli did resolve --did <DID>
```

If the DID is found, the complete DID document (and document metadata) will be printed to the terminal.

=== "Mainnet"

    !!! example "Example: DID resolution on Mainnet"

        To test that Trustchain and ION are working correctly, try resolving this example DID:
        ```
        trustchain-cli did resolve --did did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w
        ```


=== "Testnet"

    !!! example "Example: DID resolution on Testnet"

        To test that Trustchain and ION are working correctly, try resolving this example DID:
        ```
        trustchain-cli did resolve --did did:ion:test:EiClWZ1MnE8PHjH6y4e4nCKgtKnI1DK1foZiP61I86b6pw
        ```

## DID Issuance

With the Trustchain CLI, you can create and publish your own Decentralised Identifiers. This process must be carried out by the DID subject, that is, the legal entity to whom the DID will refer.

#### DID document content

Use the template below to create a fragment that will be included in your new DID document. This fragment may include either, or both, of the `services` in the template. Services are part of the W3C DID specification. A service is an endpoint (URL)

The first service has type `Identity` and is used to identify the subject of the DID by their Web domain.

The second services has type `CredentialEndpoint`. Include this service

Using a text editor, make a copy of the following template, remove any services that you do not wish to include in your DID, and then save the file.

The file can be saved anywhere, but we recommend storing it in a directory named `doc_states` inside the `TRUSTCHAIN_DATA` directory. That way it will be easy to find later, when you use it to create your DID document.

```
{
   "services": [
      {
         "id": "TrustchainID",
         "type": "Identity",
         "serviceEndpoint": "https://www.example.com"
      },
      {
         "id": "TrustchainHTTP",
         "type": "CredentialEndpoint",
         "serviceEndpoint": "https://example.com/credentials"
      }
   ]
}
```

#### Create the DID

Having defined the content of the DID document, we can now use the Trustchain CLI to create the DID itself. Run the following command, replacing `<DID_CONTENT_FILE>` with the path to the DID document content file (from the previous step):
```
trustchain-cli did create --file_path <DID_CONTENT_FILE>
```

!!! example "Example: DID creation"

    Suppose you named your DID document content file `did_content.json` and saved it in the folder `$TRUSTCHAIN_DATA/doc_states/`. Then you would create the DID with the following command:
    ```
    trustchain-cli did create --file_path $TRUSTCHAIN_DATA/doc_states/did_content.json
    ```

The `create` command prints the new DID in the terminal window.

It also creates a new file inside the folder `$TRUSTCHAIN_DATA/operations/`. To see the contents of this file, replace `<DID>` with the newly-created DID in the following command:
```
cat $TRUSTCHAIN_DATA/operations/create_operation_<DID>.json
```

Inside this file you will be able to see the services copied from the DID document content file (previous step).

You will also see a public key of type `JsonWebSignature2020`. This public key was generated automatically by the Trustchain CLI and inserted into the file, so it will be part of the published DID document content.

The counterpart private key was saved at `$TRUSTCHAIN_DATA/key_manager/` in a subfolder with the same name as the DID. This private key will enable the DID subject to perform signing operations, such as attesting to downsteam DIDs or digital credentials. Anyone will be able to verify those digital signatures by obtaining the public key from the published DID document.

In fact, four private key were generated by the CLI when the DID was created. All are contained in teh same subfolder which will now contain the following files:

| Filename    | Description       |
| ----------------------- | ----------------- |
| `signing_key.json`      | Private key counterpart to the public key in the DID document. |
| `update_key.json`       | Private key required to make the next update the DID document. |
| `next_update_key.json`  | Private key required to make the next-but-one update to the DID document. |
| `recovery_key.json`     | Private key required to recover the DID (in case other keys are lost/compromised). |

??? question "Can my DID document contain multiple keys?"

    By default, a single public-private key pair is generated for all signing/attestation purposes. However, the W3C DID specification allows for multiple keys to be contained in a single DID document.

    This can be useful if different keys are intended to be used for different purposes, or if the DID refers to an organisation in which different individuals or departments wish to hold their own keys.

    If you want to include additional public keys in your DID document, this can be achieved by manually editing the JSON create operation file (described above). However, Trustchain's key management functionality currently only provides support for a single signing key. Support for multiple keys will be added in a future version.

#### Publish the DID document

!!! warning "Note: Publishing new DIDs requires a funded Bitcoin wallet"

    Publishing a Trustchain DID involves embedding information into a Bitcoin transaction and broadcasting it to the Bitcoin network. This makes the information accessible to everyone, globally, via the Bitcoin transaction ledger.

    This will be taken care of by the Trustchain CLI, via the embedded ION node which itself contains a node on the Bitcoin network. However, since each Bitcoin transaction includes a processing fee, **you must have funds in your Bitcoin wallet before issuing any DIDs**.

    For instructions on how to fund your Bitcoin wallet, see the [ION](ion.md#funding-your-bitcoin-wallet) page.


TODO: this is currently a manual step (to be built into the CLI in future). You need to run the `publish.sh` shell script that is found in the `scripts/` subdirectory inside the Trustchain repository. This script will attempt to publish all of the DID operations that are found in the `$TRUSTCHAIN_DATA/operations/` directory.

!!! info "Network processing time"

    When a (or updated) DID document is published, it will take some time for the Bitcoin network to process the relevant transaction so that it becomes visible to all other network participants.

    Only after this processing has finished will it be possible to resolve the DID using the Trustchain CLI `resolve` command.

    Typically, the processing time will be around 10 minutes, but it might be longer depending on factors such as the level of congestion on the Bitcoin network, and the size of the fee inserted in the relevant transaction.

## Downstream DID Issuance

This process must be carried out by the DID controller, that is, the legal entity that will attest to the downstream DID. The DID controller must itself be the subject of another DID document that is already published. We refer to the controller's DID as the *upstream DID* (uDID).

!!! info "Challenge-response protocol"

    The interaction between the upstream and downstream entities, when issuing a new downstream DID, must be performed carefully so that the dDID controller (upstream entity) can be confident that the information included in the downstream DID document is correct, before attesting to it.

    The proper way to manage this interaction is via a challenge-response protocol, that includes a rigorous checks of both the identity of the legal entities involved and of the dDID document content.

    A future version of Trustchain will include such a challenge-response protocol. In the meantime, dDID issuance is a manual process, as described here.

Issuing a downstream DID is a two-step process. The first step is for the dDID subject to publish their (regular) DID by following the steps in the [DID Issuance](#did-issuance) section above.

The second step is for the dDID controller to attest to the DID by adding their signature and re-publishing an updated DID document.

#### Attest to the dDID

This step must be carried out by the dDID controller, that is, the [uDID subject](roles.md#upstream-entity-udid-subject).

We assume that the downsteam legal entity has published their candidate dDID document and shared their candidate dDID (string identifier) with the controller. In the following commands, replace `<CANDIDATE_dDID>` with the candidate dDID and `<uDID>` with the controller's DID.

First check that the candidate dDID can be successfully resolved:
```
trustchain-cli did resolve --did <CANDIDATE_dDID>
```

Next, use the CLI to attest to the dDID:
```
trustchain-cli did attest --did <uDID> --controlled_did <CANDIDATE_dDID>
```

#### Publish the updated dDID document

To publish the updated dDID document, containing the controller's attestation, follow exactly the [same steps](#publish-the-did-document) as above for publishing a regular DID document.

## Downstream DID Verification

To verify a downstream DID, run the following command with the relevant `<dDID>` identifier:
```
trustchain-cli did verify --did <dDID>
```
The Trustchain CLI will perform the following verification process and report the result:

 1. Resolve the given dDID document.
 2. Identify the controller's uDID from the dDID metadata (if no controller is found, the verification fails).
 3. If the uDID is itself a downstream DID, repeat steps 1 & 2 until reaching the root DID.
 4. Verify that the timestamp on the root DID exactly matches the [configured](getting-started.md#trustchain-configuration-file) `root_event_time` parameter.
 5. Starting at the root DID, descend down the DID chain and verify each attestation signature using the public key from the next upstream DID document (if any signature is invalid, the verification fails).
 6. If all of the attestation signatures in the chain are valid, the verification is successful.

 This process ensures that the exact content of the downstream DID (including the public keys of the downstream legal entity) has been attested to by a recognised upstream entity, whose own public keys have themselves been attested to in a chain of signatures leading back to the root DID, whose exact time of publication has also been verified.

## Credential Issuance

TODO.

## Credential Verification

TODO.

&nbsp;

# Usage

This page contains instructions for using the Trustchain command line interface (CLI).

Depending on your role within the network of Trustchain users you may need to perform some or all of the operations described below. For more information, see the [User Roles](roles.md) page.

!!! info "Prerequisites"

    To use the Trustchain CLI, first make sure that you have followed the installation and configuration instructions on the [Getting Started](getting-started.md) page.

    Your ION node will also need to be up and running, either locally or on a remote machine to which you are connected via SSH and with port forwarding. Instructions for restarting ION, and setting up port forwarding, can be found [here](ion.md#running-ion).

## Trustchain CLI

To invoke the Trustchain CLI, open a Terminal and run this command:
```console
trustchain-cli
```
You should see a list of available commands and some usage hints.

If instead you get an error that the `trustchain-cli` command is not found, make sure you have followed all of the installation steps on the [Getting Started](getting-started.md) page.

The CLI is organised into a set of subcommands for different types of operation:

| Subcommand    | Description       |
| ------------- | ----------------- |
| `did`         | DID functionality: create, attest, resolve, verify.   |
| `vc`          | Verifiable credential functionality: sign and verify. |
| `data`        | Data provenance functionality: sign and verify.       |
| `cr`          | Challenge-response functionality for dDID issuance.   |

To get help with a particular subcommand, use the `--help` flag (or `-h` for short). For example, to get help with the CLI commands relating to DIDs:
```console
trustchain-cli did --help
```

## DID Resolution

DID Resolution is a process defined in the [W3C standard](https://www.w3.org/TR/did-core/#did-resolution) for Decentralised Identifiers (DIDs).

It takes as input a DID (string identifier) and returns the corresponding DID document, containing the public keys and service endpoints (URLs) that belong to the legal entity that is the DID subject. DID document metadata is also returned.

To resolve a DID using the Trustchain CLI, execute this command replacing `<DID>` with the DID of interest:
```console
trustchain-cli did resolve --did <DID>
```

If the DID is found, the complete DID document (and document metadata) will be printed to the terminal.

=== "Mainnet"

    !!! example "Example: DID resolution on Mainnet"

        To test that Trustchain and ION are working correctly, try resolving this example DID:
        ```console
        trustchain-cli did resolve --did did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w
        ```

=== "Testnet4"

    !!! example "Example: DID resolution on Testnet4"

        To test that Trustchain and ION are working correctly, try resolving this example DID:
        ```console
        trustchain-cli did resolve --did did:ion:test:EiBt8NTmSKf3jt_FMKf-r6JMSJIp7njcTTPe24USYu4B9w
        ```

=== "Testnet3 (Deprecated)"

    !!! example "Example: DID resolution on Testnet3"

        To test that Trustchain and ION are working correctly, try resolving this example DID:
        ```console
        trustchain-cli did resolve --did did:ion:test:EiClWZ1MnE8PHjH6y4e4nCKgtKnI1DK1foZiP61I86b6pw
        ```

## DID Issuance

With the Trustchain CLI, you can create and publish your own Decentralised Identifiers. This process must be carried out by the DID subject because it involves generating new public-private key pairs.

#### DID document content

Use the template below to create a JSON object that will be included in your new DID document. This JSON object may include either or both of the `services` in the template.

Services are part of the W3C [DID specification](https://www.w3.org/TR/did-1.0/#services). They are used in DID documents to express ways of communicating with the DID subject via a service endpoint (URL), and can relate to any type of service the DID subject wants to advertise.

In the template below:

 - the first service has type `Identity` and is used to identify the DID subject by their Web domain,
 - the second service has type `CredentialEndpoint` and can be used by credential issuing authorities to advertise their issuance endpoint (URL).

Other services may also be included, at the DID subject's discretion.

Using a text editor, make a copy of the following template and modify it so it contains the services and endpoints that you wish to include in your DID, then save the file.

The file can be saved anywhere, but we recommend storing it in a directory named `doc_states` inside the `TRUSTCHAIN_DATA` directory. That way it will be easy to find later, when you use it to create your DID document.

```json
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

Having defined the document content, we can now use the Trustchain CLI to create the DID itself. Run the following command, replacing `<DID_CONTENT_FILE>` with the path to the DID document content file (from the previous step):
```console
trustchain-cli did create --file_path <DID_CONTENT_FILE>
```

!!! example "Example: DID creation"

    Suppose you named your DID document content file `did_content.json` and saved it in the folder `$TRUSTCHAIN_DATA/doc_states/`. Then you would create the DID with the following command:
    ```console
    trustchain-cli did create --file_path $TRUSTCHAIN_DATA/doc_states/did_content.json
    ```

The `create` command prints the new DID in the terminal window.

It also creates a new file inside the folder `$TRUSTCHAIN_DATA/operations/`. To see the contents of this file, replace `<DID>` with the newly-created DID in the following command:
```console
cat $TRUSTCHAIN_DATA/operations/create_operation_<DID>.json
```

Inside this file you will be able to see the services inserted from the DID document content file.

You will also see a public key of type `JsonWebSignature2020`. This public key was generated automatically by the Trustchain CLI and inserted into the file, so it will be part of the published DID document content.

The counterpart private key was saved at `$TRUSTCHAIN_DATA/key_manager/` in a subfolder with the same name as the DID. This private key will enable the DID subject to perform signing operations, such as attesting to downsteam DIDs or digital credentials. Anyone will be able to verify those digital signatures by obtaining the corresponding public key from the published DID document.

In fact, three private key were generated by the CLI when the DID was created. All are contained in the same subfolder which will now contain the following files:

| Filename    | Description       |
| ----------------------- | ----------------- |
| `signing_key.json`      | Private key counterpart to the public key in the DID document. |
| `update_key.json`       | Private key required to make the next update to the DID document. |
| `recovery_key.json`     | Private key required to recover the DID (in case other keys are lost/compromised). |

??? question "Can my DID document contain multiple signing keys?"

    By default, a single public-private key pair is automatically generated for all signing/attestation purposes. However, it is possible to include multiple keys in a single DID document.

    This can be useful if different keys are intended to be used for different purposes, or if the DID refers to an organisation in which different individuals or departments wish to hold their own keys.

    To include multiple public keys in your DID document, simply include them in the [DID document content](#did-document-content) before creating the DID, as in this example:
    ```json
    {
        "publicKeys": [
            {
                "id": "D6eRSvf6rIfhmPqQDkoCnDVnMzA3lqUPG-2VxIAm0j8",
                "type": "JsonWebSignature2020",
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "secp256k1",
                    "x": "WxRuakVQKfKPs70LwvZnvr1UhhVd2QPtu4PfEc5os_M",
                    "y": "4lb0D5ORUnsEU_Oh1xp19CzltTDH7IBVp2B0ZEU1qQs"
                },
                "purposes": [
                    "assertionMethod",
                    "authentication",
                    "keyAgreement",
                    "capabilityInvocation",
                    "capabilityDelegation"
                ]
            },
            {
                "id": "u4HckebM8ltNrU_8qOXtSD1SIE6mlCskFR7p0vTFd3U",
                "type": "JsonWebSignature2020",
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "secp256k1",
                    "x": "459af8dOpARVLRbozIvdQPGK9rTCh1e2ZVipBn8E5Lk",
                    "y": "Rn6iPKS1cNU73eoQpaYt0Z8q3t9duOZNolJEFdAaFS0"
                },
                "purposes": [
                    "assertionMethod",
                    "authentication",
                ]
            }
        ],
        "services": [
            {
                "id": "TrustchainID",
                "type": "Identity",
                "serviceEndpoint": "https://www.example.com"
            }
        ]
    }
    ```
    Then run the usual command to create the DID:
    ```console
    trustchain-cli did create --file_path <DID_CONTENT_FILE>
    ```
    When a list of public keys is specified in the DID document content (as above), Trustchain will not generate any new signing keys when creating the DID.

    To enable Trustchain's key management system to access the corresponding private keys, for signing purposes, you will need to copy and paste those private keys into a file named `signing_key.json` inside the key manager folder:
    ```sh
    $TRUSTCHAIN_DATA/key_manager/<DID>/signing_key.json
    ```
    where `<DID>` is the particular DID in question.

    The format of the `signing_key.json` file must be a list:
    ```json
    [
        KEY1,
        KEY2,
        ...
    ]
    ```
    where `KEY1`, `KEY2`, etc. are how they would appear if the individual keys were in a file on their own.

    Full support for managing DIDs with multiple keys will be added in a future version of the Trustchain CLI.

#### Publish the DID document

!!! warning "Note: Publishing new DIDs requires a funded Bitcoin wallet"

    Publishing a Trustchain DID involves embedding information into a Bitcoin transaction and broadcasting it to the Bitcoin network. This makes the information accessible to everyone, globally, via the Bitcoin transaction ledger.

    This process will be taken care of by the Trustchain CLI, via the embedded ION node which itself contains a node on the Bitcoin network. However, since each Bitcoin transaction includes a processing fee, **you must have funds in your Bitcoin wallet before publishing any DIDs**.

    Instructions on how to fund your Bitcoin wallet are available [here](ion.md#funding-your-bitcoin-wallet).

Currently the Trustchain CLI does not include a command for publishing DIDs. This will be added in a future version. In the meantime, DIDs can be published by running a script from the command line.

!!! warning "Note: The publish script assumes the default ION port number (3000)"

    By default, the ION server listens on port 3000. If you have configured ION to listen on a different port, you will need to manually edit the publish script. If you are unsure, view the ION config file with this command:
    ```console
    cat $ION_CORE_CONFIG_FILE_PATH
    ```
    and check the value of the `port` parameter. If the value is not `3000`, you will need to change the value of the `port` variable at the top of the publish script to have the same value. To edit the script, run:
    ```console
    nano "$TRUSTCHAIN_REPO"/scripts/publish.sh
    ```

When you are ready to publish one or more DIDs, execute the `publish.sh` script by running the following command:
```console
"$TRUSTCHAIN_REPO"/scripts/publish.sh
```

This script will attempt to publish all of the DID operations (JSON files) that are found in the `$TRUSTCHAIN_DATA/operations/` directory. It does this by sending each of them to your ION server as an HTTP POST request. The response to each of these requests is checked for success (HTTP status code 200).

If successful, the output should look something like this:
```{ .text .no-copy }
Found 2 DID operations.
Publishing:
- create_operation_EiBvWFdG7JUVpGu4z0qTc7WkqerZSU-K7_osR8QVPMYciw.json ✅
- create_operation_EiDzJNlBiKahsykDcAfC1C6StUurvbIyERrkDBmWIXiPzg.json ✅
All DID operations were published successfully
Files moved to the 'sent/' subdirectory
```

The script reports the outcome of each publication attempt. If any attempt failed, the HTTP error code will be reported along with the path to the output JSON file containing any error messages.

Each JSON file will be moved to either the `sent/` or `failed/` subdirectory.

After the `publish.sh` script has run, there will be some delay before the newly-published DID can be resolved. This is due to i) the ION publication mechanism, which supports batching of DID operations to reduce transaction fees, and ii) the Bitcoin network processing time. For more details, see the information panels below.

Once the publication transaction has been processed, confirm that the DID was successfully published by attempting to resolve it [using the CLI](#did-resolution).

=== "Mainnet"

    ??? info "ION DID publication mechanism"

        The `publish.sh` script takes all of the DID operations in `$TRUSTCHAIN_DATA/operations/` and dispatches them to the local ION node for publishing. They are then placed in the collection of `queued-operations` inside ION's Mongo database.

        To view the contents of this database, open the MongoDB shell with this command:
        ```console
        mongosh
        ```
        Then run the following MongoDB commands (omitting the `>` prompt character) to select the database:
        ```console
        > ion-mainnet-core
        ```
        and check how many queued DID operations exist:
        ```console
        > db["queued-operations"].countDocuments()
        ```
        The output from this command will usually be zero, indicating that there are no queued operations. Immediately after running the `publish.sh` script, the number of queued operations will increase to one (or more, if there were multiple files inside `$TRUSTCHAIN_DATA/operations/` when the script was executed).

        Periodically, ION will check if there are any queued operations and, if any exist, it will batch them together and publish them in a single Bitcoin operation. The frequency with which this check is performed can be controlled by setting the `batchingIntervalInSeconds` parameter, found in the ION core config file. To view this file, run:
        ```console
        less $ION_CORE_CONFIG_FILE_PATH
        ```

        The default batching interval is 600 seconds. This can be reduced by changing the value of the `batchingIntervalInSeconds` parameter and restarting ION.

    ??? info "Bitcoin network processing time"

        When a new (or updated) DID document is published, it will take some time for the Bitcoin network to [process](https://bitcoin.org/en/how-it-works#processing) the relevant transaction so that it becomes visible to all other network participants.

        Only after this processing has finished will it be possible to resolve the DID using the Trustchain CLI `resolve` command.

        Typically, the processing time will be between 10 and 60 minutes, but it might be longer depending on factors such as the level of congestion on the Bitcoin network and the size of the fee inserted in the relevant transaction.

    !!! tip "Tip: Identifying your DID transaction"

        While you are waiting for your DID to be published, you can track its progress by observing the Bitcoin wallet address used to publish the DID operation. Run this command to list your Bitcoin addresses:
        ```console
        bitcoin-cli -rpcwallet="sidetreeDefaultWallet" listreceivedbyaddress 1 true
        ```
        Then copy the **first address** in the list and paste it into the search bar at [mempool.space](https://mempool.space/).

        This search will return information about your Bitcoin address, including the number of confirmed transactions that have taken place and the unspent amount in the address (i.e. its current balance). Below the summary information will be a list showing every transaction associated with this address, *including any unconfirmed transactions*.

        Assuming the ION publication mechanism has executed (see the panel above), the first transaction in the list will be the new one that was created by that process.

        Click on the first transaction ID (this is a long string of hexadecimal characters that uniquely identifies the transactions). This takes you to a new page with details about that particular transaction.

        Check the "status" of the transaction. If it is marked as "Unconfirmed", this indicates that it has not yet been processed by the Bitcoin network. In that case it will not yet be possible to resolve the new DID.

        By refreshing this page, you can check its progress. When the transaction has been processed its status will change to "$n$ Confirmations", where $n$ is the number of Bitcoin blocks mined since the one containing this transaction.

        As soon as the transaction has one or more confirmations, it should be possible to resolve the newly-published DID.

        **If your are publishing a root DID**, make a note of the transaction ID so you can easily find it later. You should also make a note of the transactions's timestamp (i.e. the exact date & time that it was confirmed). The timestamp can be found on the same page as the transaction status on [mempool.space](https://mempool.space/).

=== "Testnet4"

    ??? info "ION DID publication mechanism"

        The `publish.sh` script takes all of the DID operations in `$TRUSTCHAIN_DATA/operations/` and dispatches them to the local ION node for publishing. They are then placed in the collection of `queued-operations` inside ION's Mongo database.

        To view the contents of this database, open the MongoDB shell with this command:
        ```console
        mongosh
        ```
        Then run the following MongoDB commands (omitting the `>` prompt character) to select the database:
        ```console
        > use ion-testnet-core
        ```
        and check how many queued DID operations exist:
        ```console
        > db["queued-operations"].countDocuments()
        ```
        The output from this command will usually be zero, indicating that there are no queued operations. Immediately after running the `publish.sh` script, the number of queued operations will increase to one (or more, if there were multiple files inside `$TRUSTCHAIN_DATA/operations/` when the script was executed).

        Periodically, ION will check if there are any queued operations and, if any exist, it will batch them together and publish them in a single Bitcoin operation. The frequency with which this check is performed can be controlled by setting the `batchingIntervalInSeconds` parameter, found in the ION core config file. To view this file, run:
        ```console
        less $ION_CORE_CONFIG_FILE_PATH
        ```

        The default batching interval is 600 seconds. This can be reduced by changing the value of the `batchingIntervalInSeconds` parameter and restarting ION.

    ??? info "Bitcoin network processing time"

        When a new (or updated) DID document is published, it will take some time for the Bitcoin network to [process](https://bitcoin.org/en/how-it-works#processing) the relevant transaction so that it becomes visible to all other network participants.

        Only after this processing has finished will it be possible to resolve the DID using the Trustchain CLI `resolve` command.

        Typically, the processing time will be between 10 and 60 minutes, but it might be longer depending on factors such as the level of congestion on the Bitcoin network and the size of the fee inserted in the relevant transaction.

    !!! tip "Tip: Identifying your DID transaction"

        While you are waiting for your DID to be published, you can track its progress by observing the Bitcoin wallet address used to publish the DID operation. Run this command to list your Bitcoin addresses:
        ```console
        bitcoin-cli -rpcwallet="sidetreeDefaultWallet" listreceivedbyaddress 1 true
        ```
        Then copy the **first address** in the list and paste it into the search bar at [mempool.space](https://mempool.space/testnet4).

        This search will return information about your Bitcoin address, including the number of confirmed transactions that have taken place and the unspent amount in the address (i.e. its current balance). Below the summary information will be a list showing every transaction associated with this address, *including any unconfirmed transactions*.

        Assuming the ION publication mechanism has executed (see the panel above), the first transaction in the list will be the new one that was created by that process.

        Click on the first transaction ID (this is a long string of hexadecimal characters that uniquely identifies the transactions). This takes you to a new page with details about that particular transaction.

        Check the "status" of the transaction. If it is marked as "Unconfirmed", this indicates that it has not yet been processed by the Bitcoin network. In that case it will not yet be possible to resolve the new DID.

        By refreshing this page, you can check its progress. When the transaction has been processed its status will change to "$n$ Confirmations", where $n$ is the number of Bitcoin blocks mined since the one containing this transaction.

        As soon as the transaction has one or more confirmations, it should be possible to resolve the newly-published DID.

        **If your are publishing a root DID**, make a note of the transaction ID so you can easily find it later. You should also make a note of the transactions's timestamp (i.e. the exact date & time that it was confirmed). The timestamp can be found on the same page as the transaction status on [mempool.space](https://mempool.space/testnet4).

=== "Testnet3 (Deprecated)"

    ??? info "ION DID publication mechanism"

        The `publish.sh` script takes all of the DID operations in `$TRUSTCHAIN_DATA/operations/` and dispatches them to the local ION node for publishing. They are then placed in the collection of `queued-operations` inside ION's Mongo database.

        To view the contents of this database, open the MongoDB shell with this command:
        ```console
        mongosh
        ```
        Then run the following MongoDB commands (omitting the `>` prompt character) to select the database:
        ```console
        > use ion-testnet-core
        ```
        and check how many queued DID operations exist:
        ```console
        > db["queued-operations"].countDocuments()
        ```
        The output from this command will usually be zero, indicating that there are no queued operations. Immediately after running the `publish.sh` script, the number of queued operations will increase to one (or more, if there were multiple files inside `$TRUSTCHAIN_DATA/operations/` when the script was executed).

        Periodically, ION will check if there are any queued operations and, if any exist, it will batch them together and publish them in a single Bitcoin operation. The frequency with which this check is performed can be controlled by setting the `batchingIntervalInSeconds` parameter, found in the ION core config file. To view this file, run:
        ```console
        less $ION_CORE_CONFIG_FILE_PATH
        ```

        The default batching interval is 600 seconds. This can be reduced by changing the value of the `batchingIntervalInSeconds` parameter and restarting ION.

    ??? info "Bitcoin network processing time"

        When a new (or updated) DID document is published, it will take some time for the Bitcoin network to [process](https://bitcoin.org/en/how-it-works#processing) the relevant transaction so that it becomes visible to all other network participants.

        Only after this processing has finished will it be possible to resolve the DID using the Trustchain CLI `resolve` command.

        Typically, the processing time will be between 10 and 60 minutes, but it might be longer depending on factors such as the level of congestion on the Bitcoin network and the size of the fee inserted in the relevant transaction.

    !!! tip "Tip: Identifying your DID transaction"

        While you are waiting for your DID to be published, you can track its progress by observing the Bitcoin wallet address used to publish the DID operation. Run this command to list your Bitcoin addresses:
        ```console
        bitcoin-cli -rpcwallet="sidetreeDefaultWallet" listreceivedbyaddress 1 true
        ```
        Then copy the **first address** in the list and paste it into the search bar at [mempool.space](https://mempool.space/testnet).

        This search will return information about your Bitcoin address, including the number of confirmed transactions that have taken place and the unspent amount in the address (i.e. its current balance). Below the summary information will be a list showing every transaction associated with this address, *including any unconfirmed transactions*.

        Assuming the ION publication mechanism has executed (see the panel above), the first transaction in the list will be the new one that was created by that process.

        Click on the first transaction ID (this is a long string of hexadecimal characters that uniquely identifies the transactions). This takes you to a new page with details about that particular transaction.

        Check the "status" of the transaction. If it is marked as "Unconfirmed", this indicates that it has not yet been processed by the Bitcoin network. In that case it will not yet be possible to resolve the new DID.

        By refreshing this page, you can check its progress. When the transaction has been processed its status will change to "$n$ Confirmations", where $n$ is the number of Bitcoin blocks mined since the one containing this transaction.

        As soon as the transaction has one or more confirmations, it should be possible to resolve the newly-published DID.

        **If your are publishing a root DID**, make a note of the transaction ID so you can easily find it later. You should also make a note of the transactions's timestamp (i.e. the exact date & time that it was confirmed). The timestamp can be found on the same page as the transaction status on [mempool.space](https://mempool.space/testnet).

!!! tip "Tip: Batching DID operations"

    To save time and reduce transaction fees, multiple DID operations can be batched into a single Bitcoin transaction. In fact, ION supports batching of up to 10,000 operations per transaction.

    To perform batching, simply repeat the create operation as many times as you like before running the `publish.sh` script. Then run the script once to publish all operations in a single batch.

    The only exception to this rule is that **the root DID must not be published in a batched transaction**. It must be the unique DID operation associated with the transaction in which it is published. The reason for this condition is to enable fast and efficient scanning of the Bitcoin blockchain to identify potential root DID operations.

## Downstream DID Issuance

This process must be carried out by the DID controller, that is, the legal entity whose attestation will appear on the downstream DID. The DID controller must itself be the subject of another DID document that is already published. We refer to the controller's DID as the *upstream DID* (uDID).

!!! info "Challenge-response protocol"

    The interaction between the upstream and downstream entities, when issuing a new downstream DID, must be performed carefully so that the dDID controller (upstream entity) can be confident that the information included in the downstream DID document is correct, before attesting to it.

    The proper way to manage this interaction is via a challenge-response protocol, that includes rigorous checks of both the identity of the legal entities involved and of the dDID document content.

    The latest version of the Trustchain CLI includes such a challenge-response protocol. In earlier versions, dDID issuance is a manual process, as described here.

Issuing a downstream DID is a two-step process. The first step is for the dDID subject to publish their (regular) DID by following the steps in the [DID Issuance](#did-issuance) section above.

The second step is for the dDID controller to attest to the DID by adding their signature and re-publishing an updated DID document.

#### Attest to the dDID

This step must be carried out by the [dDID issuer](roles.md#ddid-issuer).

We assume that the downsteam legal entity has published their candidate dDID document and shared their candidate dDID (string identifier) with the controller. In the following commands, replace `<CANDIDATE_dDID>` with the candidate dDID and `<uDID>` with the controller's DID.

First check that the candidate dDID can be successfully resolved:
```console
trustchain-cli did resolve --did <CANDIDATE_dDID>
```

Next, use the CLI to attest to the dDID:
```console
trustchain-cli did attest --did <uDID> --controlled_did <CANDIDATE_dDID>
```

#### Publish the updated dDID document

To publish the updated dDID document, containing the controller's attestation, follow exactly the [same steps](#publish-the-did-document) as above for publishing a regular DID document.

!!! tip "Tip: Batching DID update operations"

    As mentioned above, DID operations can be batched to save time and money. This remains true for the update operations used to convert a DID into a dDID. The only constraint is that create and update operations for the same DID cannot be batched into the same transaction, since to perform the attestion the DID must have already been published.

    Therefore, when issuing multiple dDIDs the most efficient approach is to batch together as many create operations as possible, publish them all in a single transaction, wait for that to be processed, and then batch together as many update operations as possible in a subsequent transaction.

## Downstream DID Verification

To verify a downstream DID, run the following command with the relevant `<dDID>` identifier:
```console
trustchain-cli did verify --did <dDID>
```
The Trustchain CLI will perform the following verification process and report the result:

 1. Resolve the given dDID document.
 2. Identify the controller's uDID from the dDID metadata. If no controller is found, the verification fails.
 3. If the uDID is itself a downstream DID, repeat steps 1 & 2 until reaching the root DID.
 4. Verify that the timestamp on the root DID exactly matches the [configured](getting-started.md#trustchain-configuration-file) `root_event_time` parameter. If the timestamp does not match, the verification fails.
 5. Starting at the root DID, descend down the DID chain and verify each attestation signature using the public key from the next upstream DID document. If any signature is invalid, the verification fails.
 6. If all of the attestation signatures in the chain are valid, the verification is successful.

 This process ensures that the exact content of the downstream DID (including the public keys of the downstream legal entity) has been attested to by a recognised upstream entity, whose own public keys have themselves been attested to in a chain of signatures leading back to the root DID, whose exact time of publication has also been verified.

## Credential Issuance

This section is under construction.

## Credential Verification

This section is under construction.

&nbsp;

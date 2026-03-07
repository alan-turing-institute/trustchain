# RPC Interface

For developers who want to build applications that depend on Trustchain, the JSON remote procedure call (RPC) interface provides programmatic access to the same set of functions supported by the [Trustchain CLI](usage.md#trustchain-cli). This page explains how to install and run the RPC server, so it is ready to respond to JSON RPC requests. It also details how to make calls to the server, what functions are available and how to handle the responses.

!!! info "Prerequisites"

    To use the Trustchain RPC interface, first make sure you have followed the installation and configuration instructions on the [Getting Started](getting-started.md) page.

    Your ION node will also need to be up and running, either locally or on a remote machine to which you are connected via SSH with port forwarding. Instructions for running ION, and setting up port forwarding, can be found [here](ion.md#running-ion).

## Installation

To install the Trustchain RPC server, run:
```console
cargo install --path "$TRUSTCHAIN_REPO"/crates/trustchain-rpc
```

## Configuration

Before starting the RPC server some configuation parameters will need to be set. Open the Trustchain [configuration file](getting-started.md#trustchain-configuration-file) for editing:
```console
nano $TRUSTCHAIN_CONFIG
```

Under the section headed `[rpc]`, add or edit the following configuration parameters:

- Set the `root_event_time` parameter to the integer root DID timestamp for your network (in Unix Time).
- Set the `host` parameter to the host address for the server. If you want the RPC server to be accessible only on a local network, set this to `"127.0.0.1"` (localhost). If you want the server to be accessible from the Internet, set it to `"0.0.0.0"`. In this case, ensure both your router and server are protected by a properly configured firewall.
- Set the `port` parameter to the port number on which your server will listen for RPC requests.
- Set the `ion_host` parameter to the host name of your ION instance. If ION is running on the local machine, set this to the loopback address `"127.0.0.1"`.
- Set the `ion_port` parameter to the port number of your ION instance. By default, ION listens on port `3000`.

!!! example "Example RPC server configuration"

    After completing the above steps, the `[rpc]` section of `trustchain_config.toml` should look similar to the following example:

    ```bash
    [rpc]
    root_event_time = 1769521645
    host = "127.0.0.1"
    port = 4444
    ion_host = "127.0.0.1"
    ion_port = 3000
    ```

## Running the RPC server

Open a new Terminal window and invoke the Trustchain RPC server with the following command:
```console
trustchain-rpc
```

The server will listen on the port specified in the configuration (above). Server log messages will be printed to this terminal window, so you will see a new message whenever the server responds to a request.

## JSON RPC Calls

The Trustchain JSON RPC interface accepts requests conforming to the [JSON 2.0](https://www.jsonrpc.org/specification) standard. The following subsections describe each of the functions available.

Note that there is currently no RPC function for publishing DIDs. Instead, a script is provided for this purpose, as explained on the [Usage](usage.md#publish-the-did-document) page.

### Create DID

**Purpose:** Create a new DID.

**Prerequisites:** A file containing [DID document content](usage.md#did-document-content) in JSON format.

**Request parameters:**

| Parameter Name | Type | Description |
| ---- | --------------- | --------------------- |
| None | String | The path to a file containing DID document state in JSON format |

**Example request:**
```json
{
    "jsonrpc": "2.0",
    "method": "create",
    "params": "/path/to/doc_state.txt",
    "id": 1
}
```

**Response:** The newly-created DID document and document metadata in JSON format.

### Attest DID

**Purpose:** Attest to a DID, turning it into a [downstream DID](technical-notes.md#downstream-dids).

**Prerequisites:** The intended upstream and downstream DIDs must already be [published](usage.md#publish-the-did-document). The private keys relating to the intended upstream DID must be accessible from the local Trustchain node.

| Parameter Name | Type | Description |
| ---- | --------------- | --------------------- |
| did | String | The DID of the attestor (the intended upstream DID) |
| controlled_did | String | The DID of the attestee (the intended downstream DID) |

Example JSON request:
```json
{
    "jsonrpc": "2.0",
    "method": "attest",
    "params": {
        "did": "did:ion:test:EiDs0EeoUnbPkkjhP2HxUrkDkUeZAa1WZT2GjqCO8hDX5A",
        "controlled_did": "did:ion:test:EiBijhXD8AGKu891yTssu69qRwwC46IfOphnfI9XzXQp5Q"
    },
    "id": 1
}
```

**Response:** TODO.


### Resolve DID

**Purpose:** Resolve a DID to obtain its DID document content and metadata.

**Prerequisites:** The DID specified in the request must already be [published](usage.md#publish-the-did-document).


| Parameter Name | Type | Description |
| ---- | --------------- | --------------------- |
| None   | String | The DID to be resolved |

Example JSON request:
```json
{
    "jsonrpc": "2.0",
    "method": "resolve",
    "params": "did:ion:test:EiBijhXD8AGKu891yTssu69qRwwC46IfOphnfI9XzXQp5Q",
    "id": 1
}
```

**Response:** The resolved DID document and document metadata in JSON format.

### Verify DID

**Purpose:** Verify a downstream DID.

**Prerequisites:** The DID specified in the request must already be [published](usage.md#publish-the-did-document). For successful verification, the same DID must either be the root DID, or have a valid attestation from an upstream DID in which case there must also exist a sequence of valid attestations leading to the root DID whose [verifiable timestamp](technical-notes.md#independently-verifiable-timestamping) matches that configured in the Trustchain [configuration file](getting-started.md#trustchain-configuration-file).

| Parameter Name | Type | Description |
| ---- | --------------- | --------------------- |
| None   | String | The downstream DID to be verified |

Example JSON request:
```json
{
    "jsonrpc": "2.0",
    "method": "verify",
    "params": "did:ion:test:EiBijhXD8AGKu891yTssu69qRwwC46IfOphnfI9XzXQp5Q",
    "id": 1
}
```

**Response:** The chain of DID documents (and document metadata) from the given DID to the root DID.

### DID Chain

**Purpose:** Get all of the DIDs in a chain of attestation from the given DID to the root.

**Prerequisites:** Same as for the [Verify DID](#verify-did) function.

| Parameter Name | Type | Description |
| ---- | --------------- | --------------------- |
| None   | String | The leaf DID in the requested downstream DID chain |

Example JSON request:
```json
{
    "jsonrpc": "2.0",
    "method": "chain",
    "params": "did:ion:test:EiBijhXD8AGKu891yTssu69qRwwC46IfOphnfI9XzXQp5Q",
    "id": 1
}
```

**Response:** The chain of DID documents (and document metadata) from the given DID to the root DID.

### DID Verification Bundle

**Purpose:** Request verification material for a downstream DID.

**Prerequisites:** Same as for the [Verify DID](#verify-did) function.

| Parameter Name | Type | Description |
| ---- | --------------- | --------------------- |
| None   | String | The downstream DID for which verification material is requested |

Example JSON request:
```json
{
    "jsonrpc": "2.0",
    "method": "bundle",
    "params": "did:ion:test:EiBijhXD8AGKu891yTssu69qRwwC46IfOphnfI9XzXQp5Q",
    "id": 1
}
```

**Response:** A JSON data structure containing all of the information required to verify the validity of the given downstream DID, including verification of the timestamp on the root DID.

### Sign Credential

**Purpose:** Attach a signature to a Verifiable Credential.

**Prerequisites:** The DID of the signing entity must already be [published](usage.md#publish-the-did-document) and the signing key must be accessible from the local Trustchain node.

| Parameter Name | Type | Description |
| ---- | --------------- | --------------------- |
| credential | String | The credential to be signed, in JSON format |
| did | String | The DID of the signer |
| key_id | String | Optional. The ID of the signing key in the signer's DID document |

Example JSON request:
```json
{
    "jsonrpc": "2.0",
    "method": "sign_credential",
    "params": {
        "credential": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://www.w3.org/2018/credentials/examples/v1\"],\"id\":\"urn:uuid:481935de-f93d-11ed-a309-d7ec1d02e89c\",\"credentialSubject\":{\"degree\":{\"college\":\"UniversityofOxbridge\",\"name\":\"MasterofScience\",\"type\":\"MastersDegree\"},\"familyName\":\"Smith\",\"givenName\":\"Jane\"},\"type\":[\"VerifiableCredential\"]}",
        "did": "did:ion:test:EiBijhXD8AGKu891yTssu69qRwwC46IfOphnfI9XzXQp5Q"
    },
    "id": 1
}
```

**Response:** The signed credential.

### Verify Credential

**Purpose:** Verify a credential. This process involves cryptographic verification of:

- the signature on the credential (using the signer's public key),
- the chain of attestations from the signer's DID to the root DID,
- the timestamp on the root DID (using the configured root timestamp).

**Prerequisites:** The credential must be signed and the signer's DID must already be [published](usage.md#publish-the-did-document).

| Parameter Name | Type | Description |
| ---- | --------------- | --------------------- |
| None | String | The signed credential to be verified, in JSON format |

Example JSON request:
```json
{
    "jsonrpc": "2.0",
    "method": "verify_credential",
    "params": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://www.w3.org/2018/credentials/examples/v1\"],\"id\":\"urn:uuid:481935de-f93d-11ed-a309-d7ec1d02e89c\",\"type\":[\"VerifiableCredential\"],\"credentialSubject\":{\"familyName\":\"Smith\",\"degree\":{\"college\":\"UniversityofOxbridge\",\"name\":\"MasterofScience\",\"type\":\"MastersDegree\"},\"givenName\":\"Jane\"},\"issuer\":\"did:ion:test:EiDs0EeoUnbPkkjhP2HxUrkDkUeZAa1WZT2GjqCO8hDX5A\",\"proof\":{\"type\":\"EcdsaSecp256k1Signature2019\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:ion:test:EiDs0EeoUnbPkkjhP2HxUrkDkUeZAa1WZT2GjqCO8hDX5A#B9A2p0wHJ2qoAt0Q5NJgvGGJnpeVpm8RZMtIF_Yfkk4\",\"created\":\"2026-03-07T07:38:07.816041366Z\",\"jws\":\"eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..rkflmY4iRWg2Di46Olsyj0CHlO-jEHZHYN3aZ07tJadQvTKAPoeXFCM5rjiOehVTh9mI62lld3xnN6zA2F7j9Q\"}}",
    "id": 1
}
```

**Response:** The chain of DID documents (and document metadata) from the signer's DID to the root DID.

### Sign Presentation

**Purpose:** Attach a signature to a Verifiable Presentation.

**Prerequisites:** The DID of the signing entity must already be [published](usage.md#publish-the-did-document) and the signing key must be accessible from the local Trustchain node.

| Parameter Name | Type | Description |
| ---- | --------------- | --------------------- |
| presentation | String | The presentation to be signed, in JSON format |
| did | String | The DID of the signer |
| key_id | String | Optional. The ID of the signing key in the signer's DID document |

Example JSON request:
```json
{
    "jsonrpc": "2.0",
    "method": "sign_presentation",
    "params": {
        "presentation": "TODO",
        "did": "did:ion:test:EiBijhXD8AGKu891yTssu69qRwwC46IfOphnfI9XzXQp5Q"
    },
    "id": 1
}
```

**Response:** The signed presentation.

### Verify Presentation

**Purpose:** Verify a presentation. This process involves cryptographic verification of:

- the signature on the presentation (using the signer's public key),
- the chain of attestations from the signer's DID to the root DID,
- the timestamp on the root DID (using the configured root timestamp).

**Prerequisites:** The presentation must be signed and the signer's DID must already be [published](usage.md#publish-the-did-document).

| Parameter Name | Type | Description |
| ---- | --------------- | --------------------- |
| None | String | The signed presentation to be verified, in JSON format |

Example JSON request:
```json
{
    "jsonrpc": "2.0",
    "method": "verify_presentation",
    "params": "TODO",
    "id": 1
}
```

**Response:** The chain of DID documents (and document metadata) from the signer's DID to the root DID.

### Sign Data

**Purpose:** Attach a signature to a file containing arbitrary data.

**Prerequisites:** The DID of the signing entity must already be [published](usage.md#publish-the-did-document) and the signing key must be accessible from the local Trustchain node.

| Parameter Name | Type | Description |
| ---- | --------------- | --------------------- |
| path | String | The path to the file to be signed |
| did | String | The DID of the signer |
| key_id | String | Optional. The ID of the signing key in the signer's DID document |

Example JSON request:
```json
{
    "jsonrpc": "2.0",
    "method": "sign_data",
    "params": {
        "path": "/path/to/data_file.jpg",
        "did": "did:ion:test:EiBijhXD8AGKu891yTssu69qRwwC46IfOphnfI9XzXQp5Q",
    },
    "id": 1
}
```

**Response:** A signed data credential.

### Verify Data

**Purpose:** Verify a data credential. This process involves cryptographic verification of:

- the SHA-256 hash of the data file (comparing with the hash in the credential),
- the signature on the data credential (using the signer's public key),
- the chain of attestations from the signer's DID to the root DID,
- the timestamp on the root DID (using the configured root timestamp).

**Prerequisites:** The data credential must be signed and the DID of the signer must already be [published](usage.md#publish-the-did-document).

| Parameter Name | Type | Description |
| ---- | --------------- | --------------------- |
| path | String | The path to the file to be signed |
| credential | String | The signed data credential |

Example JSON request:
```json
{
    "jsonrpc": "2.0",
    "method": "verify_data",
    "params": {
        "path": "/path/to/data_file.jpg",
        "did": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\",\"https://www.w3.org/2018/credentials/examples/v1\",\"https://schema.org/\"],\"type\":[\"VerifiableCredential\"],\"credentialSubject\":{\"dataset\":\"f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2\"},\"issuer\":\"did:ion:test:EiDs0EeoUnbPkkjhP2HxUrkDkUeZAa1WZT2GjqCO8hDX5A\",\"issuanceDate\":\"2026-03-07T07:47:15.797265602Z\",\"proof\":{\"type\":\"EcdsaSecp256k1Signature2019\",\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:ion:test:EiDs0EeoUnbPkkjhP2HxUrkDkUeZAa1WZT2GjqCO8hDX5A#B9A2p0wHJ2qoAt0Q5NJgvGGJnpeVpm8RZMtIF_Yfkk4\",\"created\":\"2026-03-07T07:47:15.797320083Z\",\"jws\":\"eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..tGzhKbYimcj2JLOwmCQTCBBxqZL0PIOMKKzitMRscQsab8vgm8FkqjfMyPBQQS1nXiD_cqrq2cr6QLApugk3fg\"}}",
    },
    "id": 1
}
```

**Response:** The chain of DID documents (and document metadata) from the signer's DID to the root DID.

&nbsp;

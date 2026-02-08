# Developer Guide [DRAFT]

<!-- ## Contents

- Project Overview and Structure
    - Repositories
        - Trustchain
        - Trustchain Mobile
        - Trustchain GUI
        - Trustchain Dart
    - Forks
        - SSI
- Trustchain details
    - Rust Crates
        - `trustchain-api`
        - `trustchain-core`
        - `trustchain-ion`
        - `trustchain-cli`
        - `trustchain-ffi`
        - `trustchain-dart`
        - `trustchain-http`
    - Running Tests
    - Coding Conventions
        - Crate Configuration
        - Error handling
- Trustchain Mobile details
    - TODO: Building the app for emulator
    - Building app for Android physical device
- Trustchain GUI details
    - TODO
- Trustchain Dart details
    - Platform agnostic error handling
    - Dart models of Trustchain structs
    - Shared UI widgets


:::info
TODO:
 - add Certbot instructions (see [#618](https://github.com/alan-turing-institute/trustworthy-id/issues/618))
::: -->

## Project Structure

The Trustchain codebase consists of four repositories:

 - [trustchain](https://github.com/alan-turing-institute/trustchain): Rust API and core reference implementation, CLI, HTTP, and FFI.
 - [trustchain-gui](https://github.com/alan-turing-institute/trustchain-gui): Desktop GUI for mirroring CLI functionality.
 - [trustchain-mobile](https://github.com/alan-turing-institute/trustchain-mobile): Mobile credential wallet forked from [credible (now called wallet)](https://github.com/spruceid/wallet)
 - [trustchain-dart](https://github.com/alan-turing-institute/trustchain-dart): common Dart library code for errors and widgets.

And a fork of the [spruceid/ssi](https://github.com/spruceid/ssi) repository:

- [ssi](https://github.com/alan-turing-institute/ssi/tree/dev): Changes on the fork are described in detail in the [PR notes](https://github.com/alan-turing-institute/ssi/pull/3):
    - New Redactable Signature scheme added, allowing selective disclosure for Verifiable Credentials.
    - TODO: mention the [IPFS-linked key feature](https://github.com/alan-turing-institute/trustchain/issues/148) added to support >1kB RSS public keys. The ION DID method imposes a 1kB limit on DID deltas, making it impossible to publish RSS keys directly in ION DID documents.
        - Unit test in `trustchain-api/src/api.rs` called `get_key_entry()` can be used to print a `PublicKeyEntry` which is the type uploaded to IPFS.

## Code Repositories

### Trustchain

The main `trustchain` repository contains the following Rust crates (details of which are given in the section below):

  - `trustchain-core`: Core logic, agnostic to implementation-specific components
  - `trustchain-ion`: Implementation of Trustchain for the ION DID method
  - `trustchain-cli`: Trustchain command line interface
  - `trustchain-ffi`: Foreign Function Interface
  - `trustchain-http`: Trustchain HTTP APIs

### Trustchain GUI

The `trustchain-gui` repository contains a Flutter application (written in Dart) which wraps the `trustchain` repository, and serves as the Trustchain desktop application.

### Trustchain Mobile

The `trustchain-mobile` repository is a fork of the Credible credential wallet developed by [SpruceID](https://www.spruceid.dev/) (also using Flutter/Dart), tailored to work with Trustchain.

### Trustchain Dart

The `trustchain-dart` repository contains platform agnostic dart code to be shared across platform specific application repositories (eg. `trustchain-mobile` and `trustchain-gui`). Including but not limited to shared ui and ffi error handling.

### SSI (Forked from SpruceID)

This is the main upstream library on which the Trustchain codebase depends.



## Rust Crates
Where required, configurable variables within crates are managed according to the [configuration convention](#Crate-Configuration).


### trustchain-core

#### Error handling

- Enums
    - Implement `std::error::Error` with `thiserror` crate
    - Add variants that wrap other errors (e.g. SSI error) so they can be passed
    - Where possible do not convert error to string
    - One variant pattern with extra context is:
        - `MyError::Variant(String, ErrorTypeToWrap)`
        - TODO: add example
    -

#### Immutable verifier
- TODO: add info on `Mutex` and `Arc` from issue 89
- Principle: lock at lowest possible level to avoid bottlenecks
- Thread safe shared ownership with `Arc` and mutability with `Mutex`

### trustchain-ion


### trustchain-cli
Install with:
```bash
cargo install --path crates/trustchain-cli
```



##### Creating a DID
```bash
trustchain-cli did create --verbose --file ~/.trustchain/doc_states/my_doc_state.json
```

Checking the queue on the ION node:
```
> use ion-testnet-core
> db
ion-testnet-core
> db["queued-operations"]
ion-testnet-core.queued-operations
> db.getCollectionNames()
[
        "confirmations",
        "operations",
        "queued-operations",
        "service",
        "transactions",
        "unresolvable-transactions"
]
> db["queued-operations"].count()
1
```


##### Attesting to DID

```bash
trustchain-cli did attest --did UPSTREAM_DID --controlled_did DOWNSTREAM_DID
```

##### Verify
```bash
trustchain-cli did verify --did DOWSTREAM_DID_TO_VERIFY
```

E.g. for Turing:
```
cargo run --bin trustchain-cli -- did verify --did did:ion:test:EiDSE2lEM65nYrEqVvQO5C3scYhkv1KmZzq0S0iZmNKf1Q
```

##### Publish DIDs
Run:
```bash!
./scripts/publish.sh
```
and all operations in the `~/.trustchain/operations/*` will be posted to the ION server at `localhost:3000`.

__You then need to manually move the operations (once satisifed published ok) to ~/.trustchain/operations/sent/./__
```bash
mv ~/.trustchain/operations/*.json* ~/.trustchain/operations/sent/./
```

### trustchain-ffi

- Modules:
    - `mobile`
    - `gui`
- Each module has a set of free functions that are to be called on the Dart side
- Functions have a return type `anyhow::Result<String>` so that error handling can be sent over FFI

#### (TODO: remove as outdated) Old notes from `trustchain-mobile` set-up for FFI
##### Trustchain FFI with flutter rust bridge

Provides Trustchain functionality in credible with FFI through [`flutter_rust_bridge`](https://github.com/fzyzcjy/flutter_rust_bridge).

###### Install
The below steps follow the guide in [section 5](https://cjycode.com/flutter_rust_bridge/integrate.html):

- Clone [trustchain](https://github.com/alan-turing-institute/trustchain) to a path adjacent to credible root path.
- Install cargo [dependencies]():
```
cargo install flutter_rust_bridge_codegen@1.64.0
```
- Follow android [instructions](https://cjycode.com/flutter_rust_bridge/template/setup_android.html)
- Add targets:
```
rustup target add \
    aarch64-linux-android \
    armv7-linux-androideabi \
    x86_64-linux-android \
    i686-linux-android
```
- Add `ANDROID_NDK` as a [gradle property](https://cjycode.com/flutter_rust_bridge/template/setup_android.html#android_ndk-gradle-property):
```
echo "ANDROID_NDK=(path to NDK)" >> ~/.gradle/gradle.properties
```
- Install [`cargo ndk`](https://cjycode.com/flutter_rust_bridge/template/setup_android.html):
```shell
cargo install cargo-ndk --version 2.6.0
```

###### Build
With an android emulator, build can be completed from credible root with:
```
flutter run
```
Upon any modifications to the Trustchain Rust API, the FFI needs to be rebuilt with:
```
flutter_rust_bridge_codegen \
    -r ../trustchain/trustchain-ion/src/api.rs \
    -d lib/bridge_generated.dart
```


### trustchain-http

- Three functionalities are provided in initial crate:
    - Issuer of credentials
    - Verifier
    - Trustchain resolver/chain/CR
- The server is run from a binary running an axum app inside a tokio async runtime
    - `#[tokio::main]` for async main
    - `#[tokio::test]` for async test
- Use axum for server impl (this uses `hyper` behind the scenes). Actix will not play nicely mixed with axum/hyper but can't remember why!
- Use `reqwest` over `hyper` for client requests
- Use traits for [API definition](https://github.com/alan-turing-institute/trustchain/blob/c17ad8e4753a104442f95f1015b960698b2c2eb6/trustchain-http/src/resolver.rs#L27-L43) and then impl for a [struct](https://github.com/alan-turing-institute/trustchain/blob/c17ad8e4753a104442f95f1015b960698b2c2eb6/trustchain-http/src/resolver.rs#L45) to bring [handler methods](https://github.com/alan-turing-institute/trustchain/blob/c17ad8e4753a104442f95f1015b960698b2c2eb6/trustchain-http/src/resolver.rs#L82-L122). These handler methods return `impl IntoResponse` an axum type that makes the everything easy to connect together. Very similar to FFI but not free functions.
- `TrustchainHTTPAPI` trait returns `Result<T, TrustchainHTTPError>`
- Handler methods convert `Result<T, TrustchainHTTPError>` into `impl Response` with the power of `impl IntoResponse for Result<T, E>` already implemented.
- `TrustchainHTTPError` will:
    - Have variants corresponding to different HTTP status error types (e.g. Internal server error) but also have variants that wrap other Trustchain errors (e.g. `VerifierError`)
    - Will have an `impl IntoResponse for TrustchainHTTPError` (see [initial implementation](https://github.com/alan-turing-institute/trustchain/blob/c17ad8e4753a104442f95f1015b960698b2c2eb6/trustchain-http/src/errors.rs#L46-L66) passing on the `TrustchainHTTPError` as a `String` along with a `StatusCode`). By implementing the `axum` crate's `IntoResponse`, we can explicitly map each variant to a `StatusCode` and benefit from being able to directly return types: `Result<T: IntoResponse, TrustchainHTTPError>`.
- A shared [AppState](https://github.com/alan-turing-institute/trustchain/blob/c17ad8e4753a104442f95f1015b960698b2c2eb6/trustchain-http/src/state.rs#L8-L11) is made available  to the handlers (e.g. for [DIDChain handler](https://github.com/alan-turing-institute/trustchain/blob/c17ad8e4753a104442f95f1015b960698b2c2eb6/trustchain-http/src/resolver.rs#L86)). This allows anything in the state struct (currently a `ServerConfig` struct and an `IONVerifier`) to be used inside the [handler](https://github.com/alan-turing-institute/trustchain/blob/c17ad8e4753a104442f95f1015b960698b2c2eb6/trustchain-http/src/resolver.rs#L89-L92). The `AppState`, as it does not implement `Clone` (the `IONVerifier` field cannot impl `Clone` and should be only be borrowed anyway as it contains a cache), needs to be passed into the shared state with an [atomic reference counter](https://github.com/alan-turing-institute/trustchain/blob/c17ad8e4753a104442f95f1015b960698b2c2eb6/trustchain-http/src/bin/main.rs#L33). The `IONVerifier` is wrapped in a tokio read-write lock ([`RWLock`](https://docs.rs/tokio/latest/tokio/sync/struct.RwLock.html)) so that it can be mutable to allow data to be stored but so that race conditions are avoided within the async context we are using it. In practice, this means that when it is used inside a handler, a call to either make the lock [read](https://github.com/alan-turing-institute/trustchain/blob/c17ad8e4753a104442f95f1015b960698b2c2eb6/trustchain-http/src/bin/main.rs#L105) or [write](https://github.com/alan-turing-institute/trustchain/blob/c17ad8e4753a104442f95f1015b960698b2c2eb6/trustchain-http/src/resolver.rs#L89) if mutability is required. [`RWLock`](https://docs.rs/tokio/latest/tokio/sync/struct.RwLock.html) is preferred over [`Mutex`](https://docs.rs/tokio/latest/tokio/sync/struct.Mutex.html) so that we only lock the `IONVerfier` when a write is required as opposed to when only read is required (as a resolver). We could implement a separate resolver field too inside the `AppState` and just use a `Mutex` if preferred. We could also revert to making `IONVerifier` instances in each handler call if verification will "lock out" other requests waiting for it to be freed (this may be an issue calling IPFS for data not cached on the server's IPFS node).
- Tests:
    - One big integration test for each of the three: issuer, verifier, TC node purposes
    - Q: Should we do lots of unit tests for each part???

#### Getting Started with trustchain-http

- Set-up [ssh config](https://github.com/alan-turing-institute/trustchain/wiki/Trustchain-Developer-Notes#ssh-config-file): Add the following config (with your azure key) to `~/.ssh/config`
```
Host ion
    HostName 51.104.16.53
    User ionuser
    IdentityFile ~/.ssh/<YOUR_AZURE_KEY>
    LocalForward 3000 localhost:3000
    LocalForward 18332 localhost:18332
    LocalForward 27017 localhost:27017
    LocalForward 5001 localhost:5001
```
Then call:
```bash
ssh ion
```
- Start the [ION node](https://github.com/alan-turing-institute/trustchain/wiki/Trustchain-Developer-Notes#using-ion).
- Symlink from SharePoint `dot_trustchain` directory to `~/.trustchain`.
    - Find the absolute path to the `dot_trustchain` folder in your local OneDrive directory (eg. `/Users/<my_user>/Library/CloudStorage/OneDrive-TheAlanTuringInstitute/dot_trustchain`).
    - `cd` to the desired target directory (eg. `~`), and symlink with:

        ```
        ln -s /Users/<my_user>/Library/CloudStorage/OneDrive-TheAlanTuringInstitute/dot_trustchain .trustchain
        ```
- Add the following to your shell profile (e.g. `~/.zshrc`) and source it.
```
# Trustchain
export TRUSTCHAIN_CONFIG=~/.trustchain/trustchain_config.toml
export TRUSTCHAIN_DATA=~/.trustchain/
```
- Clone the `trustchain` repo and checkout a branch with the `trustchain-http` crate (currently `55-issuer-backend-traits`).
- Run the server with:
```
cargo run -p trustchain-http
```
- Install [Postman](https://www.postman.com/downloads/)
- Open the Postman workspace at: `~/.trustchain/postman_workspaces/*`
- Test by executing the pre-loaded HTTP requests in the Postman workspace.

Branches (at May 2023):
- Current root for HTTP work: `55-issuer-backend-traits`
- Implementing verifier routes: `55-issuer-backend-traits-verifier-todo`
- Challenge-Response: `94-challenge-response`


##### Copying dot trustchain to a VM
```bash
rsync -azvuv --prune-empty-dirs \
    /Users/sgreenbury/ati/trustworthy-id/dot_trustchain \
    ion:./ \
    --include='dot_trustchain/key_manager/*/signing_key.json' \
    --include='**/trustchain_config.toml' \
    --include='dot_trustchain/credentials/offers/*.json' \
    --include='dot_trustchain/presentations/requests/*.json' \
    --include='*/' --exclude='*'
```


##### Running the HTTP server on the VM over https
- Go trustchain repo, install from branch you would like to serve:
```
cargo install --path crates/trustchain-http
```
- Allow the binary to access 443 without sudo:
```
sudo setcap CAP_NET_BIND_SERVICE=+eip .cargo/bin/trustchain-http
```
:::info
Note: the above `setcap` command must be re-run whenever the trustchain-http crate is rebuilt.
:::

- Then run the server with:
```
trustchain-http
```


#### Creating a new HTTP endpoint in trustchain-http

- Inside the `trustchain-http` crate, add a new route in the `TrustchainRouter` impl block in the `server.rs` module.
- Create a new module in the `trustchain-http` crate to handle request to the new route (or use an existing handler module). Add the new module in `lib.rs`.
- In the handler module, create a struct representing the information in the HTTP GET/POST request. This will destructure the strings in the request into Rust types and should have the annotations:
```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
```
- Write an async "backend trait" (similar to the example in `TrustchainHTTP`). Each method in this trait must return a `Result` type in which the success and error types both implement `IntoResponse` (in which case the `Result` type itself automatically implements the same trait).
- Write a trivial struct for your implementations of the backend trait (similar to `pub struct TrustchainHTTPHandler {}`).
- Implement the backend trait for the new struct.
- Also inside the same struct that implements the backend trait, implement a handler method (that's *not* in the trait) to provide the glue between the route and the backend Rust code:
    - arguments must be "extractors" (e.g. `Path`, `Query`, `Json`, `State`, etc.) corresponding to the HTTP request. For instance, a query parameter (after a `?` in the HTTP POST request) requires a `Query` extractor.
    - return type must be `impl IntoResponse`
    - In the body of the handler method, make a call to a Rust method in the "backend trait" (that's implemented for the same struct that contains the handler method).
    - Note: handler methods *could* be free functions, but by convention we include them in the impl block for the same struct that implements the backend trait.
- If you need new error variant, go to `trustchain-http/src/errors.rs` and make a new variant. Add a new block in the `impl IntoResponse` part, e.g.:
```
            err @ TrustchainHTTPError::NoCredentialIssuer => {
                (StatusCode::BAD_REQUEST, err.to_string())
            }
```
- Use the Axum test helper crate to create a unit test for your new endpoint:
    - Create a `tests` module as a child of you handler module and import The Axum test helper:
    ```
        use axum_test_helper::TestClient;
    ```
    - Inside the `tests` module, create a new (async) test case for your endpoint. Annotate it with `#[tokio::test]`.
    - Copy the boilerplate code from an existing test:
    ```
        let app = TrustchainRouter::from(HTTPConfig::default()).into_router();
        let uri = "/<your-endpoint>".to_string();
        let client = TestClient::new(app);
    ```
    - Make the request to the client, e.g.:
    ```
        let response = client.post(&uri)
            .json(<your-POST-request-params>)
            .send()
            .await;
    ```
    - This sends a request to a server instance running on a random ephemeral port (thank you Axum helper!)
    - Add a test assertion, e.g.:
    ```
    assert_eq!(response.status(), 200)
    assert_eq!(response.text().await, "Hello world!")
    ```
    - Run the specific test in VS Code by clicking "Run Test" above the test case, or run the whole test suite using cargo.


## Running Tests

Tests are implemented at either:
- module level within a library crate (unit test)
- separate test path adjacent to the library crate integration tests

Some tests require ION (IPFS, mongo, bitcoin) and trustchain nodes (trustchain-http) to be running locally. When this is the case, `#[ignored="A REASON"]` should be placed above the `fn test_fn()`:
```rust
#[test]
#[ignored="A REASON"]
fn test_fn() {
    // ...
}
```


### Set-up
- TODO: add description of init()

## Coding Conventions

### Crate Configuration
#### Defining config variables
When handling configurable variables, a distiction has been made between *crate-level constants*, *user-configurable variables*, and *environment variables*.
- *Crate-level constants* are defined in the `lib.rs` file at the root of the crate.
    - They are part of the core funtionality of the crate and will be the same for all crate use cases.
    - Any unit tests or integration tests may depend on these constants, as they are part of the core funtionality of the crate.
- *User-configurable variables* are defined in the `trustchain_config.toml` file.
    - One configuration file is used for all of the Trustchain crates being used, with one section in the file for each crate being configured.
    - The may only be used in *ignored* tests (annotated with `#[ignore = "<Reason for ignore>"`), because they depend on the user setting an enviornment variable, `TRUSTCHAIN_CONFIG`, that points to a valid `trustchain_config.toml` file.
    - An example `trustchain_config.toml` file for a project containing the `trustchain-core` and `trustchain-myexample` crates *only*, would have the following structure:
        ```
        [core]
        dummy_variable_1 = 12345

        [myexample]
        dummy_variable_2 = 123456
        dummy_variable_3 = "dummy string"
        ```
- *Environment variables* are variables set in the calling shell that can be referenced in either library or binary code with `std::env::var("ENV_VARIABLE_NAME")`. There are two in use and have corresponding `lib.rs` `&str` constants:
    - `TRUSTCHAIN_DATA`: this is the directory path for key manager and HTTP features (SSL certificates, credential store, etc).
    - `TRUSTCHAIN_CONFIG`: this is the file path for the main Trustchain `.toml` configuration file.
These may be set independently and during `cargo test` `TRUSTCHAIN_DATA` is set specifically to a tempdir location inside [`init()`](TODO).



#### Referencing config variables
The convention for referencing the *user-configurable variables* in Rust code is to introduce a `config.rs` file at the root of the crate. The role of the file is to load the variables from `trustchain_config.toml` that relate to that crate. An example `config.rs` file for a new crate `trustchain-myexample` is as follows:

```rust
use crate::TRUSTCHAIN_CONFIG;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fs;
use toml;

lazy_static! {
    /// Lazy static reference to core configuration loaded from `trustchain_config.toml`.
    pub static ref MYEXAMPLE_CONFIG: MyexampleConfig = parse_toml(
        &fs::read_to_string(std::env::var(TRUSTCHAIN_CONFIG).unwrap().as_str())
        .expect("Error reading trustchain_config.toml"));
}

/// Parses and returns core configuration.
fn parse_toml(toml_str: &str) -> MyexampleConfig {
    toml::from_str::<Config>(toml_str)
        .expect("Error parsing trustchain_config.toml")
        .core
}

/// Gets `trustchain-core` configuration variables.
pub fn myexample_config() -> &'static MYEXAMPLE_CONFIG {
    &MYEXAMPLE_CONFIG
}

/// Configuration variables for `trustchain-core` crate.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct MyexampleConfig {
    /// Variables defined in the 'myexample' section of trustchain_config.toml
    pub dummy_variable_2: u32,
    pub dummy_variable_3: String
}

/// Wrapper struct for parsing the `myexample` table.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Config {
    /// Core configuration data.
    myexample: MyexampleConfig,
}
```

The above module exposes a function `myexample_config()` which is used elsewhere in the crate to access the variables:
```rust
use crate::config::myexample_config;

let var_2 = myexample_config().dummy_variable_2
```

#### Use of config variables

In library code, config variables should be passed as arguments to functions that depend on them, rather than accessing from a static reference (as described above).

This avoids any dependency on local config files, which causes problems (e.g. when writing unit tests).

For example, the `Verifier` API **should** look this this:
```rust
pub fn new(resolver: Resolver<T>, config: &IONConfig) -> Self {
// Construct a Bitcoin RPC client to communicate with the ION Bitcoin node.
    let rpc_client = bitcoincore_rpc::Client::new(
        &config.bitcoin_connection_string,
        bitcoincore_rpc::Auth::UserPass(
            config.bitcoin_rpc_username.clone(),
            config.bitcoin_rpc_password.clone(),
        ),
    )
    // Safe to use unwrap() here, as Client::new can only return Err when using cookie authentication.
    .unwrap();
}
```
and **should not** use a getter for the static reference, like this:
```rust
// DON'T DO THIS!
pub fn new(resolver: Resolver<T>) -> Self {
// Construct a Bitcoin RPC client to communicate with the ION Bitcoin node.
    let rpc_client = bitcoincore_rpc::Client::new(
        &config.bitcoin_connection_string,
        bitcoincore_rpc::Auth::UserPass(
            ion_config().bitcoin_rpc_username.clone(),
            ion_config().bitcoin_rpc_password.clone(),
        ),
    )
    // Safe to use unwrap() here, as Client::new can only return Err when using cookie authentication.
    .unwrap();
}
```


### Error Handling

#### Use of `map_error`
Where error enums do not explicitly implement the `From<T>` conversion trait, use `.map_err()` followed by the question mark operator `?` to allow ergonomic error propagation.

#### Error enums

Module-specific error enums should be defined in the module. Error enums used in multiple modules within a crate should be defined in an `error.rs` module of the crate and make use of [`thiserror`](https://docs.rs/thiserror/latest/thiserror/) to simplify implementation.

`From<T>` can be implemented manually for types as currently in the [`trustchain-http`](https://github.com/alan-turing-institute/trustchain/blob/1c131881925ed23daf614785865640ce3a7e734f/trustchain-http/src/errors.rs#L46-L80) crate but can also be more straightforwardly implemented with thiserror. See [`KeyManagerError`](https://github.com/alan-turing-institute/trustchain/blob/1c131881925ed23daf614785865640ce3a7e734f/trustchain-core/src/key_manager.rs#L38-L40).



#### FFI Error handling with `anyhow::Result<T>`
Notes:
- `flutter_rust_bridge` currently does **not** support returning the Rust `Result` type over the bridge. Instead, returning `anyhow::Result<T>` is supported.
- Whilst a generic over the error varient, `anyhow::Result<T,E>`, is supported by `anyhow`, the bridge only supports an `anyhow` error varient of type `anyhow::Error` (the shorthand for which is `anyhow::Result<T>`).

How to implement:
- `anyhow::Result<String>` and `anyhow::Result<()>` are to two return types used for any of the ffi functions (called from Dart).
- The `String` option is flexible to cover any serialised Rust types. A Dart model with a deserialisation method will handle the json string on the Dart side.
- See the example Rust code below, demonstrating an ffi function to be called by Dart:
```
use thiserror::Error;

#[derive(Error, Debug)]
enum MyFFIError {

    #[error("JSON Deserialisation Error: {0}.")]
    FailedToDeserialise(serde_json::Error),

    #[error("My_func Error: {0}.")]
    FailedToDoIt(Box<dyn std::error::Error>),
}

pub fn my_ffi_function(arg1: String) -> anyhow::Result<String> {

    match TrustchainAPI::my_function(&arg1) {

        Ok(my_answer) => Ok(serde_json::to_string_pretty(&my_answer)
            .expect("Serialize implemented for my_answer struct")),

        Err(err) => Err(anyhow!("{}", MyFFIError::FailedToDoIt(err))),
    }
}
```

Some notes on the above:
- Aligned with the wider convention on custom Error enums, `thiserror::Error` is derived with the `#[error("...")]` macro.
- Under the hood, the `anyhow!()` macro uses this to build the string passed over the bridge to Dart.
- The error received by Dart will be: `"My_func Error: <Whatever the Boxed error returned from my_function was>."`
- Dart code can pattern match on the first part of the string, before the colon.
- **When implementing a new variant on an ffi error enum in Rust, a corresponding varient must be added to the dart `FfiError` enum, maintained in the `trustchain-dart` repository.**
- Under certain circumstances, it is possible to return `Err(MyFFIError::my_varient(err).into())` without using the `anyhow!()` macro. However, this shortcut will **not** work if `MyFFIError` contains varients wrapping `Box<dyn Error>` (boxed trait objects).
- In line with the wider convention on error handling, it is possible to have a custom error enum wrapping a tuple `(String, Error)`, in order to provide some additional information:
```
#[error("JSON Deserialisation Error: {1} \n Info: {0}")]
    FailedToDeserialiseVerbose(String, serde_json::Error),
```


---
## Trustchain Mobile details

Trustchain mobile installation instructions: https://github.com/alan-turing-institute/trustchain-mobile/blob/dev/install_trustchain_mobile.md

### Building for an Android emulator
TODO

### Building app for Android physical device

- Build app:
```
flutter build apk --debug --dart-define-from-file flutter-config.json
```
with `flutter-config.json` containing a default endpoint, for example:
```json
{
    "trustchainEndpoint": "https://trustchain.uksouth.cloudapp.azure.com",
    "rootEventTime": "<YOUR_ROOT_EVENT_TIME>"
}
```

- Log in to trustchaindevstest google account:
- Go to [drive](https://drive.google.com/drive/my-drive)
- Upload the built apk to drive. Path should be:
```
build/app/outputs/flutter-apk/app-debug.apk
```
- Update shared permissions/access settings on google drive for the file to "Share with anyone by link"
- Copy link
- Use e.g. `qrencode` command line util (or any QR code maker) to generate a QR code picture:
```
brew install qrencode
qrencode <LINK> -o qrcode.png
```
A recent one is:
https://drive.google.com/file/d/1tXvnOI8Zbqav-JwM2tKtuo84kGfVinBt/view

- Open with preview and scan from device to download the file
- Open the APK and allow to install

---

## Trustchain GUI details

## Trustchain Dart details
In principal, front-end applications on all platforms should share as much code in Trustchain Dart as possible.

This work was not completed. Trustchain Mobile currently **does not** depend on Trustchain Dart. Trustchain GUI **does** depend on Trustchain Dart, but there is some dupicate code between the two repositories.
### Platform agnostic error handling
- `FfiError`, an extended dart enum, maps all Rust error variants returned over the ffi.
    - The enum variants contain string constants within them (analogous to Rust enums containing data).
    - A static method on `FfiError`, called `parseFfiError()`, automatically supports any new enum variants added to FfiError and parses the serialised Rust errors into `FfiError` variants.

### Dart models of Trustchain structs
This work was not completed.
- Platform agnostic dart models, constructable from serialised Rust structs.

### Shared UI widgets
This work was not completed.
- Trustchain Mobile and Trustchain GUI use _different_ dart widgets to display the same trustchain Rust structs.
- **Platform agnostic widgets** could be shared and ensure consistent UI for applications on all platforms.
- **Palettes, styling and assets** should be maintained in this repository to ensure consistency across applications on all platforms.

## Documentation

The Trustchain Docs documentation site is built with [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/).

### Terminal commands

All Terminal commands in the documentation should be rendered in full-line code blocks (not inline) and tagged with the identifier `console` after the three opening backticks. They should include the `$` character to indicate the command prompt.

The prompt character helps to distinguish between Terminal commands and other code snippets that should not be entered at the command line, and is omitted when the "Copy to clipboard" icon is clicked (or the code is selected).

For example, the Markdown code block:
````
```console
echo "hello, world"
```
````
will be rendered as:
```console
echo "hello, world"
```
but only the command `echo "hello, world"` will be copied to the clipboard.

!!! info

    The feature to omit the command prompt character when copying to the clipboard is [not implemented](https://github.com/squidfunk/mkdocs-material/issues/3647#issuecomment-1108132654) in Material for MkDocs. Instead it was added via custom Javascript following [this approach](https://github.com/SensorsIot/IOTstack/pull/547).


&nbsp;

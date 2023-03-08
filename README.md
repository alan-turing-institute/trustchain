# Trustchain

This repo hosts the reference implementation of **Trustchain**.

Trustchain is a decentralised approach to public key infrastructure designed for application to digital identity. In particular, it builds on the W3C standards for [decentralised identifiers (DID)](https://www.w3.org/TR/did-core/) and [verifiable credentials (VC)](https://www.w3.org/TR/vc-data-model/).

These two standards are closely linked: credential verification involves retrieval of verification material contained in the issuer's DID document. For example, the verification material may be a public key, in which case the verification method is to use the key to verify a digital signature contained in the VC.

Trustchain enables the creation of DIDs which are themselves verifiable. Via this mechanism, chains of trustworthy DIDs can be constructed in which **downstream DIDs** (dDIDs) contain an attestation from an entity represented by an **upstream DID** (uDID).

More information about the concept and state of development can be found on our [wiki](https://github.com/alan-turing-institute/trustchain/wiki). The following links may be of particular interest:
- [Trustchain on Github pages](https://alan-turing-institute.github.io/trustchain/#/)
- [Trustchain FAQ](https://github.com/alan-turing-institute/trustchain/wiki/Trustchain-FAQ)
- [Slides & Videos](https://github.com/alan-turing-institute/trustchain/wiki#communication)
- [Technical Notes](https://github.com/alan-turing-institute/trustchain/wiki/Trustchain-Technical-Notes)

## Installation guide

This brief guide is intended for experienced users/developers who want to get started quickly.

#### Step 1. Install ION
Trustchain delegates all DID method operations to a node on the [ION](https://identity.foundation/ion/) network.

The [ION install guide](https://identity.foundation/ion/install-guide/) gives step-by-step instructions on how to setup and run your own ION node.

We encountered a few problems with the official installation guide. Hence we recommend to use our modified instructions for [ION installation on Mac](https://alan-turing-institute.github.io/trustchain/#/./installation?id=ion-installation-on-mac) or [ION installation on Linux](https://alan-turing-institute.github.io/trustchain/#/./installation?id=ion-installation-on-linux).

#### Step 2. Install Rust
Follow the [Rust install guide](https://www.rust-lang.org/tools/install).

#### Step 3. Install Trustchain
Trustchain can be built and tested using cargo:
```
git clone https://github.com/alan-turing-institute/trustchain.git
cd trustchain
cargo build
```
Install the Trustchain CLI with:
```shell
cargo install --path trustchain-ion
```
Run tests:
```
cargo test
```
To include integration tests, which will fail unless a running ION node is reachable on localhost, use:
```
cargo test -- --include-ignored
```

## Usage Guide
Once installed, the CLI is callable with:
```
trustchain-cli --help
```
DID subcommands:
```
truscthain-cli did --help
```
Verifiable credential subcommands:
```
trustchain-cli vc --help
```

## License & disclaimer
Trustchain is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.

## Acknowledgements
This work was supported, in whole or in part, by the Bill & Melinda Gates Foundation [INV-001309].

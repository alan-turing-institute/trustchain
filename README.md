# Trustchain

This repo hosts the development for prototype tools that provide the functionality required for **Trustchain**.

Trustchain is a decentralised approach to public key infrastructure, with applications in digital identities. In particular, it builds on the W3C standards for [decentralised identifiers (DID)](https://www.w3.org/TR/did-core/) and [verififiable credentials (VC)](https://www.w3.org/TR/did-core/).

These two standards are already closely linked: Verifying a VC involves performing the verification method specified in the DID document using verification material contained in the same DID document. For example, the verification material may be a public key, in which case the verification method is to use the key to verify a digital signature contained in the VC.

Trustchain aims to combine the two standards to create DIDs which are themselves verifiable credentials. In doing so, verifiable **downstream DIDs** (dDIDs) can be constructed, which are signed by an entity represented in an **upstream DID** (uDID). dDIDs are essential building blocks to create a chain of trusted DIDs.

This repository is under construction. Please see the [wiki](https://github.com/alan-turing-institute/trustchain/wiki) for more information about the concept and state of development. The following links may be of particular interest:
- [Trustchain on Github pages](https://alan-turing-institute.github.io/trustchain/#/)
- [Trustchain FAQ](https://github.com/alan-turing-institute/trustchain/wiki/Trustchain-FAQ)
- [Slides & Videos](https://github.com/alan-turing-institute/trustchain/wiki#communication)
- [Technical Notes](https://github.com/alan-turing-institute/trustchain/wiki/Trustchain-Technical-Notes)

## Installation guide

This brief guide is intended for experienced users/developers who want to get started quickly.


#### Step 1. Install ION
Trustchain delegates all DID method operations to a node on the [ION](https://identity.foundation/ion/) network.

The [ION install guide](https://identity.foundation/ion/install-guide/) gives step-by-step instructions on how to setup and run your own ION node.

We encountered a few problems with the official installation guide. Hence we recommend to use our [modified instructions](https://alan-turing-institute.github.io/trustchain/#/installation) for ION installation on Mac or ION installation on Linux.

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

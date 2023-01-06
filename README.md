# Trustchain

A decentralised approach to public key infrastructure.

This repository is under construction. Please see the [wiki](https://github.com/alan-turing-institute/trustchain/wiki) for more information about the concept and state of development. The following links may be of particular interest:
- [Trustchain FAQ](https://github.com/alan-turing-institute/trustchain/wiki/Trustchain-FAQ)
- [Slides & Videos](https://github.com/alan-turing-institute/trustchain/wiki#communication)
- [Technical Notes](https://github.com/alan-turing-institute/trustchain/wiki/Trustchain-Technical-Notes)

## Architecture
TODO

## Installation guide
This brief guide is intended for experienced users/developers who want to get started quickly.

For detailed installation instructions please see the [full installation guide](TODO).

#### Step 1. Install ION
Trustchain delegates all DID method operations to a node on the [ION](https://identity.foundation/ion/) network.

The [ION install guide](https://identity.foundation/ion/install-guide/) gives step-by-step instructions on how to setup and run your own ION node.

At the time of writing, however, the ION guide does not support

#### Step 2. Install Rust
Follow the [Rust install guide](https://www.rust-lang.org/tools/install).

#### Step 3. Install Trustchain
Trustchain can be built and tested using cargo:
```
git clone https://github.com/alan-turing-institute/trustchain.git
cd trustchain
cargo build
```
You can run tests with:
```
cargo test
```
To include integration tests, which will fail unless a running ION node is reachable on localhost, use:
```
cargo test -- --include-ignored
```

## Usage Guide

```
trustchain-cli did
trustchain-cli vc
trustchain-cli -h, --help

trustchain-cli vc attest
trustchain-cli vc verify
trustchain-cli vc -h, --help

trustchain-cli vc attest [OPTIONS] --did <DID> --credential_file <CREDENTIAL FILE>

trustchain-cli vc attest -v, --verbose
trustchain-cli vc attest -d, --did <DID>
trustchain-cli vc attest -f, --credential_file <CREDENTIAL FILE> --key_id <KEY_ID>
trustchain-cli vc attest -h, --help


trustchain-cli vc verify [OPTIONS] --credential_file <CREDENTIAL FILE>

trustchain-cli vc verify -v, --verbose
trustchain-cli vc verify -f, --credential_file <CREDENTIAL FILE>
trustchain-cli vc verify -s, --signature_only
trustchain-cli vc verify -t, --root_event_time
trustchain-cli vc verify -h, --help

```


```
trustchain-cli vc attest -f [filename].jsonld --did did:ion:[identity] > vc.jsonld
```

```
trustchain-cli vc verify --credential_file vc.jsonld

trustchain-cli vc verify --credential_file vc.jsonld --verbose
```

## License & disclaimer
Trustchain is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.

## Acknowledgements
This work was supported, in whole or in part, by the Bill & Melinda Gates Foundation [INV-001309].

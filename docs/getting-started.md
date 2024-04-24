# Getting Started

## Installation

Trustchain can be installed on all major operating systems. The steps below have been tested on Linux and Mac OS. On Windows the process will be similar, with instructions available via the links provided.

### Step 1. Install ION

As the main Trustchain dependency, ION has its own secction on this site. Please follow the installation instructions provided on the [ION page](ion.md).

### Step 2. Install Rust

Instructions for installing the Rust language can be found [here](https://www.rust-lang.org/tools/install).

On Linux or Mac OS, the recommended method is to run the following command:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then check the installation was successfully by running:
```bash
rustc --version
```

### Step 3. Install Trustchain

Run the following commands to clone the Trustchain repository and build the package:
```bash
git clone https://github.com/alan-turing-institute/trustchain.git
cd trustchain
cargo build
```

Install the Trustchain CLI with:
```bash
cargo install --path trustchain-cli
```

Install the Trustchain HTTP server with:
```bash
cargo install --path trustchain-http
```

## CLI

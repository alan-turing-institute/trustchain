# Getting Started

The instructions below will guide you through the installation and configuration of the Trustchain software.

Trustchain can be installed on all major operating systems. The steps below have been tested on Linux and Mac OS. On Windows the process will be similar, with instructions available via the links provided.

!!! info "Running commands in the Terminal"

    This guide will make frequent use of the command line interface provided by the Terminal application, which is available on all operating systems.

    Commands will be presented in code blocks like this one:
    ```console
    $ echo "Hello World"
    ```
    The initial prompt character `$` indicates that this is a Terminal command that you should copy and paste into your Terminal, followed by the ++return++ key to execute the command.

    To copy commands to the clipboard, click on the :material-content-copy: icon at the right-hand side of the code block. Only the command will be copied (the prompt character will be omitted), so it can be pasted straight in to the Terminal.

## Preparation

In order to provide Terminal commands that will work on any computer, we shall define some environment variables to keep track of the folders that are important to Trustchain.

Environment variables are defined in your Terminal configuration file.

If you're not sure which shell environment config file to use, run the following command and pick one of them:
```console
$ ls ~/.*shrc
```

In these instructions we assume that the data directory will be `~/.trustchain`, but if you prefer to use a different one simply change the value of the `TRUSTCHAIN_DATA` environment variable below.

Now create three environment variables by adding the following lines to your shell environment config file (e.g. `~/.zshrc` or `~/.bashrc`):
```
export TRUSTCHAIN_REPO=<PATH_TO_TRUSTCHAIN_REPOSITORY>
export TRUSTCHAIN_DATA=~/.trustchain/
export TRUSTCHAIN_CONFIG=$TRUSTCHAIN_DATA/trustchain_config.toml
```

TODO: this isn't quite right yet because the repo hasn't been cloned

To check that these environment variables were added successfully, close and re-open the Terminal window and then run the following command:
```console
$ echo $TRUSTCHAIN_REPO; $TRUSTCHAIN_DATA; echo $TRUSTCHAIN_CONFIG;
```
You should see the value of each environment variable printed to the screen.

## Installation

### Step 1. Install ION

As the main Trustchain dependency, ION has its own section on this site. Please follow the installation instructions provided on the [ION page](ion.md).

### Step 2. Install Rust

Instructions for installing the Rust language can be found [here](https://www.rust-lang.org/tools/install).

On Linux or Mac OS, the recommended method is to run the following command:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then check the installation was successful by running:
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

Install the Trustchain command line interface (CLI):
```bash
cargo install --path trustchain-cli
```

!!! info "This step is optional."

    Trustchain includes a built-in HTTP server that can be used to issue and verify digital credentials over the Web. It can also respond to requests made by the Trustchain mobile app.

    To install the Trustchain HTTP server, run:
    ```bash
    cargo install --path trustchain-http
    ```

## Configuration

### Trustchain data directory

Your Trustchain node will use the `TRUSTCHAIN_DATA` directory for storing data related to its operation.

Create the `TRUSTCHAIN_DATA` directory on your file system:
```
mkdir $TRUSTCHAIN_DATA
```

### Trustchain configuration file

Configuration parameters relating to Trustchain are stored in a file named `trustchain_config.toml`.

Copy the template configuration file From the Trustchain repository to the data directory:
```
cp $TRUSTCHAIN_REPO/trustchain_config.toml $TRUSTCHAIN_DATA
```

Then edit the following parameters inside your copy of `trustchain_config.toml`:

- In the `[ion]` section, add the `bitcoin_rpc_username` and `bitcoin_rpc_password` that were chosen when you [installed](ion.md#install-bitcoin-core) Bitcoin Core.
- If you intend to act as an issuer of digital credentials, and you already have you own DID for this purpose, add it in the `[http]` section to the `issuer_did` parameter value. Otherwise, the `[http]` section can be ignored.
- If you know the root event time for your DID network, add it in the `[cli]` section to the `root_event_time` parameter value. This must be an integer in Unix time format, e.g.:
```
root_event_time = 1697213008
```

!!! warning "Root event time"

    The "root event time" refers to the exact time at which the root DID was published. It is imperative that this configuration parameter is entered correctly, because it identifies the root public key certificate.

    If you are not sure about the correct root event time for your network, or you are intending to create your own root DID, leave this parameter unset for now.

    In future versions of Trustchain, this Unix time parameter will be replaced by a calendar date (the "root event date") plus a short confirmation code.

## Using Trustchain

Trustchain is controlled via its command line interface (CLI). Supported operations include DID resolution, issuance, attestation and verification. It can also be used to issue and verify digital credentials.

Instructions on how to use the Trustchain CLI are provided on the [Usage page](usage.md).

&nbsp;

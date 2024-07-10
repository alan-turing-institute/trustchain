# Getting Started

The instructions below will guide you through the installation and configuration of the Trustchain software.

Trustchain can be installed on all major operating systems. The steps below have been tested on Linux and Mac OS. On Windows the process will be similar, with instructions available via the links provided.

!!! info "Running commands in the Terminal"

    This guide will make frequent use of the command line interface provided by the Terminal application, which is available on all operating systems.

    Commands will be presented in code blocks like this one:
    ```console
    $ echo "Hello World"
    ```
    The initial prompt character `$` indicates that this is a command that you should copy and paste into your Terminal, followed by the ++return++ key to execute the command.

    To copy such commands to the clipboard, click on the :material-content-copy: icon at the right-hand side of the code block. Only the command itself will be copied (the prompt character will be omitted), so it can be pasted straight into the Terminal.

## Environment Variables

As far as possible, we would like the Terminal commands given in this guide to work on any computer, so they can be copied and pasted without modification. This makes the installation process quicker and less error-prone. However, many commands depend on particular files or folders, which different users may wish to store in different locations.

To solve this problem, we shall define **environment variables** to keep track of the location of relevant files and folders. An environment variable is just like a variable in any programming language. It enables us to use a generic and meaningful name to refer to something specific which is not known in advance (in this case the path to a particular file or folder).

Environment variables are defined in your Terminal configuration file. Since we will need to edit this file several times during the installation, it will be convenient to have an environment variable containing its path on the file system.

To do this, run the following command:
```console
$ echo "export SHELL_CONFIG=" $(find ~/.*shrc -maxdepth 0 | head -n 1) | sed 's/= /=/g' >> $(find ~/.*shrc -maxdepth 0 | head -n 1)
```
Then close and reopen the Terminal window that you're working in, so that the change takes effect. Now check that the new environment variable exists:
```console
$ echo $SHELL_CONFIG
```
This command should output the path to your Terminal configuration file. From now on, whenever we want to refer to that file we will be able to use the `SHELL_CONFIG` environment variable.

!!! tip "Creating environment variables"

    Now that we have defined the `SHELL_CONFIG` environment variable (above), we can use it to conveniently create new environment variables. Whenever we need to define a new variable, you will be given a command similar to the following (don't run this one, it's just an example):
    ```console
    $ echo "export NAME=VALUE" >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```
    This command adds a new environment variable named `NAME` with value `VALUE` to your Terminal config file, and then reads the updated file so the change takes effect inside the current Terminal session.

## Installation

### Step 1. Install ION

As the main Trustchain dependency, ION has its own section on this site. Please follow the installation instructions provided on the [ION page](ion.md).

### Step 2. Install Rust

Instructions for installing the Rust language can be found [here](https://www.rust-lang.org/tools/install).

On Linux or Mac OS, the recommended method is to run the following command:
```console
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then check the installation was successful by running:
```console
$ rustc --version
```

### Step 3. Install Trustchain

Choose a directory in which you want to store the Trustchain software and change to that directory using the command `$ cd <DIRECTORY_NAME>`. For instance, to change to your home directory run the `cd` command without any arguments:
```console
$ cd
```
Now clone the Trustchain code repository from GitHub:
```console
$ git clone https://github.com/alan-turing-institute/trustchain.git
```
and change into the newly-created `trustchain` subfolder:
```console
$ cd trustchain
```

!!! tip "Create the `TRUSTCHAIN_REPO` environment variable"

    Since we will need to refer to this folder in future, let's create an [environment variable](#environment-variables) containing its file path:
    ```console
    $ echo "export TRUSTCHAIN_REPO=" $(pwd) | sed 's/= /=/g' >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

The next step is to build the Trustchain software from its source code (this may take a minute or two):
```console
$ cargo build
```

Finally, we install the Trustchain command line interface (CLI):
```console
$ cargo install --path trustchain-cli
```

!!! info "This step is optional."

    Trustchain includes a built-in HTTP server that can be used to issue and verify digital credentials via an HTTP API. It can also respond to requests made by the Trustchain mobile app.

    To install the Trustchain HTTP server, run:
    ```console
    $ cargo install --path trustchain-http
    ```

## Configuration

### Trustchain data directory

Trustchain uses a data directory to store files related to its operation. Here we assume that the data directory will be `~/.trustchain`, but if you prefer to use a different one simply change the path in the following command when creating the `TRUSTCHAIN_DATA` environment variable.

!!! tip "Create the `TRUSTCHAIN_DATA` environment variable"

    ```console
    $ echo 'export TRUSTCHAIN_DATA=~/.trustchain/' >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

Now create the `TRUSTCHAIN_DATA` directory on your file system:
```console
$ mkdir $TRUSTCHAIN_DATA
```

### Trustchain configuration file

Configuration parameters relating to Trustchain are stored in a file named `trustchain_config.toml`, which will be stored in the data directory (created above). Once again, we create an environment variable containing the path to this file.

!!! tip "Create the `TRUSTCHAIN_CONFIG` environment variable"

    ```console
    $ echo 'export TRUSTCHAIN_CONFIG="$TRUSTCHAIN_DATA"trustchain_config.toml' >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

Copy the template configuration file from the Trustchain repository to the data directory (unless it already exists):
```console
$ cp -n $TRUSTCHAIN_REPO/trustchain_config.toml $TRUSTCHAIN_CONFIG
```

Then open your copy of `trustchain_config.toml` in a text editor:
```console
$ open $TRUSTCHAIN_CONFIG
```
and edit the following configuration parameters:

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

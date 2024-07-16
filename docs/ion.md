# ION

The [Identity Overlay Network](https://identity.foundation/ion/) (ION) is an open source [DID method](https://www.w3.org/TR/did-core/#methods) implementation developed by the Decentralized Identity Foundation.

In other words, ION is a software tool that can be used to perform DID operations, such as creating and publishing new DIDs and DID documents, and resolving existing ones. It does this by reading and writing data to the [Bitcoin](https://bitcoin.org/en/) blockchain and to the [IPFS](https://ipfs.tech/) distributed file system. As such, every ION instance is a node on these two peer-to-peer networks.

Trustchain delegates the execution of DID operations to an ION node. Therefore to use Trustchain you must first install and run ION, either on the same machine or a connected one.

!!! warning "ION resource requirements"

    An ION installation includes a full node on the Bitcoin network, which must download and store the entire Bitcoin blockchain. This is a large amount of data that typically takes several hours, or even days, to download.

    The recommended system requirements for an ION installation are:

    - 6GB of RAM
    - 1TB of storage (or 256GB for [Testnet](#bitcoin-mainnet-vs-testnet)).

Note, however, that **Trustchain makes no assumptions about the trustworthiness of the ION system** and the Trustchain security model does not rely on the correct functioning of the ION software. Trustchain independently verifies all of the data it receives from ION, so a faulty or compromised ION node would not represent a security vulnerability in Trustchain (although it could cause a loss of service).

This page explains how to install and run ION.

<!-- TODO: insert the architecture schematic diagram here? (from the paper). -->

## Preliminaries

Before beginning the installation, a few decisions must be made that will determine exactly what steps should be taken.

### Docker Container vs. Full Installation

The simplest way to run ION is using Docker, and it can be a useful way to experiment with the system before performing a full installation. However, this method provides a **read-only ION node**. This means that it provides access to existing DIDs, but cannot be used to create and publish new ones.

If you would like to be able to use Trustchain to create and publish your own DIDs, follow the full installation instructions below (and ignore the [ION with Docker](#ion-with-docker) section).

If you want to run ION using Docker, you can skip most of this page and just follow the instructions in the [ION with Docker](#ion-with-docker) section.

### Bitcoin Mainnet vs. Testnet

The Bitcoin client wrapped inside an ION node can be configured either for **Mainnet** (the main Bitcoin network) or **Testnet** (an alternative blockchain designed for testing and software development).

Mainnet should be used for a production deployment of Trustchain because DID operations published on the Bitcoin blockchain have extremely strong immutability, persistence and discoverability properties. When testing Trustchain, however, it is sensible to configure the ION Bitcoin client for Testnet, since coins on the test network have no monetary value and therefore "test" DID operations can be executed at zero cost.

Testnet coins can be requested from a Testnet "faucet", such as [this one](https://coinfaucet.eu/en/btc-testnet/).

In this guide, commands and configuration settings may depend on which network is in use. In those cases, choose the appropriate tab (Mainnet or Testnet) for your setup.

### Local vs. Remote Installation

You can install ION on your local machine or a remote one, e.g. a virtual machine in the Cloud. If you are using a remote machine, connect to it using SSH and follow the instructions below.

Once installed, follow the port forwarding instructions in the [SSH config](#ssh-config) section to produce a setup that is indistinguishable from running an ION node locally.

## ION Installation Guide

These instructions are based on the official [ION Install Guide](https://identity.foundation/ion/install-guide/) but contain additional details, several minor corrections and a workaround to support the latest versions of Bitcoin Core.

Both Linux and macOS are supported and tested. For Linux, our instructions assume a Debian-based distribution, such as Ubuntu. Some minor changes will be needed for other distributions. Instructions for installing on Windows are given in the official [ION guide](https://identity.foundation/ion/install-guide/).

In all cases, administrator privileges are required.

### Prerequisites

Run the following commands to set up your environment.

=== "Linux"

    Update the package lists on your machine:
    ```console
    $ sudo apt update
    ```
    and install essential build tools:
    ```console
    $ sudo apt install build-essential
    ```
    Install Snap ... (assumes Debian-based Linux distro):
    ```console
    $ sudo apt install snapd
    ```
    Add the Snap binaries to the `PATH` environment variable:
    ```console
    $ echo 'export PATH="$PATH:/snap/bin"' >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```
    Install Node.js version 14:
    ```console
    $ sudo snap install node --classic --channel=14
    ```

=== "macOS"

    Install Xcode [command line tools](https://developer.apple.com/download/all/):
    ```console
    $ xcode-select --install
    ```
    Install the [Homebrew](https://brew.sh/#install) package manager:
    ```console
    $ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```

### Install IPFS

IPFS is the InterPlanetary File System, a peer-to-peer protocol and network used by ION for storing and sharing data.

=== "Linux"

    Follow the official IPFS [installation instructions](https://docs.ipfs.tech/install/command-line/#install-kubo-linux) for Linux.

=== "macOS"

    Install IPFS:
    ```console
    $ brew install ipfs
    ```

    Initialise with:
    ```console
    $ ipfs init
    ```
    Check the installation was successful by running:
    ```console
    $ ipfs cat /ipfs/QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc/readme
    ```
    which should output a welcome message.

### Install MongoDB

=== "Linux"

    Open the [MongoDB Community Server Download](https://www.mongodb.com/try/download/community) page and download the package for your platform.

    Then following [these instructions](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/) to install MongoDB on Linux


=== "macOS"

    Following [these instructions](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-os-x/):
    ```console
    $ brew tap mongodb/brew
    ```
    then:
    ```console
    $ brew install mongodb-community
    ```

### Install Bitcoin Core

Trustchain has been tested with Bitcoin Core v24.0.1 and therefore the instructions below assume that version. More recent versions of Bitcoin Core are [available](https://bitcoincore.org/en/releases/) and can be used, but will require some minor changes to the commands in the following steps.

=== "Linux"

    Begin by downloading the [Bitcoin Core release](https://bitcoincore.org/bin/bitcoin-core-24.0.1/) for your system:

     - [Download link](https://bitcoincore.org/bin/bitcoin-core-24.0.1/bitcoin-24.0.1-x86_64-linux-gnu.tar.gz) for Linux with x86-64 processor.
     - [Download link](https://bitcoincore.org/bin/bitcoin-core-24.0.1/bitcoin-24.0.1-arm-linux-gnueabihf.tar.gz) for Linux with ARM processor.

    Verify the download by comparing the [published hash](https://bitcoincore.org/bin/bitcoin-core-24.0.1/SHA256SUMS) with the result of this command:
    ```console
    $ shasum -a 256 ~/Downloads/bitcoin-24.0.1-*.tar.gz
    ```

    Unzip the archive: TODO: UNZIP COMMAND IS SPECIFIC TO ARCHITECTURE.
    ```console
    $ (cd ~/Downloads && tar xvzf bitcoin-27.0-x86_64-linux-gnu.tar.gz)
    ```
    and install Bitcoin Core:
    ```console
    $ sudo install -m 0755 -t /usr/local/bin bitcoin-24.0.1/bin/*
    ```
    The installation includes an executable file named `bitcoind` which we will run to start Bitcoin Core.

=== "macOS"

    Begin by downloading the [Bitcoin Core release](https://bitcoincore.org/bin/bitcoin-core-24.0.1/) for your system:

     - [Download link](https://bitcoincore.org/bin/bitcoin-core-24.0.1/bitcoin-24.0.1-x86_64-apple-darwin.tar.gz) for Mac with x86-64 processor.
     - [Download link](https://bitcoincore.org/bin/bitcoin-core-24.0.1/bitcoin-24.0.1-arm64-apple-darwin.tar.gz) for Mac with Apple M1 processor.

    Verify the download by comparing the [published hash](https://bitcoincore.org/bin/bitcoin-core-24.0.1/SHA256SUMS) with the result of this command:
    ```console
    $ shasum -a 256 ~/Downloads/bitcoin-24.0.1-*.tar.gz
    ```

    Unzip the archive: TODO: UNZIP COMMAND IS SPECIFIC TO ARCHITECTURE.
    ```console
    $ (cd ~/Downloads && tar xvzf bitcoin-24.0.1-arm64-apple-darwin.tar.gz)
    ```
    and move the contents to the `/Applications` folder:
    ```console
    $ mv ~/Downloads/bitcoin-24.0.1 /Applications
    ```
    The download contains an executable file named `bitcoind` which we will run to start Bitcoin Core.

    !!! info "Sign the Bitcoin Core executable files"

        Newer macOS systems will refuse to run an executable file unless it is signed. Run the following command to check whether this is a requirement on your machine:
        ```console
        $ codesign -d -vvv --entitlements :- /Applications/bitcoin-24.0.1/bin/bitcoind
        > /Applications/bitcoin-24.0.1/bin/bitcoind: code object is not signed at all
        ```
        If you see the message "code object is not signed at all" (as in the example above), you will need to create a [self-signed certificate](https://support.apple.com/en-gb/guide/keychain-access/kyca8916/mac) for the executable file. Do this by running:
        ```console
        $ codesign -s - /Applications/bitcoin-24.0.1/bin/bitcoind
        ```
        And do the same for the Bitcoin CLI executable:
        ```console
        $ codesign -s - /Applications/bitcoin-24.0.1/bin/bitcoin-cli
        ```

### Configure Bitcoin Core

We shall need to specify a folder to store the Bitcoin blockchain data.

!!! warning "Bitcoin data storage requirements"

    The Bitcoin data folder will store the entire Bitcoin blockchain, which is >580GB for Mainnet and >75GB for Testnet.

For convenience, we create an environment variable for the Bitcoin data folder.

!!! tip "Create the `BITCOIN_DATA` environment variable"

    Our convention is to use the folder `~/.bitcoin` for Bitcoin Core data. If you want to use a different folder, just change the path in the following command:
    ```console
    $ echo "export BITCOIN_DATA=~/.bitcoin" >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

Having defined the `BITCOIN_DATA` environment variable, use it to create the data folder itself:
```console
$ mkdir $BITCOIN_DATA
```

=== "Mainnet"

    Bitcoin configuration parameters will be stored in a file named `bitcoin.conf` inside the `$BITCOIN_DATA` folder.
    The following command creates that file with the required parameters and user permissions:
    ```console
    $ echo "server=1\ndaemon=1\ntxindex=1\ndatadir=$BITCOIN_DATA\n" > $BITCOIN_DATA/bitcoin.conf && chmod 640 $BITCOIN_DATA/bitcoin.conf
    ```

    To confirm these changes were made correctly, check the first three lines in the `bitcoin.conf` file by running:
    ```console
    $ head -n 4 $BITCOIN_DATA/bitcoin.conf
    ```
    You should see lines like these printed to the Terminal:
    ```
    server=1
    daemon=1
    txindex=1
    datadir=<YOUR_BITCOIN_DATA_DIRECTORY>
    ```

=== "Testnet"

    Bitcoin configuration parameters will be stored in a file named `bitcoin.conf` inside the `$BITCOIN_DATA` folder.
    The following command creates that file with the required parameters and user permissions:
    ```console
    $ echo "testnet=1\nserver=1\ndaemon=1\ntxindex=1\ndatadir=$BITCOIN_DATA\n" > $BITCOIN_DATA/bitcoin.conf && chmod 640 $BITCOIN_DATA/bitcoin.conf
    ```

    To confirm these changes were made correctly, check the first three lines in the `bitcoin.conf` file by running:
    ```console
    $ head -n 5 $BITCOIN_DATA/bitcoin.conf
    ```
    You should see lines like these printed to the Terminal:
    ```
    testnet=1
    server=1
    daemon=1
    txindex=1
    datadir=<YOUR_BITCOIN_DATA_DIRECTORY>
    ```

!!! warning "Note: Do not use the `~` shorthand in the `datadir` parameter"

    The directory path in the `datadir` parameter must not contain the `~` character as a shorthand for the user's home directory.

    The example given in the official [ION install guide](https://identity.foundation/ion/install-guide/) does use this shorthand, which causes an error, so beware of this issue if you are following that guide and/or editing the `bitcoin.conf` file manually.

When we start Bitcoin Core we will need to make sure it uses the correct configuration file that was created above. To make this more convenient, let's create an alias in our `SHELL_CONFIG` file:

=== "Linux"

    ```console
    $ echo 'alias bitcoind="/usr/local/bin/bitcoind -conf=$BITCOIN_DATA/bitcoin.conf"' >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

    Now we can use the following simple command to start Bitcoin Core:
    ```console
    $ bitcoind
    ```

=== "macOS"

    ```console
    $ echo 'alias bitcoind="/Applications/bitcoin-24.0.1/bin/bitcoind -conf=$BITCOIN_DATA/bitcoin.conf"' >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

    Now we can use the following simple command to start Bitcoin Core:
    ```console
    $ bitcoind
    ```
    The first time your run this command, you will see the following pop-up message:

    ![bitcoind macOS pop-up](assets/bitcoind-macOS-pop-up.png){: style="height:250px"}

    You need to tell macOS that this is not malicious software. To do this, open the "Security & Privacy" settings in System Preferences, choose the "General" tab, and click the button on the right-hand side that says "Allow Anyway":

    ![bitcoind macOS pop-up](assets/bitcoind-allow-anyway.png){: style="height:350px"}

    Now re-run the command to start Bitcoin Core:
    ```console
    $ bitcoind
    ```
    Another pop-up message will appear, similar to the first one, but this time there will be an option to allow the program to run by clicking the "Open" button.

    You should now see the message "Bitcoin Core starting" in the Terminal.

!!! warning "Bitcoin synchronisation"

    When Bitcoin Core starts for the first time, it will begin synchronising with the rest of the Bitcoin network. This means downloading all of the blocks in the Bitcoin blockchain, which is a large data structure containing every Bitcoion transaction that has ever been processed.

    **The synchronisation process may take several hours, or even days, to complete.** You can continue with the installation steps below while it is in progress, but you will not be able to use Trustchain until your Bitcoin node has finished synchronising.

### Bitcoin CLI

Now that your Bitcoin Core node is up and running, you will want to be able to communicate with it. Bitcoin Core provides a command line interface (CLI) for this purpose.

Run the following command to create an alias, making to easy to access the CLI:

=== "Linux"

    ```console
    $ echo 'alias bitcoin-cli="/usr/local/bin/bitcoin-cli -conf=$BITCOIN_DATA/bitcoin.conf"' >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

=== "macOS"

    ```console
    $ echo 'alias bitcoin-cli="/Applications/bitcoin-24.0.1/bin/bitcoin-cli -conf=$BITCOIN_DATA/bitcoin.conf"' >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

!!! info "Bitcoin RPC username and password"

    Before you can make use of the CLI you will need to add a username and password to the Bitcoin configuration file. These same parameters will also be used for authentication when ION interacts with Bitcoin Core. In both cases, the interaction is possible because Bitcoin Core provides access via a Remote Procedure Call (RPC) interface.

    We shall use `admin` for the RPC username. To set up the RPC password, copy and paste the following command into the Terminal and then change `<password>` to something of your choice before hitting the ++return++ key:
    ```console
    $ RPC_PASSWORD="<password>"
    ```
    Now run the following command to add the username and password to the `bitcoin.conf` file:
    ```console
    $ sed -i '' "1s|^|rpcuser=admin\nrpcpassword=$RPC_PASSWORD\n|" /Applications/bitcoin-24.0.1/bitcoin.conf
    ```
    To confirm these changes were made correctly, check the first two lines in the `bitcoin.conf` file by running:
    ```console
    $ head -n 2 /Applications/bitcoin-24.0.1/bitcoin.conf
    ```
    You should see these lines printed to the Terminal (with your chosen password):
    ```
    rpcuser=admin
    rpcpassword=<password>
    ```



Now, whenever Bitcoin Core is running, you can invoke the Bitcoin CLI with commands beginning `bitcoin-cli`. A full list of commands available via the Bitcoin CLI can be found [here](https://developer.bitcoin.org/reference/rpc/).

One useful example is the following `-getinfo` command. It reports information about the state of your Bitcoin node, including whether it is fully synchronised:
```console
$ bitcoin-cli -getinfo
```

!!! info "Create a Bitcoin wallet for ION"

    Before using ION you must create a Bitcoin wallet by running the following CLI command:
    ```console
    $ bitcoin-cli createwallet "sidetreeDefaultWallet"
    ```

### Configure ION

Choose a directory in which you want to store the ION software and change to that directory using the command `$ cd <DIRECTORY_NAME>`. For instance, to change to your home directory run the `cd` command without any arguments:
```console
$ cd
```
Now clone the ION code repository from GitHub:
```console
$ git clone https://github.com/decentralized-identity/ion
```
and change into the newly-created `ion` subfolder:
```console
$ cd ion
```

!!! tip "Create the `ION_REPO` environment variable"

    Since we will need to refer to this folder in future, let's create an [environment variable](#environment-variables) containing its file path:
    ```console
    $ echo "export ION_REPO=" $(pwd) | sed 's/= /=/g' >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

We will need a folder for storing ION configuration files. For convenience, we'll also create an environment variable for that folder.

!!! tip "Create the `ION_CONFIG` environment variable"

    Our convention is to use the folder `~/.ion` for ION configuration files. If you want to use a different folder, just change the path in the following command:
    ```console
    $ echo "export ION_CONFIG=~/.ion" >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```


Having defined the `ION_CONFIG` environment variable (above), use it to create the folder itself:
```console
$ mkdir $ION_CONFIG
```

=== "Mainnet"

    Next, copy the template ION configuration files to your `ION_CONFIG` directory:
    ```console
    $ cp $ION_REPO/config/mainnet-bitcoin-config.json $ION_REPO/config/mainnet-bitcoin-versioning.json $ION_REPO/config/mainnet-core-config.json $ION_REPO/config/mainnet-core-versioning.json $ION_CONFIG
    ```
    and set appropriate user permissions:
    ```console
    $ chmod 640 $ION_CONFIG/mainnet-bitcoin-config.json $ION_CONFIG/mainnet-bitcoin-versioning.json $ION_CONFIG/mainnet-core-config.json $ION_CONFIG/mainnet-core-versioning.json
    ```

    The following commands will edit some of the configuration parameters inside the file named `mainnet-bitcoin-config.json`.

    Set the `bitcoinDataDirectory` parameter (skip this step if your `BITCOIN_DATA` directory is on a network drive):
    ```console
    $ sed -i '' 's|"bitcoinDataDirectory": ".*"|"bitcoinDataDirectory": "'$BITCOIN_DATA'"|g' $ION_CONFIG/mainnet-bitcoin-config.json
    ```

    Set the `bitcoinRpcUsername` and `bitcoinRpcPassword` parameters. These must match the username and password chosen in the [Bitcoin CLI](#bitcoin-cli) section above.

    We chose `admin` for the RPC username. The following command sets this same value inside the ION config file:
    ```console
    $ sed -i '' 's|"bitcoinRpcUsername": ".*"|"bitcoinRpcUsername": "admin"|g' $ION_CONFIG/mainnet-bitcoin-config.json
    ```

    For the RPC password, copy and paste the following command into the Terminal and then change `<password>` to the **same password** you chose when setting up the [Bitcoin CLI](#bitcoin-cli):
    ```console
    $ RPC_PASSWORD="<password>"
    ```

    Then run this command to update the `bitcoinRpcPassword` parameter in the ION config file:
    ```console
    $ sed -i '' 's|"bitcoinRpcPassword": ".*"|"bitcoinRpcPassword": "'$RPC_PASSWORD'"|g' $ION_CONFIG/mainnet-bitcoin-config.json
    ```

    Set the `bitcoinWalletImportString` parameter. This must be a mainnet-compatible key in wallet import format (WIF). If you intend to use Trustchain to write your own DID operations, this parameter must be populated with your private key in the appropriate format. Otherwise, you can use [this tool](https://learnmeabitcoin.com/technical/wif) to generate a WIF string without any bitcoin.

    Copy and paste the following command into the Terminal and then change `<wif>` to your WIF string:
    ```console
    $ WIF="<wif>"
    ```

    Then run this command to update the `bitcoinWalletImportString` parameter in the ION config file:
    ```console
    $ sed -i '' 's|"bitcoinWalletImportString": ".*"|"bitcoinWalletImportString": "'$WIF'"|g' $ION_CONFIG/mainnet-bitcoin-config.json
    ```

=== "Testnet"

    Next, copy the template ION configuration files to your `ION_CONFIG` directory:
    ```console
    $ cp $ION_REPO/config/testnet-bitcoin-config.json $ION_REPO/config/testnet-bitcoin-versioning.json $ION_REPO/config/testnet-core-config.json $ION_REPO/config/testnet-core-versioning.json $ION_CONFIG
    ```
    and set appropriate user permissions:
    ```console
    $ chmod 640 $ION_CONFIG/testnet-bitcoin-config.json $ION_CONFIG/testnet-bitcoin-versioning.json $ION_CONFIG/testnet-core-config.json $ION_CONFIG/testnet-core-versioning.json
    ```

    The following commands will edit some of the configuration parameters inside the file named `testnet-bitcoin-config.json`.

    Set the `bitcoinDataDirectory` parameter (skip this step if your `BITCOIN_DATA` directory is on a network drive):
    ```console
    $ sed -i '' 's|"bitcoinDataDirectory": ".*"|"bitcoinDataDirectory": "'$BITCOIN_DATA'testnet3/"|g' $ION_CONFIG/testnet-bitcoin-config.json
    ```

    Set the `bitcoinRpcUsername` and `bitcoinRpcPassword` parameters. These must match the username and password chosen in the [Bitcoin CLI](#bitcoin-cli) section above.

    We chose `admin` for the RPC username. The following command sets this same value inside the ION config file:
    ```console
    $ sed -i '' 's|"bitcoinRpcUsername": ".*"|"bitcoinRpcUsername": "admin"|g' $ION_CONFIG/testnet-bitcoin-config.json
    ```

    For the RPC password, copy and paste the following command into the Terminal and then change `<password>` to the **same password** you chose when setting up the [Bitcoin CLI](#bitcoin-cli):
    ```console
    $ RPC_PASSWORD="<password>"
    ```

    Then run this command to update the `bitcoinRpcPassword` parameter in the ION config file:
    ```console
    $ sed -i '' 's|"bitcoinRpcPassword": ".*"|"bitcoinRpcPassword": "'$RPC_PASSWORD'"|g' $ION_CONFIG/testnet-bitcoin-config.json
    ```

### Build ION

Change directory into the ION repository:
```console
$ cd $ION_REPO
```
Now install the ION dependencies:
```console
$ npm i
```
make sure Typescript is installed:
```console
$ npm install typescript
```
and then build the ION package:
```console
$ npm run build
```

!!! info "Note: Rebuild ION whenever a configuration file is modified"

    You must rerun the command `npm run build` if changes are made to the JSON configuration files in the `ION_CONFIG` folder.

### Test ION

Before running ION for the first time, make sure that you have started IPFS, MongoDB and Bitcoin Core (by following the instructions above). Also make sure that Bitcoin Core is fully synchronised by running:
```console
$ bitcoin-cli -getinfo
```

You should see output similar to the following. Bitcoin Core is synchronised if the number of `Blocks` is equal to the number of `Headers`:

=== "Mainnet"
    ```sh
    Blocks: 852429
    Headers: 852429
    Verification progress: ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒ 100%
    Difficulty: 79.620365071432086

    Network: in 0, out 10, total 10
    Version: 240001
    Time offset (s): 0
    Proxies: n/a
    Min tx relay fee rate (BTC/kvB): 0.00001000

    Warnings: (none)
    ```

    In a new Terminal, start the ION Bitcoin microservice with:
    ```console
    $ (cd $ION_REPO && npm run bitcoin)
    ```

=== "Testnet"
    ```sh
    Chain: test
    Blocks: 2868427
    Headers: 2868427
    Verification progress: ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒ 100%
    Difficulty: 3.620365071432086

    Network: in 0, out 10, total 10
    Version: 240001
    Time offset (s): 0
    Proxies: n/a
    Min tx relay fee rate (BTC/kvB): 0.00001000

    Warnings: (none)
    ```

    In a new Terminal, start the ION Bitcoin microservice with:
    ```console
    $ (cd $ION_REPO && npm run bitcoin)
    ```

    When running this command for the first time, expect the error:
    ```
    Non-base58 character
    Is bitcoinWalletImportString valid? Consider using <testnet> key generated below:
    ```
    followed by a base58 string. In this case, copy the base58 string and paste it into the following command in place of `<wif>`:
    ```console
    $ WIF="<wif>"
    ```

    Then run this command to update the `bitcoinWalletImportString` parameter in the ION config file:
    ```console
    $ sed -i '' 's|"bitcoinWalletImportString": ".*"|"bitcoinWalletImportString": "'$WIF'"|g' $ION_CONFIG/testnet-bitcoin-config.json
    ```

    Now repeat the attempt to start the ION Bitcoin microservice:
    ```console
    $ (cd $ION_REPO && npm run bitcoin)
    ```

??? tip "Troubleshooting Tip"

    - If you see an `ECONNREFUSED` error message when starting the ION Bitcoin microservice, this indicates that it has failed to communicate with Bitcoin Core. In this case, make sure that Bitcoin Core started successfully.

!!! warning "ION synchronisation"

    When the ION Bitcoin microservice starts for the first time, it will begin scanning the Bitcoin blockchain for ION DID operations, by making calls to the Bitcoin Core RPC interface.

    **The synchronisation process may take >1 hour to complete.** Wait until it has finished before running the ION Core microservice in the following step.

In another new Terminal, start the ION Core microservice with:
```console
$ (cd $ION_REPO && npm run core)
```

??? tip "Troubleshooting Tip"

    If you see an `ECONNREFUSED` error message when starting the ION Core microservice, this indicates that it has failed to communicate with the ION Bitcoin microservice. In this case, make sure that the ION Bitcoin microservice started successfully.

Finally, to confirm that ION is working properly, open yet another new Terminal and resolve a sample DID:

=== "Mainnet"

    ```console
    $ curl http://localhost:3000/identifiers/did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w | json_pp
    ```

=== "Testnet"

    ```console
    $ curl http://localhost:3000/identifiers/did:ion:test:EiClWZ1MnE8PHjH6y4e4nCKgtKnI1DK1foZiP61I86b6pw | json_pp
    ```

If ION is working properly, the command above will return a JSON data structure containing the resolved DID document and document metadata for the sample DID.

Congratulations! Your ION installation is now complete.

## Running ION

The following commands must be run each time you start your ION node, e.g. after restarting your computer. Some of them will keep control of the Terminal, so you will need to open a new Terminal window to continue.

!!! tip "Tip: Use tmux"

    A convenient way to start all of the following processes is to use [tmux](https://github.com/tmux/tmux/wiki) (the terminal multiplexer). Once installed, open a tmux session with the command:
    ```console
    $ tmux new -s ion
    ```
    and hit ++ctrl+b++ followed by ++c++ each time you need to open a new window.

    When all of the processes are started, detach the tmux session with ++ctrl+b++ followed by ++d++. To reattach the session later, run:
    ```console
    $ tmux a -t ion
    ```

Follow these steps to start your ION node:

**1. Start IPFS**

```console
$ ipfs daemon
```

??? info "Other IPFS commands"

    Stop:
    ```console
    $ ipfs shutdown
    ```

**2. Start MongoDB**

=== "Linux"

    ```console
    $ sudo systemctl start mongod
    ```

    ??? info "Other MongoDB commands"

        Stop MongoDB:
        ```
        sudo systemctl stop mongod
        ```
        Restart:
        ```
        sudo systemctl restart mongod
        ```
        Check status:
        ```
        sudo systemctl status mongod
        ```

=== "macOS"

    ```console
    $ brew services start mongodb-community
    ```

    ??? info "Other MongoDB commands"

        Stop:
        ```console
        $ brew services stop mongodb-community
        ```
        Restart:
        ```console
        $ brew services restart mongodb-community
        ```


**3. Start Bitcoin Core**
```console
$ bitcoind
```

??? info "Other Bitcoin Core commands"

    === "Mainnet"

        Check status:
        ```console
        $ bitcoin-cli -getinfo
        ```

        Stop Bitcoin Core:
        ```console
        $ bitcoin-cli stop
        ```

        Print the log file to the Terminal (hit ++ctrl+c++ to exit):
        ```console
        $ tail -f $BITCOIN_DATA/debug.log
        ```

        Reindex the chain (may take >1 hour):
        ```console
        $ bitcoind -reindex-chainstate
        ```

        Check which port bitcoind is listening on (should be 8333 for Mainnet):
        ```console
        $ netstat -tulpn | grep 'bitcoind'
        ```

    === "Testnet"

        Check status:
        ```console
        $ bitcoin-cli -getinfo
        ```

        Stop Bitcoin Core:
        ```console
        $ bitcoin-cli stop
        ```

        Print the log file to the Terminal (hit ++ctrl+c++ to exit):
        ```console
        $ tail -f $BITCOIN_DATA/testnet3/debug.log
        ```

        Reindex the chain (may take >1 hour):
        ```console
        $ bitcoind -reindex-chainstate
        ```

        Check which port bitcoind is listening on (should be 18333 for Testnet):
        ```console
        $ netstat -tulpn | grep 'bitcoind'
        ```

**4. Start the ION bitcoin service.**
```console
$ (cd $ION_REPO && npm run bitcoin)
```

**5. Start the ION core service.**
```console
$ (cd $ION_REPO && npm run core)
```

**6. Test ION.** To confirm that ION is working properly, resolve a sample DID:

=== "Mainnet"

    ```console
    $ curl http://localhost:3000/identifiers/did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w | json_pp
    ```

=== "Testnet"

    ```console
    $ curl http://localhost:3000/identifiers/did:ion:test:EiClWZ1MnE8PHjH6y4e4nCKgtKnI1DK1foZiP61I86b6pw | json_pp
    ```

This command should print the contents of the resolved DID document and document metadata to the Terminal. If it does not, see the Troubleshoot tips [above](#test-ion).

## Funding your Bitcoin wallet

ION can be used to resolve existing DIDs and to publish new ones. New DIDs are published by writing the DID document content to IPFS and inserting an identifier for that content inside a Bitcoin transaction. This has the effect of timestamping the DID document and also making it easily discoverable (by scanning the Bitcoin blockchain).

Every Bitcoin transaction must include a processing fee, and therefore some funds must be available in your ION Bitcoin wallet before it can be used to publish any new DIDs. No funds are needed to resolve existing DIDs.

First check that `sidetreeDefaultWallet`, that was created [earlier](#configure-bitcoin-core), is loaded. You should see the following output when running this command:
```console
$ bitcoin-cli listwallets
[
  "sidetreeDefaultWallet"
]
```
Then use this command to list the receiving addresses for this wallet (with their balances):
```console
$ bitcoin-cli -rpcwallet="sidetreeDefaultWallet" listreceivedbyaddress 1 true
```

To fund your wallet, send Bitcoins to the **first** receive address in this list.

=== "Mainnet"

    !!! tip "Purchase BTC on a Bitcoin exchange"

        If you do not already own any bitcoins, they can be purchased on a [Bitcoin exchange](https://bitcoin.org/en/exchanges). Make sure that you acquire genuine bitcoins, which are identified by the ticker symbol `BTC`. When withdrawing your coins from the exchange, enter the receive address obtained in the preceding step to send them to your ION wallet.

    After sending bitcoins to your wallet, you will need to wait for the transaction to be confirmed by the Bitcoin network. This should take around 10 minutes on average, but may take longer depending on the size of the transaction fee paid.

    After sending bitcoins to your wallet, you will need to wait for the transaction to be confirmed by the Bitcoin network. To check the status of your transaction, paste the transaction ID into a Bitcoin blockchain explorer such as [blockstream.info](https://blockstream.info/).


=== "Testnet"

    !!! tip "Request tBTC from a Testnet faucet"

        Testnet bitcoins are identified by the ticker symbol tBTC, to distinguish them from the Mainnet bitcoins which have the symbol BTC.

        Since coins on the Bitcoin Testnet have no monetary value they can be obtained free of charge from a "faucet", which is an automated service that will dispense a small quantity of tBTC on request.

        Visit a Bitcoin Testnet faucet, such as [coinfaucet.eu](https://coinfaucet.eu/en/btc-testnet/), and enter the recieve address obtained in the preceding step to send them to your ION wallet.

    After sending bitcoins to your wallet, you will need to wait for the transaction to be confirmed by the Bitcoin network. To check the status of your transaction, paste the transaction ID into a Bitcoin Testnet explorer such as [blockstream.info](https://blockstream.info/testnet/).

Then check your wallet balance with:
```console
$ bitcoin-cli getbalances
```
The output should look something like this, with a non-zero balance for the `watchonly` wallet:
```
{
  "mine": {
    "trusted": 0.00000000,
    "untrusted_pending": 0.00000000,
    "immature": 0.00000000
  },
  "watchonly": {
    "trusted": 0.00017612,
    "untrusted_pending": 0.00000000,
    "immature": 0.00000000
  }
}
```


## SSH config

When running a remote ION node, it can be convenient to open an SSH connection (with port forwarding) from your local machine. This produces a setup that is indistinguishable from running ION locally.

!!! warning "Allow incoming connections on the remote machine"

    The remote machine must be configured to accept incoming connections on all of the ports listed below. If you are using a Virtual Machine from a cloud provider, this can be done from the Network Settings page in the management portal.

We recommend adding the following lines to your SSH configuration file at `~/.ssh/config`:

=== "Mainnet"

    ```bash
    Host ion
        HostName <IP_ADDRESS>
        User <USERNAME>
        IdentityFile ~/.ssh/<KEY_FILE>
        LocalForward 3000 localhost:3000
        LocalForward 5001 localhost:5001
        LocalForward 8332 localhost:8332
        LocalForward 27017 localhost:27017
    ```

=== "Testnet"

    ```bash
    Host ion
        HostName <IP_ADDRESS>
        User <USERNAME>
        IdentityFile ~/.ssh/<KEY_FILE>
        LocalForward 3000 localhost:3000
        LocalForward 5001 localhost:5001
        LocalForward 18332 localhost:18332
        LocalForward 27017 localhost:27017
    ```

where `<IP_ADDRESS>` is the public IP address of the remote machine, `<USERNAME>` is the login username, and `<KEY_FILE>` is the name of the SSH key file used for key pair authentication.

The port forwarding rules in the above configuration assume that the default ports are used for the following processes. These ports are shown in the following table. If you wish, you can change any of these ports by editing the ION configuration files as described [earlier](#configure-ion).

=== "Mainnet"

    | Port        | Process           |
    | ----------- | ----------------- |
    | 3000        | ION               |
    | 5001        | IPFS              |
    | 8332        | Bitcoin           |
    | 27017       | MongoDB           |

=== "Testnet"

    | Port        | Process           |
    | ----------- | ----------------- |
    | 3000        | ION               |
    | 5001        | IPFS              |
    | 18332       | Bitcoin           |
    | 27017       | MongoDB           |

With this configuration in place, connect to the remote machine with the following command:
```console
$ ssh ion
```

As long as this connection is active, data sent to the ports specified in the SSH configuration (above) will be relayed to the same ports on the remote machine, producing a setup equivalent to running ION and its related processes locally.

## ION using Docker

!!! warning "ION using Docker is read-only"

    The simplest way to run ION is using Docker, and it can be a useful way to experiment with the system before performing a full installation. However, **this method provides a read-only ION node**. This means that it provides access to existing DIDs, but cannot be used to create and publish new ones.


These instructions are based on the [guide](https://github.com/decentralized-identity/ion/tree/master/docker) available on the ION GitHub repository.

**Step 1: Install Docker**

=== "Linux"

    Install Docker:
    ```
    sudo apt-get update
    sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common

    curl -fsSL --max-time 10 --retry 3 --retry-delay 3 --retry-max-time 60 https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

    sudo apt-get install -y docker-ce
    sudo systemctl enable docker
    ```

    Install Docker Compose:
    ```
    sudo curl -L --max-time 60 --retry 3 --retry-delay 3 --retry-max-time 100 "https://github.com/docker/compose/releases/download/v2.6.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    ```

=== "macOS"

    Install [Docker Desktop](https://www.docker.com/products/docker-desktop/).

**Step 2: Run the ION Docker container**

To obtain the required `docker-compose.*` files, clone the ION repository and enter the `docker` directory:
```
git clone https://github.com/decentralized-identity/ion.git
cd ion/docker
```

Now run the ION container. This command depends on whether you wish to run a Mainnet or a Testnet ION node.

=== "Mainnet"

    ```
    docker-compose up -d
    ```

=== "Testnet"

    ```
    docker-compose -f docker-compose.yml -f docker-compose.testnet-override.yml up -d
    ```

!!! warning "Bitcoin and ION synchronisation"

    When the ION container starts for the first time, it will begin synchronising with the Bitcoin network. This means downloading all of the blocks in the Bitcoin blockchain, which is a large data structure containing every Bitcoion transaction that has ever been processed. Once this has finished, ION itself will then scan the entire blockchain for ION DID operations, which is also a lengthy process.

    **In total, the synchronisation process may take several hours, or even days, to complete.** You will not be able to use Trustchain until your ION node has finished synchronising.


<!-- TODO: screenshots! -->

When the synchronisation process has finished, confirm that ION is working properly by running the following command to resolve a sample DID:

=== "Mainnet"

    ```console
    $ curl http://localhost:3000/identifiers/did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w | json_pp
    ```

=== "Testnet"

    ```console
    $ curl http://localhost:3000/identifiers/did:ion:test:EiClWZ1MnE8PHjH6y4e4nCKgtKnI1DK1foZiP61I86b6pw | json_pp
    ```

If ION is working properly, the command above will return a JSON data structure containing the resolved DID document and document metadata for the sample DID.


&nbsp;

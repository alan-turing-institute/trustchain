# ION

The [Identity Overlay Network](https://identity.foundation/ion/) (ION) is an open source [DID method](https://www.w3.org/TR/did-core/#methods) implementation developed by the Decentralized Identity Foundation.

In other words, ION is a software tool that can be used to perform DID operations, such as creating and publishing new DIDs and DID documents, and resolving existing ones. It does this by reading and writing data to the [Bitcoin](https://bitcoin.org/en/) blockchain and to the [IPFS](https://ipfs.tech/) distributed file system. As such, every ION instance is a node on these two peer-to-peer networks.

Trustchain delegates the execution of DID operations to an ION node. Therefore to use Trustchain you must first install and run ION, either on the same machine or a connected one.

!!! warning "ION resource requirements"

    An ION installation includes a full node on the Bitcoin network, which must download and store the entire Bitcoin blockchain. This is a large amount of data that typically takes several hours, or even days, to download.

    The recommended system requirements for an ION installation are:

    - 6GB of RAM
    - 1.5TB of storage (or 100GB for [Testnet4](#bitcoin-mainnet-vs-testnet)).

Note, however, that **Trustchain makes no assumptions about the trustworthiness of the ION system** and the Trustchain security model does not rely on the correct functioning of the ION software. Trustchain independently verifies all of the data it receives from ION, so a faulty or compromised ION node would not represent a security vulnerability in Trustchain (although it could cause a loss of service).

This page explains how to install and run ION.

<!-- TODO: insert the architecture schematic diagram here? (from the paper). -->

## Preliminaries

Before beginning the installation, a few decisions must be made that will determine exactly what steps should be taken.

### Docker Container vs. Full Installation

The simplest way to run ION is using Docker, and it can be a useful way to experiment with the system before performing a full installation. However, this method provides a **read-only ION node**. This means that it provides access to existing DIDs, but cannot be used to create and publish new ones.

If you would like to be able to use Trustchain to create and publish your own DIDs, follow the full installation instructions below (and ignore the [ION with Docker](#ion-using-docker) section).

If you want to run ION using Docker, you can skip most of this page and just follow the instructions in the [ION with Docker](#ion-with-docker) section.

### Bitcoin Mainnet vs. Testnet

The Bitcoin client wrapped inside an ION node can be configured either for **Mainnet** (the main Bitcoin network) or **Testnet** (an alternative blockchain designed for testing and software development).

**Mainnet should be used for a production deployment of Trustchain** because DID operations published on the Bitcoin blockchain have extremely strong immutability, persistence and discoverability properties. When testing Trustchain, however, it is sensible to configure the ION Bitcoin client for Testnet, since coins on the test network have no monetary value and therefore "test" DID operations can be executed at zero cost.

The current iteration of Bitcoin's test network is Testnet4, which since May 2024 has replaced the (now deprecated) Testnet3. It is possible to run ION on either of these networks, but **Testnet4 is strongly recommended over Testnet3**.

Testnet coins can be requested from a Testnet "faucet", such as [this one for Testnet4](https://faucet.testnet4.dev/) or [this one for Testnet3](https://coinfaucet.eu/en/btc-testnet/).

In this guide, commands and configuration settings may depend on which network is in use. In those cases, choose the appropriate tab for your setup: Mainnet, Testnet4 or Testnet3 (Deprecated).

### Local vs. Remote Installation

You can install ION on your local machine or a remote one, e.g. a virtual machine in the Cloud. If you are using a remote machine, connect to it using SSH and follow the instructions below.

Once installed, follow the port forwarding instructions in the [SSH config](#ssh-config) section to produce a setup that is indistinguishable from running an ION node locally.

## ION Installation Guide

These instructions are based on the official [ION Install Guide](https://identity.foundation/ion/install-guide/) but contain additional details, several minor corrections and a workaround to support recent versions of Bitcoin Core.

Both Linux and macOS are supported and tested. For Linux, our instructions assume a Debian-based distribution, such as Ubuntu. Some minor changes will be needed for other distributions. Instructions for installing on Windows are given in the official [ION guide](https://identity.foundation/ion/install-guide/).

In all cases, administrator privileges are required.

### Prerequisites

!!! info "Create the `SHELL_CONFIG` environment variable"

    Before continuing, make sure you have created the `SHELL_CONFIG` environment variable by following the instructions on the [Getting Started](getting-started.md#environment-variables) page.

Run the following commands to set up your environment.

=== "Linux"

    Update the package lists on your machine and install essential build tools:
    ```console
    $ sudo apt update && sudo apt install build-essential
    ```
    Install Git:
    ```console
    $ sudo apt install git
    ```
    Install Node.js:
    ```console
    $ sudo apt install nodejs
    ```
    and the Node package manager:
    ```console
    $ sudo apt install npm
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
    Install Node.js via the [download page](https://nodejs.org/en/download) or with this command:
    ```console
    $ brew install node
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

Then initialise your IPFS node:
```console
$ ipfs init
```
To check the installation was successful, open a new Terminal window and start the IPFS daemon:
```console
$ ipfs daemon
```
Then (back in the original Terminal window) run:
```console
$ ipfs cat /ipfs/QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc/readme
```
which should output a welcome message.

### Install MongoDB

=== "Linux"

    Instructions for installing MongoDB on Linux are available on the [MongoDB website](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/).

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

Trustchain has been tested with Bitcoin Core v28.0 and therefore the instructions below assume that version. Other versions of Bitcoin Core are [available](https://bitcoincore.org/en/releases/) and can be used, but will require some minor changes to the commands in the following steps.

!!! info "Testnet4 requires Bitcoin Core v28.0 or above"

    If you are intending to run ION on Testnet4 you must install Bitcoin Core v28.0 or above, as this is the earliest version that supports the new test network.

=== "Linux"

    Begin by downloading the [Bitcoin Core release](https://bitcoincore.org/bin/bitcoin-core-28.0/) for your system:

     - [Download link](https://bitcoincore.org/bin/bitcoin-core-28.0/bitcoin-28.0-x86_64-linux-gnu.tar.gz) for Linux with x86-64 processor.
     - [Download link](https://bitcoincore.org/bin/bitcoin-core-28.0/bitcoin-28.0-arm-linux-gnueabihf.tar.gz) for Linux with ARM processor.

    Verify the download by comparing the [published hash](https://bitcoincore.org/bin/bitcoin-core-28.0/SHA256SUMS) with the result of this command:
    ```console
    $ shasum -a 256 ~/Downloads/bitcoin-28.0-*.tar.gz
    ```

    Unzip the archive:
    ```console
    $ (cd ~/Downloads && tar xvzf bitcoin-28.0-*.tar.gz)
    ```
    and install Bitcoin Core:
    ```console
    $ sudo install -m 0755 -t /usr/local/bin ~/Downloads/bitcoin-28.0/bin/*
    ```
    The installation includes an executable file named `bitcoind` which we will run to start Bitcoin Core.

=== "macOS"

    Begin by downloading the [Bitcoin Core release](https://bitcoincore.org/bin/bitcoin-core-28.0/) for your system:

     - [Download link](https://bitcoincore.org/bin/bitcoin-core-28.0/bitcoin-28.0-x86_64-apple-darwin.tar.gz) for Mac with x86-64 processor.
     - [Download link](https://bitcoincore.org/bin/bitcoin-core-28.0/bitcoin-28.0-arm64-apple-darwin.tar.gz) for Mac with Apple M-series processor.

    Verify the download by comparing the [published hash](https://bitcoincore.org/bin/bitcoin-core-28.0/SHA256SUMS) with the result of this command:
    ```console
    $ shasum -a 256 ~/Downloads/bitcoin-28.0-*.tar.gz
    ```

    Unzip the archive:
    ```console
    $ (cd ~/Downloads && tar xvzf bitcoin-28.0-*.tar.gz)
    ```
    and move the contents to the `/Applications` folder:
    ```console
    $ mv ~/Downloads/bitcoin-28.0 /Applications
    ```
    The download contains an executable file named `bitcoind` which we will run to start Bitcoin Core.

    !!! info "Sign the Bitcoin Core executable files"

        Newer macOS systems will refuse to run an executable file unless it is signed. Run the following command to check whether this is a requirement on your machine:
        ```console
        $ codesign -d -vvv --entitlements :- /Applications/bitcoin-28.0/bin/bitcoind
        > /Applications/bitcoin-28.0/bin/bitcoind: code object is not signed at all
        ```
        If you see the message "code object is not signed at all" (as in the example above), you will need to create a [self-signed certificate](https://support.apple.com/en-gb/guide/keychain-access/kyca8916/mac) for the executable file. Do this by running:
        ```console
        $ codesign -s - /Applications/bitcoin-28.0/bin/bitcoind
        ```
        And do the same for the Bitcoin CLI executable:
        ```console
        $ codesign -s - /Applications/bitcoin-28.0/bin/bitcoin-cli
        ```

### Configure Bitcoin Core

We shall need to specify a folder to store the Bitcoin blockchain data.

!!! warning "Bitcoin data storage requirements"

    The Bitcoin data folder will store the entire Bitcoin blockchain, which is >800GB for Mainnet and >15GB for Testnet4.

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
    $ printf "server=1\ndaemon=1\ntxindex=1\nblocksxor=0\ndatadir=$BITCOIN_DATA\ndeprecatedrpc=create_bdb\ndeprecatedrpc=warnings\n" > $BITCOIN_DATA/bitcoin.conf && chmod 640 $BITCOIN_DATA/bitcoin.conf
    ```

    To confirm these changes were made correctly, check the first three lines in the `bitcoin.conf` file by running:
    ```console
    $ head -n 7 $BITCOIN_DATA/bitcoin.conf
    ```
    You should see lines like these printed to the Terminal:
    ```
    server=1
    daemon=1
    txindex=1
    blocksxor=0
    datadir=<YOUR_BITCOIN_DATA_DIRECTORY>
    deprecatedrpc=create_bdb
    deprecatedrpc=warnings
    ```

=== "Testnet4"

    Bitcoin configuration parameters will be stored in a file named `bitcoin.conf` inside the `$BITCOIN_DATA` folder.
    The following command creates that file with the required parameters and user permissions:
    ```console
    $ printf "testnet4=1\nserver=1\ndaemon=1\ntxindex=1\nblocksxor=0\ndatadir=$BITCOIN_DATA\ndeprecatedrpc=create_bdb\ndeprecatedrpc=warnings\n" > $BITCOIN_DATA/bitcoin.conf && chmod 640 $BITCOIN_DATA/bitcoin.conf
    ```

    To confirm these changes were made correctly, check the first three lines in the `bitcoin.conf` file by running:
    ```console
    $ head -n 8 $BITCOIN_DATA/bitcoin.conf
    ```
    You should see lines like these printed to the Terminal:
    ```
    testnet4=1
    server=1
    daemon=1
    txindex=1
    blocksxor=0
    datadir=<YOUR_BITCOIN_DATA_DIRECTORY>
    deprecatedrpc=create_bdb
    deprecatedrpc=warnings
    ```

=== "Testnet3 (Deprecated)"

    Bitcoin configuration parameters will be stored in a file named `bitcoin.conf` inside the `$BITCOIN_DATA` folder.
    The following command creates that file with the required parameters and user permissions:
    ```console
    $ printf "testnet=1\nserver=1\ndaemon=1\ntxindex=1\nblocksxor=0\ndatadir=$BITCOIN_DATA\ndeprecatedrpc=create_bdb\ndeprecatedrpc=warnings\n" > $BITCOIN_DATA/bitcoin.conf && chmod 640 $BITCOIN_DATA/bitcoin.conf
    ```

    To confirm these changes were made correctly, check the first three lines in the `bitcoin.conf` file by running:
    ```console
    $ head -n 8 $BITCOIN_DATA/bitcoin.conf
    ```
    You should see lines like these printed to the Terminal:
    ```
    testnet=1
    server=1
    daemon=1
    txindex=1
    blocksxor=0
    datadir=<YOUR_BITCOIN_DATA_DIRECTORY>
    deprecatedrpc=create_bdb
    deprecatedrpc=warnings
    ```

!!! info "Configuration in older versions of Bitcoin Core"

    If you are running an older version of Bitcoin Core, you may need to omit the `deprecatedrpc` parameters from your configuration file:

    - the settings `blocksxor=0` and `deprecatedrpc=warnings` were introduced in Bitcoin Core v28.0, so they must be omitted if you are running an earlier version.
    - the setting `deprecatedrpc=create_bdb` was introduced in Bitcoin Core v26.0, so it must be omitted if you are running an earlier version.

!!! warning "Note: Do not use the `~` shorthand in the `datadir` parameter"

    The directory path in the `datadir` parameter must not contain the `~` character as a shorthand for the user's home directory.

    The example given in the official [ION install guide](https://identity.foundation/ion/install-guide/) does use this shorthand, which causes an error, so beware of this issue if you are following that guide and/or editing the `bitcoin.conf` file manually.

### Configure Bitcoin CLI

When your Bitcoin Core node is up and running, you will want to be able to communicate with it. Bitcoin Core provides a command line interface (CLI) for this purpose.

Run the following command to create an alias, making to easy to access the CLI:

=== "Linux"

    ```console
    $ echo 'alias bitcoin-cli="/usr/local/bin/bitcoin-cli -conf=$BITCOIN_DATA/bitcoin.conf"' >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

=== "macOS"

    ```console
    $ echo 'alias bitcoin-cli="/Applications/bitcoin-28.0/bin/bitcoin-cli -conf=$BITCOIN_DATA/bitcoin.conf"' >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

!!! info "Bitcoin RPC username and password"

    Before you can make use of the CLI you will need to add a username and password to the Bitcoin configuration file. These same parameters will also be used for authentication when ION interacts with Bitcoin Core. In both cases, the interaction is possible because Bitcoin Core provides access via a Remote Procedure Call (RPC) interface.

    We shall use `admin` for the RPC username. To set up the RPC password, copy and paste the following command into the Terminal and then change `<password>` to something of your choice before hitting the ++return++ key:
    ```console
    $ RPC_PASSWORD="<password>"
    ```
    Now run the following command to add the username and password to the `bitcoin.conf` file:

    === "Linux"
        ```console
        $ sed -i "1s|^|rpcuser=admin\nrpcpassword=$RPC_PASSWORD\n|" $BITCOIN_DATA/bitcoin.conf
        ```
    === "macOS"
        ```console
        $ sed -i '' $'1s|^|rpcuser=admin\\\nrpcpassword='"$RPC_PASSWORD"$'\\\n|' $BITCOIN_DATA/bitcoin.conf
        ```

    To confirm these changes were made correctly, check the first two lines in the `bitcoin.conf` file by running:
    ```console
    $ head -n 2 $BITCOIN_DATA/bitcoin.conf
    ```
    You should see these lines printed to the Terminal (with your chosen password):
    ```
    rpcuser=admin
    rpcpassword=<password>
    ```

### Start Bitcoin Core

Before we start Bitcoin Core, we need to make sure it can find the correct configuration file that was created above. To make this convenient, let's create an alias in our `SHELL_CONFIG` file:

=== "Linux"

    ```console
    $ echo 'alias bitcoind="/usr/local/bin/bitcoind -conf=$BITCOIN_DATA/bitcoin.conf"' >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

    Now, use the following simple command to start Bitcoin Core:
    ```console
    $ bitcoind
    ```

=== "macOS"

    ```console
    $ echo 'alias bitcoind="/Applications/bitcoin-28.0/bin/bitcoind -conf=$BITCOIN_DATA/bitcoin.conf"' >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

    Now, use the following simple command to start Bitcoin Core:
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

    **The synchronisation process on Mainnet may take several hours, or even days, to complete.** You can continue with the installation steps below while it is in progress, but you will not be able to use Trustchain until your Bitcoin node has finished synchronising.

    Fortunately, the synchronisation process on Testnet4 is much quicker, as only ~15GB of data must be downloaded.

Whenever Bitcoin Core is running, you can invoke the Bitcoin CLI with commands beginning `bitcoin-cli`. A full list of commands available via the Bitcoin CLI can be found [here](https://developer.bitcoin.org/reference/rpc/).

One useful example is the following `-getinfo` command. It reports information about the state of your Bitcoin node, including whether it is fully synchronised:
```console
$ bitcoin-cli -getinfo
```

!!! info "Create a Bitcoin wallet for ION"

    Before using ION you must create a Bitcoin wallet by running the following CLI command:
    ```console
    $ bitcoin-cli -named createwallet wallet_name="sidetreeDefaultWallet" descriptors=false
    ```
    Expected output:
    ```json
    {
      "name": "sidetreeDefaultWallet",
      "warnings": [
        "Wallet created successfully. The legacy wallet type is being deprecated and support for creating and opening legacy wallets will be removed in the future."
      ]
    }
    ```
    Note that we have chosen to create a "legacy" Bitcoin wallet, for compatibility with ION.


### Configure ION

Choose a directory in which you want to store the ION software and change to that directory using the command `$ cd <DIRECTORY_NAME>`. For instance, to change to your home directory run the `cd` command without any arguments:
```console
$ cd
```
Now clone the ION code repository from GitHub:
```console
$ git clone https://github.com/decentralized-identity/ion.git
```
and change into the newly-created `ion` subfolder:
```console
$ cd ion
```

!!! tip "Create the `ION_REPO` environment variable"

    Since we will need to refer to this folder in future, let's create an [environment variable](getting-started.md#environment-variables) containing its file path:
    ```console
    $ echo "export ION_REPO=" $(pwd) | sed 's/= /=/g' >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

We will need a folder for storing ION configuration files. For convenience, we'll also create an environment variable for that folder.

!!! tip "Create the `ION_CONFIG` environment variables"

    Our convention is to use the folder `~/.ion` for ION configuration files. If you want to use a different folder, just change the path in the following command:
    ```console
    $ echo "export ION_CONFIG=~/.ion" >> $SHELL_CONFIG; source $SHELL_CONFIG
    ```

    We also need environment variables for each of the four files that will be stored in the ION config folder, so ION can find them when it starts up. The following command creates all four environment variables:

    === "Mainnet"
        ```console
        $ printf "export ION_BITCOIN_CONFIG_FILE_PATH=$ION_CONFIG/mainnet-bitcoin-config.json\nexport ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH=$ION_CONFIG/mainnet-bitcoin-versioning.json\nexport ION_CORE_CONFIG_FILE_PATH=$ION_CONFIG/mainnet-core-config.json\nexport ION_CORE_VERSIONING_CONFIG_FILE_PATH=$ION_CONFIG/mainnet-core-versioning.json" >> $SHELL_CONFIG; source $SHELL_CONFIG
        ```
    === "Testnet4"
        ```console
        $ printf "export ION_BITCOIN_CONFIG_FILE_PATH=$ION_CONFIG/testnet-bitcoin-config.json\nexport ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH=$ION_CONFIG/testnet-bitcoin-versioning.json\nexport ION_CORE_CONFIG_FILE_PATH=$ION_CONFIG/testnet-core-config.json\nexport ION_CORE_VERSIONING_CONFIG_FILE_PATH=$ION_CONFIG/testnet-core-versioning.json" >> $SHELL_CONFIG; source $SHELL_CONFIG
        ```
    === "Testnet3 (Deprecated)"
        ```console
        $ printf "export ION_BITCOIN_CONFIG_FILE_PATH=$ION_CONFIG/testnet-bitcoin-config.json\nexport ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH=$ION_CONFIG/testnet-bitcoin-versioning.json\nexport ION_CORE_CONFIG_FILE_PATH=$ION_CONFIG/testnet-core-config.json\nexport ION_CORE_VERSIONING_CONFIG_FILE_PATH=$ION_CONFIG/testnet-core-versioning.json" >> $SHELL_CONFIG; source $SHELL_CONFIG
        ```

Having defined the `ION_CONFIG` environment variable (above), use it to create the folder itself:
```console
$ mkdir $ION_CONFIG
```

Next, copy the template ION configuration files to your `ION_CONFIG` directory:

=== "Mainnet"
    ```console
    $ cp $ION_REPO/config/mainnet-bitcoin-config.json $ION_REPO/config/mainnet-bitcoin-versioning.json $ION_REPO/config/mainnet-core-config.json $ION_REPO/config/mainnet-core-versioning.json $ION_CONFIG
    ```
=== "Testnet4"
    ```console
    $ cp $ION_REPO/config/testnet-bitcoin-config.json $ION_REPO/config/testnet-bitcoin-versioning.json $ION_REPO/config/testnet-core-config.json $ION_REPO/config/testnet-core-versioning.json $ION_CONFIG
    ```
=== "Testnet3 (Deprecated)"
    ```console
    $ cp $ION_REPO/config/testnet-bitcoin-config.json $ION_REPO/config/testnet-bitcoin-versioning.json $ION_REPO/config/testnet-core-config.json $ION_REPO/config/testnet-core-versioning.json $ION_CONFIG
    ```

and set appropriate user permissions:
```console
$ chmod 640 $ION_BITCOIN_CONFIG_FILE_PATH $ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH $ION_CORE_CONFIG_FILE_PATH $ION_CORE_VERSIONING_CONFIG_FILE_PATH
```

Having made copies of the template configuration files, we now edit some of their parameters to match our Bitcoin Core configuration.

=== "Mainnet"

    Set the `bitcoinDataDirectory` parameter (skip this step if your `BITCOIN_DATA` directory is on a network drive):

    === "Linux"
        ```console
        $ sed -i 's|"bitcoinDataDirectory": ".*"|"bitcoinDataDirectory": "'$BITCOIN_DATA'"|' $ION_BITCOIN_CONFIG_FILE_PATH
        ```
    === "macOS"
        ```console
        $ sed -i '' 's|"bitcoinDataDirectory": ".*"|"bitcoinDataDirectory": "'$BITCOIN_DATA'"|' $ION_BITCOIN_CONFIG_FILE_PATH
        ```

=== "Testnet4"

    Set the `bitcoinDataDirectory` parameter in the ION Bitcoin config file:

    === "Linux"
        ```console
        $ sed -i 's|"bitcoinDataDirectory": ".*"|"bitcoinDataDirectory": "'$BITCOIN_DATA'/testnet4"|' $ION_BITCOIN_CONFIG_FILE_PATH
        ```
    === "macOS"
        ```console
        $ sed -i '' 's|"bitcoinDataDirectory": ".*"|"bitcoinDataDirectory": "'$BITCOIN_DATA'/testnet4"|' $ION_BITCOIN_CONFIG_FILE_PATH
        ```

    Next, for Testnet4 only, set two further parameters in the same file. First the `bitcoinPeerUri` parameter:
    === "Linux"
        ```console
        $ sed -i 's|"bitcoinPeerUri": "http://localhost:18332"|"bitcoinPeerUri": "http://localhost:48332"|' $ION_BITCOIN_CONFIG_FILE_PATH
        ```
    === "macOS"
        ```console
        $ sed -i '' 's|"bitcoinPeerUri": "http://localhost:18332"|"bitcoinPeerUri": "http://localhost:48332"|' $ION_BITCOIN_CONFIG_FILE_PATH
        ```

    and second, the `genesisBlockNumber` parameter:
    === "Linux"
        ```console
        $ sed -i 's|"genesisBlockNumber": .*,|"genesisBlockNumber": 2000,|' $ION_BITCOIN_CONFIG_FILE_PATH
        ```
    === "macOS"
        ```console
        $ sed -i '' 's|"genesisBlockNumber": .*,|"genesisBlockNumber": 2000,|' $ION_BITCOIN_CONFIG_FILE_PATH
        ```

    Also for Testnet4 only, set the `startingBlockchainTime` parameter in the ION Bitcoin versioning config file:

    === "Linux"
        ```console
        $ sed -i 's|"startingBlockchainTime": .*,|"startingBlockchainTime": 2000,|' $ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH
        ```
    === "macOS"
        ```console
        $ sed -i '' 's|"startingBlockchainTime": .*,|"startingBlockchainTime": 2000,|' $ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH
        ```

    and the same parameter in the ION Core versioning config file:

    === "Linux"
        ```console
        $ sed -i 's|"startingBlockchainTime": .*,|"startingBlockchainTime": 2000,|' $ION_CORE_VERSIONING_CONFIG_FILE_PATH
        ```
    === "macOS"
        ```console
        $ sed -i '' 's|"startingBlockchainTime": .*,|"startingBlockchainTime": 2000,|' $ION_CORE_VERSIONING_CONFIG_FILE_PATH
        ```

=== "Testnet3 (Deprecated)"

    Set the `bitcoinDataDirectory` parameter (skip this step if your `BITCOIN_DATA` directory is on a network drive):

    === "Linux"
        ```console
        $ sed -i 's|"bitcoinDataDirectory": ".*"|"bitcoinDataDirectory": "'$BITCOIN_DATA'/testnet3"|' $ION_BITCOIN_CONFIG_FILE_PATH
        ```
    === "macOS"
        ```console
        $ sed -i '' 's|"bitcoinDataDirectory": ".*"|"bitcoinDataDirectory": "'$BITCOIN_DATA'/testnet3"|' $ION_BITCOIN_CONFIG_FILE_PATH
        ```

<br>
Next we shall set the `bitcoinRpcUsername` and `bitcoinRpcPassword` parameters. These must match the username and password chosen in the [Bitcoin CLI](#bitcoin-cli) section above.

We chose `admin` for the RPC username. The following command sets this same value inside the ION Bitcoin config file:

=== "Linux"
    ```console
    $ sed -i 's|"bitcoinRpcUsername": ".*"|"bitcoinRpcUsername": "admin"|' $ION_BITCOIN_CONFIG_FILE_PATH
    ```
=== "macOS"
    ```console
    $ sed -i '' 's|"bitcoinRpcUsername": ".*"|"bitcoinRpcUsername": "admin"|' $ION_BITCOIN_CONFIG_FILE_PATH
    ```

For the RPC password, copy and paste the following command into the Terminal and then change `<password>` to the **same password** you chose when setting up the [Bitcoin CLI](#bitcoin-cli):
```console
$ RPC_PASSWORD="<password>"
```

Then run this command to update the `bitcoinRpcPassword` parameter in the ION config file:

=== "Linux"
    ```console
    $ sed -i 's|"bitcoinRpcPassword": ".*"|"bitcoinRpcPassword": "'$RPC_PASSWORD'"|g' $ION_BITCOIN_CONFIG_FILE_PATH
    ```
=== "macOS"
    ```console
    $ sed -i '' 's|"bitcoinRpcPassword": ".*"|"bitcoinRpcPassword": "'$RPC_PASSWORD'"|g' $ION_BITCOIN_CONFIG_FILE_PATH
    ```

The final configuration step is to set the `bitcoinWalletOrImportString` parameter.

=== "Mainnet"

    This must be a mainnet-compatible private key in wallet import format (WIF).

    If you do **not** intend to use Trustchain to write your own DID operations, you can use [this tool](https://learnmeabitcoin.com/technical/wif) to randomly generate a WIF string without any bitcoin.

    If you are intending to use Trustchain to write your own DID operations, this parameter must be populated with your private key in the appropriate format. To do this, first check that `sidetreeDefaultWallet` (that was created [earlier](#configure-bitcoin-core)) is loaded. You should see the following output when running this command:
    ```console
    $ bitcoin-cli listwallets
    [
      "sidetreeDefaultWallet"
    ]
    ```
    Next create a wallet address with this command:
    ```console
    $ bitcoin-cli getnewaddress
    bc1qr5f53xkgfehq3tr0rjg478kvxdjfkc5tatma3u
    ```
    This command will output a new address (similar to the example above, but a different string of characters).

    Now, to get the private key for this Bitcoin address, run the following command but with `<address>` replaced with the output from the previous step:
    ```console
    $ bitcoin-cli dumpprivkey <address>
    L1eokPoQRzBXEddxWAyejiR49FopMj5iKyEZNSMaQKMqcZWFVLR5
    ```
    Once again, the output will look similar to the above, but with different characters. This is the WIF string to be used in the following command.

    !!! warning "Never share your Bitcoin private keys"

        The output from the previous command is the Bitcoin private key corresponding to your wallet address. Anyone who has access to this private key can spend the bitcoins in that address, so you should be careful to keep it secret.

        In the following step we will copy the private key into an ION configuration file, to enable ION to execute the Bitcoin transactions necessary to create and update DIDs. The permissions on this configuration file have already been set (above) so that only the user and their group can read the file contents.

    Copy and paste this command into the Terminal and then change `<wif>` to your WIF string:
    ```console
    $ WIF="<wif>"
    ```

    Then run this command to update the `bitcoinWalletOrImportString` parameter in the ION config file:

    === "Linux"
        ```console
        $ sed -i 's|"bitcoinWalletOrImportString": ".*"|"bitcoinWalletOrImportString": "'$WIF'"|g' $ION_BITCOIN_CONFIG_FILE_PATH
        ```
    === "macOS"
        ```console
        $ sed -i '' 's|"bitcoinWalletOrImportString": ".*"|"bitcoinWalletOrImportString": "'$WIF'"|g' $ION_BITCOIN_CONFIG_FILE_PATH
        ```

=== "Testnet4"

    On Testnet4, a key will be automatically generated when ION runs for the first time which can be used for the `bitcoinWalletOrImportString` parameter, so you don't need to do anything in this step.

=== "Testnet3 (Deprecated)"

    On Testnet3, a key will be automatically generated when ION runs for the first time which can be used for the `bitcoinWalletOrImportString` parameter, so you don't need to do anything in this step.

!!! tip "Tip: Set the `requestMaxRetries` configuration parameter"

    This step is optional but is strongly recommended because it may significantly speed up the synchronisation process which takes place when ION runs for the first time.

    When ION requests information from the local Bitcoin node it may have to retry several times before receiving a response. This is particularly common during its initial synchronisation, when many requests are made at high frequency.

    After several failed requests ION will stop trying and the synchronisation process will restart, forfeiting the progress already made. By default this will happen after only three failed attempts, but this can be increased by setting the `requestMaxRetries` config parameter.

    Run the following command to increase the maximum number of retry attempts:
    === "Linux"
        ```console
        $ N=$(grep -n '\"port\"' $ION_BITCOIN_CONFIG_FILE_PATH | cut -d':' -f1); sed -i "$((N+1))"'i\'$'\n''  "requestMaxRetries": 6,'$'\n' $ION_BITCOIN_CONFIG_FILE_PATH
        ```
    === "macOS"
        ```console
        $ N=$(grep -n '\"port\"' $ION_BITCOIN_CONFIG_FILE_PATH | cut -d':' -f1); sed -i '' "$((N+1))"'i\'$'\n''  "requestMaxRetries": 6,'$'\n' $ION_BITCOIN_CONFIG_FILE_PATH
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

??? warning "Additional configuration steps required for Testnet4"

    ION has built-in support for Bitcoin Mainnet and Testnet3, but not for Testnet4. To fix this, the following additional steps must be performed (after completing the ION build procedure) **only if you are running on Testnet4**.

    Run the following command to update your ION installation with the Testnet4 [magic bytes](https://learnmeabitcoin.com/technical/networking/magic-bytes/), used to delimit messages on the Bitcoin network:
    === "Linux"
        ```console
        $ sed -i "s/testnet: Buffer\.from('0b110907', 'hex')/testnet: Buffer.from('1c163f28', 'hex')/" $ION_REPO/node_modules/@decentralized-identity/sidetree/dist/lib/bitcoin/BitcoinRawDataParser.js
        ```
    === "macOS"
        ```console
        $ sed -i '' "s/testnet: Buffer\.from('0b110907', 'hex')/testnet: Buffer.from('1c163f28', 'hex')/" $ION_REPO/node_modules/@decentralized-identity/sidetree/dist/lib/bitcoin/BitcoinRawDataParser.js
        ```

    Run this command to fix the way ION computes the Testnet4 block height:
    === "Linux"
        ```console
        $ sed -i 's/magicBytes\.equals(BitcoinRawDataParser\.magicBytes\.regtest)/(magicBytes\.equals(BitcoinRawDataParser\.magicBytes\.regtest) || (magicBytes\.equals(BitcoinRawDataParser\.magicBytes\.testnet)))/' $ION_REPO/node_modules/@decentralized-identity/sidetree/dist/lib/bitcoin/BitcoinRawDataParser.js
        ```
    === "macOS"
        ```console
        $ sed -i '' 's/magicBytes\.equals(BitcoinRawDataParser\.magicBytes\.regtest)/(magicBytes\.equals(BitcoinRawDataParser\.magicBytes\.regtest) || (magicBytes\.equals(BitcoinRawDataParser\.magicBytes\.testnet)))/' $ION_REPO/node_modules/@decentralized-identity/sidetree/dist/lib/bitcoin/BitcoinRawDataParser.js
        ```

    Finally, run the following command to avoid errors when performing fee estimation on Testnet4 (required for publishing DID operations from your ION node):
    === "Linux"
        ```console
        $ sed -i 's|1 // Number of confirmation targets|50 // Number of confirmation targets|' $ION_REPO/node_modules/@decentralized-identity/sidetree/dist/lib/bitcoin/BitcoinClient.js
        ```
    === "macOS"
        ```console
        $ sed -i '' 's|1 // Number of confirmation targets|50 // Number of confirmation targets|' $ION_REPO/node_modules/@decentralized-identity/sidetree/dist/lib/bitcoin/BitcoinClient.js
        ```

### Test ION

Before running ION for the first time, **make sure that you have started IPFS, MongoDB and Bitcoin Core** (by following the instructions above or using the command summary in the [Running ION](#running-ion) section). Also make sure that Bitcoin Core is fully synchronised by running:
```console
$ bitcoin-cli -getinfo
```

You should see output similar to the following. Bitcoin Core is synchronised if the number of `Blocks` is equal to the number of `Headers`:

=== "Mainnet"
    ```
    Chain: main
    Blocks: 933111
    Headers: 933111
    Verification progress: 99.9998%
    Difficulty: 146472570619930.8

    Network: in 0, out 10, total 10
    Version: 280000
    Time offset (s): 0
    Proxies: n/a
    Min tx relay fee rate (BTC/kvB): 0.00001000

    Wallet: sidetreeDefaultWallet
    Keypool size: 1000
    Transaction fee rate (-paytxfee) (BTC/kvB): 0.00000000

    Balance: 0.00000000
    ```

    In a new Terminal, start the ION Bitcoin microservice with:
    ```console
    $ (cd $ION_REPO && npm run bitcoin)
    ```

=== "Testnet4"
    ```
    Chain: testnet4
    Blocks: 119371
    Headers: 119371
    Verification progress: 100.0000%
    Difficulty: 1

    Network: in 0, out 11, total 11
    Version: 280000
    Time offset (s): 0
    Proxies: n/a
    Min tx relay fee rate (BTC/kvB): 0.00001000

    Wallet: sidetreeDefaultWallet
    Keypool size: 1000
    Transaction fee rate (-paytxfee) (BTC/kvB): 0.00000000

    Balance: 0.00000000
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

    Then run this command to update the `bitcoinWalletOrImportString` parameter in the ION config file:

    === "Linux"
        ```console
        $ sed -i 's|"bitcoinWalletOrImportString": ".*"|"bitcoinWalletOrImportString": "'$WIF'"|g' $ION_BITCOIN_CONFIG_FILE_PATH
        ```
    === "macOS"
        ```console
        $ sed -i '' 's|"bitcoinWalletOrImportString": ".*"|"bitcoinWalletOrImportString": "'$WIF'"|g' $ION_BITCOIN_CONFIG_FILE_PATH
        ```

    Now repeat the attempt to start the ION Bitcoin microservice:
    ```console
    $ (cd $ION_REPO && npm run bitcoin)
    ```

=== "Testnet3 (Deprecated)"
    ```
    Chain: test
    Blocks: 4834624
    Headers: 4834624
    Verification progress: 99.9999%
    Difficulty: 2154250.232295683

    Network: in 0, out 10, total 10
    Version: 280000
    Time offset (s): 0
    Proxies: n/a
    Min tx relay fee rate (BTC/kvB): 0.00001000

    Wallet: sidetreeDefaultWallet
    Keypool size: 1000
    Transaction fee rate (-paytxfee) (BTC/kvB): 0.00000000

    Balance: 0.00000000
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

    Then run this command to update the `bitcoinWalletOrImportString` parameter in the ION config file:

    === "Linux"
        ```console
        $ sed -i 's|"bitcoinWalletOrImportString": ".*"|"bitcoinWalletOrImportString": "'$WIF'"|g' $ION_BITCOIN_CONFIG_FILE_PATH
        ```
    === "macOS"
        ```console
        $ sed -i '' 's|"bitcoinWalletOrImportString": ".*"|"bitcoinWalletOrImportString": "'$WIF'"|g' $ION_BITCOIN_CONFIG_FILE_PATH
        ```

    Now repeat the attempt to start the ION Bitcoin microservice:
    ```console
    $ (cd $ION_REPO && npm run bitcoin)
    ```

!!! warning "ION synchronisation"

    When the ION Bitcoin microservice starts for the first time, it will begin scanning the Bitcoin blockchain for ION DID operations, by making calls to the Bitcoin Core RPC interface.

    On Mainnet **the synchronisation process may take several hours to complete.** Wait until it has finished before running the ION Core microservice in the following step.

    On Testnet4 the synchronisation process is much quicker, as there are fewer blocks to scan, and should take only a few minutes.

??? tip "Troubleshooting Tips"

    - When running the ION Bitcoin microservice for the first time, it may fail with an error message similar to the following:
    ```bash
    Sidetree-Bitcoin node initialization failed with error: {"stack":"Error: Unexpected fetch HTTP response: [500]: {\"result\":null,\"error\":{\"code\":-4,\"message\":\"Wallet already loading.\"}...}}
    ```
    This error can usually be overcome by simply re-starting the microservice with same command:
    ```console
    $ (cd $ION_REPO && npm run bitcoin)
    ```

    - If you see an `ECONNREFUSED` error message when starting the ION Bitcoin microservice, this indicates that it has failed to communicate with Bitcoin Core. In this case, make sure that Bitcoin Core started successfully.

In another new Terminal, start the ION Core microservice with:
```console
$ (cd $ION_REPO && npm run core)
```

??? tip "Troubleshooting Tip"

    If you see an `ECONNREFUSED` error message when starting the ION Core microservice, this indicates that it has failed to communicate with the ION Bitcoin microservice. In this case, make sure that the ION Bitcoin microservice started successfully and is fully synchronised.

Finally, to confirm that ION is working properly, open yet another new Terminal and resolve a sample DID:

=== "Mainnet"

    ```console
    $ curl http://localhost:3000/identifiers/did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w | json_pp
    ```

=== "Testnet4"

    ```console
    $ curl http://localhost:3000/identifiers/did:ion:test:EiBt8NTmSKf3jt_FMKf-r6JMSJIp7njcTTPe24USYu4B9w | json_pp
    ```

=== "Testnet3 (Deprecated)"

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

    === "Testnet4"

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
        $ tail -f $BITCOIN_DATA/testnet4/debug.log
        ```

        Reindex the chain (may take >1 hour):
        ```console
        $ bitcoind -reindex-chainstate
        ```

        Check which port bitcoind is listening on (should be 48333 for Testnet4):
        ```console
        $ netstat -tulpn | grep 'bitcoind'
        ```

    === "Testnet3 (Deprecated)"

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

        Check which port bitcoind is listening on (should be 18333 for Testnet3):
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

=== "Testnet4"

    ```console
    $ curl http://localhost:3000/identifiers/did:ion:test:EiBt8NTmSKf3jt_FMKf-r6JMSJIp7njcTTPe24USYu4B9w | json_pp
    ```

=== "Testnet3 (Deprecated)"

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

To fund your wallet, send Bitcoins to the **first address** in this list.

=== "Mainnet"

    !!! tip "Purchase BTC on a Bitcoin exchange"

        If you do not already own any bitcoins, they can be purchased on a [Bitcoin exchange](https://bitcoin.org/en/exchanges). Make sure that you acquire genuine bitcoins, which are identified by the ticker symbol `BTC`. When withdrawing your coins from the exchange, enter the receive address obtained in the preceding step to send them to your ION wallet.

    After sending bitcoins to your wallet, you will need to wait for the transaction to be confirmed by the Bitcoin network. This should take around 10 minutes on average, but may take longer depending on the size of the transaction fee paid. To check the status of your transaction, paste the transaction ID into a Bitcoin blockchain explorer such as [mempool.space](https://mempool.space/).

=== "Testnet4"

    !!! tip "Request tBTC from a Testnet4 faucet"

        Testnet4 bitcoins are identified by the ticker symbol tBTC, to distinguish them from the Mainnet bitcoins which have the symbol BTC.

        Since coins on Bitcoin Testnet4 have no monetary value they can be obtained free of charge from a "faucet", which is an automated service that will dispense a small quantity of tBTC on request.

        Visit a Bitcoin Testnet4 faucet, such as [this one](https://faucet.testnet4.dev/), and enter the recieve address obtained in the preceding step to send them to your ION wallet.

    After sending bitcoins to your wallet, you will need to wait for the transaction to be confirmed by the Bitcoin network. To check the status of your transaction, paste the transaction ID into a Bitcoin Testnet4 explorer such as [mempool.space](https://mempool.space/testnet4).

=== "Testnet3 (Deprecated)"

    !!! tip "Request tBTC from a Testnet3 faucet"

        Testnet3 bitcoins are identified by the ticker symbol tBTC, to distinguish them from the Mainnet bitcoins which have the symbol BTC.

        Since coins on Bitcoin Testnet3 have no monetary value they can be obtained free of charge from a "faucet", which is an automated service that will dispense a small quantity of tBTC on request.

        Visit a Bitcoin Testnet3 faucet, such as [coinfaucet.eu](https://coinfaucet.eu/en/btc-testnet/), and enter the recieve address obtained in the preceding step to send them to your ION wallet.

    After sending bitcoins to your wallet, you will need to wait for the transaction to be confirmed by the Bitcoin network. To check the status of your transaction, paste the transaction ID into a Bitcoin Testnet3 explorer such as [mempool.space](https://mempool.space/testnet).

When the transaction is confirmed, check your wallet balance with:
```console
$ bitcoin-cli getbalances
```
The output should look something like this, with a non-zero balance for the `watchonly` wallet:
```json
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

=== "Testnet4"

    ```bash
    Host ion
        HostName <IP_ADDRESS>
        User <USERNAME>
        IdentityFile ~/.ssh/<KEY_FILE>
        LocalForward 3000 localhost:3000
        LocalForward 5001 localhost:5001
        LocalForward 48332 localhost:48332
        LocalForward 27017 localhost:27017
    ```

=== "Testnet3 (Deprecated)"

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

=== "Testnet4"

    | Port        | Process           |
    | ----------- | ----------------- |
    | 3000        | ION               |
    | 5001        | IPFS              |
    | 48332       | Bitcoin           |
    | 27017       | MongoDB           |

=== "Testnet3 (Deprecated)"

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

To access the required `docker-compose.*` files, enter the ION `docker` directory:
```
cd $ION_REPO/docker
```

Now run the ION container. This command depends on whether you wish to run a Mainnet, Testnet4 or Testnet3 ION node:

=== "Mainnet"

    ```
    docker-compose up -d
    ```

=== "Testnet4"

    To run ION with Docker on Testnet4, the `docker-compose.testnet-override.yml` config file must be modified to set the correct RPC port number for the Bitcoin client:
    === "Linux"
        ```console
        $ sed -i 's|"18332:18332"|"48332:48332"|' $ION_REPO/docker/docker-compose.testnet-override.yml
        ```
    === "macOS"
        ```console
        $ sed -i '' 's|"18332:18332"|"48332:48332"|' $ION_REPO/docker/docker-compose.testnet-override.yml
        ```

    Then run the container with:
    ```
    docker-compose -f docker-compose.yml -f docker-compose.testnet-override.yml up -d
    ```

=== "Testnet3 (Deprecated)"

    ```
    docker-compose -f docker-compose.yml -f docker-compose.testnet-override.yml up -d
    ```

!!! warning "Bitcoin and ION synchronisation"

    When the ION container starts for the first time, it will begin synchronising with the Bitcoin network. This means downloading all of the blocks in the Bitcoin blockchain, which is a large data structure containing every Bitcoion transaction that has ever been processed. Once this has finished, ION itself will then scan the entire blockchain for ION DID operations, which is also a lengthy process.

    **In total, the synchronisation process may take several hours, or even days, to complete.** You will not be able to use Trustchain until your ION node has finished synchronising.

    Fortunately, the synchronisation process on Testnet4 is much quicker, as only ~15GB of data must be downloaded.

<!-- TODO: screenshots! -->

When the synchronisation process has finished, confirm that ION is working properly by running the following command to resolve a sample DID:

=== "Mainnet"

    ```console
    $ curl http://localhost:3000/identifiers/did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w | json_pp
    ```

=== "Testnet4"

    ```console
    $ curl http://localhost:3000/identifiers/did:ion:test:EiBt8NTmSKf3jt_FMKf-r6JMSJIp7njcTTPe24USYu4B9w | json_pp
    ```

=== "Testnet3 (Deprecated)"

    ```console
    $ curl http://localhost:3000/identifiers/did:ion:test:EiClWZ1MnE8PHjH6y4e4nCKgtKnI1DK1foZiP61I86b6pw | json_pp
    ```

If ION is working properly, the command above will return a JSON data structure containing the resolved DID document and document metadata for the sample DID.


&nbsp;

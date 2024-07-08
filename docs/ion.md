# ION

The [Identity Overlay Network](https://identity.foundation/ion/) (ION) is a open source [DID method](https://www.w3.org/TR/did-core/#methods) implementation developed by the Decentralized Identity Foundation. Trustchain delegates the execution of DID operations to a locally-running ION node, which itself contains a client on each of the Bitcoin and IPFS peer-to-peer networks.

Here we assume that ION has been installed (link to Install guide), either locally or on a remote machine to which the user can connect via SSH.

## Mainnet vs. Testnet

The Bitcoin client wrapped inside an ION node can be configured either for **Mainnet** (the main Bitcoin network) or **Testnet** (an alternative blockchain designed for testing and software development).

Mainnet should be used for a production deployment of Trustchain, because DID operations published on the Bitcoin blockchain have extremely strong immutability, persistence and discoverability. When testing Trustchain, however, it is sensible to configure the ION Bitcoin client for Testnet, since coins on the test network have no monetary value and therefore DID operations can be executed at zero cost.

Testnet coins can be requested from a Testnet "faucet", such as [this one](https://bitcoinfaucet.uo1.net/).

In this guide, commands and configuration settings may depend on which network is in use. In those cases, choose the appropriate tab (Mainnet or Testnet) for your setup.

## ION Installation

[ION Install Guide](https://identity.foundation/ion/install-guide/)

### Prerequisites

...set up your environment...

=== "Linux"

    Run:
    ```
    sudo apt update
    ```
    before running the ION step:
    ```
    sudo apt install build-essential
    ```

=== "Mac OS"

    Install [Xcode command line tools](https://developer.apple.com/download/all/)
    ```
    xcode-select --install
    ```
    Install [Homebrew](https://brew.sh/#install)
    ```
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```

### Install Bitcoin Core

DIDs published with ION are anchored into the Bitcoin blockchain, endowing them with an independently-verifiable timestamp. Therefore ION wraps a node on the Bitcoin network...


### Install IPFS

=== "Linux"

    If using sidetree bitcoin install script(https://github.com/decentralized-identity/sidetree/blob/master/lib/bitcoin/setup.sh), pay attention to the following:

    * By default the script writes the `testnet` flag to the `bitcoin.conf` file it generates - for a mainnet install, remove this flag.
    * It's advised to further edit the `bitcoin.conf` file by setting the `datadir` flag with an absolute path to the desired directory. This ensures the bitcoin chain sync data is directed to a disk with enough space (1T is recommended).
    * The `start.sh` file generated by the script is unlikely to work and it is not advised to run it.

    It's advised to set an alias in `~/.bash_profile` for the bitcoin daemon binary with the `-conf` flag set to the path where the `.conf` file is. This ensures that the binary is not accidentally run without the configuration of the `datadir` path.
    * Adjust the path to `bitcoind` and `bitcoin.conf`
    ```
    alias bitcoind='$insert_correct_path$/bin/bitcoind -conf=$insert_correct_path$/bitcoin.conf'
    ```



=== "Mac OS"

    - Install with: `brew install ipfs`
    - Initialise with: `ipfs init`. This produces output similar to:
    ```
    generating ED25519 keypair...done
    peer identity: 12D3KooWHJkC16aSxJ8eNfkiChuKywjW1Mzazht6LPQCpRHjFEz1
    to get started, enter:

        ipfs cat /ipfs/QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc/readme
    ```
    - Run the command given above:
    ```
    ipfs cat /ipfs/QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc/readme`
    ```
    to produce the welcome message:
    ```
    Hello and Welcome to IPFS!
    ...
    If you're seeing this, you have successfully installed
    IPFS and are now interfacing with the ipfs merkledag!
    ```

### Install MongoDB

=== "Linux"

    TODO.


=== "Mac OS"

    - Following [these instructions](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-os-x/):
        ```
        brew tap mongodb/brew
        brew install mongodb-community
        ```
    - Start MongoDB with:
        ```
        brew services start mongodb-community@6.0
        ```

### Configure & Build ION Microservices

... explain...

=== "Linux"

    TODO.

=== "Mac OS"

    - Clone the ION repository:
        ```
        git clone https://github.com/decentralized-identity/ion
        cd ion
        ```
    - Create your configuration files from templates.
        - Copy the ION microservice configuration files (for both the Bitcoin and core microservices) to another directory, (e.g. `~/.ion/`):
            ```
            mkdir ~/.ion
            cp json/testnet-bitcoin-config.json ~/.ion
            cp json/testnet-bitcoin-versioning.json ~/.ion
            cp json/testnet-core-config.json ~/.ion
            cp json/testnet-core-versioning.json ~/.ion/
            ```
    - Update the config parameters for the ION Bitcoin microservice in the config file `testnet-bitcoin-config.json`:
        - `bitcoinPeerUri`
            - Ensure it points to the RPC endpoint of the Bitcoin Core client you setup earlier in this guide
            - For testnet: `http://localhost:18332`
            - For mainnet: `http://localhost:8332`
        - `bitcoinDataDirectory`
            - This is an optional config value. By configuring this value, instead of using rpc call to initialize Bitcoin microservice, the node will read from the block binary files. This is useful in speeding up init time if you have fast access to the files (local SSD is optimal). If the files are stored and retrieved across network, such as on the cloud in AWS S3 Bucket or Azure Blob Storage, then this will be slower than using RPC as it has to download GB worth of files.
            - Leave it blank if you do not wish to init from file. If you want to init from files, it needs to point to the block files folder specified in the `datadir` config parameter in `bitcoin.conf`:
            - testnet: `<datadir>/testnet3`
            - mainnet: `<datadir>` (i.e. exactly the same as the `datadir` value configured for Bitcoin Core in [Set up Bitcoin Core](/installation#Set-up-Bitcoin-Core).)
        - `bitcoinWalletImportString`
            - For testnet: this can be left unchanged for now; a valid testnet example wallet will be generated each time ion-bitcoin fails to load a valid WIF string on startup, so we shall update this parameter later.
            - For mainnet: (must be a mainnet-compatible WIF)
        - `bitcoinRpcUsername`
            - Must match what was set for `rpcuser` in the `bitcoin.conf` file in [Set up Bitcoin Core](/installation#Set-up-Bitcoin-Core).
        - `bitcoinRpcPassword`
            - must match what was set for `rpcpassword` in the `bitcoin.conf` file in [Set up Bitcoin Core](/installation#Set-up-Bitcoin-Core).
    - Update the ION microservice config file `testnet-core-config.json`:
        - `didMethodName`
            - testnet: `ion:test`
            - mainnet: `ion`
    - Build ION
        - From the root of the cloned ION repository:
            ```
            npm i
            npm run build
            ```
        - NOTE: You may need to run `npm install tsc` before running `npm run build` to install TypeScript in Linux/Mac environments.
        - NOTE: You must rerun `npm run build` every time a configuration JSON file is modified.
    - Fix an **upstream bug** in the ION Bitcoin microservice:
        - From the root of the ION repository (cloned in step 5.), open the file `node_modules/@decentralized-identity/sidetree/dist/lib/bitcoin/BitcoinClient.js`
        and comment out the following lines inside the `initializeBitcoinCore` function:
            ```
            // yield this.createWallet();
            // yield this.loadWallet();
            ```
        - Create a Bitcoin wallet with the following RPC call (where `<rpcuser>` is the username given in `bitcoin.conf` in Step 2, and when prompted enter the `rpcpassword` also given in `bitcoin.conf`):
        ```
        curl --user <rpcuser> --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "createwallet", "params": {"wallet_name": "sidetreeDefaultWallet", "descriptors": false}}' -H 'content-type: text/plain;' http://127.0.0.1:18332/
        ```
        **NOTE** the name of the wallet in the previous command **MUST** be `sidetreeDefaultWallet` (as this is hard-coded in Sidetree).
        The output from this command should look like this:
        ```
        {"result":{"name":"sidetreeDefaultWallet","warning":"Wallet created successfully. The legacy wallet type is being deprecated and support for creating and opening legacy wallets will be removed in the future."},"error":null,"id":"curltest"}
        ```

### Run the ION microservices

See section below on Restarting ION.


## Restarting ION

Follow these steps to manually restart your ION node:

!!! tip "Tip: Use tmux"
    A convenient way to start all of the following processes is to use [tmux](https://github.com/tmux/tmux/wiki) (the terminal multiplexer). Open a tmux session with the command `tmux new -s ion` and run each process in its own window. Then detach the tmux session with `Ctrl+b`. To reattach the session later, run `tmux a -t ion`.

1. **Start IPFS.**
    ```bash
    ipfs daemon
    ```

    ??? info "Other IPFS commands"

        Stop:
        ```
        ipfs shutdown
        ```

1. **Start MongoDB.**
    ```
    sudo systemctl start mongod
    ```

    ??? info "Other MongoDB commands"

        Stop:
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

1. **Start Bitcoin Core.** With aliases set up for `bitcoind` and `bitcoin-cli` (see [link](TODO)):
    ```
    bitcoind -daemon
    ```

    ??? info "Other Bitcoin Core commands"

        Check status:
        ```
        bitcoin-cli -getinfo
        ```

        Stop the daemon:
        ```
        bitcoin-cli stop
        ```

        Reindex the chain (may take >1 hour):
        ```
        bitcoind -reindex-chainstate
        ```

        Check which port bitcoind is listening on (should be 8333 for mainnet, or 18333 for testnet):
        ```bash
        netstat -tulpn | grep 'bitcoind'
        ```

1. **Start the ION bitcoin service.**
    From the ION repository root:
    ```bash
    npm run bitcoin
    ```

    ??? tip "Troubleshooting Tips"

        - If you get an `ECONNREFUSED` error, make sure bitcoind has started and is listening on the expected port (see the dropdown info box in Step 3).
        - A [known issue](https://github.com/decentralized-identity/sidetree/pull/1192) with the ION "Sidetree" library may cause the `loadwallet` jRPC call to fail. See the Troubleshooting section (TODO) for a workaround.

1. **Start the ION core service.**
    From the ION repository root:
    ```bash
    npm run core
    ```

1. **Test ION.** To confirm that ION is working properly, resolve a sample DID:

    === "Mainnet"

        ```bash
        curl http://localhost:3000/identifiers/did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w | json_pp
        ```

    === "Testnet"

        ```bash
        curl http://localhost:3000/identifiers/did:ion:test:EiClWZ1MnE8PHjH6y4e4nCKgtKnI1DK1foZiP61I86b6pw | json_pp
        ```

## SSH config

If connecting to your ION node via SSH, we recommend adding the following lines to your SSH configuration file at `~/.ssh/config`:

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

The port forwarding rules in the above configuration assume that the default ports are used for the following processes:

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
```bash
ssh ion
```

As long as this connection is active, data sent to the ports specified in the SSH configuration (above) will be relayed to the same ports on the remote machine, producing a setup equivalent to running ION and its related processes locally.

## ION Usage
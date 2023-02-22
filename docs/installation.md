# Installation guide
## Quick install
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

## ION installation on Mac

These instructions are based on the [ION Install Guide](https://identity.foundation/ion/install-guide/) but contain additional details, several minor corrections and a workaround to support the latest versions of Bitcoin Core.

### Prerequites
- Install [Xcode command line tools](https://developer.apple.com/download/all/)
    ```
     xcode-select --install
    ```
- Install [Homebrew](https://brew.sh/#install)
    ```
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```

### Prepare your local environment
- Install node.js from https://nodejs.org/en/ or with `brew install node`. Instructions call for `v14` but latest is `v19.3.0`.
- Inbound Ports to Open: If you wish to run a node that writes ION DID operations, you will need to enable uPnP on your router or open ports `4002` and `4003` so that the operation data files can be served to others via IPFS.

### Set up Bitcoin Core
- Download the Bitcoin core binary tar archive: https://bitcoincore.org/en/releases/
    - 24.0.1 version for **Apple with Intel processor** is: https://bitcoincore.org/bin/bitcoin-core-24.0.1/bitcoin-24.0.1-x86_64-apple-darwin.tar.gz
    - 24.0.1 version for **Apple M1** is: https://bitcoincore.org/bin/bitcoin-core-24.0.1/bitcoin-24.0.1-arm64-apple-darwin.dmg
- Verify the download by comparing the [published hash](https://bitcoincore.org/bin/bitcoin-core-24.0.1/SHA256SUMS) with the result of this command:
    ```
    shasum -a 256 ~/Downloads/bitcoin-24.0.1-arm64-apple-darwin.dmg
    ```
- Unzip and move to installation folder, e.g. 
    ```
    cd ~/Downloads
    tar -xvzf bitcoin-24.0.1-x86_64-apple-darwin.tar.gz
    mv bitcoin-24.0.1 /Applications
    ```
- Edit the `bitcoin.conf` file (as per the ION instructions), setting: 
    ```
    testnet=1
    server=1
    datadir=/Users/<username>/.bitcoin
    rpcuser=<your-rpc-username>
    rpcpassword=<your-rpc-password>
    txindex=1
    ```
    The `rpcuser` and `rpcpassword` parameters are for the username and password to access the Bitcoin node's JSON RPC interface. This will be used by ION to communicate with the Bitcoin node.
    Note that the path to the `datadir` must not use the `~` shorthand (as it does in the ION guide).
- Create the data directory
    ```
    mkdir /Users/<username>/.bitcoin
    ```
- Run bitcoind (note the flags are given incorrectly in the [ION install guide](https://identity.foundation/ion/install-guide/)):
    ```
    /Applications/bitcoin-24.0.1/bin/bitcoind -conf=/Applications/bitcoin-24.0.1/bitcoin.conf -daemon
    ```
- In case of this pop-up message,

<img src="https://i.imgur.com/oUhtx4t.png" alt="drawing" width="300"/>

go to the `Security & Privacy` settings, and click "Allow Anyway" in the `General` tab:
<img src="https://i.imgur.com/Ojiran4.png" alt="drawing" width="300"/>

Then re-run bitcoind with the command above. This time, when the pop up appears, choose "Open" to allow the program to run.
- You should see the message:
    ```
    Bitcoin Core starting
    ```
- Check the progress of the initial block download:
    ```
    /Applications/bitcoin-24.0.1/bin/bitcoin-cli -conf=/Applications/bitcoin-24.0.1/bitcoin.conf -getinfo
    ```
    Note that the `bitcoin-cli` will also need to be allowed to run via `Security & Privacy` settings, as above.
    This command prints a status summary:
    ```
    Chain: test
    Blocks: 468435
    Headers: 2411764
    Verification progress: ▒▒░░░░░░░░░░░░░░░░░░░ 6.5054%
    Difficulty: 3.620365071432086

    Network: in 0, out 10, total 10
    Version: 240001
    Time offset (s): 0
    Proxies: n/a
    Min tx relay fee rate (BTC/kvB): 0.00001000

    Warnings: (none)
    ```
- Check the Bitcoin JSON RPC interface:
    ```
    curl --user <rpcuser> --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getblockcount", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:18332/
    ```
    where `<rpcuser>` is the value configured in the `bitcoin.conf` file (above). When prompted, enter the `rpcpassword` value from the same config file. 
    ```
    {"result":2411901,"error":null,"id":"curltest"}
    ```
    The node should return a JSON object containing the number of blocks in the blockchain, similar to the above.

### Install Kubo (IPFS)
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


### Set up MongoDB
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

### Run the ION Bitcoin microservice
- Set environment variables
    - Edit the `package.json` file in the root of the clone ION repository. Replace the line:
    ```
        "bitcoin": "node dist/src/bitcoin.js",
    ```
    with this line:
    ```
        "bitcoin": "ION_BITCOIN_CONFIG_FILE_PATH=$HOME/.ion/testnet-bitcoin-config.json ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH=$HOME/.ion/testnet-bitcoin-versioning.json node dist/src/bitcoin.js",
    ```
    **NOTE** that the ION install guide gives incorrect instructions in this step. It has environment variables created in the shell, but they are not passed on to the npm scripts, resulting in the error message:
    ```
    Environment variable ION_BITCOIN_CONFIG_FILE_PATH undefined, using default path ../json/testnet-bitcoin-config.json instead.
    ```
- If `bitcoind` core is not alredy running, start it with the command:
```
/Applications/bitcoin-24.0.1/bin/bitcoind -conf=/Applications/bitcoin-24.0.1/bitcoin.conf -daemon
```
- Run the microservice:
```
npm run bitcoin
```
- Wait while the `getaddressinfo` command is processed. This can take up to an hour because it requires scanning the entire blockchain.

### Run the ION core microservice
- Start IPFS (in a separate shell):
```
ipfs daemon
```
- Start MongoDB:
```
brew services start mongodb-community
```
- Set environment variables
    - Edit the `package.json` file in the root of the clone ION repository. Replace the line:
    ```
        "core": "node dist/src/core.js",
    ```
    with this line:
    ```
        "core": "ION_CORE_CONFIG_FILE_PATH=$HOME/.ion/testnet-core-config.json ION_CORE_VERSIONING_CONFIG_FILE_PATH=$HOME/.ion/testnet-core-versioning.json node dist/src/core.js"
    ```
    Note that the ION install guide gives incorrect instructions in this step. It has environment variables created in the shell, but they are not passed on to the npm scripts, resulting in the error message:
    ```
    Environment variable ION_CORE_CONFIG_FILE_PATH undefined, using default path ../json/testnet-core-config.json instead.
    ```
- Run the microservice:
```
npm run core
```
Note: this will fail unless the ION Bitcoin microservice has started successfully (Step 6).
- Wait while the microservice synchronises its database of ION transactions.

### Verify ION is working properly
Check the following DID resolution in your browser:
    - testnet: http://localhost:3000/identifiers/did:ion:test:EiClWZ1MnE8PHjH6y4e4nCKgtKnI1DK1foZiP61I86b6pw
    - mainnet: http://localhost:3000/identifiers/did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w

If ION is working you will see a resolved DID Document in the browser. 
        
### Shut down the ION node
Before shutting down the computer running ION, you can stop the two microservices by hitting `CTRL+C` in the terminals in which they are running, then stop Bitcoin with the following command:
```
/Applications/bitcoin-24.0.1/bin/bitcoin-cli -conf=/Applications/bitcoin-24.0.1/bitcoin.conf stop
```

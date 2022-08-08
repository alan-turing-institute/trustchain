const ION = require('@decentralized-identity/ion-tools')
const IONSDK = require('@decentralized-identity/ion-sdk');
const jwt_decode = require('jwt-decode');
const fsSync = require('fs')
const fs = require('fs').promises
const fetch = require('cross-fetch');
const { AnchorRequest } = require('@decentralized-identity/ion-tools');

// let did = new ION.DID({ ... });
// let longFormURI = await did.getURI();
// let shortFormURI = await did.getURI('short');

async function main() {
    let did_uri = "did:ion:test:EiClWZ1MnE8PHjH6y4e4nCKgtKnI1DK1foZiP61I86b6pw";
    // ION.generateKeyPair('secp256k1');
    let did = await ION.resolve(did_uri, options = {nodeEndpoint: "http://localhost:3000/identifiers/"});
    console.log(JSON.stringify(did, null, 2));
    // let actual_did = new ION.DID({"content": did});
}
main()
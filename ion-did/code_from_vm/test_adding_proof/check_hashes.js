const ION = require('@decentralized-identity/ion-tools');
const IONSDK = require('@decentralized-identity/ion-sdk');

const fs = require('fs').promises
// const fetch = require('cross-fetch');


// TODO: checking whether we can hash the delta and get the same value as that recorded
// in the request body.
// 1. Expect uneditted to be same. IT IS!
// 2. Expect any edit to diff. IT IS!
// Hope that if edit to diff, and update the deltaHash in the request body, it successfully resolves on ION.

const main = async () => {
    // Load request body from `ion operation create`
    // const requestBody = JSON.parse(await fs.readFile("request-body-EiAvZ_Dl0jHYI3zroklAlnZx9BsPKvipXxJf63ko_gTORQ.json"))
    // const requestBody = JSON.parse(await fs.readFile("request-body-editted-EiAvZ_Dl0jHYI3zroklAlnZx9BsPKvipXxJf63ko_gTORQ.json"))
    // const requestBody = JSON.parse(await fs.readFile("anchorRequestBody_290722.json"))
    const requestBody = JSON.parse(await fs.readFile("anchorRequestBody_edited_290722.json"))
    // console.log(JSON.stringify(requestBody))


    const delta = requestBody.delta
    
    // Get the delta
    console.log(JSON.stringify(delta))

    // ION.SDK.IonSdkConfig.hashAlgorithmInMultihashCode
    // ION.SDK.IonSdkConfig
    // console.log("")
    // Get the hash algo
    const hashAlgorithmInMultihashCode = IONSDK.IonSdkConfig.hashAlgorithmInMultihashCode;
    
    // IONSDK.IonRequest.
    // const hashAlgorithmInMultihashCode = 18;
    // IONSDK
    console.log(ION.SDK.IonSdkConfig.hashAlgorithmInMultihashCode);

    // Hash the delta
    const deltaHash = IONSDK.MultiHash.canonicalizeThenHashThenEncode(delta, hashAlgorithmInMultihashCode);

    console.log(deltaHash);
}

main()
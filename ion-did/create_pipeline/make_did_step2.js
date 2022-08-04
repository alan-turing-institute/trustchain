const ION = require('@decentralized-identity/ion-tools')
const IONSDK = require('@decentralized-identity/ion-sdk');
const fs = require('fs').promises
const fetch = require('cross-fetch');

const main = async () => {
    
    // Step 1: load keys
    const privateKey = JSON.parse(await fs.readFile('privateKey.json'))
    const myData = 'This message is signed and cannot be tampered with'
    const signature = await ION.signJws({
        payload: myData,
        privateJwk: privateKey
    });
    console.log("Signed JWS:", signature)
    

    // Testing
    const randomKeyPair = await ION.generateKeyPair('secp256k1')
    let verifiedJws = await ION.verifyJws({
        jws: signature,
        publicJwk: randomKeyPair.publicJwk
    })
    console.log("Verify with random new key:", verifiedJws)
    
    const publicKey = JSON.parse(await fs.readFile('publicKey.json'))
    verifiedJws = await ION.verifyJws({
        jws: signature,
        publicJwk: publicKey
    })
    console.log("Verify with my public key:", verifiedJws)


    //  Make object to store the keys
    const authnKeys = {
        privateJwk: privateKey,
        publicJwk: publicKey
    };

    // Load DID Request Body
    const didRequestBody = JSON.parse(await fs.readFile('anchorRequestBody_030822.json'))

    //  Hashing the delta. 
    // We have edited the did request body and need to rehash. 
    const delta = didRequestBody.delta

    const hashAlgorithmInMultihashCode = IONSDK.IonSdkConfig.hashAlgorithmInMultihashCode;

    const deltaHash = IONSDK.MultiHash.canonicalizeThenHashThenEncode(delta, hashAlgorithmInMultihashCode);

    console.log(deltaHash);

    // const didUri = await did.getURI('short');

    // Sign new DID
    const signature_did = await ION.signJws({
        payload: deltaHash,
        privateJwk: privateKey
    });
    console.log("Signed JWS:", signature_did)

    // Testing

    let verifiedSignedHash = await ION.verifyJws({
        jws: signature_did,
        publicJwk: publicKey
    })
    console.log("Verify Signed Hash:", verifiedSignedHash)
    

}

main()
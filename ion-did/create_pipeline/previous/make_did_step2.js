const ION = require('@decentralized-identity/ion-tools')
const IONSDK = require('@decentralized-identity/ion-sdk');
const jwt_decode = require('jwt-decode');
const fs = require('fs').promises
const fetch = require('cross-fetch');
const { AnchorRequest } = require('@decentralized-identity/ion-tools');

const main = async () => {
    // Load keys and store in authnKeys for signing of DID
    const privateKey = JSON.parse(await fs.readFile('privateKey.json'));
    const publicKey = JSON.parse(await fs.readFile('publicKey.json'))
    const controlleruDID = "did:ion:test:upstream_DID_that_is_the_controller"

    //  Make object to store the keys
    const authnKeys = {
        privateJwk: privateKey,
        publicJwk: publicKey
    };

    // Load DID Request Body
    const didRequestBody = JSON.parse(await fs.readFile('anchorRequestBody.json'))

    // Add uDID controller to request
    didRequestBody.delta["patches"][0]["document"]["services"][0]["serviceEndpoint"]["signer"] = {"uDID": controlleruDID}

    // Hashing the delta, if unedited should be the same as that generated 
    // const delta = didRequestBody.delta
    // const hashAlgorithmInMultihashCode = IONSDK.IonSdkConfig.hashAlgorithmInMultihashCode;
    // const deltaHash = IONSDK.MultiHash.canonicalizeThenHashThenEncode(delta, hashAlgorithmInMultihashCode);
    // console.log("Recomputed deltaHash:", deltaHash);
    // console.log("Same deltHash as generated request:", deltaHash == didRequestBody.suffixData.deltaHash);

    // Just sign the publicJWK with uDID controller keys for simplicity
    // TODO: consider whether more information than just the keys needs to be signed
    // Of note, the DID is derived from the deltaHash and should be derivable from the
    // resolved DID which includes the signed public key, so this is verfiable and only
    // derivable with the same signed public key
    
    // Get JWK of public key
    const requestJWK = didRequestBody.delta["patches"][0]["document"]["publicKeys"][0]["publicKeyJwk"];
    // Get hash algorithm and hash JWK
    const hashAlgorithmInMultihashCode = IONSDK.IonSdkConfig.hashAlgorithmInMultihashCode;
    const requestJWKHash = IONSDK.MultiHash.canonicalizeThenHashThenEncode(requestJWK, hashAlgorithmInMultihashCode);

    // Sign JWK as JWS
    const signedJWKHash = await ION.signJws({
        payload: requestJWKHash,
        privateJwk: privateKey
    });
    // Print JWS ignature
    console.log("Signed JWS of JWKHash to be anchored:", signedJWKHash)

    // Optional: Verify signature
    let verifiedSignedHash = await ION.verifyJws({
        jws: signedJWKHash,
        publicJwk: publicKey
    })
    console.log("Verify Signed Hash:", verifiedSignedHash)
    
    // Decode JWT to confirm hash is same
    var decodedJWKHash = jwt_decode(signedJWKHash);
    console.log("Decoded signed payload:", decodedJWKHash);
    console.log("Decoded same as signed:", decodedJWKHash == requestJWKHash);

    // Add the signed hash of the JWK to the request
    didRequestBody.delta["patches"][0]["document"]["services"][0]["serviceEndpoint"]["signer"]["proof"] = signedJWKHash;

    // Recompute and replace the deltaHash
    const newDeltaHash = IONSDK.MultiHash.canonicalizeThenHashThenEncode(didRequestBody.delta, hashAlgorithmInMultihashCode);
    didRequestBody["suffixData"]["deltaHash"] = newDeltaHash;

    // Print final request body
    console.log(JSON.stringify(didRequestBody, null, 2))

    // Write request body
    await fs.writeFile(
       'anchorRequestBody_with_proof.json', 
        JSON.stringify(didRequestBody)
    )
}

main()
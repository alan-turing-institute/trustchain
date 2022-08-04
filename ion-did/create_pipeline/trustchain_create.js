const ION = require('@decentralized-identity/ion-tools')
const IONSDK = require('@decentralized-identity/ion-sdk');
const jwt_decode = require('jwt-decode');
const fs = require('fs').promises
const fetch = require('cross-fetch');
const { AnchorRequest } = require('@decentralized-identity/ion-tools');


async function generateDID(new_keys=false, verbose=true) {
    // Make variable for storing keys
    var authnKeys;

    if(new_keys) {
        // Create private/public key pair
        authnKeys = await ION.generateKeyPair('secp256k1')
        console.log("Created private/public key pair")
        console.log("Public key:", authnKeys.publicJwk)
        // Write private and public key to files
        await fs.writeFile(
            'publicKey.json', 
            JSON.stringify(authnKeys.publicJwk)
        )
        await fs.writeFile(
            'privateKey.json', 
            JSON.stringify(authnKeys.privateJwk)
        )
        console.log("Wrote public key to publicKey.json")
        console.log("Wrote private key to privateKey.json")
    }
    else {
        // Load keys and store in authnKeys for signing of DID
        const privateKey = JSON.parse(await fs.readFile('privateKey.json'));
        const publicKey = JSON.parse(await fs.readFile('publicKey.json'))
        //  Make object to store the keys
        authnKeys = {
            privateJwk: privateKey,
            publicJwk: publicKey
        };
    }

    // Create a DID
    const did = new ION.DID({
        content: {
        // Register the public key for authentication
        publicKeys: [
            {
                id: 'auth-key',
                type: 'EcdsaSecp256k1VerificationKey2019',
                publicKeyJwk: authnKeys.publicJwk,
                purposes: ['authentication']
            }
        ],
        // Register an IdentityHub as a service
        services: [
            {
            id: "IdentityHub",
            type: "IdentityHub",
            serviceEndpoint: {
                "@context": "schema.identity.foundation/hub",
                "@type": "UserServiceEndpoint",
                instance: [
                    "did:test:hub.id",
                ]
            }
            }
        ]
        }
    })
    
    // Print initial DID document
    console.log(did.content)

    // Print initial DID. Note this changes when the delta changes
    const didUri = await did.getURI('short');
    const didUriLong = await did.getURI('short');
    console.log("Generated initial short DID:", didUri)
    console.log("Generated initial long DID:", didUriLong)

    // Generate request body from did
    const anchorRequestBody = await did.generateRequest()
    if(verbose) {
        console.log(anchorRequestBody)
    }
    const anchorRequest = new ION.AnchorRequest(anchorRequestBody)
    if(verbose) {
        console.log(anchorRequest)
    }
    return did, anchorRequestBody
}


async function attachProof(
    didRequestBody,
    privateKeyFile='privateKey.json',
    publicKeyFile="publicKey.json",
    uDID="did:ion:test:upstream_DID_that_is_the_controller",
    verbose=true
) {
    
    // Load keys and store in authnKeys for signing of DID
    const privateKey = JSON.parse(await fs.readFile(privateKeyFile));
    const publicKey = JSON.parse(await fs.readFile(publicKeyFile))
    const controlleruDID = uDID

    // Add uDID controller to request
    console.log(JSON.stringify(didRequestBody, null, 2));
    didRequestBody.delta["patches"][0]["document"]["services"][0]["serviceEndpoint"]["signer"] = {"uDID": controlleruDID}

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

    if(verbose) {
        // Print JWS ignature
        console.log("Signed JWS of JWKHash to be anchored:", signedJWKHash)
    }
    
    // Optional: Verify signature
    let verifiedSignedHash = await ION.verifyJws({
        jws: signedJWKHash,
        publicJwk: publicKey
    })

    if(verbose) {
        console.log("Verify Signed Hash:", verifiedSignedHash)
    }
    
    // Decode JWT to confirm hash is same
    var decodedJWKHash = jwt_decode(signedJWKHash);
    if(verbose) {
        console.log("Decoded signed payload:", decodedJWKHash);
        console.log("Decoded same as signed:", decodedJWKHash == requestJWKHash);
    }

    // Add the signed hash of the JWK to the request
    didRequestBody.delta["patches"][0]["document"]["services"][0]["serviceEndpoint"]["signer"]["proof"] = signedJWKHash;

    // Recompute and replace the deltaHash
    const newDeltaHash = IONSDK.MultiHash.canonicalizeThenHashThenEncode(didRequestBody.delta, hashAlgorithmInMultihashCode);
    didRequestBody["suffixData"]["deltaHash"] = newDeltaHash;

    if(verbose) {
        // Print final request body
        console.log(JSON.stringify(didRequestBody, null, 2));
    }

    return didRequestBody
}

// Main
async function main() {
    // Generate intial request body
    const anchorRequestBody = await generateDID(new_keys=true);
    
    // Sign request body and update deltaHash
    const anchorRequestBodyWithProof = await attachProof(
        anchorRequestBody,
        privateKeyFile='privateKey.json',
        publicKeyFile="publicKey.json",
        uDID="did:ion:test:upstream_DID_that_is_the_controller",
        verbose=true
    );

    // TODO: compute the DID given the update to the content
    // Get the DID from the request
    // const longDID = IONSDK.IonDid.createLongFormDid({
        // recoveryKey: create.recovery.publicJwk,
        // updateKey: create.update.publicJwk,
        // document: create.content
    // });
    // console.log(longDID);

    // Write request body
    await fs.writeFile(
        'anchorRequestBodyWithProof.json', 
         JSON.stringify(anchorRequestBodyWithProof)
     )
}

main()

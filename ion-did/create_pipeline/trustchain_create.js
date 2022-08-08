const ION = require('@decentralized-identity/ion-tools')
const IONSDK = require('@decentralized-identity/ion-sdk');
const jwt_decode = require('jwt-decode');
const fsSync = require('fs')
const fs = require('fs').promises
const fetch = require('cross-fetch');
const { AnchorRequest } = require('@decentralized-identity/ion-tools');

async function main() {
    var authnKeys;
    load = true;
    if(load == false) {
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
        console.log("Load keys...")
        const privateKey = JSON.parse(await fs.readFile('privateKey.json'));
        const publicKey = JSON.parse(await fs.readFile('publicKey.json'));
        const controlleruDID = "did:ion:test:upstream_DID_that_is_the_controller";
    

        //  Make object to store the keys
        authnKeys = {
            privateJwk: privateKey,
            publicJwk: publicKey
        };
    }

    const controlleruDID = "did:ion:test:upstream_DID_that_is_the_controller";

    // Just sign the publicJWK with uDID controller keys for simplicity
    // TODO: consider whether more information than just the keys needs to be signed
    // Of note, the DID is derived from the deltaHash and should be derivable from the
    // resolved DID which includes the signed public key, so this is verfiable and only
    // derivable with the same signed public key

    // Get JWK of public key
    const requestJWK = authnKeys.publicJwk;

    // Get hash algorithm and hash JWK
    const hashAlgorithmInMultihashCode = IONSDK.IonSdkConfig.hashAlgorithmInMultihashCode;
    const requestJWKHash = IONSDK.MultiHash.canonicalizeThenHashThenEncode(requestJWK, hashAlgorithmInMultihashCode);

    
    // Sign JWK as JWS
    const signedJWKHash = await ION.signJws({
        payload: requestJWKHash,
        privateJwk: authnKeys.privateJwk
    });
    
    // Optional: Verify signature
    let verifiedSignedHash = await ION.verifyJws({
        jws: signedJWKHash,
        publicJwk: authnKeys.publicJwk
    })

    console.log("Verify Signed Hash:", verifiedSignedHash);

    // Decode JWT to confirm hash is same
    var decodedJWKHash = jwt_decode(signedJWKHash);
    console.log("Decoded signed payload:", decodedJWKHash);
    console.log("Decoded same as signed:", decodedJWKHash == requestJWKHash);


    content =  {
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
                ],
                signer: {
                    "uDID": controlleruDID,
                    "proof": signedJWKHash
                }
            }
            }
        ]
    }

    // Generate blank new did
    const did = new ION.DID();

    // Perform create operation from content object
    let createOperation = await did.generateOperation("create", content);

    // Log createOperation
    console.log(JSON.stringify(createOperation, null, 2));
    
    // Get DID
    const didUri = await did.getURI('short');
    const didUriLong = await did.getURI('short');
    console.log("Generated initial short DID:", didUri)
    console.log("Generated initial long DID:", didUriLong)

    console.log(JSON.stringify(did.content, null, 2))

    // Get timstamp path
    let dt = new Date().toISOString().split('.')[0].replace(/[^\d]/gi,'');
    dt = dt.substring(2, 8) + "-" + dt.substring(8)
    let dir = "./" + dt;
    let mostRecent = "./most_recent"
    
    //  Make path if doesn't exist
    if (!fsSync.existsSync(dir)){
        fsSync.mkdirSync(dir);
    }
    if (!fsSync.existsSync(mostRecent)){
        fsSync.mkdirSync(mostRecent);
    }

    // Write signing key
    await fs.writeFile(
        dir + '/signingKey.json',
        JSON.stringify(authnKeys)
    );
    await fs.writeFile(
        mostRecent + '/signingKey.json',
        JSON.stringify(authnKeys)
    );

    // Write update key
    await fs.writeFile(
        dir + '/updateKey.json',
        JSON.stringify(createOperation.update)
    );
    await fs.writeFile(
        mostRecent + '/updateKey.json',
        JSON.stringify(createOperation.update)
    );

    // Write recovery key
    await fs.writeFile(
        dir + '/recoveryKey.json', 
        JSON.stringify(createOperation.recovery)
    );
    await fs.writeFile(
        mostRecent + '/recoveryKey.json', 
        JSON.stringify(createOperation.recovery)
    );

    // Make request body
    const anchorRequestBody = await did.generateRequest(createOperation);
    console.log(anchorRequestBody);

    // Write request body
    await fs.writeFile(
        dir + '/createRequest.json', 
         JSON.stringify(anchorRequestBody)
    );
    await fs.writeFile(
        mostRecent + '/createRequest.json', 
         JSON.stringify(anchorRequestBody)
    );
}

main()

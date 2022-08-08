const ION = require('@decentralized-identity/ion-tools')
const IONSDK = require('@decentralized-identity/ion-sdk');
const jwt_decode = require('jwt-decode');
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
                ],
                signer: {
                    "uDID": controlleruDID,
                    "proof": signedJWKHash
                }
            }
            }
        ]
        }
    })


    // Print initial DID. Note this changes when the delta changes
    const didUri = await did.getURI('short');
    const didUriLong = await did.getURI('short');
    console.log("Generated initial short DID:", didUri)
    console.log("Generated initial long DID:", didUriLong)

    // Generate request body from did
    const anchorRequestBody = await did.generateRequest();
    console.log(anchorRequestBody);

    // Write request body
    await fs.writeFile(
        'anchorRequestBodyWithProofStreamline.json', 
         JSON.stringify(anchorRequestBody)
    );
}

main()

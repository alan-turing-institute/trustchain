const ION = require('@decentralized-identity/ion-tools')
const fs = require('fs').promises
const fetch = require('cross-fetch');

const main = async () => {
    
    // Create private/public key pair
    // const authnKeys = await ION.generateKeyPair('secp256k1')
    // console.log("Created private/public key pair")
    // console.log("Public key:", authnKeys.publicJwk)
    // Write private and public key to files
    // await fs.writeFile(
    // 'publicKey.json', 
    // JSON.stringify(authnKeys.publicJwk)
    // )
    // await fs.writeFile(
    // 'privateKey.json', 
    // JSON.stringify(authnKeys.privateJwk)
    // )


    console.log("Wrote public key to publicKey.json")
    console.log("Wrote private key to privateKey.json")
    

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
    // Create a DID
    const did = new ION.DID({
        content: {
        // Register the public key for authentication
        publicKeys: [
            {
            id: 'auth-key',
            type: 'EcdsaSecp256k1VerificationKey2019',
            publicKeyJwk: authnKeys.publicJwk,
            purposes: [ 'authentication' ]
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
    const didUri = await did.getURI('short');

    // Sign new DID
    const signature_did = await ION.signJws({
        // payload: JSON.stringify(did),
        payload: "EiBNuGcRTQxSQROX3u-zO7tEqodBnrV0kM0OsypMt_U40g",
        privateJwk: privateKey
    });
    console.log("Signed JWS:", signature_did)


    // console.log("Generated DID:", didUri)
    // End Step 6

    // Step 7
    // const anchorRequestBody = await did.generateRequest()
    // console.log(anchorRequestBody)
    // console.log("****")
    // const anchorRequest = new ION.AnchorRequest(anchorRequestBody)
    // console.log(anchorRequest)
    // console.log("****")
    // const anchorRequest = new ION.AnchorRequest(anchorRequestBody,
    //     options = {challengeEndpoint: "http://localhost:3000/proof-of-work-challenge",
    //                solutionEndpoint: "http://localhost:3000/operations"})

    // const anchorResponse = await anchorRequest.submit()
    // const response = await fetch("http://localhost:3000/operations", {
    //     method: 'POST',
    //     mode: 'cors',
    //     body: anchorRequestBody.body,
    //     headers: {
    //         'Content-Type': 'application/json'
    //     }
    // });

    // await fs.writeFile(
    //     'anchorRequestBody_290722.json', 
    //     JSON.stringify(anchorRequestBody)
    // )



    // console.log(JSON.stringify(anchorResponse))
    // End of Step 7
}

main()
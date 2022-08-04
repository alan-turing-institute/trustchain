const ION = require('@decentralized-identity/ion-tools')
const fs = require('fs').promises
const fetch = require('cross-fetch');

const main = async () => {
    
    // Create private/public key pair
    const authnKeys = await ION.generateKeyPair('secp256k1')
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
    console.log(anchorRequestBody)
    console.log("****")
    const anchorRequest = new ION.AnchorRequest(anchorRequestBody)
    console.log(anchorRequest)
    console.log("****")

    // Write request body
    await fs.writeFile(
        'anchorRequestBody.json', 
        JSON.stringify(anchorRequestBody)
    )

}

main()
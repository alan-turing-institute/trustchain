#![allow(dead_code)]

// Note on test fixtures:
//
// This file contains samples of content from the three ION file types written to IPFS:
// 1. coreIndexFile
// 2. provisionalIndexFile
// 3. chunkFile
//
// The samples contain content associated with the following DIDs:
// ROOT DID:    did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg
// ROOT+1 DID:  did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A
// ROOT+2 DID:  did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q
//
// The OP_RETURN data for the create operation is:
// ion:3.QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97
//
// The Bitcoin transaction containing this OP_RETURN data has TxID:
// 9dc43cca950d923442445340c2e30bc57761a62ef3eaf2417ec5c75784ea9c2c
// and is the transaction with index 3 in testnet block 2377445 with hash:
// 000000000000000eaa9e43748768cd8bf34f43aaa03abd9036c463010a0c6e7f
// The transaction Merkle root for that block is:
// 7dce795209d4b5051da3f5f5293ac97c2ec677687098062044654111529cad69
//
// The IPFS CID (for the coreIndexFile) is:
// QmRvgZm4J3JSxfk4wRjE2u2Hi2U7VmobYnpqhqH5QP6J97
//
// The DID Document and Document Metadata are test fixtures in trustchain-core
// named TEST_ROOT_DOCUMENT and TEST_ROOT_DOCUMENT_METADATA. They are as follows:
// Document:
// {
//   "@context": [
//     "https://www.w3.org/ns/did/v1",
//     {
//       "@base": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
//     }
//   ],
//   "id": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
//   "verificationMethod": [
//     {
//       "id": "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es",
//       "type": "JsonWebSignature2020",
//       "controller": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
//       "publicKeyJwk": {
//         "kty": "EC",
//         "crv": "secp256k1",
//         "x": "7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso",
//         "y": "kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"
//       }
//     }
//   ],
//   "authentication": [
//     "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
//   ],
//   "assertionMethod": [
//     "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
//   ],
//   "keyAgreement": [
//     "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
//   ],
//   "capabilityInvocation": [
//     "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
//   ],
//   "capabilityDelegation": [
//     "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
//   ],
//   "service": [
//     {
//       "id": "#TrustchainID",
//       "type": "Identity",
//       "serviceEndpoint": "https://identity.foundation/ion/trustchain-root"
//     }
//   ]
// }
// ---
// Document metadata:
// {
//   "method": {
//     "recoveryCommitment": "EiCymv17OGBAs7eLmm4BIXDCQBVhdOUAX5QdpIrN4SDE5w",
//     "published": true,
//     "updateCommitment": "EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg"
//   },
//   "canonicalId": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
// }

// Sample ION coreIndexFile content (see https://identity.foundation/sidetree/spec/#core-index-file).
pub const TEST_CORE_INDEX_FILE_CONTENT: &'static str = r#"{"provisionalIndexFileUri":"QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs","operations":{"create":[{"suffixData":{"deltaHash":"EiBkAX9y-Ts_siMzTzkfAzPKPIIbB033PlF0RlvF97ydJg","recoveryCommitment":"EiCymv17OGBAs7eLmm4BIXDCQBVhdOUAX5QdpIrN4SDE5w"}},{"suffixData":{"deltaHash":"EiBBkv0j587BDSTjJtIv2DJFOOHk662n9Uoh1vtBaY3JKA","recoveryCommitment":"EiClOaWycGv1m-QejUjB0L18G6DVFVeTQCZCuTRrmzCBQg"}},{"suffixData":{"deltaHash":"EiDTaFAO_ae63J4LMApAM-9VAo8ng58TTp2K-2r1nek6lQ","recoveryCommitment":"EiCy4pW16uB7H-ijA6V6jO6ddWfGCwqNcDSJpdv_USzoRA"}}]}}"#;

// Sample ION coreIndexFile content (see https://identity.foundation/sidetree/spec/#provisional-index-file).
pub const TEST_PROVISIONAL_INDEX_FILE_CONTENT: &'static str =
    r#"{"chunks":[{"chunkFileUri":"QmWeK5PbKASyNjEYKJ629n6xuwmarZTY6prd19ANpt6qyN"}]}"#;

// Sample ION chunk file content (see https://identity.foundation/sidetree/spec/#chunk-files).
pub const TEST_CHUNK_FILE_CONTENT: &'static str = r#"{"deltas":[{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso","y":"kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root"}]}}],"updateCommitment":"EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg"},{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU","y":"dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-1"}]}}],"updateCommitment":"EiC0EdwzQcqMYNX_3aqoZNUau4AKOL3gXQ5Pz3ATi1q_iA"},{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"0nnR-pz2EZGfb7E1qfuHhnDR824HhBioxz4E-EBMnM4","y":"rWqDVJ3h16RT1N-Us7H7xRxvbC0UlMMQQgxmXOXd4bY"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-2"}]}}],"updateCommitment":"EiBDfsKvBaSAYO8Hp77eP9NHOpUWRMhcUNMJNHTDWQNw2w"}]}"#;

// OTHER TEST FIXTURES:

// Sample ION chunk file content with multiple keys.
pub const TEST_CHUNK_FILE_CONTENT_MULTIPLE_KEYS: &'static str = r#"{"deltas":[{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso","y":"kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root"}]}}],"updateCommitment":"EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg"},{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU","y":"dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]},{"id":"ljqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMR","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU","y":"dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-1"}]}}],"updateCommitment":"EiC0EdwzQcqMYNX_3aqoZNUau4AKOL3gXQ5Pz3ATi1q_iA"},{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"0nnR-pz2EZGfb7E1qfuHhnDR824HhBioxz4E-EBMnM4","y":"rWqDVJ3h16RT1N-Us7H7xRxvbC0UlMMQQgxmXOXd4bY"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-2"}]}}],"updateCommitment":"EiBDfsKvBaSAYO8Hp77eP9NHOpUWRMhcUNMJNHTDWQNw2w"}]}"#;

// Sample ION chunk file content with multiple services.
pub const TEST_CHUNK_FILE_CONTENT_MULTIPLE_SERVICES: &'static str = r#"{"deltas":[{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso","y":"kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root"}]}}],"updateCommitment":"EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg"},{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU","y":"dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-1"},{"id":"TrustchainIDa","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-1a"}]}}],"updateCommitment":"EiC0EdwzQcqMYNX_3aqoZNUau4AKOL3gXQ5Pz3ATi1q_iA"},{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"0nnR-pz2EZGfb7E1qfuHhnDR824HhBioxz4E-EBMnM4","y":"rWqDVJ3h16RT1N-Us7H7xRxvbC0UlMMQQgxmXOXd4bY"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-2"}]}}],"updateCommitment":"EiBDfsKvBaSAYO8Hp77eP9NHOpUWRMhcUNMJNHTDWQNw2w"}]}"#;

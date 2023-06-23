//! Test fixtures for crate.
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

/// Sample ION [Core Index File](https://identity.foundation/sidetree/spec/#core-index-file) content.
pub(crate) const TEST_CORE_INDEX_FILE_CONTENT: &str = r#"{"provisionalIndexFileUri":"QmfXAa2MsHspcTSyru4o1bjPQELLi62sr2pAKizFstaxSs","operations":{"create":[{"suffixData":{"deltaHash":"EiBkAX9y-Ts_siMzTzkfAzPKPIIbB033PlF0RlvF97ydJg","recoveryCommitment":"EiCymv17OGBAs7eLmm4BIXDCQBVhdOUAX5QdpIrN4SDE5w"}},{"suffixData":{"deltaHash":"EiBBkv0j587BDSTjJtIv2DJFOOHk662n9Uoh1vtBaY3JKA","recoveryCommitment":"EiClOaWycGv1m-QejUjB0L18G6DVFVeTQCZCuTRrmzCBQg"}},{"suffixData":{"deltaHash":"EiDTaFAO_ae63J4LMApAM-9VAo8ng58TTp2K-2r1nek6lQ","recoveryCommitment":"EiCy4pW16uB7H-ijA6V6jO6ddWfGCwqNcDSJpdv_USzoRA"}}]}}"#;

/// Sample ION [Provisional Index File](https://identity.foundation/sidetree/spec/#provisional-index-file) content.
pub(crate) const TEST_PROVISIONAL_INDEX_FILE_CONTENT: &str =
    r#"{"chunks":[{"chunkFileUri":"QmWeK5PbKASyNjEYKJ629n6xuwmarZTY6prd19ANpt6qyN"}]}"#;

/// Sample ION [Chunk File](https://identity.foundation/sidetree/spec/#chunk-files) content.
pub(crate) const TEST_CHUNK_FILE_CONTENT: &str = r#"{"deltas":[{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso","y":"kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root"}]}}],"updateCommitment":"EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg"},{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU","y":"dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-1"}]}}],"updateCommitment":"EiC0EdwzQcqMYNX_3aqoZNUau4AKOL3gXQ5Pz3ATi1q_iA"},{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"0nnR-pz2EZGfb7E1qfuHhnDR824HhBioxz4E-EBMnM4","y":"rWqDVJ3h16RT1N-Us7H7xRxvbC0UlMMQQgxmXOXd4bY"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-2"}]}}],"updateCommitment":"EiBDfsKvBaSAYO8Hp77eP9NHOpUWRMhcUNMJNHTDWQNw2w"}]}"#;

// OTHER TEST FIXTURES:

// Sample ION chunk file content with multiple keys.
pub(crate) const TEST_CHUNK_FILE_CONTENT_MULTIPLE_KEYS: &str = r#"{"deltas":[{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso","y":"kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root"}]}}],"updateCommitment":"EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg"},{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU","y":"dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]},{"id":"ljqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMR","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU","y":"dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-1"}]}}],"updateCommitment":"EiC0EdwzQcqMYNX_3aqoZNUau4AKOL3gXQ5Pz3ATi1q_iA"},{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"0nnR-pz2EZGfb7E1qfuHhnDR824HhBioxz4E-EBMnM4","y":"rWqDVJ3h16RT1N-Us7H7xRxvbC0UlMMQQgxmXOXd4bY"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-2"}]}}],"updateCommitment":"EiBDfsKvBaSAYO8Hp77eP9NHOpUWRMhcUNMJNHTDWQNw2w"}]}"#;

// Sample ION chunk file content with multiple services.
pub(crate) const TEST_CHUNK_FILE_CONTENT_MULTIPLE_SERVICES: &str = r#"{"deltas":[{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso","y":"kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root"}]}}],"updateCommitment":"EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg"},{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU","y":"dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-1"},{"id":"TrustchainIDa","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-1a"}]}}],"updateCommitment":"EiC0EdwzQcqMYNX_3aqoZNUau4AKOL3gXQ5Pz3ATi1q_iA"},{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI","type":"JsonWebSignature2020","publicKeyJwk":{"crv":"secp256k1","kty":"EC","x":"0nnR-pz2EZGfb7E1qfuHhnDR824HhBioxz4E-EBMnM4","y":"rWqDVJ3h16RT1N-Us7H7xRxvbC0UlMMQQgxmXOXd4bY"},"purposes":["assertionMethod","authentication","keyAgreement","capabilityInvocation","capabilityDelegation"]}],"services":[{"id":"TrustchainID","type":"Identity","serviceEndpoint":"https://identity.foundation/ion/trustchain-root-plus-2"}]}}],"updateCommitment":"EiBDfsKvBaSAYO8Hp77eP9NHOpUWRMhcUNMJNHTDWQNw2w"}]}"#;

pub(crate) const TEST_CORE_INDEX_FILE_HEX: &str = "1f8b08000000000000038590dd8ea2300046dfa5d743228845bd6b4114c441e44777371bd381a2e5b7db222318df7ddd7d8099eb2f39e7e47b002eda9e49d636a4729a8cde6d56d15830b004419d9f10d1767223791a8583b8e9adfa51ec8395e731a849a171b465a32d3b720f2578032da782742f9404cb074805251d05cb5f0f206f79ceee16e9c8bf21a3554736445e5f8e15c3253a2d06259267c976633496391af7dbbde37ce0c974baafecc9a1eaed853164eee5e510346d7b2a06b3ad6bd6d5b4e9fe53cca1ee55c35f63240dead5b58e9d93650638b9667e8c4eb320e38e78d7436b35fb04cfe7db374db8ec27c56c6e602b8c0ab7737acd726ddfdf94106acd226eaf6adf61f263ea6ed1174d954f8e43baeed55a0968111778e2a9f335b4123ba15160fe346fd141d4a38983cbf74d56446ce49f09855357f77688a39db248503b6f2eb37914716dab68426d6809abe0ab9f747e54e10d1b1b85150826b0f061961df3b5f9f9e73db5429767fd390ec7f6805e4dbf9fcfbf8ea7c07522020000";
pub(crate) const TEST_PROVISIONAL_INDEX_FILE_HEX: &str = "1f8b0800000000000003ab564ace28cdcb2e56b28aae8630dd327352438b3295ac940273c353bd4d0392bc1d832bfdb25c23bdbdcc8c2cf3cc2a4acb73138ba24222cd0a8a520c2d1dfd0a4acc0a2bfd946a636b015039962d4e000000";
pub(crate) const TEST_CHUNK_FILE_HEX: &str = "1f8b0800000000000003e5934f73a24c10c6bf0be7f046c508e626328a124010d4b895b2069800f267066640612bdf7dc724957d4f7bd9dcf630555dcdd3ddc3d3bff929442867900a8f3f7e0a04b230411f310c598a4be151a811c96188843b21c26153a092098f5cda04791a1aa8fb50a711574ee7a6e74a51bb6c2fc5c4b03b780060651b0ab03d8632b194d5dd74bb53eb11a0bc1beb08e2456b8acb3d0ab6695c42d6d46834180df8d7affeeb4b769b17d62d17531492d1c3241b7245c63a9e01731e5e7920bbc8d1f58e2eaf41d718c0292871ecf3938c1dbfd2bc3cf2f4269cee24b1a39857dc4ab37d5b6ce5a3dd6a7eb25068670f948dda030232493d9a4d93652d58dbc6f65c01e1ed76a39a60faee8e002945f5cd1f13b10447bc216c58c2ad4943f86e1bbf1eea66718dd0bb61774208090cd23c65ddaa6cf197ea775a43398a3fd22f6f2f77fc57eb360dd1ffecf5ea86f2fdc0b45c69bffd5b45b7b1dc8baf12504604a7b735090963843ededfa79fa2ff5e715346ef53ee6f877db5146b8c99f0f6f2769bdd10ae41735c1429fb58b800526de702af3d6ad374eb97b811757fd63f3c17d9692131d2f5b1bc580ecf91bb148f6eccfdfa6b9ab27355d7d2dccb8abc5f1f7778c03772b5a8d2d6c6830d6876b243acdae32d329defa709ce8881838dade8cac56e45bcf41443b2a0a8e4a23a9c01a9518ff57ee94d166bff93a6881250e56cc672cf58cbe1cedd9c62d3ccca4edb54fe455ceb39b96c47c5a24906ff084d22c91b2a0eff08d57c00a24bef8495f96c1d4e12acf0d1f261339e19f693141f9c874d2fcdbc74589dd2d977408536dd8142ab874ad0ec27b1758078791cc84fa6778d9fe653430e03b83aafd2de5b7d3f5483b27445d28fc071f91ac86058bd367a526aae321aeb899ae26b3f062250cdd21c7f4255ef2b6db79692e1c4f58696e8535997afeeb50de6033f374dc789afc5c13e44e3e0f99f826af447a854ed951aad0ab7b367fe80892ca3cdd4d26de2ef5d33097dcb5c5bbaa7ed1deb32badc1afd02caca123d04070000";
pub(crate) const TEST_TRANSACTION_HEX: &str = "020000000171dd04bd101ae70230e01c5d39078cc395a12d756ee6cd673d34b8fe7df35359010000006a473044022021cc3feacddcdda52b0f8313d6e753c3fcd9f6aafb53e52f4e3aae5c5bdef3ba02204774e9ae6f36e9c58a635d64af99a5c2a665cb1ad992a983d0e6f7feab0c0502012103d28a65a6d49287eaf550380b3e9f71cf711069664b2c20826d77f19a0c035507ffffffff020000000000000000366a34696f6e3a332e516d5276675a6d344a334a5378666b3477526a453275324869325537566d6f62596e7071687148355150364a39376d4cee00000000001976a914c7f6630ac4f5e2a92654163bce280931631418dd88ac00000000";
pub(crate) const TEST_MERKLE_BLOCK_HEX: &str = "00e0e42c325b885a35b8655986db88288f0264d4f67f5cc90e6d0d11270000000000000069ad9c5211416544200698706877c62e7cc93a29f5f5a31d05b5d4095279ce7d3d315163c0ff3f1971ea2df61d0000000603d3ca69a3614acb45a14966c812cd9ee034c705f20fac3daf8f796c99f4d805a5fd8e761ae2eb9e0b0e4d62d19599586fb98e8a7be6fc7113441e556fb31ff82c9cea8457c7c57e41f2eaf32ea66177c50be3c24053444234920d95ca3cc49d00a31f6e6d1864017f9cf9d48b51274871c4700e7091dfef14af9c92c5340215b7d88cc8202188e3837b171dba14ffede8f145b2c87c1dbc3642669930517958fb75429c45acaa51c416b283604d515f80f95ddb4f610e8ddb7876985713877602af00";
pub(crate) const TEST_BLOCK_HEADER_HEX: &str =
"00e0e42c325b885a35b8655986db88288f0264d4f67f5cc90e6d0d11270000000000000069ad9c5211416544200698706877c62e7cc93a29f5f5a31d05b5d4095279ce7d3d315163c0ff3f1971ea2df6";

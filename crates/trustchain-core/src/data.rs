//! Test fixtures for crate.
#![allow(dead_code)]
pub(crate) const TEST_SIDETREE_DOCUMENT: &str = r##"
{
   "@context" : [
      "https://www.w3.org/ns/did/v1",
      {
         "@base" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
      }
   ],
   "assertionMethod" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "authentication" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "capabilityDelegation" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "capabilityInvocation" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "id" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
   "keyAgreement" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "service" : [
      {
         "id" : "#trustchain-controller-proof",
         "type" : "TrustchainProofService",
         "serviceEndpoint" : {
            "proofValue" : "eyJhbGciOiJFUzI1NksifQ.IkVpQmNiTkRRcjZZNHNzZGc5QXo4eC1qNy1yS1FuNWk5T2Q2S3BjZ2c0RU1KOXci.Nii8p38DtzyurmPHO9sV2JLSH7-Pv-dCKQ0Y-H34rplwhhwca2nSra4ZofcUsHCG6u1oKJ0x4AmMUD2_3UIhRA",
            "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
         }
      }
   ],
   "verificationMethod" : [
      {
         "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
         "id" : "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84",
         "publicKeyJwk" : {
            "crv" : "secp256k1",
            "kty" : "EC",
            "x" : "RbIj1Y4jeqkn0cizEfxHZidD-GQouFmAtE6YCpxFjpg",
            "y" : "ZcbgNp3hrfp3cujZFKqgFS0uFGOn2Rk16Y9nOv0h15s"
         },
         "type" : "JsonWebSignature2020"
      }
   ]
}
"##;

pub const TEST_SIDETREE_DOCUMENT_SERVICE_AND_PROOF: &str = r##"
{
   "@context" : [
      "https://www.w3.org/ns/did/v1",
      {
         "@base" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
      }
   ],
   "assertionMethod" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "authentication" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "capabilityDelegation" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "capabilityInvocation" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "id" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
   "keyAgreement" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "service" : [
      {
         "id" : "#trustchain-controller-proof",
         "type" : "TrustchainProofService",
         "serviceEndpoint" : {
            "proofValue" : "eyJhbGciOiJFUzI1NksifQ.IkVpQmNiTkRRcjZZNHNzZGc5QXo4eC1qNy1yS1FuNWk5T2Q2S3BjZ2c0RU1KOXci.Nii8p38DtzyurmPHO9sV2JLSH7-Pv-dCKQ0Y-H34rplwhhwca2nSra4ZofcUsHCG6u1oKJ0x4AmMUD2_3UIhRA",
            "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
         }
      },
      {
         "id":"did:example:123#linked-domain",
         "type": "LinkedDomains",
         "serviceEndpoint": "https://bar.example.com"
      }
   ],
   "verificationMethod" : [
      {
         "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
         "id" : "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84",
         "publicKeyJwk" : {
            "crv" : "secp256k1",
            "kty" : "EC",
            "x" : "RbIj1Y4jeqkn0cizEfxHZidD-GQouFmAtE6YCpxFjpg",
            "y" : "ZcbgNp3hrfp3cujZFKqgFS0uFGOn2Rk16Y9nOv0h15s"
         },
         "type" : "JsonWebSignature2020"
      }
   ]
}
"##;

pub const TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF: &str = r##"
{
   "@context" : [
      "https://www.w3.org/ns/did/v1",
      {
         "@base" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
      }
   ],
   "assertionMethod" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "authentication" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "capabilityDelegation" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "capabilityInvocation" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "id" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
   "keyAgreement" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "service" : [
      {
         "id":"did:example:123#linked-domain",
         "type": "LinkedDomains",
         "serviceEndpoint": "https://bar.example.com"
      }
   ],
   "verificationMethod" : [
      {
         "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
         "id" : "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84",
         "publicKeyJwk" : {
            "crv" : "secp256k1",
            "kty" : "EC",
            "x" : "RbIj1Y4jeqkn0cizEfxHZidD-GQouFmAtE6YCpxFjpg",
            "y" : "ZcbgNp3hrfp3cujZFKqgFS0uFGOn2Rk16Y9nOv0h15s"
         },
         "type" : "JsonWebSignature2020"
      }
   ]
}
"##;

pub const TEST_SIDETREE_DOCUMENT_MULTIPLE_PROOF: &str = r##"
{
   "@context" : [
      "https://www.w3.org/ns/did/v1",
      {
         "@base" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
      }
   ],
   "assertionMethod" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "authentication" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "capabilityDelegation" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "capabilityInvocation" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "id" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
   "keyAgreement" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "service" : [
      {
         "id" : "#trustchain-controller-proof",
         "type" : "TrustchainProofService",
         "serviceEndpoint" : {
            "proofValue" : "eyJhbGciOiJFUzI1NksifQ.IkVpQmNiTkRRcjZZNHNzZGc5QXo4eC1qNy1yS1FuNWk5T2Q2S3BjZ2c0RU1KOXci.Nii8p38DtzyurmPHO9sV2JLSH7-Pv-dCKQ0Y-H34rplwhhwca2nSra4ZofcUsHCG6u1oKJ0x4AmMUD2_3UIhRA",
            "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
         }
      },
      {
         "id" : "#trustchain-controller-proof",
         "type" : "TrustchainProofService",
         "serviceEndpoint" : {
            "proofValue" : "eyJhbGciOiJFUzI1NksifQ.IkVpQmNiTkRRcjZZNHNzZGc5QXo4eC1qNy1yS1FuNWk5T2Q2S3BjZ2c0RU1KOXci.Nii8p38DtzyurmPHO9sV2JLSH7-Pv-dCKQ0Y-H34rplwhhwca2nSra4ZofcUsHCG6u1oKJ0x4AmMUD2_3UIhRA",
            "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
         }
      }
   ],
   "verificationMethod" : [
      {
         "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
         "id" : "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84",
         "publicKeyJwk" : {
            "crv" : "secp256k1",
            "kty" : "EC",
            "x" : "RbIj1Y4jeqkn0cizEfxHZidD-GQouFmAtE6YCpxFjpg",
            "y" : "ZcbgNp3hrfp3cujZFKqgFS0uFGOn2Rk16Y9nOv0h15s"
         },
         "type" : "JsonWebSignature2020"
      }
   ]
}
"##;

pub const TEST_SIDETREE_DOCUMENT_MULTIPLE_KEYS: &str = r##"
{
   "@context" : [
      "https://www.w3.org/ns/did/v1",
      {
         "@base" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
      }
   ],
   "assertionMethod" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "authentication" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "capabilityDelegation" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "capabilityInvocation" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "id" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
   "keyAgreement" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "service" : [
      {
         "id" : "#trustchain-controller-proof",
         "type" : "TrustchainProofService",
         "serviceEndpoint" : {
            "proofValue" : "eyJhbGciOiJFUzI1NksifQ.IkVpQmNiTkRRcjZZNHNzZGc5QXo4eC1qNy1yS1FuNWk5T2Q2S3BjZ2c0RU1KOXci.Nii8p38DtzyurmPHO9sV2JLSH7-Pv-dCKQ0Y-H34rplwhhwca2nSra4ZofcUsHCG6u1oKJ0x4AmMUD2_3UIhRA",
            "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
         }
      }
   ],
   "verificationMethod" : [
      {
         "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
         "id" : "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84",
         "publicKeyJwk" : {
            "crv" : "secp256k1",
            "kty" : "EC",
            "x" : "RbIj1Y4jeqkn0cizEfxHZidD-GQouFmAtE6YCpxFjpg",
            "y" : "ZcbgNp3hrfp3cujZFKqgFS0uFGOn2Rk16Y9nOv0h15s"
         },
         "type" : "JsonWebSignature2020"
      },
      {
         "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
         "id" : "#V9jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU85",
         "publicKeyJwk" : {
            "crv": "secp256k1",
            "kty": "EC",
            "x": "7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso",
            "y": "kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"
         },
         "type" : "JsonWebSignature2020"
      }
   ]
}
"##;

// Previous versions that don't match example keys, to remove:
// "recoveryCommitment" : "EiBKWQyomumgZvqiRVZnqwA2-7RVZ6Xr-cwDRmeXJT_k9g",
// "updateCommitment" : "EiCe3q-ZByJnzI6CwGIDj-M67W-Yv78L3ejxcuEDxnWzMg"
pub const TEST_SIDETREE_DOCUMENT_METADATA: &str = r#"
{
   "canonicalId" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
   "method" : {
      "published" : true,
      "recoveryCommitment" : "EiDZpHjQ5x7aRRqv6aUtmOdHsxWktAm1kU1IZl1w7iexsw",
      "updateCommitment" : "EiBWPR1JNdAQ4j3ZMqurb4rt10NA7s17lztFF9OIcEO3ew"
   }
}
"#;

// Previous versions that don't match example keys, to remove:
// "recoveryCommitment" : "EiBKWQyomumgZvqiRVZnqwA2-7RVZ6Xr-cwDRmeXJT_k9g",
// "updateCommitment" : "EiCe3q-ZByJnzI6CwGIDj-M67W-Yv78L3ejxcuEDxnWzMg"
pub const TEST_TRUSTCHAIN_DOCUMENT_METADATA: &str = r#"
{
   "canonicalId" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
   "method" : {
      "published" : true,
      "recoveryCommitment" : "EiDZpHjQ5x7aRRqv6aUtmOdHsxWktAm1kU1IZl1w7iexsw",
      "updateCommitment" : "EiBWPR1JNdAQ4j3ZMqurb4rt10NA7s17lztFF9OIcEO3ew"
   },
   "proof" : {
      "id" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
      "type" : "JsonWebSignature2020",
      "proofValue" : "eyJhbGciOiJFUzI1NksifQ.IkVpQmNiTkRRcjZZNHNzZGc5QXo4eC1qNy1yS1FuNWk5T2Q2S3BjZ2c0RU1KOXci.Nii8p38DtzyurmPHO9sV2JLSH7-Pv-dCKQ0Y-H34rplwhhwca2nSra4ZofcUsHCG6u1oKJ0x4AmMUD2_3UIhRA"
  }
}
"#;

pub const TEST_SIDETREE_DOCUMENT_WITH_CONTROLLER: &str = r##"
{
   "@context" : [
      "https://www.w3.org/ns/did/v1",
      {
         "@base" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
      }
   ],
   "assertionMethod" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "authentication" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "capabilityDelegation" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "capabilityInvocation" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "id" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
   "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP",
   "keyAgreement" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "service" : [
      {
         "id" : "#trustchain-controller-proof",
         "type" : "TrustchainProofService",
         "serviceEndpoint" : {
            "proofValue" : "eyJhbGciOiJFUzI1NksifQ.IkVpQmNiTkRRcjZZNHNzZGc5QXo4eC1qNy1yS1FuNWk5T2Q2S3BjZ2c0RU1KOXci.Nii8p38DtzyurmPHO9sV2JLSH7-Pv-dCKQ0Y-H34rplwhhwca2nSra4ZofcUsHCG6u1oKJ0x4AmMUD2_3UIhRA",
            "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
         }
      }
   ],
   "verificationMethod" : [
      {
         "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
         "id" : "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84",
         "publicKeyJwk" : {
            "crv" : "secp256k1",
            "kty" : "EC",
            "x" : "RbIj1Y4jeqkn0cizEfxHZidD-GQouFmAtE6YCpxFjpg",
            "y" : "ZcbgNp3hrfp3cujZFKqgFS0uFGOn2Rk16Y9nOv0h15s"
         },
         "type" : "JsonWebSignature2020"
      }
   ]
 }
"##;

pub const TEST_TRUSTCHAIN_DOCUMENT: &str = r##"
{
   "@context" : [
      "https://www.w3.org/ns/did/v1",
      {
         "@base" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
      }
   ],
   "assertionMethod" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "authentication" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "capabilityDelegation" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "capabilityInvocation" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "id" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
   "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
   "keyAgreement" : [
      "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84"
   ],
   "verificationMethod" : [
      {
         "controller" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
         "id" : "#V8jt_0c-aFlq40Uti2R_WiquxuzxyB8kn1cfWmXIU84",
         "publicKeyJwk" : {
            "crv" : "secp256k1",
            "kty" : "EC",
            "x" : "RbIj1Y4jeqkn0cizEfxHZidD-GQouFmAtE6YCpxFjpg",
            "y" : "ZcbgNp3hrfp3cujZFKqgFS0uFGOn2Rk16Y9nOv0h15s"
         },
         "type" : "JsonWebSignature2020"
      }
   ]
 }
"##;

pub const TEST_ROOT_DOCUMENT: &str = r##"
{
   "@context": [
     "https://www.w3.org/ns/did/v1",
     {
       "@base": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
     }
   ],
   "id": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
   "verificationMethod": [
     {
       "id": "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es",
       "type": "JsonWebSignature2020",
       "controller": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
       "publicKeyJwk": {
         "kty": "EC",
         "crv": "secp256k1",
         "x": "7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso",
         "y": "kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"
       }
     }
   ],
   "authentication": [
     "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
   ],
   "assertionMethod": [
     "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
   ],
   "keyAgreement": [
     "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
   ],
   "capabilityInvocation": [
     "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
   ],
   "capabilityDelegation": [
     "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
   ],
   "service": [
     {
       "id": "#TrustchainID",
       "type": "Identity",
       "serviceEndpoint": "https://identity.foundation/ion/trustchain-root"
     }
   ]
}
"##;

pub const TEST_ROOT_PLUS_1_DOCUMENT: &str = r##"
{
   "@context": [
     "https://www.w3.org/ns/did/v1",
     {
       "@base": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A"
     }
   ],
   "id": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
   "controller": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
   "verificationMethod": [
     {
       "id": "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ",
       "type": "JsonWebSignature2020",
       "controller": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
       "publicKeyJwk": {
         "kty": "EC",
         "crv": "secp256k1",
         "x": "aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU",
         "y": "dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0"
       }
     }
   ],
   "authentication": [
     "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
   ],
   "assertionMethod": [
     "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
   ],
   "keyAgreement": [
     "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
   ],
   "capabilityInvocation": [
     "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
   ],
   "capabilityDelegation": [
     "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
   ],
   "service": [
     {
       "id": "#TrustchainID",
       "type": "Identity",
       "serviceEndpoint": "https://identity.foundation/ion/trustchain-root-plus-1"
     }
   ]
}
"##;

pub const TEST_ROOT_PLUS_2_DOCUMENT: &str = r##"
{
   "@context": [
     "https://www.w3.org/ns/did/v1",
     {
       "@base": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"
     }
   ],
   "id": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
   "controller": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
   "verificationMethod": [
     {
       "id": "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI",
       "type": "JsonWebSignature2020",
       "controller": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
       "publicKeyJwk": {
         "kty": "EC",
         "crv": "secp256k1",
         "x": "0nnR-pz2EZGfb7E1qfuHhnDR824HhBioxz4E-EBMnM4",
         "y": "rWqDVJ3h16RT1N-Us7H7xRxvbC0UlMMQQgxmXOXd4bY"
       }
     }
   ],
   "authentication": [
     "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
   ],
   "assertionMethod": [
     "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
   ],
   "keyAgreement": [
     "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
   ],
   "capabilityInvocation": [
     "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
   ],
   "capabilityDelegation": [
     "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
   ],
   "service": [
     {
       "id": "#TrustchainID",
       "type": "Identity",
       "serviceEndpoint": "https://identity.foundation/ion/trustchain-root-plus-2"
     }
   ]
}
"##;

pub const TEST_ROOT_DOCUMENT_METADATA: &str = r#"
{
   "canonicalId": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
   "method": {
     "updateCommitment": "EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg",
     "published": true,
     "recoveryCommitment": "EiCymv17OGBAs7eLmm4BIXDCQBVhdOUAX5QdpIrN4SDE5w"
   }
}
"#;

pub const TEST_ROOT_PLUS_1_DOCUMENT_METADATA: &str = r#"
{
   "proof": {
     "type": "JsonWebSignature2020",
     "id": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
     "proofValue": "eyJhbGciOiJFUzI1NksifQ.IkVpQXM5dkx2SmdaNkFHMk5XbUFmTnBrbl9EMlNSSUFSa2tCWE9kajZpMk84Umci.awNd-_O1N1ycZ6i_BxeLGV14ok51Ii2x9f1FBBCflyAWw773sqiHvQRGHIMBebKMnzbxVybFu2qUEPWUuRAC9g"
   },
   "canonicalId": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
   "method": {
     "published": true,
     "recoveryCommitment": "EiClOaWycGv1m-QejUjB0L18G6DVFVeTQCZCuTRrmzCBQg",
     "updateCommitment": "EiA0-GpdeoAa4v0-K4YCHoNTjAPsoroDy7pleDIc4a3_QQ"
   }
}
"#;

/// Root JWK public key
pub const TEST_ROOT_JWK_PK: &str = r#"
{
   "kty": "EC",
   "crv": "secp256k1",
   "x": "7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso",
   "y": "kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"
}
"#;

/// Proof value from metadata
pub const TEST_ROOT_PLUS_1_JWT: &str = "eyJhbGciOiJFUzI1NksifQ.IkVpQXM5dkx2SmdaNkFHMk5XbUFmTnBrbl9EMlNSSUFSa2tCWE9kajZpMk84Umci.awNd-_O1N1ycZ6i_BxeLGV14ok51Ii2x9f1FBBCflyAWw773sqiHvQRGHIMBebKMnzbxVybFu2qUEPWUuRAC9g";

pub const TEST_ROOT_PLUS_2_DOCUMENT_METADATA: &str = r#"
{
   "canonicalId": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
   "method": {
     "recoveryCommitment": "EiCy4pW16uB7H-ijA6V6jO6ddWfGCwqNcDSJpdv_USzoRA",
     "updateCommitment": "EiAsmJrz7BysD9na9SMGyZ9RjpKIVweh_AFG_2Bs-2Okkg",
     "published": true
   },
   "proof": {
     "proofValue": "eyJhbGciOiJFUzI1NksifQ.IkVpQTNtT25QRklDbTdyc2ljVjRIaFMtNjhrT21xMndqa2tlMEtkRnkzQWlWZlEi.Fxlbm8osH2O5KOQ9sS21bypT_WoWxVD8toCU4baBnLk_gOxiOy_n3cMFMVANJ8usPrKAfRFeC27ATTkWBYZzuw",
     "id": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
     "type": "JsonWebSignature2020"
   }
}
"#;
/// Proof value from metadata
pub const TEST_ROOT_PLUS_2_JWT: &str = "eyJhbGciOiJFUzI1NksifQ.IkVpQTNtT25QRklDbTdyc2ljVjRIaFMtNjhrT21xMndqa2tlMEtkRnkzQWlWZlEi.Fxlbm8osH2O5KOQ9sS21bypT_WoWxVD8toCU4baBnLk_gOxiOy_n3cMFMVANJ8usPrKAfRFeC27ATTkWBYZzuw";

/// Example DID chain.
pub const TEST_DID_CHAIN: &str = r##"
{
    "did_map": {
      "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg": [
        {
          "@context": [
            "https://www.w3.org/ns/did/v1",
            {
              "@base": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
            }
          ],
          "id": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
          "verificationMethod": [
            {
              "id": "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es",
              "type": "JsonWebSignature2020",
              "controller": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
              "publicKeyJwk": {
                "kty": "EC",
                "crv": "secp256k1",
                "x": "7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso",
                "y": "kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"
              }
            }
          ],
          "authentication": [
            "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
          ],
          "assertionMethod": [
            "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
          ],
          "keyAgreement": [
            "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
          ],
          "capabilityInvocation": [
            "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
          ],
          "capabilityDelegation": [
            "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
          ],
          "service": [
            {
              "id": "#TrustchainID",
              "type": "Identity",
              "serviceEndpoint": "https://identity.foundation/ion/trustchain-root"
            }
          ]
        },
        {
          "canonicalId": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
          "method": {
            "updateCommitment": "EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg",
            "recoveryCommitment": "EiCymv17OGBAs7eLmm4BIXDCQBVhdOUAX5QdpIrN4SDE5w",
            "published": true
          }
        }
      ],
      "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q": [
        {
          "@context": [
            "https://www.w3.org/ns/did/v1",
            {
              "@base": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"
            }
          ],
          "id": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
          "controller": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
          "verificationMethod": [
            {
              "id": "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI",
              "type": "JsonWebSignature2020",
              "controller": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
              "publicKeyJwk": {
                "kty": "EC",
                "crv": "secp256k1",
                "x": "0nnR-pz2EZGfb7E1qfuHhnDR824HhBioxz4E-EBMnM4",
                "y": "rWqDVJ3h16RT1N-Us7H7xRxvbC0UlMMQQgxmXOXd4bY"
              }
            }
          ],
          "authentication": [
            "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
          ],
          "assertionMethod": [
            "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
          ],
          "keyAgreement": [
            "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
          ],
          "capabilityInvocation": [
            "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
          ],
          "capabilityDelegation": [
            "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
          ],
          "service": [
            {
              "id": "#TrustchainID",
              "type": "Identity",
              "serviceEndpoint": "https://identity.foundation/ion/trustchain-root-plus-2"
            }
          ]
        },
        {
          "method": {
            "recoveryCommitment": "EiCy4pW16uB7H-ijA6V6jO6ddWfGCwqNcDSJpdv_USzoRA",
            "updateCommitment": "EiAsmJrz7BysD9na9SMGyZ9RjpKIVweh_AFG_2Bs-2Okkg",
            "published": true
          },
          "proof": {
            "proofValue": "eyJhbGciOiJFUzI1NksifQ.IkVpQTNtT25QRklDbTdyc2ljVjRIaFMtNjhrT21xMndqa2tlMEtkRnkzQWlWZlEi.Fxlbm8osH2O5KOQ9sS21bypT_WoWxVD8toCU4baBnLk_gOxiOy_n3cMFMVANJ8usPrKAfRFeC27ATTkWBYZzuw",
            "id": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
            "type": "JsonWebSignature2020"
          },
          "canonicalId": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"
        }
      ],
      "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A": [
        {
          "@context": [
            "https://www.w3.org/ns/did/v1",
            {
              "@base": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A"
            }
          ],
          "id": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
          "controller": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
          "verificationMethod": [
            {
              "id": "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ",
              "type": "JsonWebSignature2020",
              "controller": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
              "publicKeyJwk": {
                "kty": "EC",
                "crv": "secp256k1",
                "x": "aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU",
                "y": "dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0"
              }
            }
          ],
          "authentication": [
            "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
          ],
          "assertionMethod": [
            "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
          ],
          "keyAgreement": [
            "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
          ],
          "capabilityInvocation": [
            "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
          ],
          "capabilityDelegation": [
            "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
          ],
          "service": [
            {
              "id": "#TrustchainID",
              "type": "Identity",
              "serviceEndpoint": "https://identity.foundation/ion/trustchain-root-plus-1"
            }
          ]
        },
        {
          "canonicalId": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
          "method": {
            "published": true,
            "recoveryCommitment": "EiClOaWycGv1m-QejUjB0L18G6DVFVeTQCZCuTRrmzCBQg",
            "updateCommitment": "EiA0-GpdeoAa4v0-K4YCHoNTjAPsoroDy7pleDIc4a3_QQ"
          },
          "proof": {
            "type": "JsonWebSignature2020",
            "proofValue": "eyJhbGciOiJFUzI1NksifQ.IkVpQXM5dkx2SmdaNkFHMk5XbUFmTnBrbl9EMlNSSUFSa2tCWE9kajZpMk84Umci.awNd-_O1N1ycZ6i_BxeLGV14ok51Ii2x9f1FBBCflyAWw773sqiHvQRGHIMBebKMnzbxVybFu2qUEPWUuRAC9g",
            "id": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
          }
        }
      ]
    },
    "level_vec": [
      "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
      "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
      "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"
    ]
}
"##;

/// Example DID chain (reversed).
pub const TEST_DID_CHAIN_REVERSED: &str = r##"
{
    "did_map": {
      "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg": [
        {
          "@context": [
            "https://www.w3.org/ns/did/v1",
            {
              "@base": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
            }
          ],
          "id": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
          "verificationMethod": [
            {
              "id": "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es",
              "type": "JsonWebSignature2020",
              "controller": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
              "publicKeyJwk": {
                "kty": "EC",
                "crv": "secp256k1",
                "x": "7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso",
                "y": "kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"
              }
            }
          ],
          "authentication": [
            "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
          ],
          "assertionMethod": [
            "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
          ],
          "keyAgreement": [
            "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
          ],
          "capabilityInvocation": [
            "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
          ],
          "capabilityDelegation": [
            "#9CMTR3dvGvwm6KOyaXEEIOK8EOTtek-n7BV9SVBr2Es"
          ],
          "service": [
            {
              "id": "#TrustchainID",
              "type": "Identity",
              "serviceEndpoint": "https://identity.foundation/ion/trustchain-root"
            }
          ]
        },
        {
          "canonicalId": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
          "method": {
            "updateCommitment": "EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg",
            "recoveryCommitment": "EiCymv17OGBAs7eLmm4BIXDCQBVhdOUAX5QdpIrN4SDE5w",
            "published": true
          }
        }
      ],
      "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q": [
        {
          "@context": [
            "https://www.w3.org/ns/did/v1",
            {
              "@base": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"
            }
          ],
          "id": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
          "controller": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
          "verificationMethod": [
            {
              "id": "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI",
              "type": "JsonWebSignature2020",
              "controller": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
              "publicKeyJwk": {
                "kty": "EC",
                "crv": "secp256k1",
                "x": "0nnR-pz2EZGfb7E1qfuHhnDR824HhBioxz4E-EBMnM4",
                "y": "rWqDVJ3h16RT1N-Us7H7xRxvbC0UlMMQQgxmXOXd4bY"
              }
            }
          ],
          "authentication": [
            "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
          ],
          "assertionMethod": [
            "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
          ],
          "keyAgreement": [
            "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
          ],
          "capabilityInvocation": [
            "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
          ],
          "capabilityDelegation": [
            "#ePyXsaNza8buW6gNXaoGZ07LMTxgLC9K7cbaIjIizTI"
          ],
          "service": [
            {
              "id": "#TrustchainID",
              "type": "Identity",
              "serviceEndpoint": "https://identity.foundation/ion/trustchain-root-plus-2"
            }
          ]
        },
        {
          "method": {
            "recoveryCommitment": "EiCy4pW16uB7H-ijA6V6jO6ddWfGCwqNcDSJpdv_USzoRA",
            "updateCommitment": "EiAsmJrz7BysD9na9SMGyZ9RjpKIVweh_AFG_2Bs-2Okkg",
            "published": true
          },
          "proof": {
            "proofValue": "eyJhbGciOiJFUzI1NksifQ.IkVpQTNtT25QRklDbTdyc2ljVjRIaFMtNjhrT21xMndqa2tlMEtkRnkzQWlWZlEi.Fxlbm8osH2O5KOQ9sS21bypT_WoWxVD8toCU4baBnLk_gOxiOy_n3cMFMVANJ8usPrKAfRFeC27ATTkWBYZzuw",
            "id": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
            "type": "JsonWebSignature2020"
          },
          "canonicalId": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q"
        }
      ],
      "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A": [
        {
          "@context": [
            "https://www.w3.org/ns/did/v1",
            {
              "@base": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A"
            }
          ],
          "id": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
          "controller": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
          "verificationMethod": [
            {
              "id": "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ",
              "type": "JsonWebSignature2020",
              "controller": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
              "publicKeyJwk": {
                "kty": "EC",
                "crv": "secp256k1",
                "x": "aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU",
                "y": "dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0"
              }
            }
          ],
          "authentication": [
            "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
          ],
          "assertionMethod": [
            "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
          ],
          "keyAgreement": [
            "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
          ],
          "capabilityInvocation": [
            "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
          ],
          "capabilityDelegation": [
            "#kjqrr3CTkmlzJZVo0uukxNs8vrK5OEsk_OcoBO4SeMQ"
          ],
          "service": [
            {
              "id": "#TrustchainID",
              "type": "Identity",
              "serviceEndpoint": "https://identity.foundation/ion/trustchain-root-plus-1"
            }
          ]
        },
        {
          "canonicalId": "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
          "method": {
            "published": true,
            "recoveryCommitment": "EiClOaWycGv1m-QejUjB0L18G6DVFVeTQCZCuTRrmzCBQg",
            "updateCommitment": "EiA0-GpdeoAa4v0-K4YCHoNTjAPsoroDy7pleDIc4a3_QQ"
          },
          "proof": {
            "type": "JsonWebSignature2020",
            "proofValue": "eyJhbGciOiJFUzI1NksifQ.IkVpQXM5dkx2SmdaNkFHMk5XbUFmTnBrbl9EMlNSSUFSa2tCWE9kajZpMk84Umci.awNd-_O1N1ycZ6i_BxeLGV14ok51Ii2x9f1FBBCflyAWw773sqiHvQRGHIMBebKMnzbxVybFu2qUEPWUuRAC9g",
            "id": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
          }
        }
      ]
    },
    "level_vec": [
      "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
      "did:ion:test:EiBVpjUxXeSRJpvj2TewlX9zNF3GKMCKWwGmKBZqF6pk_A",
      "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg"
    ]
}
"##;

/// Test credential: no issuer is present for the unit test
pub const TEST_CREDENTIAL: &str = r#"{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://w3id.org/citizenship/v1"
  ],
  "credentialSchema": {
    "id": "did:example:cdf:35LB7w9ueWbagPL94T9bMLtyXDj9pX5o",
    "type": "did:example:schema:22KpkXgecryx9k7N6XN1QoN3gXwBkSU8SfyyYQG"
  },
  "type": ["VerifiableCredential"],
  "image": "some_base64_representation",
  "credentialSubject": {
    "givenName": "Jane",
    "familyName": "Doe",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts",
      "college": "College of Engineering"
    }
  }
}
"#;

pub const TEST_SIGNING_KEYS: &str = r#"[
        {
            "kty": "EC",
            "crv": "secp256k1",
            "x": "aPNNzj64rnImzI60EP0iln_u5fyHZ1k47diqmlUrwXw",
            "y": "fbfKhw08ZtGy9vbyJo6kiFohhGFIrnzZIUNDvEQeAYQ",
            "d": "sfsIThyN_6EKPjhQasF8yR27-qlQPUTGiP4QtkPTKM8"
        },
        {
            "kty": "EC",
            "crv": "secp256k1",
            "x": "gjk_d4WRM5hFD7tP8vvXhHgp0MQkKwFX0uAvyjNJQJg",
            "y": "e5lq0RW41Y5MH1pOTm-3_18GcxKp1lO4SfbzApRaVtE",
            "d": "U7pUq3BovVnYT1mi1lds60wbueUKb5GobV_WvjOuY14"
        }
    ]
    "#;

pub const TEST_UPDATE_KEY: &str = r#"{
        "kty": "EC",
        "crv": "secp256k1",
        "x": "2hm19BwmXmR8Vfuw2XbGrusm89Pg6dyExlzDfc-CiM8",
        "y": "uFjW0fKdhHaY4c_5E9Wkk3cPi9sJ5rP3oyl1ssV_X6A",
        "d": "Z2vJqNRjbWvJX2NzABKlHI2V00HWmV2KNI5P4mmxRbg"
    }"#;

pub const TEST_NEXT_UPDATE_KEY: &str = r#"{
        "kty": "EC",
        "crv": "secp256k1",
        "x": "hm_Pj46yibXbFNyARPXfOKIAEI_UKqfmZwzZDfbUSSk",
        "y": "Djxgs6Ex71m6K0QCrn4l2naNo4F6IYXfu0LrBhW2RQU",
        "d": "rAUu7DWaQ2ceSap_NzJNj1YOD2yP_bf1JqabuQJz6rc"
    }"#;

pub const TEST_RECOVERY_KEY: &str = r#"{
        "kty": "EC",
        "crv": "secp256k1",
        "x": "_Z1JRmGwvj0jIpDW-QF0dmQnAL8D_FuNg2WxF7uJSYo",
        "y": "orKbmG6L6kRugAB2OWzWNgulXRfyOR06GTm353Er--c",
        "d": "YobJpI7p7T5dfU0cDRE4SQwp0eOFR6LOGrsqZE1GG1A"
    }"#;

pub const TEST_ROOT_SIGNING_PK: &str = r#"
{
   "kty": "EC",
   "crv": "secp256k1",
   "x": "7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso",
   "y": "kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"
}
"#;

pub const ROOT_PLUS_1_SIGNING_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU","y":"dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0","d":"HbjLQf4tnwJR6861-91oGpERu8vmxDpW8ZroDCkmFvY"}"#;

pub const ROOT_PLUS_2_SIGNING_KEYS: &str = r#"[{"kty":"EC","crv":"secp256k1","x":"0nnR-pz2EZGfb7E1qfuHhnDR824HhBioxz4E-EBMnM4","y":"rWqDVJ3h16RT1N-Us7H7xRxvbC0UlMMQQgxmXOXd4bY","d":"bJnhIQgj0eQoRXIw5Xna6LErnili2ajMstoJLI21HiQ"},{"kty":"OKP","crv":"RSSKey2023","x":"EyGvw3AkcUf2TZToBh6pddeaaocmvTuLCSLun_yYJpL7x0W3gVEzeKlj06J5Sej9Duk0W_yGhbOKCahOx16LszwTHVgnH9FjRk0nwOer4yKaKnjTZ2FlZsYI0OI__jhCGP9cbcOEd-1rfvUFu-ghsj6oHfSXDBm0Ekplkgs1IktoicuMsF-bD7I6tZRpP9tqFGqARUqvR2daQN-scwYUNsv5ap3XakBCDvOCBc_rPAwzapY_nuC3L6x60UGBAPtUBANdaMhAU0gxd-3JMjcSjFgwzAhw5Eorr7bIp1_od6OfBRYu3sIkij5Es6RDBLghUAx2Z3dznniJRh5Xlx_8zn4SYw_xhV1X04vY5U4O7-7veKMqKxzzoGOR7O137gSTtBk66ISXfE0k6LLsZK0Qkzi0B6YQ0Xo86d-COFNhRWQ_Lq3SCSiOaJ4lFP5_RVlHzgUXm6XY1X0jrkVPWdT42VxGjFvy_KX9f50dOkdPJTax8bGv1nEpDm-55UN8nrIzsRODaxMBooRL1y4OxyW1tpHaEdsoHvsZrLzM5g7FB2ah-62TCGkPcG3Yx84MPp50eRPIlj2omMFxMpnAZKBSRMGtk35A6xAZUI6KTYGfNI-IuWKdk0UOn6xL8W3EwMTxRgx1v7iklbgxKuCBoOeAK7FhoOVzL5YnUCHb1NUwAxDs9I5pNmrvaXsDDLKLIoz50hRAdnK92whifFoWoJOOJbQTb9sx43zmB1J7G_T28MG6UetI4dZljoNfWpXePl3vNwW979nNg7GU3N_V8ZE_slRmUv-rAw9jD0w9KXVCuZuwGIKoJ2Co8qjZxnhZUtmi3wFJin73V5BC684ebh40fnA9z-H1Kwa3ItX_mQSVYeMV-_1fydNULsdhlEnpwI5XNQ25LGqMNb4v-YRBXLSmN5CituV9rPXg5ZzQvy8VVE9qxWnicCxz2TzFrxFOOIhNTxf-YQT5Re5HJAvdy7Y9szo-i_PgskFdVm4UxMgH9ddrFUhDPNmVtVY8PoXlMzuU6gKR-1np9J6FBttHOIPu7LFFdO0Vd_Y3-Dl5mdBXFcP1Do1GN7ojcuRUB4rmB__upRAQQsqCApGurtGP1zgtMQm6ozF0gt_JpoXgvZEFK5kkm92vpedrSfDPBBn5NPIgmQgKSYfvmWRmADyr2J9bc6EjJr1-YD7QR1r2g_eGRBE1S6dexWceWTq-RktXQYOSJBnKLSkbqJniuoA70BMkjU4Jsj1EJB7oxE41RRMchA4BRlClSi31ga0T_bk31rNTLQNLGSrBrh0x2nlG8IZUZLB4fIKKweFD9pL1qhLMM-SQl3YR4-v2wxjlMXTrEDjz2xdwJsQhhzM5trtqhVdxfgBwB_ZBtU9KJqYvkB_3BhY3kYQSGDLhyCHbjyIVYl7saQGkTz_owGfj8tD3gU9oJlZHDyjf4p9AObfF4YXKjVBpPrPgwgNd-G4LAgUOn4DAVwGmGBjQaNWiLet4g4lRsLS3LkM1az1w_KyYCX_k9bptp4qLgwV6HqbLx1V5WkmubxLMpHlbV0tZFLzwThEaKpqNyz7M5qIyDvaSbTFtQ9feXhRHU7VN1MgH2AQmQzHiygXHs5qafdGSsKoMm6c_6R2-NXl3asM1TSUmD82yKonGYhSHHy60KvB4M2rVTKRENxR93u7gaYr_4cqFY9LlcqGUMzxmm6TadfSHz3rSj53C8c3Z3U9x9ftbKGOZeybdWhYbRGyES_HzmlXV5MFY5qHiE6INi_ao7Xxm8VRi5rdaHlVDWfBb8gJENbUHDDcsKQfae-4j_vXmvq4s_9L5It5kVLCT9f5NEf7jsxSP3mg9hqgwdY96ob73GsHO3HRoQARhPUt-2o7i1JzScqRH38AeDr9XnxC2Qu4LT6ffOmMKzA3qngyxKmkvyKmIl3_eEhDxpdTSf2ba6EGOD2GuzvGv2a_P9QHw52mvtEoCLNJAslzsxwxbLSnLIOkbJca1Ew26womAjSgnNwUvPCkz4lmSNTbyF63wvmNJJeD0UgkBTb2MxDw_39ukWvH0mOSJegpmENWzMhvKvxxMgB5Y1VY6Hq06V9mcg4iD0AdI-dM646yU8iLfMAAkB-EvwUUMXRE3KGU9Kx6dqhsSCrow4QDpzk0B4FCATLwawfGc1_rxQyumhF9nagl8jP1ITcLi-hlUyrOsKfSK_s3WKTw4j9iBoBWCzHrX1YC_2UTnq5XIdbY9tT4NajRzqwKLV3aYWRnqXLg_-l5k0H2GmwmRnm4ZqU-9YuAy8MQR5CM93H1gxE7oL_IWIyH_tCXrVH4hRhjd7GrWcA90s1AFpCHhBZs72ORxG_Rh8VcJpB5cTpbQfk1ESme0-UTXoSnuLPfNIQb6I6fwFkIvBx9YL7gxaVmjHMgk9BLR89iwuo3VsEsAs4ktbFfZ70l821y6q_xmOBPF-BxJzlVuHMq9hfyYVA-1ka8tBBeEy8NJ1PlYBMiVjHoKWMfqDKo0ONNv1Il_ThirUq-MM4pc0ENOqwCYkomNBFfFHdbS8L1Y5yIruufFxRbRPt6xC1TnDtq3K7JCpRjsTqv_1_u81WA4UIlW49NaruM-2lPlL6P7rWtBqG4axy6U9WYqom7aXBW0cbg31hY39xZb49G_SfSYewGr_pelurFdTag1R3ZL5VuDTggqErrppxKIBYHQP7M_reJ8fQf4JcXOmMkUOap1K7QJvvENxlQ_RQRj10d-t9spgDv5gki7uMDSA3fp4q4gf3HxZhYwPaImQ9J44zCCLUdo5dyhHsyd9neEeBniNZk5LDZRfX66ERlj49CO2dHmHLe-YQACZnMQDDug7LF0il3QHinPD-nedAAxpjfUus9Ay9vRx6nB3fHr-_9C76qx_NjCehMZHlsAOgZGU-yjdwY2uu8lvnb8dvmCbkIBYn4S_aWJ0qIOEjfWuADwWO9BXI5uzQZ0EhKuhALABMhOIi4pmnHqCE0Durvn9RaPiFz6ZKFhW2d85ZAkks_-ARI0phaKzggmB4E6k5EV3cLqkI63Oiiq21QY0VCvc0LuNoAVYzG8s4bx3udSSORrRJm2fOdURg3wtPlFq21m_7y8D09xKpHkXgEbuDJV3hWk52u0Rxv1MTY2V2_LkHIDF6my-MZLQQh0dQYnUjDfvQ3bTqj6UE4MZ07R6UZzl3Vjw53lM2x4gI17Trma17Ag6Yg6XiQA7QqgXKWy3jG6AuBLjuYRPeYo18lJm00D1D_Z_C--D6zMJKr5ohYrTi4ea_dh3CI82xBNwjeTAd95r6X0wzC3xodd7FSWJMCgt0MF6pz-MEL_jNi6sK9mIn05U4icLZLjBwl2lObaoiYxpyWEpnuMGy8J7dM1Z_aRpYt3J-Zw7i3Yf4JI2JV9u1Mo-ywQyXgRcRBhK3emrFT2fxH8SqkKwJCWn7frvbukOzSQiKD8RFuXA-SWK60mJ3erCRnka-xkGg3AiBxxeE8Prk8EGzLcB1UDRGQ_x1PXmMNtdBK65dtv1b0jGTM_uSHFndWXOrFALwi66JGyIca2WnCfQRQDR5EPyD2d2Naecbj_jMwFUsbYCxGTc76n46c1pI_QH1rxDBQ7j1Tj_rcQz6Bk7DMTNnlTFhJn2h7yVnoRPenlNCWZWZPRpr4vnvS6Ii30os5W2QaGHI_TqhhaXRFU8Z7K4PUUUVEv6u3KIZpvcuVxAbcx-ppLVkj-r2vM061Nx9aXEBFd2whV1Tw2rjf-6fm10N7U3ssLGC6sfHRpSVcsENk-ZjuYH7sY-zmN7Hf8zOYHIAZDUr1rjCgG2yCujbdOPFtPs4QKC_cFSzbpOjRmJ-urzi7duH_vH3_TBhMzM4jowgM70l1LoB9sjQ68wzlaAs74T04IroWMULoZOdaeIS54ugR79EhgqvukrIDLEoCekAY7jAs-iNW14YRPrtdul8zVUjLd4I_X3efx-IX7HvR4RUp-6lqMSN46IfvlScl0qBY_SBgCpdEw66SRo1OAIAuTy7VWX_mbvLtgZPPMkaVheFwYwBZnBLKQKyJHrNrKRQ5GdrSnJP89jdh-o6VEqG_whEec3cB1LwXipXb6v1vi-7jxU4kpU_BTMtEChb21tRhmfKGiQxHbOTRJbHVoQJ4NFlS14bTYAEuJm6yXnIW-GOVCLvlHShp5jeWc_9vvvBZnk4C7bDxY80GxadNmsKy_-AcEFN_QI9pt6lckDeTOQxgVz6Anz58RIkvJ1oPL8A5FZOl4iYuQGDAqTP6Yo-SdHbuVOuV3aM9K3L6RMgj5Z9z517O3oqsmthQdy5xtxhalD2bjV4fNsQrsXIGuNa4nAnFtfsi0uN4ahR1_YYVuQgfEQLOGSzJnw-bQ7m8tOxlDOP4MsXg6BFSBvo0LPwieTdNbZR_N4FueA59bt73HfANTd-xz6ycnZNRNO9DbxBRwXJnQogguwZQdLLLuZjqoglKwi3gmMHvCR-3QngZYQw46vAkTUuYfdG0OgaYuAAqtsEvJRaBVSud7q6pgMqM5UbG9eWv20h-bMQeBEpIuVG08HOEc9TeUzDOoE87PzBkfBqVu_s1tyItQQ-DqSvfCQBobT1pYeVsuyJSGXuaF5MXooxYfRpsAuysjWDKDNxAarmMCpioPCo5ebD0elYa6S1KV52RN15vaAZLPqNRiFkek3oy_M8C9Fi2nLzXG1Bjn_JlKzni0I3pofwFNE2ZJnoLSVpLwVLQUzzCB5GoS5P5C1DcPDxpjAr7e8pWb0QAyyIuz1EvSssczBargovo8iNxthV_MgoN4UGY3RtkDRyw2DPcFdji7AYXw_q3xlxXsWEZMfjTlkG0FfwSTHbhrL-BIXXw1u88y-w5SvjBBwk2wW0SjPVgm-qq8yonWXhnVfu4xRLMY7qNRltkzyB5pQ44rJ0iFr6tXtKus3rUTx2PbQOPNCYJynCWQnA8anAlOiTmIJV8G-MYkP3hH3g-VZSnWE8gQhbvXy9OY4YtyqX96TXRGuHNuZBDEHiPmNAvKkfgVdGE1xrxPnfZ5eN2RQWXAf5a8xgISY1bXxlt1prbFSiHTMLnikDpYNy95JBQnPEqdIYRhgzh29L_RQpIM2ItE6rPrJCl-NL0Mo3YZNdFepgL-5uOjFilpmO_EfAc06pm5sP-g6S3vOx8I9j4JrOnhygXvZx4Mr2D8-R_7s2F5QOYKCpcYmhKSqaPbdAX-q6oNQQ3fesRtmDJIVbBmioMmu5k3C8hh_L2RNAe6ItXT7XVCo-QFQ8fiUIOMWASrYHiy8qsbX4kKQJ98v070GnqCMpKVtB9522SHxJWv4h6Kpsmadh9WjAmzItl4tRV763mNcLeidWzlJFUcfZIVm9OrWbHinBUjKFnoeexpecTm2ncrzpUkMmJghWKv9hUzk6wGkQhsps-94GvQJT2ou4T5xLpeATQ3oenwez9tEwxQ07tB7FHEiIBpA4PFExNwdv8sxaEe2Zaoakh1iEjIbd4uBcEAd_E8eE3VSEPvB2_zT8nek2I9pcHEIHA52Q2_j979f-vAyJci99RN1Va8nvk3TyMz_g6OCknUZcqkhXK3lqigvhkUBl-IxjWqagdTwPfwGPtwV3JT71CZDfBWujVMLPGB_gT_dhsWlIN-sC_yiWL_thQrkgKFPqXPwQKCyz8r_iv4f8NnJIh3W6_hUURFsnu0NpVAlhi7iOU-B0cqk1NHN9BgNbT_zU2aVBEFBrlQetG5pyxxgyDSvrz-igEzZ9oqa7-EIgNv8P-0T0IUrlCIQSfPsiAUsbExwg5JwdgdQ_gD9HUt4U2Npk03XtaAySY1IXJCXeJLp0OIcc8hFeaiPMMv7Caif9RsIxjwnikwLFGtpNy70Ed6CkTMtxBR4uShDzbSz7Hk90gu5-jV5WGysOA9AbW24iqgfgCKjrjgfrod_MNG939PdD9KOV0x3MqbZJmBLB7jKCINC2ilgH3Ez4crHFZJEkuJ_Qq-KDXW7l7hjHUG_debtAu6qI1edYP09UkgmQtnZgLcGAWUhDxWhdf4XYOHfqXxfhiVu8tF-ly7iqWkmRCqhRGV5NmzUWuwvQ8-Jlh4kRa7nhpwb7ivyXiDubq85_tKuha0qKFzzz8gFuiefICHX_Uy3xM8m6Gy3KfYirumMAkuB5-IY7Dgr6IZK8YXGLZb3QEXmOjuwp8Rmm-bMnCXehgCJZplNtcWi7eQxsP4y0IoEUsmmC5Y1as1sAs8-R9XlxBfP3hdGWbOupZfS6FmMRiGD9HoWesUSVtRs_tgOUPPVav2HRIK2CLYBRwgI1NaeRcpnO8cOye4UgRm_UF36pi3hJPfIdCnhxGeOH5J0r9zYEnTDs18YsIQedQOJ9jvGBLvDi8dJ3NRzof0hk9riVtSPV7H2EKhkEL67E5pccehsmZnha0ewYbZdgEstjzjwQ6qkZRmFLOBdP11yCDzgs3eDmnk0Ztewl22-WhhpumCfNgux5OEtcSu6hcC_gtsXQgTm4QV09fFZJAH8tyfFildcaycx0w6zG_tT47jBYIwVyEI-Mvv08qYw3ZN6558VgacYehFWake3ahdjDxZ8bO_tBtLMrFXmjRpibEIYbWZW2OPgBv-4-Z_EPXtLrDpJxYjD8bUxNgxwyqxAlyqZe0FUQVo1RTWV9hzvj4GcOG7wC-_t9aEEv5h9hg3sQXBxwKwIulPSsJlAeW3dygypohfIMKiUdjDERwhgvPsvB_vsJIaVpN3SJVfNWvMEFAIRxl0o0b4upYbISICcxav7YjxARlPcV_nqG6Lnj9-6MtHOzvmwMWpcM0Y_FFro9TqKAj8TkAiGaEMYyJ8Z5EMAsGd32HwMhmdeJbA9TxNpC8CIpeNlU0H9JeSDR3bl76oGAPDIc7bDmfKjcCL_8rZamAaZucmCI4Fkkjaqyl_k0TOHrxrc8EcYzbICfu2Xp9j5Bl_w7GErvNIbMsbJejezsJxt6CR71oex_OaL_DyxGJE6bOaWZFwF3WqhVWMoMEuRwy4Z11DIsqZ2pbxyArURVFG3mIHnBJ7ffjxYbofuuuw9Ce3S0W9AwEvXRlquPr3-wLesE-Y09JL2x63dPrsfx88itwaKSyGuJyvqpTu8NwpAR8d0bU6nXG38O2ysH6-xwvDGoeApjhGaTD71tv5hYcJj1X2M-GeWFi74NjG-PYBkamWVPk8v2uimVuB402YMgUAe5RtZcKVUfHczIcj7IWreTJr8JCLl4N_X48ji2KDuBuuaBRBUYdjkl8ltWE-AQzatqUi3DF2ZDEjEarQrk8K6QDaHNbMAEQwqxIcKVB7rX6pwR4EA2xN2VYmCskYAReAbKYyzbFKgx-_kbylwjO1CMcDTdhKYHnfEznxeaxzjwopfWQR5JQ_y_4OExcY6gh_FHXXyMOQdyzdcNMPFOZDvKAf4PiXg6BV6VVbvlssgImhEbhyfKlwhmbHkrD90BVSZOfwp0m_zd_xOfwSYckSwo8ef1K6DILkCmiUSc9wiCBBGHF8ex_0u3nepPICWg30NqJPii7moRYlXNi2hKgTB2Cy1njuP9pNFSD-8cOxrrAoAz6SaxdS4QqxjykSaRko3FibccYcSE_fkx7_WWBSW_1GOKTqQltkzHWMqTbu3wEjBAbnQjYGEWn8aTNzsAh1pezmZurCOdi9uL-cjIVavKPn23HhHGfS88f3pRdohcdlszyc74acnD6VgT0VnArfeYPNBWcliVDnCE3qYSvter4l5Fe4rH1qDISEq2ni1-uxNRJx6Ck3-5bWSZxHAgvc_2gC2O5qc9TU-akXvNSqLmNtKmO2FGFtBltwgyLc8bVWAJrNxuWQVCUxXlfSkxaGXtN18lGJX-SvmRn5IsqfhUitHzJjEASiI_YOVY9OoGEkK1a532FFGdO00mS07BQCPV0w_gldLncCOgt8VPaB5d5SjOF0_whIcVAIY95y5MrZEJWcbES4zg_jdGb5SRLlr9PENPbne9VYK4_ju-MCFNo0uWibQJzJcpaKU2rZ9sAsT2goR_lu-aLGCdeimhRmual5ISX_tyMRikPCDidsweqUeRzPcriSIRDKLcQfzA3P9Lt_Mo0ql-l1EX7TcwLgCsISBJ39jyhHyPvNPbBAFAlrlF9uRhz_ATonpUwgZrQHSlpsy6Mzh-O8f57HKQTRT0VigvfIeC3J1TR4EzLkHUdC7QF4JNlprKFQl-HUh9VIOpwXfQ7VwhbxUw-MThAn8fnFAKqd8S-4S76Yn4Ns3B0FA0wlDWp9AvfCSlm50bQHUgj8FEtwz8279OoIhBEIMnA_rHNwA1gPMSAl8aU4RO4L9wTbhwVEs32i77O1pQS93ZeNwOwXXoquAAVFZwusOXz2C3jxzKzB6IdrA9LE7-ALHDvmxB-y9KUe-RgCfFgjh9EE7rdwftpCOMj30we1IOtQ1XyFSwpbIK-y6e6itkyx73nB8UicYQEQHDnl2UPtxm3TLUe5bx_E0sisng5ZV2ISypN4_CiyoAbUPCapdHnGLh5VJtaPPq0NGIVA88MkPxnJC_dTfsZKzNVDywA36U6dGzcSH16QoTfJ-ZcUJhHAKJHizKtLpdxpNKlSugnNW0P0XwgrRYAehBBqJAWrmDc2vll-f5KYy6AFEWfIub9SODwuu3j3yfdoVAjpi6Tvm_e_w18ZBYKjtRrAAg38eTrwQwdDDovzBO6t7xmJkqOxsCFl0tz0WB7YxhVMfhC6qv0ojnXM4XrhX482Ew0yMUB9Ql2_2d7u9-aM7VztBqRf9dtPj0Fc1WdfiMD1d72U2D5NukpfdO0k74QL4xFcEWgq0qAPT1Xd35HaQhe9KfUYx0d7KtbBb1BrpQ3zZWS_ThLtfTHOvGZRQH9bQQyFkx7r9Lnal_GmnKw_w-Y5ecOTXwxvtB_XQNOo2i02MTPLpYHXMCWCFB6kHee4fhJVL4yQnaac8WOYkNDZeHf7y15M6Ezs0ieyusNjY-nfeAuXS1kJ_lf-qI-1xCpx4wmOy-W4Y4Xbr5YWS8Pe17115uh3ZGN9n88HuWj_fzZ0BcrgsT4p5LvSm9lntyD3oQ8pX17phhk3xqItrnJYAq8MfnLgifMDl6XucGJj1rhsvVGfr_ccjSHxohBb0HWL6g16xEvKsXnQe-PHn8Djtpc9doxqWWC1QeFnjIFJ38TnZd2v6S9irKu2D-YTw_9TvgRZTHMLgHH7pdFo2P_-mrKP74-OvYkn0O4aUVAZ6-bCXKIZ4ZzFgt-aO6l6vyUUfhcVrQKcnRdrZ4_GYfiRdxlBL1rvcZAkVpH-iitAdQ4N0xFHFL3MO3MH_EepQXLXSgciWBbbc9lzJnd4GkCRT-uH1SKKtquXZIO28ERVLB5yD9xkl6-ch9qTYNnNcBDNSAJQeFBwCHB5xZoyuYfN9p5v40vfSDAoJU9A_3_kaYMyUBVaxQWnKjZrrA5hWy2fjRUnVpeX7PDyAyb6eZDt7dKlkWGQxvhDXRFeN9yjohquhDj9OSS0JlHsPLobIYEPThAwpAYAEH9aspydpQDzH5LdB8aSUzTmFvdt87KW_OjCX2bAvPUj7a8bhfrITHuCUwOl_hNSIaxUX9EuHEifvRKi_KnQRZvkTyN6Ji93jcr1wYk2FOjZEVdUfC_lI-xzuQDSVWUUl6URvL2tfzx5FxqScbNiq3xnIqLrNONk-p4hi1QvPbgiYvXevv6-KgoCOBN5b7E0KUoVcBh8GBPzCeP2EZwA6C9k8u55Ul0Y6dohgm5HS8NQfXCSTt7QQgchGBOyOP96JR_uRbyLPJ18KaFr9QTxkQrxpuks_tWBdd9QD7GN2MU26S9veV2mrWHNXBiKY7NNZjYSkfNyzvjsg3VCwvxU9kzvkozJ_hQnkOnEmlI8bu34cFvYy1Ms4X5fLwaFLMmG3SnAIwBsCz3HxzKU05NBHikuB3B79BGskfQK_Fe-rkahNqJgG2ya6xgeIBivC2iuCuVjM1xcVN3jM0VuwQOCIVwjPpyDgWwjm5rpjX7LfEzwjyXynX5OR8PVugx7bAFwv0UNcbkBNLadJmL5hZfeXHzgPM5u8M1_PEpwxRddCDLbmbY-Y1naQwfaKRQp_c6KwJtT3IzkOJlaYsUlEeoLQKfQI-OFr7Jy6N9-tP3x_0OpecilN6J7UQLOTQEIeygISrIiIkSQgL8m7YCl7cRejrq3kF9UutkU2OIJFseVIFtIKZL92vc3WSxj6A8NkX-yqQ9LCFljVw_acJ9tUT7tNyOF7mFKBQJPa92WpaOGgzq4OCV2nJs4GFYjXgw7uE2NjQ2i9_auhXryGm3uD3G29NjUQ6Lkingi5trDZLCzoFKtQ_-2tWnf6sC4HBlShllmYDfCCorSX3Qc9WvEwxLbRvNX0CgPCEoxIKHAE9UzN9sfWZLD6BCXAtERDgNqc458B3xIrpXpk-hmIe-Res9HtuS43LqebcFiHjjKKiBuUEBCSxSEYQPYdEII9QMsBsp9IoCOKL7y6m5EgCfQzA7hiWLlE_Xrppv625MGLzebKWzu8CP1mOPWTp4FYwaXl6sm0rgbAoR5XtNLcBazT83ji0Qhc39dVR0nFyvdSe9L-EFw6dbYUPPbQDh0hQVzwnXZYFi4wgX8iFfyvfj1cAGrQNfx2yekQfLm-vhGK_sIlCRVZf2bjS6rwAbVIhhPFuTsQ5EaYCc3QbvJg-slvxMGfr3gpUkMV24EE0dCemwKRyRyf9zH-oswETPMyAFTQmlx715Ao-RESnFuc1Ebl13oTofrWpye9ZaqqsGko3Cimdifa716i5Gkq2FJNQRRRrp979uFgzdwm2AL3Wa_5I1t4aHY0hFNXzKU5u7gNmtiTDyLSOIWLGfd44msxBYFSE9YqSdU-7KpEtOLQRppx3FR1TQooT35XW13oPp37k91Uv2j8wLJPAid7msh1AUWmpGiq9vhair7EUlZhnjNIEvhlTr6sIwFzsJPRl9Dy838w_UqVXhKcA2wJpTCjgRWXL8R8b6L7Qs2v0H554fmrK3qcTm1BgmPf6d0aeO9wsgj_cSO2gI6HgI4zL6PUQTsMTzhIY8pN8MW1jPWVa89yWjGjaanxKT6WyzdkCGj6NcG3Yh5UoKGeehwa_5FQwggBfzXYMIAK3swXYvK1bVz_68c3eLtW96nYc1mnOw0QmcuQ7ajBPpwPVqQwH1iLRS3nEWbxznVbgvcdHS1Sv8LcVU8htWp9JheVP2OCiGQPFFScImnsLDC5WZxJNohrxFO6HHJ_6T3py6zz491E_zWqb0B89YapQO7LKc_D3pU7_3-ug2A-BmtjReN5-I0QAaNX86gN5o-LNW8yl7DmVU8rDBHQBV7vZ4uijVQhDvpifKk5mqhztr7B82gamJD6gUucjs6nA9V8i9496A3dTMHdtEjeEIE5zkvtbLe44WyaDxa5KiwZikk137DL-hp9w5b2-ZjwrGqcNJrYwpTQAjHigL12EWMHKEnPEsSXqmYujeWGfB2M9_VDmSgf3J-XAZroxarSzyVuead1XNLHtLqQgT0Prh-PS1lDJ8jH5y4_JzNS6lN78BaEi-rBl-hyhXqi7ZEzGEyZVB-H9rkmCE1jnuQsHj_iWUkZFeE5wJRemTSNTxF_GqZrFTkTD68qxdtMg7nWns8pXHaqDxpWAFaONRj8JdfPCeJhQ3W9qIdugEHXFlYYtZLEuXAlBGkHQQlnL2XeZ5aYE7xDC2JYQRJBj8c5fYfusrnqBgsz4EIO5ewfwmX-OAJg2d9Pm0UVxGrXtTW1H277sVslv-2FcU32cZwwls4YthQ6fyoIVLzJTyMOYJUrpFW32r5tG425wn_Q8ezmTs90EKuVrvVo8w92JL6MDKA-orDvhvQ3beb9l7Sgc5yy9cb90rjD-lyQBgcDfJ0xHFnhjnz4S8t0yga42xeRI3r_mXd0NvRzTUHkedNMtRAdU-W382jaFGRBxXL_4YziKyewh_nGh6BlW9EQ83Qf0oSwb43IN4k6GmK6KKvwr_KiERaBougue7YpwtYyqCrEoMiEEMn-Sog4CeLzg6IuYx4awivB7VYGGGwU6Bwc2IkZkKUFxVhJK63cAwQX5Gcve_j_-WcRRGlUhI9W4RvFhQFpl0YfC3cLUzRQZfV_fWH2MIwrJm6y4VCHhnvx8O87qetR0kM7el6lY4Nrk5bNtCdBeoyy_C1sz--DjsmM-z9i9IR8PqMCZcX3gBry0Sn_js4Ka0cXPsKpM-GpR6L0CLxge1FdKNDSFUOacsiEzh3-LTu-rUUYglWzQShuc8_dtZrIEvVocirTKZ3gaImQ1M1EylwXITBxzCUW19Io1X1mxKiFpXKHtzK7AvEs0kdicMBNl1HsKSn8OH3jxwLSHI4DwFIGYBxCQ0vvG3NN5ZZ_c4OnSfQ-nojlgmeCjMGykcA9E__NgeddsOdWxnG3fVQFIiMzoJ1AtYnxHoPRbtVZdyWB3dX1L9AKxlFep77w6KS48z70KzKseRnKLa6OCPZwfXgP5kEKA7FcKwpwIaMPNxCOedtULYeDhclbLeDtjK8LA2q7a8elVyK6YRvseXaZ4-nnd7iLYLZNOv807ZLaYGm51X7aFt0YRTimfsQIGztdkY9aakmyH_XQkqPmlNa75aE4xf8FqLjwa3AZ9PcIS8EpwX_Vw_pFA0NJcvJxCBgY4Iz98FxssnBRC9dJ1aAn4Kd8lgWvHIXS974MFCCGhfI8RRVDl4S0QO7W6vrGTIZB1ngY6VHZQ1JG9NJOGtomR_8RNH98FwcPzVNUzy9AhGeKBS3WECJCxk_gKjcGB-rBogS4EU0BVCfxzCoTMJF51ufpG1k4eWlEiEpOqUYgUWAN_3XYWNhphToFLg-h1xmQWWUBiVS6tV-XVvEOgKCKp_b8dMJ_99civ11moW0s3XQpzbxo02gCBR9LQYl2OPBcoRr1bVQfmS3sljBMCgtj5NodsMpz-rIZtgbzdchFe-RE6QK4qaMwAUY0oldGd7nIW9V1C3hnGg0kekWG3JKlxMhIB3IbDAVQ4jRJ90_JbLVaj8v0cNmhAwT0QwIwuTJJYFDGM1fYrocL0UKFsHEdPGZQFnfGAeFoMQwUt3I6zpmXbIqWA0VpRYwiUwTTRNTSsH1_eX-LWUnbXBsOmr6X38Sf9SQD2giVwmji2KBw4GSfRjUsbae5gpgZZbTcXH2ZF4FK79B7kM3RW1yKHcMrT3jXyZKjfEee008n6CJraHTc2sBDtV85wr-TQgic1VgACOfee02nwbPgPGhlUsN1e1cBwTGCJiIthec58AQtsEGIsqpTwh0axbKUmUaOj7zuUjDTg0imRCdYb_iMh8ya-YUncdYTabPkBJYlnbHzCB7aXmq42akqBQTTTgVgUsrRy22Q9gn7CkGltOZRbiPZ4Oa6Uzu-CYOsK-0JcD1xUgtTd9icWNNbAg5DCHh8FhryzVmRa5VUkC81OQryM3CgKdyzyw4xSH3qw2HcCMu7VHbHYhvVEXOQQtSaedW6w1shQMbPRKt0Bf_n3DTiyvSsfAgZmA3lrhQhRzd710dzxxljzkbfYEl3Q3SKg2CNM4Pu8SzAcJj9M4WubFMqDirRgVIMgL4xthq9u4qvIGxTERgAu1h7xhUcA9f0IvKiPzBkfExW_QIYR8c9kewkGILCplgqOHbvNBtqK5uXJrnscBUm-Su8yfc3gTiWWlsb1KBm2qwj6uXOBWQ-u4xyatyltsx8AJlshq-YB-K5oJuvlwCXkeXkU3hqRM4SRwLng3VyhdL0Jr5HUv_M1ENVemAJCR1W_6IXWxbChAYiRUFVnGQMCf2Jx46eQo1sNMaO-1r1LdtVSJo4ZELftKu2X0BMQC-l9iQ5EfDT2VEPZvl5JszWbqWIlkr_RY4jwbY_OeQCkPaMxE0eywBeG5zjdTYzmPLm0YjmK5J-_7tjM_678RIQ8qyuFPuNRGFUClznKIZ-T7SYMtFie6XAQ6j3q12Mh4-zEomU1jIOcy2EzZzTVgrpmqVtZUB9wzPIsNtq27VtLz231dh2i2fAfAZHdvIy_7XQsY7-JWltkQ-fY41Dw9QOIhDb_KJHhFNH2xa3g3NGh1WxZIiJNfPXXH2pMA0xU_FnJF0uPEr2u0rEcTWqTsDgHk4krHglASUYsJYneG_YgBCHWWrGXWzbQNGYsZryPJeXNcY3hw0wO49CxV7gb56BbUNBvNIfgS6SogajoeoPTkPQAICjtAVhnrgXyIFnQ38zu9Cwjwqxy10jt04Gwm1Q6xAh_CNQwcLgtJ7elaM7zi9uEGFskPfZHF35EOhpMwR6wBoPSv0ESs8PX1_WKhYSakFyW7SewR86-W3aCDR6xznTr57lJB7BnDb9_fF6rjfysDLSjofLGwjD8qC43OlMNZB9m868hgZoCUKvSnTpVW0B2NcAoM8lgXDox6cxZPtDsW65C2fMFUmt8yqLg9MOB9QRvr8jQVvgQ75GPADaHTVbcDukGOlpWsE8qHc0y8sbWnBRwGu4lUVpyOe3R-q2Y9DVCPonQoeUt3r6EfyIPeid7GaY1S-jCTuj5GlZA4Ridz6yYYZmGXzju_OqZL9TpH14-DvywWaBu8ZUqvz9kVamnK9P_M-jTDn6iz2zy37xyEGtzWT5Mv82avznCG1l0kSoG7HPg2kdA2ngIutv3-sn-D4_H3_Wzni52iLO-5CdMjEHyo8IRF2gsHDwR0mkF5uGdXv8RD_b5KZtgMy91QfiU-h1B1OTDWxxhfSPDO00EtPBW3UPQhkMJY2_MdHzKiG6i28PRjUTIYDcQjc1RrUZFuBmD6S679gKEzKw25fKmSbk6MBIhBfV1Q0h9uX9RauUq8yFRB7mV2EQgMRzrSZd0LVqNtBcOCU7TdrpzJzk0pZkfmjIVGOAJ37T234ICX4_M28IgaNiluXWNYvW8j7k_nTy6-8uRVw30AJnkQRswmxllkn8sE8pfxq2ACMG6LhiwkUeRJU7QYz8GMhtn1HcppGw27GGLZDbd1fHQ-X8EyC_pEx6wcSKdLWOZJ-TOqBWCDHZAJJ44G9MQ_eYCZKj78LA5pooQ1OQJeno7YefrhaY7gsJEY9LqHaDBBrDYPefTlMYgHPkHKxgkT6QtpbAHN81lB5uiiN-o2HPIgI45ODYY8pmvk7SY5BVsu-lJ0K3KZJOhOsfQsoK9CWB37yZj73eFNgWO9Wd5qmmiRVbUyBrjWSXc_dLnbEAKxB08xoITcG4hDIO1TSbTIF1QsBKXbyH11lwKM9Gr3bGckU_ni5H49T8MeAx2Cce-oeZ26dj5jDGQwwwgRbDf_9eKjzVzH0MtA32QPr-ZDqwIPJlpSAIswVKI7W6-TVHeKdYjBufEUoVhjsJ2kZLNnwsgUPySarkA7PjTLxcS7L5eXTIzBWpcSqQfY6eII492F_RPgaAzRnqRW7FA0lvNcCblQJoRK80DLGM_oZajzqytR-ZgfJvWQXY5UAcW0ywx1hVklrP5H9hxJBM6LujBC-bfK2gatWTUNoo7ciIWk8WPKZf9jCnGd2s9YQhwqJfIoYWLYZj2obHw-WfedxSpLOl72ucoXM_UvtvSjnnX18plcNrQ5lkO4f23N0gh_oZhdwYeyeb1N-KADIKIdY3_6tj1AFOqN_vXTuFtEAilg5YpHC5akZeMvfOGunAVza3qucicsRDEYutxcXggArT_nUZa_j9X5lp9EItKRVyGjBvRa8VKDwoHe0Qq9JYaDk2zA0Gqz2BsXKjxS5eArOJ4t-el3UdlFrsrGz0IIM53LsVDnYFGo7G8sQWzxQHD3LqVKhumuL4q0I6gBmOZBhAzzAb-j3dE8MFDXLKOzpMXj4yY_f1BqaSVhA2LxC9FXh8xlYclwHgweVkA98obGvKfW4iMNKJza4tQ5A1QDFPDwcsF1biEPK0svQmSnHNvjhOBM_hRoZK1YD_RXmIYPWzJnULt_2Nq4Fus7QlP0m4I7qSxDSUe3Ly_RtLefBaV3G7dUa62RQJfXVKgbGQTy_64COJ89TVWD5LIEPW_LRrYvSjVlsMD7LPexlQnh6J4g3zq0uRHxcWa1bDQDUQYrQp4Ud_6qc7d7FoQqYbQgib1M_MIbRyJezKZJFNXN8aZWzAkSjR6Luk43uWgogzv_PLON19AnvbC-eLg3fE4aUvJAueCiTQGGFkBb1O2IW1kc4i8wN_II3s1TkjQ6KSvre1kN4YMOTk73lEcC6L3NcgOd-o0tPDO2O9E6I8FG4yCWmnFPjPO1FFmEnjAUSgwhEs4KdKbQwRphNPnZQ6dWsjKPVM5AfmEiLx8drX7C2NFidylmW1dpC6T9L7Qcvd2YbocFGnNv3j4ztPjt-9Z2Y4fZq-02HVNkkuOO5AB4TdPTftjgiGipnbMaBmgBNMwbxkzHuWZ-avaQfSifAvfuePdugEVjmjhcS0NQuh0_hZ-K8m0-41A-EqQ6kzgfYTwKuQ8JdIWawuYoM1Q0G1bJGpwQxG9DPDB8c6y-WupSOZ8c5l2pWsRVw7UJ47hHhFIsoDHFHVDBT9N85Y2SIRbttX2pcnKj3nw7aj6ZcTRwpNPN-Qvu8YMMjMUVV0QoIn1CEyhim0x7jqidBvcSHLamlTSqYvzDfI4l9fSA8m4Yar_VZSMYMxls278D2sxVIEjXt-fqUbXc397qGzvNniARzqZcqrataPpzQoOM-bNj5LEJJdYPqSsHioJGOkhFzWXu49UuMFYUvyNxOhrbUy8h1N6GKiGDMSwe9k9wN-5WhvfEf3wPAztWl5R4PFRf306CPhL-FW83zhBr4c1UxU56taoVNnJtsblxuTTDJr8HgIiS0bqCLpL1s-ZYOgARzAgymuZCRdaxTmK4fdFhlTs6coahCbrSXO9Iehq58t6uw55hGhAqMjVvaRn2TpgwtHS2jvGMCsLFBYnkVXeeCDwA8uIEvujo_WcIUiT7STSP1IHMyllhlhU9tb0sD8wadR8caAgHBe2CuuE6YeO4qet9JIzOLTd3kJRE9Ev7aChlmuuAElJ0o-ktfVIvUbwVAwiWV3X6AcMlmVR_6HzhwZvc64Phapf84hPMYXvnIxBSI5UbvA0X5nHU2lnqPeRlhQI0mKXvLk4Z60WTgGrJoz6mjUQNep_zG1WTSkLwk4zlLwupc492MMc-M3x-vYQBmA0J2OfXEZjnuqAQ6az1hF9SaaF87c_W-Dkd5wgzUEkoUA2kjAfLtSItyltjCzxTnH5gGs7KaeoN_9V3bj_EAquWTrF9Vdr0DyN3fVdwrjU7oZhp_CVfondyy_VQO2wtxzBICKDcgraDmcBS1Pw_VPEIXvNm0ia52zwDDo6h53kRiKECACeOLLwif-WO5IBh4DZ_DFsiuaX1dJyUUO_7vk56KjmN0QEHxaNwpvKMuPtRGOMWkRAwIKezgkGJ-GRLXbeAA_1qqT0hLDsqJUal65fXdZ_J-qEnJH9xThlPem3WrWpAYKXeVOLOCxuA-7wxyxO2DxHqJdxsvzd16aErXTcIq7OgGXL14QQXLcpQIKermnxygZf06I83xy3pkfwEY07BVX6MnouU0ybMlqeFQgsWFnP_yjPuYGA0RQGOqsL_Cz_aq94VrHtzL1M8NTQt3Jhpr_L908QQMXN7kK6CKJnDkh9Rzykak8Lig_xmz8E42bPY-RWpAgAvpju1nggo6H4oH41IfQYW2gVzTviJq9EC1rP3FtJouq9gmSH5xDo5IW09XFskxJatkvOUIjgtZhCNG_VxtML1VdSDLZSrYjMT46SO8JjWJcn__4tR6gEmTrzRE2OSjbLuZpOksXgFrOgRDsZuPSeBAE8VKVpLtHvRQKWimJumFONfHJ7JxCOaUSBzpvk88Wg9em4x7YAd_SAChQoT7XRtjlwkRszQ-TwYfGsyOOGiTyG9dzCGGy_fsTugpowfedGCGBHJpuApn7cf5NNyLsafquuDtEyUly0NDpCwF2i4Dhma5jQsDEbKOlHnq8uzAkJXRe96IQBj0FWieRJyLU-pNsgXz2PqRxNXs__iId_f1X7avOZHN7FyBa-vE-u8RuYGXuLsUtQnnA0eYesQ0hCvGHa71I5E3-w1DCu9dLeY725SC1yVZ_vJ2WJmwEPXJIXKhVgTfvw8GIEml1VGxRFvb5kMQtGbXChL1tz7Y35ux-SRoX4A23pTZVEVquaXb2QjNFOprmA0tuFeYlsUdqD82ls4R1WzgzLVRRF4Z1Jh9AFgfYHqV-7UHwJAY0OpYK9iu6PPknBPAxWsxnLxyIxQ_rRnrbD-AyW-uFhBZ5d38zkvKw68Fr24Czq84U_OlBAvHtTWSzQa_6pc6tu5KT43QDCeWwiyWt1gdahuyoqGpJNgqyD6gh5xjSr1U-ahTJpXgVjnbNBkfOWecj9GK6CMLgvcI21qVrX2IHwG9kMyQgNmu--z0VHXt0WUtEuUcHMM4PzFM5AOZ_oxSVtIbvoYGDXjUgEI-xM7BOr4e1B4n8X0aoorefQhCLe1-Lv2pKRSeUlX60RlVuRN9GkoD_UoFqz59zJwL3h2uakwjt7iehx7DeI2pHUthZL03BqsYtJth9Emw5gsDKfBIR9BAjIzbSFRnnC_pthG2E1WMRMeeKThVkL_JYkmFj4Cr1xjqXXCTAI9QFwcTqRI4ZkRgem_jqVB7H9-BzVDrqgbQoxuWhNRn3_w-xfyzv_JtRcP150_7bEN2-gbBJCexcaF-0PbkopUuQqUjE3-WYKc9X9vLWcdkEehB0F7eqzdIWqRPTsnEat4SQhSvbaOp7EgY6Ypkvjkheer3fkPelAHN86SGviWWtaxDTWMBwHQjM866tuDKWOEnLQhMb_IjQDFKHrUKUnz42saPlPWfvbas8_Ymk7bX-E263Wzb5_MWXqPHMt6UTMSOtw86MTE46YEW9Ww-WW10cmatGb4jfoQHXa_JxCRry14AjwF7CmmQLP6dnm8r4_jm8AylHV8iKCG6r6csAhY1jQ3I-24iLu01EDB6H-_bIX3uiZDXpf4T1aGBJh7I7INB-Ad7d_IV7At-qaorPyE1xvTWeFVQLymsE87ZHY0J157ggITtT95e_Q8_SEiFYg0vxg89qBpuXygL2M_Pbrb5eYTCA6K6N86CxlOvFAb2AJnhAmxe8c_KHIsFZPL6lReDGQmMPBuvdCjjLPV7seEZX30ZMTuHYXNuD7IytEJ7X1o0_04eCmcqbivHBCoQGOzDhQ86DSoX2Omx-hmQl3hI2KgKnGcnfym2Ukd-3CmHAyCDAv2kDHm38H-JdcsO2DNk9QsYtAln6XRVl5kFDnWEhm9bRh-fg9Lmt_mNkwHSwZ0YrdYhAOCMkNlukUp0EYKKhBSY8lsY7a_TPbt8vkTMSCmi2sPr7NnuyaxMvw6Jblb9OD885lSOUp3oPpoH8QPkkhYUJ4-HVmmMGD8orSe0L3k7lLbyHzz5l1EmMahHWCCbnoMGGfO2QnxV4v9YcsMmIA_NX_1CjMUh_LYKrVWE2tfmhj7Zdprbop3nTylHV6YNet5h2MVUtpfj3CFTz-7V0AxKhqmTkSE9fMv5_XY9-QxFKf9B785SPTdj1xBiOsQ0uz3TJ2CPFHOtikiqYkNu9w2cUgYejqlM0crBDpQCuFmFJCFNKrfMa7eue_4H3RSh8Yu9Yw1LXbkAuGoFMGYhegcBEvcxcDSHfZ9f1HFT7IgimpuFuoGHwaNhPnlNc1uI1ILsFeRrrXide0q3L78aMAdu7eFfSSXHm-RcZypE9LHU8caoGqd0cr8hMAFvmAacrXiUE6RtzQUZjswSOziVVwlqyszgPXIuDsA4m0AcaLyEYQ8fEsRZAg7RyRbTgMGrlo-_L1Me2JMPPbiuNi2EtBXz_85Ylbaz45KQ45mdka24ouxzs3YK5aPi-Bv-fYL7FhoIWM6AiJH5ETjucj9KrhL5u-mnEi7sYh6ttj6I-MtSpCzOLrIB5HZ-tJktRhN78f2m8h6N4FBL9ooQXR4Y-QC1MG4eRlAiugn97K-r3MDGQZR5fVwC8SPW4Pt6UDvfaxXZek0HmjYPEk63MIxeMBOLaipBGR2ziR6YsoTUZ3NOopXjZr-UsGukdLw0OIJsxA-nGjmOZCr6iDgY-EfaCAVwAOxAv47u05VBTOP1xoUhMrxNefZ1lt8hEziCDaHInMkDdc4lQVeYv6H4rR2KugX0IXGsFc-C8sfQVnALLdQNjEg8_AfTsEmY3NqE_ECIUhFwxaW8s8aWBgX97Pi8SxkCwX6DyksH9fjA76rP4P5kpWl7ynaOaCfytRliE4j5uDXXywFfwN64DWKIQt4u2gDGo9d12CWUMGrWZZdn3qn8IgEDmUdr_CGXIGcPNuS-wxWoh4G8eGNhvMk1V9zhyhcxgbjoIJLl1T9MOZZ8JQVpiy-cPgClLI2jgIbKSVZTTZ8B6T93aQj5oEbOw87RZxArjYP2XeIHMNh6JUUOND97h1D-tXlI6hlFtFTouMxLzyOpVJLfdrUcr2p0bkbNPAyk3qzxwdRWegSWH2nojJVRP5dopYDUvX3a6sXVGUefUr6llKEtyQ9W84oVESDWyhWRv6GiBkpimAlkoolaGYFYCD72gUISM-ptvaWmVvNmXdZhR2JCSn3Ec5K9TZMg0ArIgFvnJeksow6nIwDSYZ_EXqtEgn9hjLaOcKZSrixLgvGqWY5phJcyYWP7kBsJTxc9U7xCIDh_RCU8fjZzAOAl4r3DtGTEntqzqhScZ_-Fx4ygPgpi4Ko84FM0RvNQGw5VSrOWADroETQVP-La2KyDOjYo4dTauA5ArmYnXyLatcyfbnvgE5KofVhMHwPq-QSV7QAaN9aM3KdDRxBXV7YtnjPx5DzLQE_61NLQkdC0iWFjHwLwM58comkNfrKAUw3vtLzWDiLHT1nPG0pxYBn0zAid0cdOFJ3JRJl2F6-GuMSeUK6kCqbX4mtShWXp1gn0YErlKR2PFjCDNj1o56a5ejMOYAB_SNIjRLO_O7uGofXv_Om9Uevp9XKu3ca86Qt6uOpwQsifkwS6j78cGRTJeU0SlIAGBjzi6b4aJN--CpFIqF6JpuZAxhiLzsHAXRAKik3Lu6Pmb_24KBL5_ktbQRcQX6GQjGi0A4gccSOF3hdJ9j1any3RaFOA1_0HRAv-ExWoiQEyUnWALcqaC1FmXgDTxYx_VUMjeb-MqxAV4eHjJsR7e1q9cJS8qhubSQbHMH72GccTJKlZYdLBHmc0Oqejf-JKgaBMxgkGX30uCXhT9B8dag8jVrDBemQV-wak7QHgbAveaWX74ZsZZF6ZuZ6YU1llAllJlLWPVNr4aaPj_wMfurz6YyOJDnCcVxcKFjBCJRuTBF1ACh9Ye1aj5wDUVwjeKXnjEy-quQNoB5c4clujc-G-ep6-EHj6WgHZefu1HYolZNprU9zHY3T_OrisT2jDBUByHv2RajGe3K7nDZprR-e1SPApINTcKQ42Fh8SfDQsXg0qOfvMdKbfKJqQizEQiCtvkQu1oXhlO8fC4J5UkN3qsPcdG_h1TQ-_zlAPDJ97B_92zV5NkIF3XFM2iQht1oWwZdN6xwKeDRqKmpER-qz7bxiy9Hh1IxU5T_Ac5c8B5xIxbQzgTJal2t1M-_cRvGT0CjpEBjRxqts-KliiGxFl48wNePKySRiGEfnn4Xfqmy4enbmmZgyHCmo-h--qxLIxBEykrcQurpumcrK29z2_jGUNichMpAaaT3UlzgVTbOVb3gVN3Qsu8ltR1RtlO5DM_Sc6q3GQ2QpdHafa2S8Z5D_A90PuohDCpyqvS7tA24KNQEKYM2W_ONMBNNEoyU2p7hZezbbj5T_HLHVRPUiVLgugGFQkNwZ5cRgrgYqstoKu9VJWFE-odBF8G9GwHGFFqyCdBL2CADSx9AnfEssP0TSarXyn-ALo1n5f6vpUFmkcuY-4gFSang5orkODd3k7hSmsCxs5NVMLfQxPtjJcTTrKR04H7xAVNnt79YJYVW73UaXEUammc_qu0GAuNwgeaX3wIQv8ieBeqJvGbfOoXd-U6c8b2xS7b_9BCWtTKZ1A8azUrXAqOr5rXlKkq6I31ht1XzyQAWq3_YWEc8MJahqr7bR5GQqOxRg_adTocY65i1qhxebStP6XWRRurHWyHzDhi9duKfGK_eC1bbuUIevXsNDHdQBDNE8_w1BBBlg4eFuM8vSDZWJEKPxvB4Vl7ciLOs6-diW3bj_JDo1BZlpdDQFKCwDuk5RtRJmr9hGUaIbF6nrjbFduzQFh6laU7VkD_3XyqJ2C3dCD1vOOhslfiVG1fBWHpTJvKsgfLa0u94IUipo6YWCz8K-LCeOymEufdrfaI1A5qutL6tF0CaPl48rmLRMayxqTf4ZGCCDe49C74wOS_kGmxchhr8DKGUgKwiWJWQjIQLIk2PzaHSQ4cE8uBQebBsCMzlrzNr1YhYzvzhje-qorpNcwCluQeaXkqp1WST9LbExS1jN8gmJhLgS8yAOd_yGdJchugXdbfPXWD_R4oVf40bCAv3HBB3MxQKq8dZeXg_9xqr_bhwqY1oUraAHLEol6kUS--0eDJ9PzaLed1ZQ_6j-pHR-mu-OkQUvtM-THVLuNMKWGSYKcBnOFYw_1NpEkwoWtcYCzk-nq-aHJ5XnijDKutRPJQ5W6RLMmhB8qFoZpRp_aDS5LJiqp-Q4g2QhtSCckgUwHN5GSDTLaYvjkR5jeIDI0Df_tQZQv7BiusW4M-iXMunM3qpOcdAdfnBTmODqjdeBAk4dRnayZtb2Ib-JKl5ywa6WUDhpA_UQA_sIlBBbTjetvlH2sChS0D17boDPANxqPYQLorzUflL42ay1DQFsRRdnxTiNvzN3nMOxzFdIUYqWEiY29KQmAFyuERLmtWNxvUB7KB9WqxV21mbJ-yIhTsuUTHve3HdcJuWPzEtbZemmvTyJr1wckTGBWVfeT20e24dPMpBbRN24Mpx_tMxfsioxNsXFYqKHzqWqZ8Tp-gj0TUMr-dATGUJHHQ2Un1nVUYhOfB-G-cycBf8zmgcnA9EsKkTOlZY1LRmvBIknw6thweHCggBJ8Ke5N7lgYjdTTPs9HXMZk-YcGJ8Q-TkB4_Dw35xq9_hnncS-Dl-_aTs3FD-V3fAbAd9eYbttpwk9kwVnc3GzF_d-eoCntwtxNH_iYmdeBZIqLZAoDwzvFnGfVunFP4RiUtLYepxu1m7HLhPSCAQn6SNcLwGg1U0jQpfYIYGZTL3Ntq91XYv3J9vy5O1apgQZic9XEMxzOuoYf0zDEU41PaVOmGv-H-mdrmH-MI0AquibmsDkD1GoUssNDqsqGVBgMMp1kc3N6irmLeIpdrSjOLUsW8eq0YGWoMXXxp32wIfDr1fad4KV22Slqlrfv4RC2v15WxVI6j8Cn2l6ymNxCj95fk55ibBk8IgObZEwbu-O4F6focQnbqXcLMSHipxWVOo0PNAnxeG8ER8AuVaimP1nXVWhNo77VuX_Yat85m9l4Avt0Q8tR6Rpqruw0cxZRH-3GRk97-svz5QsXMJgNZsDquzmeRT7ydwFrr8NK2Ei9NmlZ4pziY4xgIjVIJgIhgkY2wEH9EBDPLuqmYrA9z2RC4KUg5aMAvhRRZ1Jrxd4uv6C7iq9o9x6AOVwA3AzuM-A42325s1cNlnURin7VjQvoDg03eXsB-G-iSEUw_WoiFatKsO1U8bW4GP1-XwaZMD2w9-NXF9JCCGp2PaYNl79WZXpoNqtOv7CS-USx0vOF6DLllVZebsUhgMTBHg6I7dmJShzC1VLrCV_XjFCVlxfSdC-HkHceCUwQwQvkH7CzkW3Xxqn9onVcL1vMKgt-D7ov_952u8jsS6gkzEkUZgSFKNUMJGZv8J1rhg-ZNUi_50EsohJTlxy8H3xw8RFN9JsTZ7T7_O2yJ-yB5bCdSHldOwfQWtPvCw0df7yzUQtkMqMY384QRdKraWO3CwhrqD5_j-iqM1nw3AKDnqvUZ_pL_MrJT5OwqvaQLlIJpSymmfw642aXt7P1TzzFnwOYb0Myjc0geBp6JKLB4MetCiKUxmYP8M3hiH8FSZLv00jUmVJj-CPVj2IVml-IiAPyPU45_2W_Sek_l6JDqxgviPNU2QfLqXLOgs7-30-8ZhrtlZLC1AYco0hIEyVvFBQC5CjorAuillJuZ02YU5_kNwGG-Avbqb2zLhjw3gO7ZB1Lz68cv8F5YVsUvCvMgRhgpr5Wj_5uFtw23HGXHKY2Ejm3Kjya_Tw1EbrPl7t-UYyUxZkF6lUh-ZnndeOB7RWVO9lDvW-kuu5XuYFbAM6ouYOPd0Am1Te__qnJe0cYwKBaqopwTCE_7cu9EH37OBm3YWyGrthggmOrcK9jSI-xA40URX30vYvyuvNzZ-0f8PrZIfTtss2f0w9om6vDpwxsWhXRlTyz9qc0ntEgVwX6t6xWklLasPIwXZpahtO8PAA9Vqy2D3t-nMSyeBaPMhkZi_k5x3ckiLR9RHH1OmiAyYkGafn1_aB381MKMv_8AS4YGzeAvaHBwwfNDBlPpBhdupAGXoGPKFCM6d5W1QoDhwQyIZ9uFKuvoPtxntY8MwG5x-Vwmg3GhIDiSmoybRNIpfIqXUVzg5_a9p9b0-Go59h9B1ntMB0K1Q0X1EtZq-tVRlv1MRpSjOl8LFyGFQ8rYS0aY54cZgE_tdOaozg5NuXDJPQR515WrBf6NyJ2E66D3u1Fde7hd-zUMSiASQXMKwCLOAMNn4f3MWoj6UR3vKPjtBNwF1umNrE8P1tErywv40kYGz8-Zy5Jub9dMgKEfXbz1s6XIqZJEDSXngwVYNQx2fhaO-uGxt-eahjkVAkt1KoTe3sDxtkX7CFQNAaVBlsy4JEqRM1-Mxg0GfAP6M5l6MMhbqkJoN4oC4TVUlASghOUHqkCorULtgKctw01Ea9UnPzXz-KKpA4RllrWdUryiRH2A5RPs3KH6mTKVjJmzXvs-tHHeQphSLLm3QV1smoj9Z-oAJrz0C-f_Y0LE4Rsaw8Ag_7G9OOrBOD1odrNT2PbpvyeMCv2179maxKeUB3WRIU_Mz8b4_vi76gODzX6t-K5zDm1ukMlpNLfRtD2FZOEu2S9dGFFy-Ut3gB8Vnu_b1wnzETDDqWZJ-6bo9qRxrRAkH6q3TF5VTKv_hnYKY6QzcmotJrdTNPQvwCztcqj4c45FtJyax2tdOQo4lhoqDapMA9TawQMxunVToG8YmNP1YKJljFq-ZFttAxcnIpaTYq9scd3cfS0S63cnjaMT_H_LEBW9FedIR53Ko12fyQn9cLgErigUWMWwgdTmE2rPo3ygRky06cEcrh6zUtNb5E0Xt8FnmR0n53wZbJHsX9N6ficGSVwanB9ZBGJz5TmRHdF2aE6NrALFCVLZ_9mUP0XVz9HSUH9YbauXqYM8afLJ_R8XNm1WtqX6gWkCG4HulNtWURyTWgVuQT4jiB392QSDulnwnUnaFiroMxbHD6UENVgg78icspfeRQ3I_wEKLpCmngQSDvgNlV-vzVct_920i-n6DSDav6Ez6MgxCa0cgrF5Fbzak-koA7olgU2xqiyoAFv02H76alrTcE6Ooi0zNIBABz8McKSqmJDhJ3RTpCYQCmJ71Xq3xdeT-9-WBX9QgNEGQ9BAcZNT8IHY7yUocfYNOQS3XbCogSc0HR260BC8-8ijyyx1RfZB2kErTGpUCo3FQJLg8QNYU4cThUe1rmgzC1aJSHdYD8OLKHflJCHZiGGaYW_MA-tBWfHiEISIUcIghjbVjF2dBoMZBW5hlzvYWOV5y1QXW0zvTJ1Tw4R6kJGWNTK4wePkrh9W3t4wMu2QvyJQLGGwb4ltSDWefD44MtkWdfquG7OTbXqEiPr2KreJ2j3DASXuBDBD25RvlZc4bhLHFj9BUJ-lulsAvDWKCb2Bou0i6akOancevmmSZUwphs-hQM2b3ugNTsgsUEoF82dXWCJ70gyr1RFBfBsZCYDMDWbiqMYC221y5Pw2zoHRdQ40xDVCmTzDZZxzBr3ywIcE0Y_6c9tlm4e6EgOkdHg5KaAV9sV_uMLbBeSxyihQgJuxA4dzQnCo3Q_owAGtnkvhQp4UgYlx2AeclHenpTuFb_t-BsO1-DV6LgRplzfXH7ocQedgUXsd-gZtA61tnwNR2qRk9dbmtOikjI7qf7tFv8r0pRbe_d_mNadmgformlLzAtUn87xkZLmcMx_iH0g7gW7gbEXnkKmX9syage0xeQ12qnGvGF-p6mBKFUM7d_8ZBFt3pSd0M2Wl1zLnK9HQJVPXjWWBf8r9UecYdpyhtZAnxREWSqG1APYDP8cPpQcewy_QaCnVqyYZRFkf6X6ch-O9sJAwzR4MLElaZ31KyCxHTj8565hGC5bJUdg_I91UgH2yJArG54y_Yc5Dl6ALUn9QgPzbqDFFUOJjwU5o9uD2XyEBYzEErekT-GqxtSGOgCFSStNay_o8OmjolNWZVRc1_aFeMUOgh_GJCAnBMs8AVNU8rG-2bL8Yn_08Lfn-QpqpZIZIVsTZinG9cCIy-nuGGUtwHtPdG8xntWD7d5rNUtro9BCoxdrnbFOkSAwCQ365HHDHG-D0bnxTd70UQLYZcAb6rkxFrENHGBQFl5f1sOWZnGhofb6snJCirTWsgJcst54Dzu14XaX-57i-J3gi6pI0alrVQhxukhTtV3oj42A2TUGD6Qb2P_PjwhVbwpyfkd9tNTRT4YKbB6v7FviTl7JKRh_lMFAeLiNc10auLFBnXOdq28pbt64ilr05QoEABo-2qj0w1qRgK1RfdC_x2WRHcrI7zWIyDONsyqumIklidGqrEh8EXCSg3a1PBLMIrUfkfyV8C7LvTL_lifHl18bZO1BJtoksrMcCmPiwEJhCCMn1olm_DSh1YHahgEFrP9PhmLrFpJrymDuzXlWENX0QfqD8_bsiaIC7sqi4ZCnGI-KCnePmdiATIkO1ROI0ty_1kRce2LFztuwYFLY_z1yJlFflviLtyjU2z3F8Dl5JjO2dWm4n7bBCRT8wAqp5eztDZdaiuQUZKi9vhIuEnqFpL5zQVTUlDpMWodeYlcEZT0pQQamulicCkRslA7Z-CThZgOW3QWCv3eYTvOlZ0merHzQFxYq-8S_0rfwK9BEA1xck28GdMIXUd5cqBN1kUPd06qbwbCAgVBABucXvWbmkCeokCXOyfxb2BHl7381ZWy3_U6M0AnKzxhtYBSmBjY8sQAeJg1WTQ0ZpbMT651_b8ipPHAUl57j9rwVzxrdtmtai0VoUVNv4UEF6gDR_byb09xWMXgCWHrBMbbs7KNNC307cI7lmSHDwFDiWjxXcZtGMCix71kfh6uZsRBursMcnUoIaGvd_Pqv7SKeo3c1DXs8d4yraU5VqtmvHuodSmfcmOCEkzLb4lmVfBZPrsJQcLb9xFH8wunqxWYhr2ERzOJDZoLIKNwQnPDcxoK7UX_tLfbHKAO_CcfHWRgB_NkcPVvf8jViQRTrskD_19WqQFq241yN8yW4a61C6v-9og8yJyy8BWPQdiKESA180YGsfujYRx40jXR1u0g-WgRF35S97vOzm963EAkAmfCPBpRckAFxeDcb9DfBvhihOeaQEobt9UNhiDTNaiSN_Hl66wA5DIPIptw0_HQQLoVQ6HUevZymcwe9A5p7_AdCf86KBN-Z6cu7-5OTmctbwROcfjMYjlJLXI4vSE1fY_BdaYPBvPWsGaPKTNr9kwy0RyDrYd4a3hzDBzEOAGUJm14pdaOSbjtwoIJ0m5TeQRm-e-EBqxv4dcABhod1agzhWgyKZarIrtkDhGW7dkDqSdxHzPCxphtD1a7SD2MdKfz0IK_IkPRSr5N690e9kBMO8r0MmuMg85Jf4vA3w3-ywnIbaW865qXxkW-3CYgJ8RloGuBcJewQH13Ozoz1FAlt1Gt5Q-uHiMokLpmbCmvGVk7xPXqDu_sqRhQSjlEXRBjmGzeotBxxhTwmzqZfJxRXEdmGAtrfqva6gzYGgSdXFWo-_wfN2-DjBa1Z8FAxpmT-dRPNvaKwOmknS-tI5xi2i7kzmh-oIn8n-AJ6WanEBaFc5vTC9SnQNxnjnnbTu-bRMj_KlXXpw-ryvlGEGhdMOqfcgSWzQLPBSVMJpDU9rSZMfGl77Q-S3q9mRfjPnd6TqlNfOskpiQijqlKNvhC_D2S8SerwBOrWTSZ2i0W2NKgtAvkgn1v7wHkNIp6iJ9CU0mXIobg1uDrdvReirxIxuznqXyf9xma99oqKmQvh4dWfhlQH-a8AB1Hl624CTjEs4CcoZfCm2pMpcDie4gVvQiGkHQosnTdOA12IX3REq8peIyawJpoyI50ConQxCFuWqKfZkxvaLMfVAHcpvRNrNEF-jD1lf6R1emRB8jW6iQLCKYVueF6qfUsmb6Ql-gmKcakkB71QGMSGTa91eBg--S11MB79NFQdZhQDpYYc5GAAKTR3PF9Cj-xk_33qn0Xz3Xw5jRTZqm-qVcqPMwcdxcB9p8JhtWuhGcfyGmON9hM83JHg8xKGUn-1qPOnvF1yWoRcI6wv7Xe3jfo-_RHLEwbPTbihfw2H6ycYxEl_iz9zlG40_WNJwwWDdHn-jsau08fNxdR4WC9FEvC7lRAUeQPVxUWE3ziJjlDMeZGz2jy4daSi-LY-QZCzarHtQ4_olBcW11Q8gtV0lOBrkATxbd7YRAL7_dh54Xw9T6X0O7TlpofzzAVMZzIn0iTai8k0eAzuj3DT2FiCHAh4-RbKHr7mzyrPQ0MUmJp2PomCnzG25BUbYSlClBcjtotLGm6YuDPzB5X7Lu_vH9eRjxMEh7ZqIYO6m81D0dwZO9aVZSSwa_LBb1iBFrHijTsL8rHXXcBSnp_jIaZrGLyKkxMaJDegmLd8HdgACP3rOqVCDg1n_CVE3_jRaqwwHJVpani_j77aSGBmItjp7HqbcgZr_CVMCBHX3XfzlhuXZkvBoc8ZaYYifhvgGFGEg0jHEaxIIU0QDqm2L6dHqCH6yAlkkT8zRgWeLH4Pey8nR2KTAZP55YtaaU38cUPOqVlvTmPihzfNHH18h0vLfaPPjA712C9V3hvVACSpU5SsXQU7NfnnIO7_5ZcX-iCaEuDsSFlJcAJFaSyKJh5kcXsGdRCAM5nVfyH6_NFHzGiNWaIqc-E3Yl4a4pS07bpe74bsEUrxUfdgmY9XULfNwuGPVg4qBsSoS8coVBn5SxwVR6OITKjr8Iq6b8EZZxxc6qJJe2Xd5mExe6NxAW3sClorNhS_wwcBYwj6HUH8SmXpZ0xqADYVqky8bn-pa5j6RFNSH5zz9deI4_1ioLhkVtvpbRFHOxCPzm56wjqQnEci9QQd8axmpiKgHP8HnpTzLHO2MgqjjunSox4sXOz_BEEPWghInV_VpmFb0KN0B4UH_M0f9Yar4O1unjCGwlLF_ZfLfNfwmi8JoDRMYIyFn6D1PxQgdBBPKN0oC_Z11E28WQqTORvTJqusVY4qoZ4d1FOkd5E9srOWuvs0gBGweaIzUAZHdRGr4NygezGmf27uWSos68ZHaB2qOc79z_TpsXiVeik5uT-pSbt2R-GEIeg8cwCH1J2u7UHsWLmJFyUmBW3K372QeHxoW8UKinTNg4Zy6uF5acVZmom5E8s957-83Qcs_unrHFoUTPy_KWoiqRefrQcpmCHra-JYSYwNxfwgzoCp-EHgl2ypCIZ5BpRQHgKweWJWeRhioSBwGejT7evYEl3-L_FazZFY5W6tKyXFktO2jIySP0NMGxFL8S-PWQERH9cdm7l1KN849iSIqeMI8cROEUCWjUIhdh9pXJnY8vYhQBfbEjJ2fJFjOEtT8ARZe1jBPNUFdoRph8YXVXRkHn0uw826uIzZGnacbNgRwgNdilq-j1Rj5iirOQwXSQ1s_L2Y2Gl8O7YZ_tuEek0ovZnebzesmYKtoY_XhunbD_U-4afK57BtBTsmm1Ed_AwfhZNV_vqKC5DraEE6c6J_7d1f3NJEMVK-QDm-iMLGdLHjOr3bf8TjpeXNjITXiBZ0kJBb_qf7Y6Sze1UueGWd_23NVi5Ufe8w--C9fE3YT0Hl0wnSRJ1WvOGlLQf2Hgk8KaazMuCVbkNFzjojCQ_IrmsEz2sbWOSMDB_E2y-6JJyET54mCpfMYhdHXVhtbAH0sdBNtp2KGfh9206nOJU-lKwjo71lgNm4XoWV5Ux1LXYSeN9r7BSrpirkFIqxyQkJez9Ulcbiz5ES5t8oaTwCOnIDE28Vy324HhGPSi5W2QPkCOV_PjOWCeM8yjS_6w_FnGuO_26ecaOEkCNBZung5p0pHSmD9D0SeQ55YvwYvwMhT3smiwDo9dRcFa6sigkWHHKtBLW29sYLB4r5pNWtHd6CihJCcG9DTTbaE5qP0-eOF1l4GKEhtIUKDPGJGwEzYHjq9emeIy1uacdIcWTCJylvCVOHdWmLaD1HefI1tjSyga1LuX-uZPAYEu4H3BHd_8RhEhTIIR2W1Zi4pcy___Mg6UnxiELbieUU9M-kBKnEG8wm1_VCAJVg6GulXQG20z5Zq0Zr8HsRUEpcO6ULm-_3zF1WYWSPU-JDi_ZiKxGdLOidzU4gb-zzrrLYtA2USFwdncVimCESLHhKPSvv6r2xX5Hz0eTuLmhshN4wL2du7QNz_mLVnI0aIGrHWQgs_DEy06L1P4ANm_Y-0xdzookmfICUGKChRsnNFH5Ardfg5JWwzC_jQrW1XM_t8g-3Hnv_A-UzUyJWBl3ezae1NPikowsbMsIwLuHHteDmQmqb9-93yiUdXB9FxycWFgaPksF17KxTvI8FS2PPwZKsSOTXMQNCQyFd4fJDR60nQhm19DhQImTl_QPvqibTAg_p5zlhxlEFdMKoMEdSrqovWF0mKoOLbIHlGum-tDlq2Ll96PE2-CrnW8NyHVDdew8iZSZ5dahyl3prZnh_EiRB8nNBESy8uH9ppuSH6XlQ0TJXdhwI1ZdOJvFonZ-7IBR1TVb4ynvpzRt-oWE-tNx1-6qwSJGzrsKnn1EYkDQaRj7nfztiOa9af0LGUR5ejBaZVx-bQ-75PO-xBTxd0UpI5kyaEf9T3rUM19GzASEzvIwPCPRplhpopMmPORqBqg1oFxqI9vzahfzntnYmWEBLGc2ks1NZWq1gLcSZLw947_EEGgyqw51cFGXLaB1DeA85qa6WT1jRmS4Fjj747XLPynyNH73NU8RWsx03F0y_fvUpPGS_vaXWR8AhEy-gdBW5CCYbsPv7WB1Ls0_DJMBSHylHgNQvC_5knHobolZyERyyye0rwmLca0TnAJS0QhgywEwaoateT_H3_aqypXAFQdqP9aXzDLINETQH-jPND97CG-mhA5bh_mmulEvQMxHyt1e4d2IWPOJjYUvSj1gaxoNl8C_v-h8719rmYl7e5jedHHzYQuDgq-i4B8HlQxgLycD2vQqtt9F8fadudBvjaa4qaHQNw_AZc_8aWNUQ23FdSfC2ZSwJvYASGSz5iwwZotTwF92WMyzfnNvdjFyluEZR4D2RXnYP9GUuwGcg6LvtzjZDq4GoOG8cZEqgSQpSUFWN4-NUVBrb8GLY-SDo08tW7Q42PvN8h6h6cPCpFgrKFrqEuNupBiw_GvD-Ihj6S81070U74EpW3yin5jY5dVGJO_Q-8GBVsyfe9VyPGlDCt9p2-FwvgP6aMZnWAQys5HjDo7QxHaLXAUAJEB4HJatbd3sDYsC3S3Py-_NDzA9_JuOI4iqvOjwf96mS8xfOkoDY0CyKso6cn7BWBDbtgGL5yjjAOrsgyRzALWaUehhq0p48D45hMtJh40lBfgA2QkEqXaqlFdooXKlfyn0nePdsQPYJWxg4O42Up_ha9yeggy_bdTtWJQlR1bpgphhsDFFhPq3rrrD54e-AmMPvLS_KnhRHR22d8t80bo2yhrXzT612iv6Z_2_wxWbm8AnUB1L4t1pnI0BW9MLhU0EC55f52wZCJQ8wJdRcH4lbuUsZ4ioBA8J6X-UtP7YjjBTeXITfvyCaLvkwGseuU4DCiTHh6mkqIq6ynzsg9kXqjCB7oDfO8yZm82JEuzLWaReeZSub0J4FAyCUQImgs3Ui1shcwK6IVbk57-Gjywva17R7qQhkYxqeDCbrd64y3QLFBnhiYSN4TrR5AaPiNz3eCYFYPTdMjNCWa7HMb8wgI8Bix513uKuS7HenMc_h1QwCzrD146GKiiEZ0LT2IIDDO8h_gKx3Y-7N5B9Og7wjsDps624fXnr889NYznFOBwuVhNmT4aULq_L32VNXYO7bvGEm8T__RrBnigqlftf0nHzP2U7gN3kKnuCg0VryDRRs30No9mmIxpCzEkGfEDb3g8SxDiiyOjZEuFTG-doTdRDPfe8DqiPTfJdFWRfDkBKFbpnV46-Dy1PKe1HdpoF82ggBjtwT6N3GZ4MPq1UVYQ6aiwlk-vUpetZHohzn1AD15XlDE_NfnZHhvGrHGApPPUFCMmZRmqQTkNH4IEpUDQM4_SacoAIdkrgHO7PoUAFoHYMpumQ2pow4VTR3mj0tpvG-iIBbcxvqc5XLQQZhXuhDVAEl3p8HPTDKqFgxTxiKT_Ns2pfkp7zHS9-Qp6VzlZgoa1Kt-ipc-BOpwBzzeDqg5bOYvDF4mySuTfNy7RnMfX2F0WZKN0j0Rbo99iNUgkvxQNTAsicaZGuGWaUbgiQI5OT_kltLhbL0Lwk4AQpgKHQ0OBgIYC7ONSWNWlHqRTR0CGRYRPPB5tOfzJ9iVeKQKgTnH-PTukqdsxJyrwalRgF9I_b3qBXCFeY7Ea1JyqYhi2c1OLLoI8UJ1kNsH9Jsuww0WjthK7U5KQEHkQTZSjdEyoD3M-daQhocYGcPqRLqt_kfDWpA9fQYJVlMCUL9aQuMdYVz0ZzZwV4PhAoqep2MwxErhdjEUPhqyt4mVopZW-Zyigqpw7ef5K8lrBvtfLV3rt0hFTzuxACp1wQOWVsYvY36I0Yff9iHGHaOArfsR0KgDgbNK7E7D5CtFrHyOn5XGjWcdjLaYKvCJ8wKrIItOXpWEMxBCcKsKsj3bo_jJKiKYS5hVeaznfwc7pi0J21-4BAkb9Vs4XqIcooEFbUlqFSxWMuBokQAsxBEdeZ4ZEWbD_jZdx8NxELKLxPuKiYYmaljKyW4NqhyeGPgFxeHV7PC8fZ5O1Zg2sTMkW7J_BkZte3oGa9zeENRYMYmVp90gURGZ9vex7-GM362BBH-Uq9w9XYGL_yVfylRVU2PGoCEmMoxqgxsYTt6t--noIEO67jMxWhOdX-i2bLo4xdZnTBBDiiCwDLBM4SS5FWv9Q1b5NO8GL9ePjw0PEowJy6Lhq1MEBrQSR_AiNr7tAQPoJc-ltUMtBCn0FrDKT8UZchBVaMPazNXHJyJB__MZfJLc36Pr3xI3YG7C7plb4MOzJ2UU7knbHbcGM8WqKykYOBlde91ywezS-WEo8EUTO9rVUTDPwSPH2NjnuFnu9cEAmXYicqip9J5WLcnWxKuo51O53VaSXa3KOwkRsh86PPoxbN_6boEBx2b78eQOgVrE8T52OD8SryaCcj7GmHsA-nLWXhAZ98WTCCR_O3N3JZSMDB8NNKaTdyjILTThzcZBAMHpCZteh3JxXO2kiw9Q53cCVt-PNAVFwgANiyFFW00sGKI1VxK2SqsCXupmVQqzwJ_VN_KyQfh56xgMWxEucdcbneMoOWUzDZduKIBBhM3BiiaidHeflnpuDid8poBugQVdxNZdxxi27cdV7h0ieu0WAJj5G4DjNY5XI-S3cilYnTXUNg3nE4kQb6jVsjVPKwS7sur3AvwPld2qHJD5Zo5_63axnH-FQuiA2oF7pZxoYiz4IYY94ydG8gOOYteoiwEDD4tDi9_p-Vh19qsJ8NyAaC3sO1mKZUhLpGX4W5vXI9bONL6KfiZtpGsNOS0al73DiqdLiFtAcp68geOr3ym7Miq2xtthT-mCiNOn4HugT-rogZbzPlRK3aHEY3MsLL2BBcPue8ffnazWOosLQuThIGdGwHxSHwk9crZito6H3rfhy5FQYRZELbjkp6XwSzWqwGNh5PvS3a4WxLOImjdS_SdeFFztTbz643sos675Aodwntlo8e97352Zl54dJVBWQQQXZe92VNcHdywcaHzSA2NyLRWz9kJA4R4jHUBq0Kd_y-f_4LZMgcnSJyB_kxotskTdJvy8K4VSB7NSgMxkfzv-DWokMaWuZ6i9lhG6laXjt8SzVmZnBXx2fcGgveBZ0cEEy_ZAjwSaqkircbn6rIcmwjOLxsSvcyHHaB4371u2OZzhoM1eRQ6I_wXHJP2FW4zESJYPOhSWtJ6Apz4rHoUnlDCcg1MnT3Q6PvRNDq0jB26NCCl4ixvXlWtuWTa6_bXBARoDauSXsf9YAX-vnSTK2lOz0pOWgz_QjQw0Lx7nEi4sMXdnGvQNxkSiGAmExZzqAPZwMGbdAJUnjc0jW7Fi28MG3G8cHvO6fcGMo-IHUlH1hr7vMVCViYqjcZQOJ6YgAQNQNe6mXCcsSJij3_AeMXOJvC55N2l9GkRBkByX7-NO0zWRMGZdtYxe-25RMM46v4AZi3A2mH-31HphZ34kIlBH9yb-8Vw4cdUHpY42kEhnXusSk0gx_bGxqJRVVpVgo0EAAAkhSRkWSqJiccp5iZ1yZ2EpHOgEM1vthLyCualal7K-fTHBm5jSjNqNNiZ85xJF3tbnHSjLNdQ-sYcUnhDFedPfS1bzfVZrJBfzjp9_itNRPeJnHhYGe-K9d5TQqjrBAtwrGnMkGhpegfK6Ac2Nklvcl-yCdX0Fx_OYe6peI4slr4S9XmZBj3ZpG7PX4NdyAKDu0GwufKIcSATJlFk-1L17vj-b54H5iFj5472wPjh-E9NJ2UWS5GbEC8TPpqw5wQH_Q4KnOIE03lgzCcImIKW4jK52uCSsBljKI5CXQzgTj2lR2lf7OqqEwyuFP6KEm4Gbd98fASaqrgFmR3CBqJfFkaIeuluglEt6hbkIQU4KlhVJ1kwkOq23gcjyxC4TXYEBNake_62MYh17xz5yxky34x6cl8B-e14KXqOG5qG5ug3gsoD334ICr72xkt-m3mICgkUYOSBE83pb2AA7YuW5IqwTLStyt03wQhYmDXd_q4FBM7ZO-uwue_cT49vvpDHBAL7zwG9if6P_wwVVqO85qFfri0-S37JXpakkJ6_9SUpM18Yo4g2SbEoFLE_psEgmhRAVyGZjGMCU2Yb2Nh6eQaVhuiciWgij3Hf69IJYKZ7dgNmCuuTMp_VlJ0_bDWGlAQZUvZoXemSxVUvOEMjNj0JxhAnuo6Pi9eWLcpy018a71RUAcCrdI6NLvPBNr6qYJgZL2YE6lLe5kN2xxuxtNIm0PdkyvAo9N0OGwXOkQcY8KxwwhBPI01FGQ1ULM51ICIEBERqQD5-RkIAICNR6o8zZD-6Iqah6mvg2OOhpEWzyTuIV6y3d_hOKpYtdPZ0tYpmGdXjl0CM6UZmUyAxk43Frunx0UQg3pA_Awwu5YhXCPek64_gbjQve8bn5Dxl6ZAvBAk85VngWQNtjH4JNk2GABmghnZr2ZHWhO_GX-q3KKTyOqbUjACY1il-tUhIs0TkcQqrYLRMXRrSACeDKw1VWm6iTI_6IYfcUGs_H1Y0fgyCSI3lq3495MNy-dbp-G5WiAQCZI_mqzoxTcr0EifYsDKQuzpSs4e6e4beFerRgJmLVr9Jgo9heM988Va39i0Vo0AEIPlaZqLXrAz--eT1xxSdBi6JlxKS2uzYsl800ySl66rIKPUoXdkVni_F_20mmkwEGCAQ4ZJS1g52aDOSjCYPuP4nUfCCL1868DyocogHBIwr7PCQ4-_0e7rKflnzCoPtETbNRKJj55oRaiAlFdqaTWWSMp_LjH7w0GFXxzTtnuur3GA3QaeaCO9bIPf-kiFhBArunZ4iY6SdxqV2bu3ANgoc35zfPy7r4wZDnS2BfHFn6KXRHhns5yN5U-OVjT2pIBWbLxQj8J8TOrSGYkpcTwJ526XWPKA03qIn2pOEe4wUDkW0tkxyyIgt5cCjSPWhhQQLsYYKJ8rk2ojWvIHSdHSgIof0eVI51RGCW4jcg2pJ3I25sFIfpgqI5QipxB75eTIB32XCBtzWmK2E6dPAQfnHNPYITbjLmOrH2f6zbW1_LJ3LVtMMijseSomNhA0v4KUEBy5aOriMgwBRc2doCITBcWz0OD6TCXbcrNvW7g6BDK67Ym4Vpn6bl3B4tIH19TNQB4YhX4z2kAyhlOOlvwqMcfhtdiNxuSZ7BAqQYixn5dDpswpCqiI_MjH51TMikt-YBBCHTr-RGRIXaWxk2sTl01agDUdyWGJ8wsP1f0ndpLm3fHdejNab0MOn6osZGpP3ZgZIYoX0o7CoF_5lVDdc08Dt7L_yEmzk4ccF-JQ0JtbfYdzvc4OrUBm3zQfNVsdw_AQHE0H8y3wolZFgsPzAOF39j-_9SDKkZQAHkO42MKEBuDYNRANGd41ztyybua00Dn8XEYC7OiWofp6CNgeFts0oXhYM7YU-0A8h4n_xVYrk-0Rb-zpprX3pmPsLySXIDR0EBHRdi54BjFeutO1ODlZUI0JXKinpc3TEq1Q8Umhk5Yid-CmzYfaVtt65hsdKIybzDgZkBSqOZHNlU-qgtHZsZjB7HhlsQH_hsJMfO_GDYmvUyL61zZ_6i-kzVl9kQzarBALNWbFaReiu2SG9cY4n8raKYyXQxQXE31wFUrKaibEAXJlq26xQzmZmf12t4-3ZVxMi15PRbREWLYGzqNRARqU3mHd3_FPTeaLxcWy-KfufvSTVOIYkKoAXAbHfGckSZgQMlCPqKvao0Lss7N3bdcI04kJRmOcExYhAXvepyznGreKpfwWLm2YpoPgFuWq2cbkOg_KNOxeI-SCe8WL5geA7u7S-PPZZ89jarsvO7kPAIQXxHg7a46y9wzDLclZD7UcECTva6MEKRlMP5zsg4EfRkmZ8AQcykymQikio50dvSITkyqtD5XLkLYv2eypab6-1CHu3z-YUQSHYLOw4fsU6dR8lToK4I4pl9auL2j4z2FqwZTt-wnGkTXTevikprpz7BBaY78BYmJHquSGjIEoy59aBoFNWsKLhyB7r-JFAVRXgZAspE59-JmzJVSIfyNWXThYFzabEXW2VmUNRAcb2pRUP7KYWY8xqgZTvQZ2mtXQBY4GpAoXR6jgH-fmWg988kAQBxRnDoZgb0VqOUNQK29C5BIEt8CsHE97YSouTsqqGtATh9YQUinkIpjyHMAYRfnkMiywoFYeaJdEd4DFPIvJ_MmDWtg43nh4dbJahewqSfAzmFH1B-js9WAG7bivifCkEFdHfWcyDybAKICp2iZ4clqNYH9EoSgYJuDnUoyHrBvhWbaG4CZFi6bALdp68fj_7D6MCId76bo2D47SRj-q6bzrQFHvrbfK86EdM5KbJftG9ieNvuE7PjAEAheezl1fxBBKKZDCnxPzovqnmBX3mnEy_giFlxpBfUm7g0ot-FrszjXCMAcw4PNQchogsmtV8zQ8XZOo2Rlay3YmS9-nK2Z1jEBXckY8C8y2IavccKdbWAOUidl9LsHe0wLA0tC0YcAQH5HF1yfqhXeaUXmVA1tF7vJW6tBMsm443zWLqD3MvCjC6DoUb1O6IMaeSwvS7spYGuleZPr4OvXuWcylIBgHS8TlIwoo4P1zBFAlYOYCGsulS8TBKmLxOWskPS-grktYEBBK-uDxU9pVaKCMWy_l_LV8-r3z2HRajh54V3cEsSiG5CF5_EVeFJzAzQTGd79k-AjLERnGw7kNMs4LWMhPS-00_R3nRt_OPxiVnSY_vNyT3HHpf8Lf7NQnZQQ7jM6d3BBSmIUlvlECPBpaVgP6oc1FKSkSPs-6DGL-DkJW3Xo0WlcJKwl7rIXjCrM0t6n3ioRNkxBOg3grZKqF12fnWOn-jtqr0V0Iw4Lf-3Gh007OcyCIy1-RENp6DXM8JKsg1XwQTo7OfDfyf3ZSDWOLan4L6hrHPXKBKtk0m1fJvJQ9dwEM3jzPWJBilBQDI_09Nr2MCbLzNTGi2wzGMlMt4B8u7g6B5wmRWKDZchS0pSFgP8B6maEEZ8JH-c6p7wk6YfeMEC2Ih-KN9IEUvnsh-b6jj0FwcqtpWKlHBJFWJtGnXMT8rDuYX5Mm_-lAWornFLriTA8I9uu1ZOGiej0pWVgoQVWFawXYkYuoZRW5q4OGBwpiPtZIYAyDoZeAUOu7FAqrTBA2NfYfJr9vsXJOaDiYPDHRgf9IPb4xQHM0YSgpvkCDTERAkFVgQ0lLemlf2qcUXjgmQg2MNuI1NcMCu9A9o8-g15M6Sswsu2uLf8PD13MAUsf2bSudfdKaViZvkMCJ-VgQKsy2y-9J6nybC5tzJ9S3yfnlqMyHkbrxFAUf7NnocSzZcRtuRUpuGZsx20gb8xHIA7aUuwd41zsDvsOUpovILruvtFXnA2_18wbHXFKUGmKPHYYGLsz3rhJNtjs0dZF8EDD2XVmxsow3EHn4CXSQkJ8x3D5sDdyQE74fx_9l-BybhGK0-Ww_qLjHwwArVN6GcDacya-onH823CihgmmZKN3bg_XP0Q1c37IUApEO-R6ywQpAOWGv_re4uecj_1jmbBAxwRcvCNpNSwoGTm8_KSozpV6-vadvp_RC3TDHkH7f97yLxJ7ROIt5J8cQl-9eNJBHtVvWv0H0oe8V42gg4FsXB7_Fv8Ou9YUFWaJYb7FVU3IyWGVNYJyPoT662ImG2kQQHTzoNdHPdqTT_kh421XyfaJINAHA3KzKTcOq_4uNp3hq158xepsHM8HLizQKPI_oM3qvpSMxj-BuMVfkDGTnsX-JLAe3NA8yuFiZXyziuYw6hC4rMLuV5UTNJZnGS-3EEGSXXHCfghBQslnMt4jDj1X9FYwL8cJCmPPC9sEgpCfBdPYZCJUjoxwd2i4Nd2vweECi1KOOoFCdmTcDcp6WmlQxv06XLgfCiyC50yBmqw034Ukq2IsrYFPDsITQIQG_HBAe6k-2dxanLxJGlZK6CPCx2MKGElRlIESSqa99pCuUgzdvs-_ZbG-fjr42LTHtP0hHJy_ngCjrt8IgDmUKI3xEvlXZRnxnp4jkH-7FwZoKkh01DjFYkAscw5BjAlcWFqgQFnqle20OyaUTMaYIvjf-0ZUOpGi_wab0RYW1i5s61xvKyIk_2evZ87LyS57WccbcLy88MJ26kRxPMf9rOcEetd1aZxykk73d7A_pj7zxIrvjeExHyxUrM0XFgLN79kvoEAhyhFdZ_FZItdc98yLjaToxZPORBhTn1w0nj4spz5FjshbItFfVLfGCsAxgxRI88AO2oB8389PNPMe8tA4uMPMC2PFTqK795Hek8Vos_khmzeiXwo1BQaVfwLglOeKhUBAuoVvCyh93vTjhapy14oMAt24rP1eeHnQjee5Lfb_8p3gXOMQ39yxQ0Ts32B-CfxQzbPQrRQtJls8Y6lVDr0oOFz1gMHDWRrzA5z3tqHpj0Cxe3R1luIIQ06DHrv73dswQFCY6mYUsMfumIz3WAO0sa7s8fzbGRpG4zcA5_zxQpkwOEmTbBf8n_7vCRaS3weOMVJBuNSJCiQGBHR2eESoSSbV_ESxcoPGf-Wz_Fam4chWBty66ZX9gMqaAE1zWKAGMEF9zlemaUpKjF_NQJkTSbvh94a6Rtr-WR9QhWFzNxPBPIxItxGb5yNTiGZ6Ie-tQJE2Kyd1SmcfUY5fJnCdItfpnyXL4WSAbSsob9XVg4Op0uBGG4yXL__kme-X8WI0wABAACDV6iueeDk3PptXUV0BSR3PCdB9sa2FWGoPt81rhXS1voD5ApICH0CYlLLFnsnBNNi0fB0f7ZKC8y4286yDEl0NhkKDvq2n9HkwBGA_oiFOcGotvk5QXufiP82pBzLwQOow95Fx6OM7HK_uPVjzxxdawXQgSdHoQiMJwbUK2UYbfr0iYvGr8ERELWRTOOiBcZYsSsNhYHMvwVW5ahDFqpCiW8JJOq6gjlJmZ3cvwVWD7kgLmJXMnnRqtqaYl9Uk0EBEw6CZI8R0Fprd4sn-AM5SIgL6PkVm0AsR9FkBxFO5F6x3-DMWIZnbpEFcOjgpkwAtbmPtesiKe7w_XeKXSYKPfzCM5wyVZ7sq4BZaQSMzOEOgpFp7_W4kjVZuWL4HvPBA0eaJkqCCnO9CvTPynRPisSgqY5zcysrcKLAAHSQ247c1yi8smlgYsFznlptT_2rAD8h2xfxUSv9KDaokZ9LROVtS1pGJumZfwAKuHqEis6B5GAG1uZw8SgmRDB5-_dcAQWOP6jgn5PBB08RKA4xGMxzHTTF0iQgF1HMX4ScdvPmR2tC1g2_z9NYw5VvHewjIQTVUgKhl6WkLiggz4qCItjEQ-sQaFctZo2QgTphAAhAPbVVKGmXydWSPn9-MLyRxMEFd_MFPx0xEKWUtWopZnXoAnB6cuRUlaR7Ex1bd9kSJeRT-zS9vg6SmVVeqqF10HbBydZAp2CPsaAXMzrohNXkjT1tHa5DFsGCWN8Pl96gZ4XU0hcy0-v_g66wmMXmP7XBBUEh8wlJ2tg5_32LC9uz3mUecfSbUnNnM7jzPEBx0MWh0T5W4oXWkjl0JtkiRFaawUveTNuckzEnkGqxWKC3Pfi-4_c19f14CGUzZTVXhAWYKQD15Ldl65r6xU7U87dFAQUOHcEY6KUiQ-xEZztcLU_KDfunv1hTy9IE73SiYpIvhvSeus46KY7z9D_G1Hw7nQFhHgxspVLEjejdXY5Pms0wE_YhQ-bkrCOPXpnJxE194xSi57ykPsPH5TBygVP_fwEFAdqOPwiKKQ4MV-d2G2-omn1DCyqoL0Vc-bvCee7FYytR_RFO2_xikbrBZwnj_buFvANP_K1TtKf04nY7mjKJiSbrTdpywo8PvxNB2JpBD9gkVPuA2oMFvUFHHownN0jBA9yWmiKpQTY_ZqT2TR2bmCTmwL3sZEdPVl0oaBlPiFZbDTLGgF-4fBlm_xZl1OiAhj4KxXwB7w_DqvCS0V34A0o-Su4VjZzaEqO3cTuPCBuJRfnExkN0QMMtx-OMPaumAQSyZ7-x27l3q_-q2ABDt7hOImYxGar-1FLvfxxmv_aAUPWCKHHyEk-TpdjgaLYs3EWC2FD-DNMegViiW_kEhe5hNwBo_JVCn82HCUH14yb3mZwFNe2vAp5WvSVoSdkBCgEELEZw33U_IZSQ5fm0BtguhMiFPbE86oWsZYU3cs3LiC3hW-hEBIIiqIh3zxWg7Z8AcaoK_0hQeGI2DANl22GKyVTRdHgB6Vv2Ggz-KqB3NYkLJ3AirxooP_x_mqVVoIj","d":"AAAAAAAAAAAAAAAAAAAAAAQQHdztdAVXIoTgm7Xd9zaoEa2kecrShecJiMnQEMlsAAAAAAAAAAAAAAAAAAAAAAqEwcVDOrlXsHq8pVsXulokLqs7djt2KF6JUTbvIi5b"}]"#;

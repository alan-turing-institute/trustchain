#![allow(dead_code)]
pub const TEST_SIDETREE_DOCUMENT: &str = r##"
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

// Previous versions that don't match example keys, to remove:
// "recoveryCommitment" : "EiBKWQyomumgZvqiRVZnqwA2-7RVZ6Xr-cwDRmeXJT_k9g",
// "updateCommitment" : "EiCe3q-ZByJnzI6CwGIDj-M67W-Yv78L3ejxcuEDxnWzMg"
pub const TEST_SIDETREE_DOCUMENT_METADATA: &str = r##"
{
   "canonicalId" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
   "method" : {
      "published" : true,
      "recoveryCommitment" : "EiDZpHjQ5x7aRRqv6aUtmOdHsxWktAm1kU1IZl1w7iexsw",
      "updateCommitment" : "EiBWPR1JNdAQ4j3ZMqurb4rt10NA7s17lztFF9OIcEO3ew"
   }
}
"##;

// Previous versions that don't match example keys, to remove:
// "recoveryCommitment" : "EiBKWQyomumgZvqiRVZnqwA2-7RVZ6Xr-cwDRmeXJT_k9g",
// "updateCommitment" : "EiCe3q-ZByJnzI6CwGIDj-M67W-Yv78L3ejxcuEDxnWzMg"
pub const TEST_TRUSTCHAIN_DOCUMENT_METADATA: &str = r##"
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
"##;

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

pub const TEST_SIGNING_KEYS: &str = r##"[
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
    "##;

pub const TEST_UPDATE_KEY: &str = r##"{
        "kty": "EC",
        "crv": "secp256k1",
        "x": "2hm19BwmXmR8Vfuw2XbGrusm89Pg6dyExlzDfc-CiM8",
        "y": "uFjW0fKdhHaY4c_5E9Wkk3cPi9sJ5rP3oyl1ssV_X6A",
        "d": "Z2vJqNRjbWvJX2NzABKlHI2V00HWmV2KNI5P4mmxRbg"
    }"##;

pub const TEST_NEXT_UPDATE_KEY: &str = r##"{
        "kty": "EC",
        "crv": "secp256k1",
        "x": "hm_Pj46yibXbFNyARPXfOKIAEI_UKqfmZwzZDfbUSSk",
        "y": "Djxgs6Ex71m6K0QCrn4l2naNo4F6IYXfu0LrBhW2RQU",
        "d": "rAUu7DWaQ2ceSap_NzJNj1YOD2yP_bf1JqabuQJz6rc"
    }"##;

pub const TEST_RECOVERY_KEY: &str = r##"{
        "kty": "EC",
        "crv": "secp256k1",
        "x": "_Z1JRmGwvj0jIpDW-QF0dmQnAL8D_FuNg2WxF7uJSYo",
        "y": "orKbmG6L6kRugAB2OWzWNgulXRfyOR06GTm353Er--c",
        "d": "YobJpI7p7T5dfU0cDRE4SQwp0eOFR6LOGrsqZE1GG1A"
    }"##;

pub const TEST_ROOT_SIGNING_PK: &str = r##"
{
   "kty": "EC",
   "crv": "secp256k1",
   "x": "7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso",
   "y": "kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"
}
"##;

pub const TEST_ROOT_PLUS_1_SIGNING_KEY: &str = r##"
{
   "kty": "EC",
   "crv": "secp256k1",
   "x": "aApKobPO8H8wOv-oGT8K3Na-8l-B1AE3uBZrWGT6FJU",
   "y": "dspEqltAtlTKJ7cVRP_gMMknyDPqUw-JHlpwS2mFuh0"
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

pub const TEST_ROOT_DOCUMENT_METADATA: &str = r##"
{
   "canonicalId": "did:ion:test:EiCClfEdkTv_aM3UnBBhlOV89LlGhpQAbfeZLFdFxVFkEg",
   "method": {
     "updateCommitment": "EiDVRETvZD9iSUnou-HUAz5Ymk_F3tpyzg7FG1jdRG-ZRg",
     "published": true,
     "recoveryCommitment": "EiCymv17OGBAs7eLmm4BIXDCQBVhdOUAX5QdpIrN4SDE5w"
   }
}
"##;

pub const TEST_ROOT_PLUS_1_DOCUMENT_METADATA: &str = r##"
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
"##;

/// Root JWK public key
pub const TEST_ROOT_JWK_PK: &str = r##"
{
   "kty": "EC",
   "crv": "secp256k1",
   "x": "7ReQHHysGxbyuKEQmspQOjL7oQUqDTldTHuc9V3-yso",
   "y": "kWvmS7ZOvDUhF8syO08PBzEpEk3BZMuukkvEJOKSjqE"
}
"##;

/// Proof value from metadata
pub const TEST_ROOT_PLUS_1_JWT: &str = "eyJhbGciOiJFUzI1NksifQ.IkVpQXM5dkx2SmdaNkFHMk5XbUFmTnBrbl9EMlNSSUFSa2tCWE9kajZpMk84Umci.awNd-_O1N1ycZ6i_BxeLGV14ok51Ii2x9f1FBBCflyAWw773sqiHvQRGHIMBebKMnzbxVybFu2qUEPWUuRAC9g";

pub const TEST_ROOT_PLUS_2_DOCUMENT_METADATA: &str = r##"
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
"##;
/// Proof value from metadata
pub const TEST_ROOT_PLUS_2_JWT: &str = "eyJhbGciOiJFUzI1NksifQ.IkVpQTNtT25QRklDbTdyc2ljVjRIaFMtNjhrT21xMndqa2tlMEtkRnkzQWlWZlEi.Fxlbm8osH2O5KOQ9sS21bypT_WoWxVD8toCU4baBnLk_gOxiOy_n3cMFMVANJ8usPrKAfRFeC27ATTkWBYZzuw";

/// Test credential: no issuer is present for the unit test
pub const TEST_CREDENTIAL: &str = r##"{
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
 "##;

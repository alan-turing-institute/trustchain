#![allow(dead_code)]
pub const TEST_SIDETREE_DOCUMENT: &'static str = r##"
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

pub const TEST_SIDETREE_DOCUMENT_SERVICE_AND_PROOF: &'static str = r##"
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

pub const TEST_SIDETREE_DOCUMENT_SERVICE_NOT_PROOF: &'static str = r##"
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

pub const TEST_SIDETREE_DOCUMENT_MULTIPLE_PROOF: &'static str = r##"
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

pub const TEST_SIDETREE_DOCUMENT_METADATA: &'static str = r##"
{
   "canonicalId" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
   "method" : {
      "published" : true,
      "recoveryCommitment" : "EiBKWQyomumgZvqiRVZnqwA2-7RVZ6Xr-cwDRmeXJT_k9g",
      "updateCommitment" : "EiCe3q-ZByJnzI6CwGIDj-M67W-Yv78L3ejxcuEDxnWzMg"
   }
}
"##;

pub const TEST_TRUSTCHAIN_DOCUMENT_METADATA: &'static str = r##"
{
   "canonicalId" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
   "method" : {
      "published" : true,
      "recoveryCommitment" : "EiBKWQyomumgZvqiRVZnqwA2-7RVZ6Xr-cwDRmeXJT_k9g",
      "updateCommitment" : "EiCe3q-ZByJnzI6CwGIDj-M67W-Yv78L3ejxcuEDxnWzMg"
   },
   "proof" : {
      "id" : "did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ",
      "type" : "JsonWebSignature2020",
      "proofValue" : "eyJhbGciOiJFUzI1NksifQ.IkVpQmNiTkRRcjZZNHNzZGc5QXo4eC1qNy1yS1FuNWk5T2Q2S3BjZ2c0RU1KOXci.Nii8p38DtzyurmPHO9sV2JLSH7-Pv-dCKQ0Y-H34rplwhhwca2nSra4ZofcUsHCG6u1oKJ0x4AmMUD2_3UIhRA"
  }
}
"##;

pub const TEST_SIDETREE_DOCUMENT_WITH_CONTROLLER: &'static str = r##"
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

pub const TEST_TRUSTCHAIN_DOCUMENT: &'static str = r##"
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

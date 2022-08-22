pub const TEST_ION_DOCUMENT: &'static str = r##"
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
         "id" : "#controller-proof",
         "serviceEndpoint" : {
            "proof" : "eyJhbGciOiJFUzI1NksifQ.IkVpQmNiTkRRcjZZNHNzZGc5QXo4eC1qNy1yS1FuNWk5T2Q2S3BjZ2c0RU1KOXci.Nii8p38DtzyurmPHO9sV2JLSH7-Pv-dCKQ0Y-H34rplwhhwca2nSra4ZofcUsHCG6u1oKJ0x4AmMUD2_3UIhRA",
            "signer_did" : "EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
         },
         "type" : "signature"
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

pub const TEST_ION_DOCUMENT_WITH_CONTROLLER: &'static str = r##"
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
         "id" : "#controller-proof",
         "serviceEndpoint" : {
            "proof" : "eyJhbGciOiJFUzI1NksifQ.IkVpQmNiTkRRcjZZNHNzZGc5QXo4eC1qNy1yS1FuNWk5T2Q2S3BjZ2c0RU1KOXci.Nii8p38DtzyurmPHO9sV2JLSH7-Pv-dCKQ0Y-H34rplwhhwca2nSra4ZofcUsHCG6u1oKJ0x4AmMUD2_3UIhRA",
            "signer_did" : "EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ"
         },
         "type" : "signature"
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

//! Test fixtures.

pub(crate) const TEST_CANDIDATE_DDID_DOCUMENT: &str = r##"
{
   "authentication" : [
      "#bZdi2pQK5dk6YF8uVKz_P7SvRgZJ6DUT1KcsLM7L1QA",
      "#a9vxpkAsksMUOXqjAdnZhQiVOKY-a0QDOdnrDL6lw40"
   ],
   "service" : [
      {
         "id" : "#TrustchainID",
         "serviceEndpoint" : "https://identity.foundation/ion/trustchain-root-plus-2-not-downstream-yet",
         "type" : "Identity"
      }
   ],
   "verificationMethod" : [
      {
         "type" : "JsonWebSignature2020",
         "controller" : "did:ion:test:EiC5GlkBZaC6SYiCexvcr2hgMPVdSoREIhK8KbekQRgphg",
         "publicKeyJwk" : {
            "crv" : "secp256k1",
            "y" : "MSxXXbRIm3OWYgyhJBC3mpAg3uCniPsxkQs486i8XTw",
            "kty" : "EC",
            "x" : "0vYBCPbQLlPCTW_iTdh9ubbrQqhZh9JWyP89tDKsbew"
         },
         "id" : "#bZdi2pQK5dk6YF8uVKz_P7SvRgZJ6DUT1KcsLM7L1QA"
      },
      {
         "type" : "JsonWebSignature2020",
         "controller" : "did:ion:test:EiC5GlkBZaC6SYiCexvcr2hgMPVdSoREIhK8KbekQRgphg",
         "publicKeyJwk" : {
            "x" : "aeq7ALPoynBWX_QDFzJxyX8USRTHzL9lm52Orvzy-DM",
            "crv" : "secp256k1",
            "y" : "25MLCu-qxD_axvomnLZVgGHehJ_CO6pNE4IklQMaVzA",
            "kty" : "EC"
         },
         "id" : "#a9vxpkAsksMUOXqjAdnZhQiVOKY-a0QDOdnrDL6lw40"
      }
   ],
   "assertionMethod" : [
      "#bZdi2pQK5dk6YF8uVKz_P7SvRgZJ6DUT1KcsLM7L1QA",
      "#a9vxpkAsksMUOXqjAdnZhQiVOKY-a0QDOdnrDL6lw40"
   ],
   "@context" : [
      "https://www.w3.org/ns/did/v1",
      {
         "@base" : "did:ion:test:EiC5GlkBZaC6SYiCexvcr2hgMPVdSoREIhK8KbekQRgphg"
      }
   ],
   "keyAgreement" : [
      "#bZdi2pQK5dk6YF8uVKz_P7SvRgZJ6DUT1KcsLM7L1QA",
      "#a9vxpkAsksMUOXqjAdnZhQiVOKY-a0QDOdnrDL6lw40"
   ],
   "capabilityInvocation" : [
      "#bZdi2pQK5dk6YF8uVKz_P7SvRgZJ6DUT1KcsLM7L1QA",
      "#a9vxpkAsksMUOXqjAdnZhQiVOKY-a0QDOdnrDL6lw40"
   ],
   "capabilityDelegation" : [
      "#bZdi2pQK5dk6YF8uVKz_P7SvRgZJ6DUT1KcsLM7L1QA",
      "#a9vxpkAsksMUOXqjAdnZhQiVOKY-a0QDOdnrDL6lw40"
   ],
   "id" : "did:ion:test:EiC5GlkBZaC6SYiCexvcr2hgMPVdSoREIhK8KbekQRgphg"
}
"##;

// key_id: #bZdi2pQK5dk6YF8uVKz_P7SvRgZJ6DUT1KcsLM7L1QA
pub(crate) const TEST_SIGNING_KEY_1: &str = r##"
{
   "kty": "EC",
   "crv": "secp256k1",
   "x": "0vYBCPbQLlPCTW_iTdh9ubbrQqhZh9JWyP89tDKsbew",
   "y": "MSxXXbRIm3OWYgyhJBC3mpAg3uCniPsxkQs486i8XTw",
   "d": "JqWC8hlh9KX0XaUsl6xbiYtSX0TC1cEaqb338boJHDs"
 }
"##;

// key_id: #a9vxpkAsksMUOXqjAdnZhQiVOKY-a0QDOdnrDL6lw40
pub(crate) const TEST_SIGNING_KEY_2: &str = r##"
{
   "kty": "EC",
   "crv": "secp256k1",
   "x": "aeq7ALPoynBWX_QDFzJxyX8USRTHzL9lm52Orvzy-DM",
   "y": "25MLCu-qxD_axvomnLZVgGHehJ_CO6pNE4IklQMaVzA",
   "d": "YoSojHkEat0RefQxbzeS-X2JIW3BCJTgc8-VM6ombWk"
 }
"##;
// TODO: Duplicated from trustchain-http test fixtures. Attestor business logic to be moved into
// the trustchain-cr crate, after which these fixtures can be removed from trustchain-http.
pub(crate) const TEST_TEMP_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"JokHTNHd1lIw2EXUTV1RJL3wvWMgoIRHPaWxTHcyH9U","y":"z737jJY7kxW_lpE1eZur-9n9_HUEGFyBGsTdChzI4Kg","d":"CfdUwQ-CcBQkWpIDPjhSJAq2SCg6hAGdcvLmCj0aA-c"}"#;
pub(crate) const TEST_UPDATE_KEY: &str = r#"{"kty":"EC","crv":"secp256k1","x":"AB1b_4-XSem0uiPGGuW_hf_AuPArukMuD2S95ypGDSE","y":"suvBnCbhicPdYZeqgxJfPFmiNHGYDjPiW8XkYHxwgBU"}"#;

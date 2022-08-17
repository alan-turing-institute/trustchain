use did_ion::sidetree::DIDStatePatch;
use did_ion::sidetree::{
    DIDSuffix, Operation, ServiceEndpointEntry, Sidetree, SidetreeClient, SidetreeDID,
    SidetreeOperation,
};
use did_ion::sidetree::{DocumentState, PublicKeyEntry, PublicKeyJwk};
use did_ion::ION;
use ssi::did::ServiceEndpoint;
use ssi::jwk::{Base64urlUInt, ECParams, Params, JWK};
use std::convert::TryFrom;
use std::fmt::format;
use std::fs::{read, write};
// use anyhow::{anyhow, bail, ensure, Context, Error as AError, Result as AResult};
// use failure::Fail;
use serde_json::{to_string_pretty as to_json, from_str, Map, Value};
// use failure::result_ext::ResultExt;

fn main() {
    // Public key entries can look like this
    let ion_server_uri: &str = "http://localhost:3000";
    let ion_client = SidetreeClient::<ION>::new(Some(ion_server_uri.to_string()));
    // TODO: consider whether this is the resolver format
    // ion_client.to_resolver().resolve_representation(&did_short, ...);
}

fn add_controller(did_doc: &str, controller_did: &str) -> String {

    // let did_doc_json : Map<String, Value> = from_str(did_doc).unwrap();

    // // If the controller field already exists, check the DID is correct.
    // // IMP: make sure we're checking the controller field in the root
    // // level of the DID document (i.e. at the same level as the id field).

    // if did_doc_json.contains_key("controller") {
    //     if did_doc.get("controller") == controller_did {
    //         // Nothing to do.
    //         return did_doc
    //     }
    //     else {
    //         panic // Controller DID conflict
    //     }
    // }

    // let doc_clone = did_doc.clone();
    // doc_clone.add("controller : {controller_did}");s
    // doc_clone
    String::from("abc")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_controller() {

        let did_doc = String::from("{
            \"@context\" : [
               \"https://www.w3.org/ns/did/v1\",
               {
                  \"@base\" : \"did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ\"
               }
            ],
            \"id\" : \"did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ\"
         }");
         let controller_did = String::from("did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP");
         let result = add_controller(&did_doc, &controller_did);

         let expected = String::from("{
            \"@context\" : [
               \"https://www.w3.org/ns/did/v1\",
               {
                  \"@base\" : \"did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ\"
               }
            ],
            \"id\" : \"did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9ZQ\",
            \"controller\" : \"did:ion:test:EiCBr7qGDecjkR2yUBhn3aNJPUR3TSEOlkpNcL0Q5Au9YP\",
         }");
         assert_eq!(result, expected);
    }
}
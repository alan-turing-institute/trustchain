//! Verifiable credential functionality for Trustchain.

use std::collections::{BTreeMap, HashMap};

use crate::verifier::VerifierError;
use ps_sig::rsssig::RSignature;

use serde_json::{Map, Value};
use ssi::{
    one_or_many::OneOrMany,
    vc::{Context, Contexts, Credential, CredentialSubject, Proof, VerificationResult, URI},
};
use thiserror::Error;

/// An error relating to verifiable credentials and presentations.
#[derive(Error, Debug)]
pub enum CredentialError {
    /// No issuer present in credential.
    #[error("No issuer.")]
    NoIssuerPresent,
    /// No proof present in credential.
    #[error("No proof.")]
    NoProofPresent,
    /// Wrapped error for Verifier error.
    #[error("A wrapped Verifier error: {0}")]
    VerifierError(VerifierError),
    /// Wrapped verification result with errors.
    #[error("A wrapped verification result error: {0:?}")]
    VerificationResultError(VerificationResult),
}

impl From<VerifierError> for CredentialError {
    fn from(err: VerifierError) -> Self {
        CredentialError::VerifierError(err)
    }
}

pub trait CanonicalFlatten {
    fn flatten(&self) -> Vec<String>;
}

fn convert_map(map: &HashMap<String, Value>) -> Map<String, Value> {
    // json Value enum varients are all 'ordered' already, so only the top level HashMap must be
    // sorted (the serde_json `Map` implementation uses either BTreeMap or indexmap::IndexMap
    // depending on the selected feature)
    Map::from_iter(map.clone().into_iter())
}

fn flatten_map(map: &Map<String, Value>) -> Vec<String> {
    let mut res = Vec::new();
    for (k, v) in map {
        match v {
            Value::Null => {}
            Value::Bool(_) => res.push(k.to_owned() + ":" + &v.flatten().first().unwrap()),
            Value::Number(_) => res.push(k.to_owned() + ":" + &v.flatten().first().unwrap()),
            Value::String(_) => res.push(k.to_owned() + ":" + &v.flatten().first().unwrap()),
            Value::Array(_) => {
                res.push(k.to_owned() + ":[");
                res.append(&mut v.flatten());
            }
            Value::Object(_) => {
                res.push(k.to_owned() + ":{");
                res.append(&mut v.flatten());
            }
        }
    }
    res
}

impl CanonicalFlatten for Value {
    fn flatten(&self) -> Vec<String> {
        let mut res = Vec::new();
        match self {
            Value::Null => {}
            Value::Bool(b) => res.push(b.to_string()),
            Value::Number(n) => res.push(n.to_string()),
            Value::String(s) => res.push(s.to_string()),
            Value::Array(a) => {
                res = a.iter().fold(res, |mut acc, val| {
                    acc.append(&mut val.flatten());
                    acc
                });
            }
            Value::Object(map) => {
                res.append(&mut flatten_map(map));
            }
        }
        res
    }
}

impl CanonicalFlatten for Credential {
    fn flatten(&self) -> Vec<String> {
        let mut res = Vec::new();

        // pub fn convert_map(map: HashMap<String, Value>) -> BTreeMap<String, Value> {
        //     let btreemap = BTreeMap::from_iter(map.into_iter());
        //     btreemap
        // }

        fn handle_context(ctx: &Context) -> Vec<String> {
            match ctx {
                Context::URI(uri) => vec![handle_uri(uri)],
                Context::Object(map) => flatten_map(&convert_map(map)),
            }
        }

        fn handle_uri(uri: &URI) -> String {
            match uri {
                URI::String(s) => s.to_string(),
            }
        }

        fn handle_credential_subject(cs: &CredentialSubject) -> Vec<String> {
            let mut res = Vec::new();
            if let Some(uri) = &cs.id {
                res.push("id:".to_string() + &handle_uri(uri));
            }
            if let Some(map) = &cs.property_set {
                res.push("propertySet:{".to_string());
                res.append(&mut flatten_map(&convert_map(map)));
            }
            res
        }

        // context
        res.push("context:{".to_string());
        match &self.context {
            Contexts::One(ctx) => res.append(&mut handle_context(&ctx)),
            Contexts::Many(ctx_vec) => {
                res = ctx_vec.iter().fold(res, |mut acc, ctx| {
                    acc.append(&mut handle_context(ctx));
                    acc
                });
            }
        }

        // id
        if let Some(uri) = &self.id {
            res.push("id".to_string() + ":" + &handle_uri(uri));
        }

        // type_
        match &self.type_ {
            OneOrMany::One(t) => res.push("type".to_string() + ":" + t),
            OneOrMany::Many(t_vec) => {
                res.push("type:[".to_string());
                for t in t_vec {
                    res.push(t.to_string());
                }
            }
        }

        // credential_subject
        res.push("credentialSubject:{".to_string());
        match &self.credential_subject {
            OneOrMany::One(cs) => {
                res.push("credentialSubject:{".to_string());
                res.append(&mut handle_credential_subject(cs));
            }
            OneOrMany::Many(cs_vec) => {
                res.push("credentialSubject:[".to_string());
                res.append(cs_vec.iter().fold(&mut Vec::new(), |acc, cs| {
                    acc.append(&mut handle_credential_subject(cs));
                    acc
                }));
            }
        }

        // issuer
        if let Some(issuer) = &self.issuer {
            match issuer {
                ssi::vc::Issuer::URI(uri) => {
                    res.push("issuer".to_string() + ":" + &handle_uri(uri));
                }
                ssi::vc::Issuer::Object(obj) => {
                    res.push("issuer:{".to_string());
                    res.push("id:".to_string() + &handle_uri(&obj.id));
                    if let Some(map) = &obj.property_set {
                        res.push("propertySet:{".to_string());
                        res.append(&mut flatten_map(&convert_map(&map)));
                    }
                }
            }
        }

        // issuance_date
        if let Some(date) = &self.issuance_date {
            res.push("issuanceDate:".to_string() + &serde_json::to_string(date).unwrap());
        }

        res
    }
}

/// More flexible interface (compared to ssi::ldp::ProofSuite) to implement verification of
/// `ssi::vc::Proof`s for new proof types (with access to the credential fields, which is required
/// in the case of RSS proofs)
pub trait ProofVerify {
    // TODO: is ssi::vc::Proof the same as ssi::vp::Proof?
    fn verify_proof(proof: &Proof, credential: &Credential) -> VerificationResult;
}

impl ProofVerify for RSignature {
    fn verify_proof(proof: &Proof, credential: &Credential) -> VerificationResult {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::{Map, Value};

    use super::*;

    const TEST_UNSIGNED_VC: &str = r##"{
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1",
          "https://w3id.org/citizenship/v1",
          {
            "3":"did:example:testdidsuffix",
            "1":"did:example:testdidsuffix",
            "2":"did:example:testdidsuffix",
            "0":"did:example:testdidsuffix"
          }
        ],
        "id": "did:ion:test_id_field",
        "type": ["VerifiableCredential"],
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

    //   "credentialSchema": {
    //     "id": "did:example:cdf:35LB7w9ueWbagPL94T9bMLtyXDj9pX5o",
    //     "type": "did:example:schema:22KpkXgecryx9k7N6XN1QoN3gXwBkSU8SfyyYQG"
    //   },
    //   "issuer": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
    //   "image": "some_base64_representation",

    #[test]
    fn deserialize() {
        // let vc: OCredential = serde_json::from_str(TEST_UNSIGNED_VC).unwrap();
        // println!("{}", serde_json::to_string_pretty(&vc.flatten()).unwrap());
    }

    #[test]
    fn test_convert_map() {
        let mut map = HashMap::new();
        map.insert("c".to_string(), Value::String("conversion".to_string()));
        map.insert("b".to_string(), Value::String("the".to_string()));
        map.insert("a".to_string(), Value::String("test".to_string()));
        map.insert(
            "d".to_string(),
            Value::Object(Map::from_iter(
                vec![
                    ("b".to_string(), Value::String("the".to_string())),
                    ("c".to_string(), Value::String("conversion".to_string())),
                    ("a".to_string(), Value::String("test".to_string())),
                ]
                .into_iter(),
            )),
        );

        let json_map = convert_map(&map);
        for (k, v) in json_map {
            println!("{:?} : {:?}", k, v);
        }
    }
}

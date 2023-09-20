use serde_json::{Map, Value};
use ssi::{
    one_or_many::OneOrMany,
    vc::{Context, Contexts, Credential, CredentialSubject, Issuer, URI},
};
use std::collections::{BTreeMap, HashMap, VecDeque};

pub trait CanonicalFlatten {
    fn flatten(&self) -> Vec<String>;
}

// Trivial impl to satify trait bound on RedactValues
impl CanonicalFlatten for Vec<String> {
    fn flatten(&self) -> Vec<String> {
        self.to_owned()
    }
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
                res.append(&mut map.flatten());
            }
        }
        res
    }
}

impl CanonicalFlatten for Credential {
    fn flatten(&self) -> Vec<String> {
        let mut res = Vec::new();

        // flatten only credential_subject
        match &self.credential_subject {
            OneOrMany::One(cs) => {
                res.append(&mut handle_credential_subject(cs));
            }
            OneOrMany::Many(_) => {
                panic!("TODO find *unique* flat representation for multiple subjects");
            }
        }

        // helper functions
        fn handle_credential_subject(cs: &CredentialSubject) -> Vec<String> {
            let mut res = Vec::new();
            if let Some(uri) = &cs.id {
                res.push("id:".to_string() + &handle_uri(uri));
            }
            if let Some(map) = &cs.property_set {
                // res.push("propertySet:{".to_string());
                res.append(&mut convert_map(map).flatten());
            }
            res
        }
        fn handle_uri(uri: &URI) -> String {
            match uri {
                URI::String(s) => s.to_string(),
            }
        }

        // Build a metadata map containing all other fields, to then be compressed into one String.
        // This simplifies the implementation, whilst only allowing the holder to redact fields from
        // the credentialSubject field.
        let mut metadata = BTreeMap::new();

        // The metadata map must be strictly ordered (along with the flattened credentialSubject
        // fields). All fields in the `Credential` struct that contain un-ordered data structures must
        // be converted to ordered structures before serializing into metadata map values.
        // Fields with unordered data structures are:
        // context
        // credential_subject
        // issuer
        // proof (this field is ignored by `flatten()` because the RSS proofs handled seperately)
        // credential_status
        // terms_of_use
        // evidence
        // credential_schema
        // refresh_service
        // property_set

        // context _________________________________
        let context_string = match &self.context {
            Contexts::One(ctx) => match ctx {
                Context::URI(_) => serde_json::to_string(ctx).unwrap(),
                Context::Object(map) => serde_json::to_string(&convert_map(map)).unwrap(),
            },
            Contexts::Many(ctx_vec) => serde_json::to_string(
                &ctx_vec
                    .iter()
                    .map(|ctx| {
                        if let Context::Object(map) = ctx {
                            serde_json::to_string(&convert_map(map)).unwrap()
                        } else {
                            serde_json::to_string(ctx).unwrap()
                        }
                    })
                    .collect::<Vec<String>>(),
            )
            .unwrap(),
        };
        metadata.insert("@context", context_string);

        // id _________________________________
        metadata.insert("id", serde_json::to_string(&self.id).unwrap());

        // type _________________________________
        metadata.insert("type", serde_json::to_string(&self.type_).unwrap());

        // issuer _________________________________
        if let Some(v) = &self.issuer {
            let issuer_string = match v {
                Issuer::URI(_) => serde_json::to_string(v).unwrap(),
                Issuer::Object(obj) => {
                    if let Some(prop_set) = &obj.property_set {
                        serde_json::to_string(&obj.id).unwrap()
                            + &serde_json::to_string(&convert_map(&prop_set)).unwrap()
                    } else {
                        serde_json::to_string(v).unwrap()
                    }
                }
            };
            metadata.insert("issuer", issuer_string);
        }

        // issuance_date _________________________________
        if let Some(v) = &self.issuance_date {
            metadata.insert("issuanceDate", serde_json::to_string(v).unwrap());
        }

        // expiration_date _________________________________
        if let Some(v) = &self.expiration_date {
            metadata.insert("expirationDate", serde_json::to_string(v).unwrap());
        }

        // credential_status _________________________________
        if let Some(v) = &self.credential_status {
            let c_s_string = if let Some(prop_set) = &v.property_set {
                serde_json::to_string(&v.id).unwrap()
                    + &serde_json::to_string(&v.type_).unwrap()
                    + &serde_json::to_string(&convert_map(&prop_set)).unwrap()
            } else {
                serde_json::to_string(v).unwrap()
            };
            metadata.insert("credentialStatus", c_s_string);
        }

        // unimplemented _________________________________
        if let Some(_) = &self.terms_of_use {
            todo!()
        }
        if let Some(_) = &self.evidence {
            todo!()
        }
        if let Some(_) = &self.credential_schema {
            todo!()
        }
        if let Some(_) = &self.refresh_service {
            todo!()
        }
        if let Some(prop_set) = &self.property_set {
            if prop_set.len() != 0 {
                todo!()
            }
        }

        res.push("metadata:".to_string() + &serde_json::to_string(&metadata).unwrap());
        res
    }
}

/// Convert an un-ordered HashMap over json Value objects into an ordered json Map (which is used
/// under the hood within json Value objects)
fn convert_map(map: &HashMap<String, Value>) -> Map<String, Value> {
    // json Value enum varients are all 'ordered' already, so only the top level HashMap must be
    // sorted (the serde_json `Map` implementation uses either BTreeMap or indexmap::IndexMap
    // depending on the selected feature - it's important that the indexMap feature is **not** set
    // so that the ordering is canonical, based on sorting the keys)
    let mut key_value_pairs = map.clone().into_iter().collect::<Vec<(String, Value)>>();
    key_value_pairs.sort_by(|(ak, _), (bk, _)| ak.cmp(bk));
    Map::from_iter(key_value_pairs)
}

// Flatten a json Map of json Values with a 1-to-1 algorithm (ensuring two distinct map cannot
// produce the same flattened result)
impl CanonicalFlatten for Map<String, Value> {
    fn flatten(&self) -> Vec<String> {
        let mut res = Vec::new();
        for (k, v) in self {
            match v {
                Value::Null => res.push(k.to_owned() + ":"),
                Value::Bool(_) => res.push(k.to_owned() + ":" + &v.flatten().first().unwrap()),
                Value::Number(_) => res.push(k.to_owned() + ":" + &v.flatten().first().unwrap()),
                Value::String(_) => res.push(k.to_owned() + ":" + &v.flatten().first().unwrap()),
                Value::Array(_) => {
                    res.append(
                        &mut v
                            .flatten()
                            .iter()
                            .map(|s| k.to_owned() + ":[" + s)
                            .collect(),
                    );
                }
                Value::Object(_) => {
                    res.append(
                        &mut v
                            .flatten()
                            .iter()
                            .map(|s| k.to_owned() + ":{" + s)
                            .collect(),
                    );
                }
            }
        }
        res
    }
}

pub trait RedactValues: CanonicalFlatten {
    /// Redact values from a nested object, **keeping** the values that map to the values at the
    /// indicies idxs of the flattened object.
    /// Eg. when idxs.is_empty(), self maintains the same data structure, but all leaf Values are set
    /// to Value::Null.
    fn redact(&mut self, idxs: &[usize]) -> Result<(), RedactError>;
}

#[derive(Debug)]
pub enum RedactError {
    InvalidSequenceElement(String),
    MissingKeyInSourceSequence,
    NullLeafInSourceSequence(String),
    MissingCredentialSubject,
}

impl RedactValues for Vec<String> {
    fn redact(&mut self, idxs: &[usize]) -> Result<(), RedactError> {
        for (i, m) in self.iter_mut().enumerate() {
            // redact using math indexing
            if !idxs.contains(&(i + 1)) {
                let mut m_vec = m.split(":").collect::<Vec<&str>>();
                // special case if redacting metadata field (key-value seperates on first colon)
                if m_vec
                    .first()
                    .ok_or(RedactError::InvalidSequenceElement(m.to_owned()))?
                    == &"metadata"
                {
                    *m = "metadata:".to_string();
                    continue;
                }
                // redact value from key value pair
                let tail = m_vec
                    .pop()
                    .ok_or(RedactError::InvalidSequenceElement(m.to_owned()))?;
                let mut rejoined = m_vec.join(":") + ":";
                // in the case that this index was an element in an array
                if tail
                    .chars()
                    .next()
                    .ok_or(RedactError::MissingKeyInSourceSequence)?
                    == '['
                {
                    // include array tag in the key after value has been redacted
                    rejoined += "["
                }
                *m = rejoined;
            }
        }
        Ok(())
    }
}

impl RedactValues for Map<String, Value> {
    fn redact(&mut self, idxs: &[usize]) -> Result<(), RedactError> {
        let redacted: Vec<String> = self
            .flatten()
            .into_iter()
            .enumerate()
            .filter_map(|(i, string)| {
                if !idxs.contains(&(i + 1)) {
                    Some(string)
                } else {
                    None
                }
            })
            .collect();
        for path in redacted {
            let mut parts = path.split(":").collect::<VecDeque<&str>>();
            let root_k = parts
                .pop_front()
                .ok_or(RedactError::InvalidSequenceElement(path.clone()))?;

            // initialise cursors
            let mut k = root_k;
            let mut parent = &mut *self;
            let mut part = parts.pop_front();

            while let Some(p) = part {
                if let Some(leading_char) = p.chars().nth(0) {
                    match leading_char {
                        '[' => {
                            todo!("redacting arrays")
                        }
                        '{' => {
                            let val = parent.get_mut(k).unwrap();
                            match val {
                                Value::Object(map) => {
                                    parent = map;
                                    k = p.strip_prefix("{").expect("Previously matched.");
                                }
                                _ => panic!("Error parsing path:{}", path),
                            }
                        }
                        _ => {
                            *parent.get_mut(k).unwrap() = Value::Null;
                        }
                    }
                } else {
                    // Redacting an already partially redacted Map (with Value::Null leaves) is not supported
                    return Err(RedactError::NullLeafInSourceSequence(path));
                }
                part = parts.pop_front();
            }
        }
        Ok(())
    }
}

impl RedactValues for Credential {
    fn redact(&mut self, idxs: &[usize]) -> Result<(), RedactError> {
        match &mut self.credential_subject {
            OneOrMany::One(cs) => {
                let mut redacted = convert_map(
                    cs.property_set
                        .as_ref()
                        .ok_or(RedactError::MissingCredentialSubject)?,
                );
                println!("{}", serde_json::to_string_pretty(&redacted).unwrap());
                redacted.redact(idxs)?;
                *cs.property_set
                    .as_mut()
                    .ok_or(RedactError::MissingCredentialSubject)? =
                    HashMap::from_iter(redacted.into_iter());
            }
            OneOrMany::Many(_) => {
                panic!("TODO CanonicalFlatten unimplimented for multiple subjects")
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, Value};
    use std::collections::HashMap;

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
        "issuer": "did:ion:test:EiAtHHKFJWAk5AsM3tgCut3OiBY4ekHTf66AAjoysXL65Q",
        "id": "did:ion:test_id_field",
        "type": ["VerifiableCredential"],
        "credentialSubject": {
            "givenName": "",
            "familyName": "Doe",
            "degree": {
              "type": "",
              "name": "Bachelor of Science and Arts",
              "college": "College of Engineering",
              "nested" : {
                "key" : "value"
              },
              "testArray": [
                "element",
                {"objectInArray": {
                    "two":"",
                    "one":""
                }}
              ]
            }
        }
      }
      "##;

    fn test_map() -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("a".to_string(), Value::String("test".to_string()));
        map.insert(
            "d".to_string(),
            Value::Object(Map::from_iter(
                vec![
                    ("b".to_string(), Value::String("the".to_string())),
                    (
                        "c".to_string(),
                        Value::Object(Map::from_iter(
                            vec![
                                ("b".to_string(), Value::String("the".to_string())),
                                ("c".to_string(), Value::String("conversion".to_string())),
                            ]
                            .into_iter(),
                        )),
                    ),
                ]
                .into_iter(),
            )),
        );
        map
    }

    #[test]
    fn test_redact_vec_of_strings() {
        let mut data: Vec<String> = vec![
            "degree:{college:College of Engineering",
            "degree:{name:Bachelor of Science and Arts",
            "degree:{nested:{key:value",
            "degree:{testArray:[element",
            "degree:{testArray:[objectInArray:{one:valTwo",
            "degree:{testArray:[objectInArray:{two:valOne",
            "degree:{type:Degree Certificate",
            "familyName:Doe",
            "givenName:Jane",
            "metadata:Remove:After:First:Colon",
        ]
        .into_iter()
        .map(|el| el.to_string())
        .collect();

        data.redact(&vec![1, 2, 4, 6]).unwrap();
        assert_eq!(
            data,
            vec![
                "degree:{college:College of Engineering",
                "degree:{name:Bachelor of Science and Arts",
                "degree:{nested:{key:",
                "degree:{testArray:[element",
                "degree:{testArray:[objectInArray:{one:",
                "degree:{testArray:[objectInArray:{two:valOne",
                "degree:{type:",
                "familyName:",
                "givenName:",
                "metadata:"
            ]
        )
    }

    #[test]
    fn test_redact_map() {
        let mut map = test_map();
        println!("{}", serde_json::to_string_pretty(&map.flatten()).unwrap());
        map.redact(&vec![1, 3]).unwrap();
        println!("{}", serde_json::to_string_pretty(&map).unwrap());

        let mut expected = Map::new();
        expected.insert("a".to_string(), Value::String("test".to_string()));
        expected.insert(
            "d".to_string(),
            Value::Object(Map::from_iter(
                vec![
                    ("b".to_string(), Value::Null),
                    (
                        "c".to_string(),
                        Value::Object(Map::from_iter(
                            vec![
                                ("b".to_string(), Value::String("the".to_string())),
                                ("c".to_string(), Value::Null),
                            ]
                            .into_iter(),
                        )),
                    ),
                ]
                .into_iter(),
            )),
        );

        assert_eq!(expected, map);
    }

    #[test]
    fn redact_impl_integrations() {
        let mut map = test_map();
        let mut flat = map.flatten();
        // redact values from paths in Vec<String> (Vec length unchanged)
        flat.redact(&vec![1, 3]).unwrap();
        // redact values from nested map by setting Value::Null at redacted indicies
        map.redact(&vec![1, 3]).unwrap();
        // redacted Vec<String> = flattened redacted map
        assert_eq!(flat, map.flatten());
    }

    #[test]
    fn deserialize() {
        let vc: Credential = serde_json::from_str(TEST_UNSIGNED_VC).unwrap();
        println!("{}", serde_json::to_string_pretty(&vc.flatten()).unwrap());
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

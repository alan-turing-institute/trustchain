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
use serde_json::{to_string_pretty as to_json, Map, Value};
// use failure::result_ext::ResultExt;

fn main() {
    // Public key entries can look like this
    let ion_server_uri: &str = "http://localhost:3000";
    let ion_client = SidetreeClient::<ION>::new(Some(ion_server_uri.to_string()));
    // TODO: consider whether this is the resolver format
    // ion_client.to_resolver().resolve_representation(&did_short, ...);
}

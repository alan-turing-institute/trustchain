//! DID resolution and `DIDResolver` implementation.
use async_trait::async_trait;
use ipfs_api_backend_hyper::IpfsClient;
use serde_json::Value;
use ssi::did::{RelativeDIDURL, ServiceEndpoint, VerificationMethod, VerificationMethodMap};
use ssi::did_resolve::DocumentMetadata;
use ssi::one_or_many::OneOrMany;
use ssi::{
    did::Document,
    did_resolve::{DIDResolver, ResolutionInputMetadata, ResolutionMetadata},
};
use std::collections::HashSet;
use std::marker::PhantomData;
use std::str::FromStr;
use trustchain_core::resolver::{ResolverError, TrustchainResolver};

use crate::utils::{decode_ipfs_content, query_ipfs};
use crate::{FullClient, LightClient};
use crate::{CONTROLLER_KEY, SERVICE_TYPE_IPFS_KEY};

/// Struct for performing resolution from a sidetree server to generate
/// Trustchain DID document and DID document metadata.
pub struct HTTPTrustchainResolver<T: DIDResolver + Sync + Send, U = FullClient> {
    pub wrapped_resolver: T,
    pub ipfs_client: Option<IpfsClient>,
    _marker: PhantomData<U>,
}

impl<T: DIDResolver + Sync + Send> HTTPTrustchainResolver<T, FullClient> {
    /// Constructs a full client Trustchain resolver.
    pub fn new(resolver: T) -> Self {
        Self {
            wrapped_resolver: resolver,
            ipfs_client: Some(IpfsClient::default()),
            _marker: PhantomData,
        }
    }
    fn ipfs_client(&self) -> &IpfsClient {
        self.ipfs_client.as_ref().unwrap()
    }
}

impl<T: DIDResolver + Sync + Send> HTTPTrustchainResolver<T, LightClient> {
    /// Constructs a light client Trustchain resolver.
    pub fn new(resolver: T) -> Self {
        Self {
            wrapped_resolver: resolver,
            ipfs_client: None,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<T> DIDResolver for HTTPTrustchainResolver<T, FullClient>
where
    T: DIDResolver + Sync + Send,
{
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        self.trustchain_resolve(did, input_metadata).await
    }
}

#[async_trait]
impl<T> DIDResolver for HTTPTrustchainResolver<T, LightClient>
where
    T: DIDResolver + Sync + Send,
{
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        self.trustchain_resolve(did, input_metadata).await
    }
}

#[async_trait]
impl<T> TrustchainResolver for HTTPTrustchainResolver<T, FullClient>
where
    T: DIDResolver + Sync + Send,
{
    fn wrapped_resolver(&self) -> &dyn DIDResolver {
        &self.wrapped_resolver
    }

    async fn extended_transform(
        &self,
        (res_meta, doc, doc_meta): (
            ResolutionMetadata,
            Option<Document>,
            Option<DocumentMetadata>,
        ),
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        // If a document and document metadata are returned, try to convert.
        if let (Some(did_doc), Some(did_doc_meta)) = (doc, doc_meta) {
            // Convert to trustchain-ion version.
            let tc_result =
                transform_as_result(res_meta, did_doc, did_doc_meta, self.ipfs_client()).await;
            match tc_result {
                // Map the tuple of non-option types to have tuple with optional document metadata.
                Ok((tc_res_meta, tc_doc, tc_doc_meta)) => {
                    (tc_res_meta, Some(tc_doc), Some(tc_doc_meta))
                }
                // If failed to convert, return the relevant error.
                Err(err) => {
                    let res_meta = ResolutionMetadata {
                        error: Some(err.to_string()),
                        content_type: None,
                        property_set: None,
                    };
                    (res_meta, None, None)
                }
            }
        } else {
            // If doc or doc_meta None, return sidetree resolution as is.
            (res_meta, None, None)
        }
    }
}

#[async_trait]
impl<T> TrustchainResolver for HTTPTrustchainResolver<T, LightClient>
where
    T: DIDResolver + Sync + Send,
{
    fn wrapped_resolver(&self) -> &dyn DIDResolver {
        &self.wrapped_resolver
    }
}

/// Converts DID Document + Metadata to the Trustchain resolved format.
async fn transform_as_result(
    res_meta: ResolutionMetadata,
    doc: Document,
    doc_meta: DocumentMetadata,
    ipfs_client: &IpfsClient,
) -> Result<(ResolutionMetadata, Document, DocumentMetadata), ResolverError> {
    Ok((res_meta, transform_doc(&doc, ipfs_client).await?, doc_meta))
}

async fn transform_doc(
    doc: &Document,
    ipfs_client: &IpfsClient,
) -> Result<Document, ResolverError> {
    // Clone the passed DID document.
    let mut doc_clone = doc.clone();

    let endpoints = ipfs_key_endpoints(doc);
    if endpoints.is_empty() {
        return Ok(doc_clone);
    }

    // Get the existing verification methods (public keys) in the DID document.
    let mut verification_methods = match &doc.verification_method {
        Some(x) => x.clone(),
        None => vec![],
    };

    // Create set of verification method ids to check if candidates are already present
    let verification_methods_ids: HashSet<String> = verification_methods
        .iter()
        .map(|vm| vm.get_id(&doc.id))
        .collect();

    // Add any public keys found on IPFS.
    for endpoint in endpoints {
        // Download the content of the corresponding CID
        let ipfs_file = query_ipfs(endpoint.as_str(), ipfs_client)
            .await
            .map_err(|err| ResolverError::FailedToConvertToTrustchain(err.to_string()))?;

        let mut json = decode_ipfs_content(&ipfs_file, false)
            .map_err(|err| ResolverError::FailedToConvertToTrustchain(err.to_string()))?;

        // Add the controller in the decoded IPFS content.
        // TODO: We are only supporting one of the possible ways to express verification methods here.
        json.as_object_mut()
            .ok_or(ResolverError::FailedToConvertToTrustchain(String::from(
                "Unsupported document verification_method, use Vec<VerificationMethod::VerificationMethodMap>.",
            )))?
            .insert(
                CONTROLLER_KEY.to_owned(),
                serde_json::Value::String(doc.id.to_owned()),
            );

        // Can deserialize into untagged enum VerificationMethod from VerificationMethodMap str
        let mut new_vm_map: VerificationMethodMap = serde_json::from_str(&json.to_string())
            .map_err(|err| ResolverError::FailedToConvertToTrustchain(err.to_string()))?;

        // Transform public key id into RelativeDIDURL format.
        if !new_vm_map.id.starts_with('#') {
            new_vm_map.id.insert(0, '#');
        }
        // Create RelativeDIDURL verification method
        let relative_did_url: &str = new_vm_map.id.as_ref();
        let relative_did_url_vm = VerificationMethod::RelativeDIDURL(
            RelativeDIDURL::from_str(relative_did_url)
                .map_err(|err| ResolverError::FailedToConvertToTrustchain(err.to_string()))?,
        );

        // Continue if verification method is already present
        if verification_methods_ids.contains(&relative_did_url_vm.get_id(&doc.id)) {
            continue;
        }

        // Extract the verification method purposes
        if let Some(extra_properties) = new_vm_map.property_set.as_mut() {
            if let Some(purposes) = extra_properties.remove("purposes") {
                let purposes_vec = purposes
                    .as_array()
                    .ok_or(ResolverError::FailedToConvertToTrustchain(String::from(
                        "Expected public key 'purposes' to be a JSON Array.",
                    )))?
                    .to_vec();

                // TODO: consider separate function to avoid repetition here.
                // Propagate public key purposes to associated DID fields.
                if purposes_vec.contains(&Value::String("authentication".to_string())) {
                    if let Some(authentication) = &doc.authentication {
                        let mut new_authentication = authentication.to_owned();
                        new_authentication.push(relative_did_url_vm.clone());
                        doc_clone.authentication = Some(new_authentication);
                    } else {
                        doc_clone.authentication = Some(vec![relative_did_url_vm.clone()])
                    }
                }
                if purposes_vec.contains(&Value::String("assertionMethod".to_string())) {
                    if let Some(assertion_method) = &doc.assertion_method {
                        let mut new_assertion_method = assertion_method.to_owned();
                        new_assertion_method.push(relative_did_url_vm.clone());
                        doc_clone.assertion_method = Some(new_assertion_method);
                    } else {
                        doc_clone.assertion_method = Some(vec![relative_did_url_vm.clone()])
                    }
                }
                if purposes_vec.contains(&Value::String("keyAgreement".to_string())) {
                    if let Some(key_agreement) = &doc.key_agreement {
                        let mut new_key_agreement = key_agreement.to_owned();
                        new_key_agreement.push(relative_did_url_vm.clone());
                        doc_clone.key_agreement = Some(new_key_agreement);
                    } else {
                        doc_clone.key_agreement = Some(vec![relative_did_url_vm.clone()])
                    }
                }
                if purposes_vec.contains(&Value::String("capabilityInvocation".to_string())) {
                    if let Some(capability_invocation) = &doc.capability_invocation {
                        let mut new_capability_invocation = capability_invocation.to_owned();
                        new_capability_invocation.push(relative_did_url_vm.clone());
                        doc_clone.capability_invocation = Some(new_capability_invocation);
                    } else {
                        doc_clone.capability_invocation = Some(vec![relative_did_url_vm.clone()])
                    }
                }
                if purposes_vec.contains(&Value::String("capabilityDelegation".to_string())) {
                    if let Some(capability_delegation) = &doc.capability_delegation {
                        let mut new_capability_delegation = capability_delegation.to_owned();
                        new_capability_delegation.push(relative_did_url_vm.clone());
                        doc_clone.capability_delegation = Some(new_capability_delegation);
                    } else {
                        doc_clone.capability_delegation = Some(vec![relative_did_url_vm.clone()])
                    }
                }
            }
        }

        verification_methods.push(VerificationMethod::Map(new_vm_map));
    }

    // Update the verification methods in the DID document.
    doc_clone.verification_method = Some(verification_methods.to_owned());
    Ok(doc_clone)
}

fn ipfs_key_endpoints(doc: &Document) -> Vec<String> {
    let services = &doc.service;
    if services.is_none() {
        return vec![];
    }
    services
        .as_ref()
        .unwrap()
        .iter()
        .filter(|s| s.type_.to_single().is_some())
        .filter_map(|s| {
            if s.type_.to_single().unwrap().eq(SERVICE_TYPE_IPFS_KEY) {
                match s.service_endpoint {
                    Some(OneOrMany::One(ServiceEndpoint::URI(ref uri))) => Some(uri.to_owned()),
                    _ => None,
                }
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::data::{TEST_DOCUMENT_IPFS_KEY, TEST_RSS_VM_JSON};

    use super::*;

    #[test]
    fn test_ipfs_key_endpoints() {
        let doc: Document = serde_json::from_str(TEST_DOCUMENT_IPFS_KEY).unwrap();
        let result = ipfs_key_endpoints(&doc);

        assert_eq!(
            vec!("QmNqvEP6qmRLQ6aGz5G8fKTV7BcaBoq8gdCD5xY8PZ33aD"),
            result
        );
    }

    #[tokio::test]
    #[ignore = "Integration test requires IPFS"]
    async fn test_transform_doc() {
        let doc: Document = serde_json::from_str(TEST_DOCUMENT_IPFS_KEY).unwrap();
        let ipfs_client = IpfsClient::default();
        let result = transform_doc(&doc, &ipfs_client).await.unwrap();

        // Check the IPFS key is in the transformed DID doc verification methods.
        assert!(result.verification_method.unwrap().into_iter().any(|vm| {
            match vm {
                VerificationMethod::Map(map) => {
                    map.id.eq("#YGmbDaADvTGg3wopszo23Uqcgr3rNQY6njibaO9_QF4")
                }
                _ => false,
            }
        }));
    }

    #[test]
    fn test_verification_method_deserialisation() {
        let mut json: serde_json::Value = serde_json::from_str(TEST_RSS_VM_JSON).unwrap();

        json.as_object_mut()
            .ok_or(ResolverError::FailedToConvertToTrustchain(String::from(
                "Verification Method Map missing keys.",
            )))
            .unwrap()
            .insert(
                CONTROLLER_KEY.to_owned(),
                serde_json::Value::String("did:ion:abc".to_owned()),
            );

        let _new_verification_method: ssi::did::VerificationMethod =
            serde_json::from_str(&json.to_string()).unwrap();
    }
}

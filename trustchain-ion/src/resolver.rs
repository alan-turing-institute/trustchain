//! DID resolution and `DIDResolver` implementation.
use async_trait::async_trait;
use ipfs_api_backend_hyper::IpfsClient;
use serde_json::from_str;
use ssi::did::{ServiceEndpoint, VerificationMethod};
use ssi::did_resolve::DocumentMetadata;
use ssi::one_or_many::OneOrMany;
use ssi::{
    did::{DIDMethod, Document},
    did_resolve::{DIDResolver, ResolutionInputMetadata, ResolutionMetadata},
};
use trustchain_core::resolver::{TrustchainResolver, ResolverError};

use crate::utils::{query_ipfs, decode_ipfs_content};
use crate::SERVICE_TYPE_IPFS_KEY;

// Newtype pattern (workaround for lack of trait upcasting coercion).
// Specifically, the DIDMethod method to_resolver() returns a reference but we want ownership.
// The workaround is to define a wrapper for DIDMethod that implements DIDResolver.
// See https://doc.rust-lang.org/book/ch19-03-advanced-traits.html#using-the-newtype-pattern-to-implement-external-traits-on-external-types.
pub struct DIDMethodWrapper<S: DIDMethod>(pub S);

#[async_trait]
impl<S: DIDMethod> DIDResolver for DIDMethodWrapper<S> {
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        self.0.to_resolver().resolve(did, input_metadata).await
    }
}

/// Struct for performing resolution from a sidetree server to generate
/// Trustchain DID document and DID document metadata.
pub struct Resolver<T: DIDResolver + Sync + Send> {
    pub wrapped_resolver: T,
    pub ipfs_client: IpfsClient,
}

impl<T: DIDResolver + Sync + Send> Resolver<T> {
    /// Constructs a Trustchain resolver.
    pub fn new(resolver: T) -> Self {
        Self {
            wrapped_resolver: resolver,
            ipfs_client: IpfsClient::default()
        }
    }
    /// Constructs a Trustchain resolver from a DIDMethod.
    pub fn from<S: DIDMethod>(method: S) -> Resolver<DIDMethodWrapper<S>> {
        // Wrap the DIDMethod.
        Resolver::<DIDMethodWrapper<S>>::new(DIDMethodWrapper::<S>(method))
    }
}

#[async_trait]
impl<T> DIDResolver for Resolver<T>
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
impl<T> TrustchainResolver for Resolver<T>
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
        // TODO (copied from trustchain-core):

        // If a document and document metadata are returned, try to convert
        if let (Some(did_doc), Some(did_doc_meta)) = (doc, doc_meta) {
            // Convert to trustchain versions
            let tc_result = transform_as_result(res_meta, did_doc, did_doc_meta, &self.ipfs_client).await;
            match tc_result {
                // Map the tuple of non-option types to have tuple with optional document
                // document metadata
                Ok((tc_res_meta, tc_doc, tc_doc_meta)) => {
                    (tc_res_meta, Some(tc_doc), Some(tc_doc_meta))
                }
                // If cannot convert, return the relevant error
                Err(ResolverError::FailedToConvertToTrustchain) => {
                    let res_meta = ResolutionMetadata {
                        error: Some(
                            "Failed to convert to Truschain document and metadata.".to_string(),
                        ),
                        content_type: None,
                        property_set: None,
                    };
                    (res_meta, None, None)
                }
                Err(ResolverError::MultipleTrustchainProofService) => {
                    let res_meta = ResolutionMetadata {
                        error: Some(
                            "Multiple Trustchain proof service entries are present.".to_string(),
                        ),
                        content_type: None,
                        property_set: None,
                    };
                    (res_meta, None, None)
                }
                // If not defined error, panic!()
                _ => panic!(),
            }
        } else {
            // If doc or doc_meta None, return sidetree resolution as is
            (res_meta, None, None)
        }
    }
}

/// Converts DID Document + Metadata to the Trustchain resolved format.
async fn transform_as_result(
    res_meta: ResolutionMetadata,
    doc: Document,
    doc_meta: DocumentMetadata,
    ipfs_client: &IpfsClient
) -> Result<(ResolutionMetadata, Document, DocumentMetadata), ResolverError> {
    Ok((res_meta, transform_doc(&doc, ipfs_client).await, doc_meta))
}

async fn transform_doc(doc: &Document, ipfs_client: &IpfsClient) -> Document {

    // TODO: handle errors throughout:
    
    // Clone the passed DID document.
    let mut doc_clone = doc.clone();

    let endpoints = ipfs_key_endpoints(doc);
    if endpoints.is_empty() { 
        return doc_clone 
    }

    // Get the existing verification methods (public keys) in the DID document.
    let mut verification_methods = match &doc.public_key {
        Some(x) => x.clone(),
        None => vec!(),
    };

    // Add any public keys found on IPFS.
    for endpoint in endpoints {
        // Download the content of the corresponding CID
        let ipfs_file = match query_ipfs(endpoint.as_str(), ipfs_client).await{
            Ok(bytes) => bytes,
            Err(_) => todo!(), // see transform method in trustchain-core
        };
        let json = match decode_ipfs_content(&ipfs_file){
            Ok(value) => value,
            Err(_) => todo!(), // see transform method in trustchain-core
        };

        let new_verification_method = match from_str::<VerificationMethod>(&json.to_string()) {
            Ok(x) => x,
            Err(_) => todo!(),
        };
        verification_methods.push(new_verification_method);
    }
    // Update the verification methods in the DID document.
    doc_clone.public_key = Some(verification_methods.to_owned());
    doc_clone
}

fn ipfs_key_endpoints(doc: &Document) -> Vec<String> {
    let services = &doc.service;
    if services.is_none() {
        return vec!()
    }
    services.as_ref().unwrap().iter()
        .filter(|s| s.type_.to_single().is_some())
        .filter_map(|ref s| {
            if s.type_.to_single().as_deref().unwrap().eq(SERVICE_TYPE_IPFS_KEY) {
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
    use super::*;

    #[test]
    fn test_ipfs_key_endpoints() {
        
        let doc: Document = serde_json::from_str(TEST_DOCUMENT_IPFS_KEY).unwrap();
        let result = ipfs_key_endpoints(&doc);
        
        assert_eq!(vec!("QmNqvEP6qmRLQ6aGz5G8fKTV7BcaBoq8gdCD5xY8PZ33aD"), result);
    }
    
    #[tokio::test]
    #[ignore = "Integration test requires IPFS"]
    async fn test_transform_doc() {

        let doc: Document = serde_json::from_str(TEST_DOCUMENT_IPFS_KEY).unwrap();
        let ipfs_client = IpfsClient::default();
        let result = transform_doc(&doc, &ipfs_client).await;

        let expected : Document = serde_json::from_str(TEST_TRANSFORMED_DOCUMENT_IPFS_KEY).unwrap();
        // assert_eq!(result, expected);
    }
    
    const TEST_DOCUMENT_IPFS_KEY: &str = r##"
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
            "id": "RSSPublicKey",
            "type": "IPFSKey",
            "serviceEndpoint": "QmNqvEP6qmRLQ6aGz5G8fKTV7BcaBoq8gdCD5xY8PZ33aD"
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

    const TEST_TRANSFORMED_DOCUMENT_IPFS_KEY: &str = r##"
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
            "id": "RSSPublicKey",
            "type": "IPFSKey",
            "serviceEndpoint": "QmNqvEP6qmRLQ6aGz5G8fKTV7BcaBoq8gdCD5xY8PZ33aD"
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
            "id": "YGmbDaADvTGg3wopszo23Uqcgr3rNQY6njibaO9_QF4",
            "type": "JsonWebSignature2020",
            "publicKeyJwk": {
              "kty": "OKP",
              "crv": "RSSKey2023",
              "x": "EyGvw3AkcUf2TZToBh6pddeaaocmvTuLCSLun_yYJpL7x0W3gVEzeKlj06J5Sej9Duk0W_yGhbOKCahOx16LszwTHVgnH9FjRk0nwOer4yKaKnjTZ2FlZsYI0OI__jhCGP9cbcOEd-1rfvUFu-ghsj6oHfSXDBm0Ekplkgs1IktoicuMsF-bD7I6tZRpP9tqFGqARUqvR2daQN-scwYUNsv5ap3XakBCDvOCBc_rPAwzapY_nuC3L6x60UGBAPtUBANdaMhAU0gxd-3JMjcSjFgwzAhw5Eorr7bIp1_od6OfBRYu3sIkij5Es6RDBLghUAx2Z3dznniJRh5Xlx_8zn4SYw_xhV1X04vY5U4O7-7veKMqKxzzoGOR7O137gSTtAjdkWm_q35_KBo-SuO9RrHI8J91pJ4cJktXxMm2yhO1UnmzrQ6hu9YiKeI1kOsq2QJfLlCebKkvOI_KHmx3hUIu1wfEPCp8R7TWeP0LV3hjo0fpTg4fK9hizfCy5agdog6piegS_MB9Myka0DAInA-_YyRXUF1YhXW-Olza-Bk7-33xpfWiQK-78IN8VgcQ8AZ0eVn0L9s2hOpUXCmMmlZT4OQ9uryBJ17HMpR-EbxaqYlmMj7H2toZWjeNOprsexP9S2ZP0fqJbno2oLdhLLW3KyP4UzJltdR0IpsMDpT7nf05HxpJxNKCwMCASuVYMhAK0mZiL-3IjYO2Xa8N0oQxMwq3UuAgcQqSoqrk-CukR3JzS4lQk6LUUrH9Sej47RndsdAqjitadwznsTvxCHSNrWEjjh7aKxHW03jtGwfIZCwROF7mglHdhuzHYTE9Pw7S_fOcXfTglQbs6iz5OEVqyvUMcz8LPfK1SC-H3160XkL_8_4hxMo4ftKRkRRMmBZ-xDTbhCMtpJ5hEy85hD3LP2hPwuCPS2mOOGuaLXDm8CkNe_g52568yQM978Bv6BULHgYtl__wxn83Yvks1wNyTozFZJAV3mWXxS6vg8aiqcWBS5-bvEBsNu0PIzrHVQfAPz19e2kDSM2D59naZzg5Cyl7AuUYpYX_Ad9pt_Ro-wuXsiw7TTolCoyhgj7n6QEnESZ2zflXCDCYK09HDUnD9nFkBli8-DNqBRuzY2FGH3MknjdUCaREEziBuVhHQxfb-beH_VOxRSEHguz6JkMM8nB7myCz2dEQzr2KhdDvfsjtbso_mniq9_Ag4RxBZwkGxUWReivSLqI6AuufQXoK2FBRMoIuiadv1qYlzVM6lqWN0RXAFRtV9B3Z5bCLDwLW2ZcDobmXkk62STpkPaVUNVq8BwrRxGyuvmCPrX5e2Se5AxYIegOwd-Nbo3Xa8gy3jod3B9NCTiiqrgwl4RtYxcmh7RAydl7YV200RK1QRnRCdZwGYOHoTQrtEZTO0gswCgVCEyvg1RdhQlILYgRs_A3woHeUOaXeEdfUK_DvXM9TW8vegoZCZXDjYjmwcRBwrfZs1nDuUajev02fJPioJhoSaZH387XO93J3O4KmfvLOE4mgryrIAAyVJU0eohdBMbmLblvTAH1_Hdv_usK6XkOpEttkxII_nHGL0SHNHeJrMpltGaAFIfZaHX15OgbWsF53fe7Ds20NvuKSQCbUv62bYE6aiHWtsZX1L4n1b0UIN2QOr6VE3MdYSCD_twoIceEiWDH9-JxzDwJkHR4QwYbnzlVNggEKmjoS8gjrlr4se2gQvpn736EnDC7S5hnEoy09VqQ2H_xkEAVmNbExw4E0Fk56hByZQSSMDpDo0vcqSCYGSESlK0KkQUg31Qkf3TbUSjXF-rn73o9IgfMhzAKA3GAWHoi-ruQlgNMxN0UhSgelL3Qj5E1sv_EuIwgTap0SRBni2n9tCcCXVy3cnGeGgOQjdIhlta-o5g0smoY4t06sw566Mv3LjMxy1gD4QivJxPuyeifnIZqBkDm2SyAGeg3I_sVB2PaIAPyIx5154cE92ESLfKIBuiJ_9whJYCjSwfWq4sU89GiiAbbUdaWmQKrVy3GIGZ8sWMeAdg5CNWOqZb6TazY7KggXgwpbm0oyXSljjyLqcgxDk2CiNvWhQhrYC9NdWo1ZipuUsx7uEuQxaVpFLG-2gG1I7xZAL5n9mTIoLopK9BA_VM7et4QSmSrUbeA_adabCOY_4V9dxo1hH7aRQr43O0q2OBJhz9cBqaDNwmDzkjHbx73ja2QR90A1QGo1f98RMJ58nxb0lZfr4Kox3QVSKnrIvxhiNy8VwNBI8_P4AE_N6BX6uB_dAgNjBL5nzgu5m-PivAHAn8jSAK2Esbkf5UafTwPOUuO2dZtFYfq_lMDPomqqoF4idKpaD3qH1s_lRM1p0sHRdjjt1oG15CAUcaJTFBHwSOIsa8tzVYn-MrBOseZl6HtDVYp0CLhwsEUSiokH4mtfpbCaCm-ZAz4yGBRyUBHhAFeZFS2iNrkOo-wtmlWoryUPI5tFuOKZkm2oCsGdOARRYp0WVBKajVunZdgnmQJzww8kVbAvK0mpMcmeYyRBfevFkjGLWbye8XeN-jwnZ5ljuk8Ix9Jonr4PIrQJnwVQtU2DLjm5A8w1NdynibZHmNMd6gRd2dIzAWrlBmVotw3GXqsKM40azVPkZ4qxIQnKXQEVNJ0zgMRZrcBgfGp4ZFH2zXf1AqUV0noDSfPdkb3NK2rWy6h2VxbhgOGKkRJDR221ixdrSWuHYtrjt2vFSF5Z52sFusDer0YkVeq8mB9DW9rmrRNK4E1LSskpLQT1w8b78vXdo3V69oSxHgo1hGIphFIf9E7Ab5e99mY9KX6ixqLS8P8OO1zpm9ofzxSouDzHMraMIc6Gx7EtExRzWFyzmT6JdKMzTJVAobQHMvIuFGv-s3JjORXvaXbixAl-EVopmiCTu5-HBsDJhXSi1rnM4DuwihrXOu6cD9mAi97oDSWCvFQYSOp9gKnNxAJO8sEy8ibgJ5BNj6KTt-H6aa5x2TFTXdjPEuwKMVJ9YPLQPofx07rcRXLMr7_BHATwPmuIkBCAfoOeNmW-VsFve1Ev8PW9P-C5wEZ0lMnKjws9fLUbDkXF3kfPGbY3Sw6icPfAuZVeMffzon2tRBzbf62vTd6qfwnE8Oh0__xRXqmXkjNcqwQlw6PwA6Azlg1OwSww6EGXRTkmfGdP5WE8ghfZvWe3rkY0Z2QGH_Rk647pOhK0YJ9TAcqcPzkL2g64e-9VQdnRUfpo-E8RLDpjrdp4mtOPeE39Yzjv27uJcHghI6dzffGAB-SeYcHmtwJpx9rykn2-14JHYPBeFf4okRdHZeOmgV1qvk_wrkRvnYeB8oS9y_P7K5Nl2izkxBncB-UOO16zvqeplUxDe2AD-iXEaMUVrPKDPmBXUW8cJdFEd7pFu00UddZoER0XyAIP3XCw3wZuhtlXvwJBz5DIMXhmL2u-zI-uL13VTW043jlqPrQptQCzZdZgK9DOeAutUfsq_lA_wtFXcfjr4H7GwbnTL92WcB4ulzWboEFeh1hVDgp1cAcdqPztpCMCXBOM_gb4zNtMi21I4vLd_RpTcwCBQRD2YBHEPlCNiUhIx59xmO6U1rJ5J_ym1vQEbgwAOnAnLWJfmTqJAzACrR3OYiG0Lx7_wcqVONiU6ReWPjHkZW-iDLZXoomBbTxhfg0zD6TnKRhv33PTmc8ZWZF57tCG4jNR-Y7MNyTErtFGScKgW1oAZvQbF7UzDMm3GAV7EYOkF_AB0jNVNZ_UtoFDpSHkNc_rVIKz12hp_xZl0_TC1ujk7v9GU7SFWxRLTBbMVyCN_nvLPbFMlbSDb_xpBIm5w0U-k511pNPno3SvPLe0vViAXSTDmvdok5FbQQ7jIEl8tOTVEI1cTnj0WAAo-GfuUWrRiL8UzrNXX13I7Iy5CryhUTq75csDs_m_oQua7vQdTdihdSqxoXuPykB7d-oh-LKvezLmeI-2BKpkgA47IoD01_HUa6RojeULFAT-vt1eD_-BT6_K4H56iNRYrxq3huHpzG5hxseoG_-CNKdaTF9nTZ0rtu8J8z4jWQqpseCnfFNgojgjU7qxzobD4046t0IjrU3l2Oe1xoTk0oTt_K_6ppY1wpXOeSUrHAWi5tD3QMjuK7CVvZ-6qsaZjIorqsZlWP14difoQujNtJ-0dWxs0lB88F13o3T3kReZ5wheIuLH_s24sgr2KKn8zAUAf6FYasQJXo0ZIqrvLqfMs8Q2nq-zoz6HFsiJxgNsEYIiUtz0X4RSRCQxpen6LSpamF1a8uKGrgXeVZKops0YyCDor_3IIR8eTRbnlAFE-CdarlA4KW-7xdlDp4zOfyGs5NZFMCX1CVUt38STXcvqAkOzjoTN1TQmO2AFzAKonHLo8DF_ZgdDE83i-1pQjfJ3rCgF6FLz74t5IRozJMIL_olUwoOwzFd24R7xxRMfAPT9kMFwB0EmqR_CmIuHNIuH0V7BgkVCV5AaaTOXm5XRK_Gs-14_AkO-kK9jugzqtWsZc7A6XoG3X6Wca3BKNYY_PZZfsJKL2Ttb-qzGRC5P4dBlexvyf9VlxiZqfgWe2i-gfd0Zdb0trUcklxrAZ84HVaXgxifHJ6A2XYb_4SiBtbR5AowOpfBd4dBsWgeY1VbJNk_1rdONv2et7NSTGsPnnL7b1s0Rwwcn4BG3k-YmPPOpiRluKSVGVOeYuRYi57JEBYgkT4Ndq1EzCJsy43AEmpfQW3rPw_7NxFDYOP-_gsISPCma1rvN6M4kkhaBY-TO748qd0gQnYPPnOVhab07thWR6ENQaF0ZTfd9chNlweVqYyj1hM5rKxaXIhahCpz0XHJsmtOiKrqkHSuyxfm8zjD3ZX7ov1wsoo9cRE88vedbNHEsb9JJfOay7gT0Su2sIwWeTep_3LjmMDKNzWtfV3dCH0QuBqSU_hHilryRg3XNsT8SeSP6YBPjehHf8MDNR-_cCaayEWW5hlkiSaWrOqNjvDXwHtyTSlh6dD4MGbJQw-WFcLfdVZ4qBRFUFJdblau-B4JWioWFM0DC6zNrVMXrKzMCfQVT_s6O5KF5cp7rH9mez-sqbW1W-QqPUTs0LcbD3rnDDch6EuamnVHDPzOgsT04VnOzuvMBhkXWIS96hzHcsyZMUDewTxef2QJoNl4TJs3tjJskxTbYIhwNbD5zvYgrGTarnI1EvuBZqXvgvrWYfIXYDUsiMxWiPMeFeMLFPO1eOdha5pVuRmQbhH2UdFcwHKgzwtUbD1YkVf1yxzb1SRkWs2G4pAIFDsQ0Ag88h_aMchsJ6Kz2bgtUTwwklyzbnR-jp5RINaiKCfh2zoDrKNC9elKUSBLOpk4Z8l4-lwfm1dYlM_I5h9nwwZAZXcn6LNE4ee6XNY3A8JJy2y180iGyHyXhPgkSUmQzFvPQH8Tf6N0oEHPfOgoCpMdx7gH4MX91rT3axkZBdQCvOl1cD5iKF05lHgbMX30bwMwI5mipnu-EvuBnlE67O7O_O-xJNw7HpuGbXKRXu8eipzkLK0B81jwuVAJYeMnHNprXMUw3zk_DPZ3hZ-ieg7GyPwdbM3AuKgcJwAtRPYS8YGE86OH-EHVAZQwp-8SNcNKFPqsIV6WGzd7Rri0_KRA0yDUNPq5vwuaAelefzeqJa-ax-MPzH5mBiQWSGTRjT8OUU-KkP3nyRi4wLEeqbPfTwxPgECJeiPx25JHngqWtpa5RBrRk5FEkGxcsXWPNHG6pZvRZGJh1Jl8C80LiOS-JeXZzCNp9WYRkuNrLTeC1YPJzYFdxMMRZHgqRfUxiwHv2eBfM88n8MapLuRt-p_1_Dgbg4x5SRJEjo1ePLwQ_liGwXKUaOKgMswYvQlVPs6CSpmGzC8ZLix1w281LhSAjYBTBG0TLmzlyaFDiNDH_X9KVW4AdNVLodAOa4TbvXT1OQzH5BmsNPCEdOczYCIdKjEyQcRsV2F6U4A-3asdTTvCbxckRBoeP2w2CFop470c01mUT6Dnx3d3CIu3B5PeDbEl37tBrLx46mw5M_TTCZeNOSfPd5bDodg9B6B3mQdzRNzW-w0ZqIWIHs4XCsfzJ-m1HajS_Eo9mgBG_PcykUNfrAJ67hI_KPBHGq1F8Ef6-wdDnyNm0frIXFds79ileVsV_BHaItzFTf2LcG-Ye6-TqsCcr7UI6ShVwOviVaF_phaA-5qqumhWfNB5eWeoN2SxX_IZDtqDT42_YeJeR2P1cvj1iSIBk5A6W_Fi_7t_YiCPnvlFSCIDpW9WX4nxPtIqT-G1GTRPFBC35Deila5ARY6MdT2THwxnwL_HNNZvTEcPgSLcKjenpnxuyWffYNhtUDjE58bc_NwziOdFJPQJjXe3GyicinxQYJjnx1nB9O-_M2Y4Nj0u2kz6lnnyGqJTlX0aA72q4YNXXGxKeWI-rtX0lSV7cZw7PYByJicLeWXi_LEePFr3wlaLpJplHTf62pyXXn3XFJVB17tIEDoMYMcHeFIdJ8wjt0RWHiNkBMusSzpptoTD2duxjE9jC71FlBPNIjtxmcsquPHaNaVMVlsH8aIXXgxiLS94GA2j7P-7Q7Af9gXIXwTETGngv4_n3W3K0wVzuh9O-wItAc4KsCR4kP8dt-g0kOmUpt7gr_JiAwjd3arImJc9xFlhOB3tOoVULj-yaTa0fwT63zqPRJ288sHFL_AdQlSUj8KtcDBbyVyopXgSNTMxczcxpyB8fU6z0SgWnxXPiGEgeyYdOt5MKGLNxBAf0c1sCaW4Fa-UK_BBjmrupMvXBVYvXMzW8i-gx31D3ziA15GZOAdXeNEQdmxBGoRX9mgh5d0IjGA0iuFX0mnZfR8z0LSkH9pF5-F96CENxmXU3j_AcPM2ZlxhtdOAKuQ18knQWgxTBtR-RAqX9AOzHHnltlgn998tVl9qII9GY6VuudYe_J0jiNLSuRImS_wkNp1a6s6ZfQ0jOuJgv2M6Ip1Kj_MfLTD0YL4S8hvgfFR2UdMt9ddN5tTqV4NBdlREJftBii86VflrQ5Ec7KG6_EGfPRmD7J5MfZuS461yrNShIB6YiISTpef9gbvkXagIzSlZn8dc8QKN2Ltcih8bb9JfYUDAr4ndWJrUc58Y--S6YPl9R6xv62n-XE0FVShPkJI-LAAKFqT-UtdIwPcVb2qfqWytLPUGrrqMrOZZL-AN4zM4tWgObxuld78Ql7BaMnEZ-f1NYHzKExys6XdIX0bqTuyeNXruzTvnbis1fnzV41j9rqAxAcP3kvLhmkA7QmH28-Tdhaog3fk83eA--S2ef1MFq1P8-xrb3t73YaUWxYaDrRuJ_kntaNDafTRmsqWI7ptDssFOqzvmPgWgQM6PY_cDOnoJdedIZ3NMfrePJIDQxWF94nzJJAnaGbRCSJ0AJpfhYyZF8fTT8OB-kgh_mmNf46Mem1V_unkkUL-hRWL0HYXxWmD-ztDEZThiEBq5JmT22fOK8OrF7HtfQNBJxRkmzV1ZJCN9oZntgKRh_N1N6-PmDUXH-qiKmGQ82hNNq7K9_-ooG4TTOgLnrKrlpPARI7MAOeCnBUkrpL61IDN4Ktaet6LpZwlktRgF5WEhAS6WjJx8jk0xL6OBLeggTvJieB8YlOqO4r6it3CsEwj0IqbniaooJosTd1wRknHq5cFKG4IAwjMsSv8f1UTIFhwCa2wID_pcRpWA6ujjPg97AZk2QwxAO8zQJ3wkSukzsbgOWC_jIWM2Lf8P9YXkgCAh9-tlpP3yRnpDG1t4efBQE4LK9Fxy3sa_FXxnHFagTENdQ6fG05Ao89lNJG3fvNUwCDjeNmWCy-IYfyblVQnYAZgCi-6hB7FlDfAC9PbkgX9RqA3q8dGfnn5h52VQ-Ts90X-B2Rqh_lOQAy8haZrzBCY-Spvvw1NMg_hBe49MTATla_OPh4rsRtSkIj2JR3D7OOYQALwIshjCquOJOxk4_S4X9rcVuQjbApwmk15wlibnWLIwrLuFJw_q7hKywfcznPJqsolADHqMcDWi0vR9Fd_1cQxgWicacfQlwaLw4y74NYaIo7-rePg6M16uz_Aa1NfrCb9ftxb7f2IDcoEIMQOglFR6FigIe-xgctCIq_vaTmr3fbAafXIefNL2HEv8_lfByaaGmUlgOz0eTg2RNHiAY5G56YdpEqAXfO3wepFPjfzgdOvwZXn3t6_FrUwMgCtLMKjElfSKGt9ZcrV3bWH2BaS9q8031sg7CFHQWet2dgZJZcIF6FGhkabOKrPLTiKeyoygKdAQCKKBX5KF4EYImL99mvhXkNgACP5YTkjiP93zj4Ibf13xPbI5z18WnevAhIUMCuDiZ-pbn0rCCEFROV0PPsq2s4xBDDuqs2p6s6yICabaO3QNq3CbikaUNZLg1e9YnNtCi1xfr4z7gcnHu2C2XBNaMGwk9_31pGCtOrKfRgR2eKaq7UD6Tkki6eM-dc2q7Jw-LHWMn5t_XloH5ZPsipT9FvhfdNWn0qYBN9sVe9XfvZkdsfxbC2Sm7-tg9JgD3TplSQK8YgkHgXjEP2gZ77Le50wZHwmDtNT20rHvzs7cCyDFU-G77suehlsFBGOTCrc3yjckOlTZRpmVijpFRtHPYkA1ZvtBBRpGQsaxTZvN84nWwXP4sVC2urXVCvbTTBbrPK4M5AH-bfTI_LhSDyh4Avg_eIBFJMonXUjgkRI4rUyK1xXnhoc-Du3JrtbGAB9i4Ed-3ymWD5buZXUYIg6EUVAdITzsAeJqrP6NEH42DUP4SB6flNPIyAjTg3lfikkcHvt5V9UCkxBYBdwrdC5ZnXgPR7OECsUsPcZtKM3qM8J2RICjXHqTzx8gJYMQ3c7L0kZbkSVA-guf9LlQrfz9GdgKSe6sNRGBbvLH2CemyjXO78p-F2SiD5kwfdAYkhIe0ULz8S4prsbiXl-qQvd90gAKVHlDQtjdDEOgTvtYbyE--6Hqvd9mKpuG3bzGnwTLZ02x4syrQ6NS0ekrEynx9PBdFxipZj-dz5-Ydjc-FWe74kj_G9VsHztfWg_hc1lLztKgJuwNNum_pseEJlqgpLRCLhJxTFchrws68j3M36CfzOFq4U7ptTkLEj0ZuHKt8wUqEqEj_iP4JkL2q-C6-8QUBYjSWGZZItIxvx8PpMUVgitYGvyx7p4SuEXoccrSa1FhbpFlKyyBZn8BbCbJPIgzuK_Fcltn5n2l_xDxJzR5GneV-SC0RKT_5vdd2Db2GFGaXjBTTg1wq1bP5bJIZoRCSU8R2Tc20ktYvgi3THLBtuV0fxriQNhzp3kLi0gNZr-4Xzd9Qz5x3JyBS_k1SRQeMvrUQghv2BGZOKHN35UMhTv9J5cpZGPASdts0tFKmyvhhPe0RPjpDUhbU_oeUVANY8kYtlwD7VN-HmnPXEaoAbVyX89EMqFQHNff6WR1sW1DlcPZlfgGh1QbrTt8kIA0aJEYO8pWbwXAKTxoF6MWdkUxxbMdc0m9IlNkGugq71eEXeCbFMDX1YRmYOJ7iIghkp3F3lPJNqxNNMXDKqkfHIPbo8eYB2vgB0yXfwGQGJyr_zYtAIXNIQJNp1M14MxhE_Cq0TwZtVIf8_KuWnkM_D1gGZT6NUibgcebd8j-_UnKn26pT-axRX8yVxwXDbRmczSuuH-_dXCijOFXsiPwc7cFgJK4UnPlITAXfKGE3ueDB-SHjCC8u8rCVi5Iy7wVAkeMTju2cDIqs-MVkqP4j2WyP9k4OAC_nXEMjEina-aFeW2VtZSx97b0Bbdfdkgj5qUCBi1bT7rFDGe_tL8vor4K9lywqD5rxqvztcsV3XDvoqdUgSSCX9jyHTSVTCg_ro_XiJj1XvuxL2tW6Yw_9ApAZNI3lOJlXWDy9dt7KKq3rbKQExXhpcubSUHTRGg6KqDjdjWxbCFzcciuOJHqS3sKDeZ3KEzFRUJP4xwg-yFnBs3D16p4V1rQ4kKeqyAU2tiznpxT-ez1hmLkZdvGrmCOtQnuNz9xstCkqPegAIuXCcTOz_fHHvqpmCud0chb4co1CvJc8i5LFUTGApkqsTJKst9fPzkENpUqP_esLhiCwGTCJkphz73EcPcUhdACZ-BfW6yy8aPVvjNIzdEQuAqGykOqYhZSzIEUdmeSwvc3-vmfwh0YiWzo8CWotaRLcM7iSrePowP2rhu7T1prvyWh2nPwJeHY2xtI0CVswOl2MVXNBBGFJVaVnaygOiQfUQw--ZYZnXP3YWji4xXlAGQzZNMOdETHi0L2DgBhr5AT_OM1X3qP-VLGB9ClylQIHQByUgsSzsL7LNf2Qj1gsFyigynan01U-2Ipr-fHlsmuQgHL84FmHL_8FQsXL2gukAxPDHEFVNEyZl-LZ8mJWynoJGrm09xjD99J8Boh_AuO6vEYrlq6x_aVagctMXAVtYaliPTY_apio9gr3Vpj0OrEe4W-_he3tt5Wu2OlcTMIQ6O3b-Q1MFHIzxCZphRZj6wwOGg15m3EfIICR1172hW_5zq5LRY0hWhppbC6JOqJ0kS1tQYXu-Yj8ulqcIQarKnPucYmkqUfbkA9x1Jcbrd6vbhy-FTZFmF5S1bTQAKKp0wdi_GmzhWSX7NryzBN4D5leqpbXq5JgKfcKdGroW_-LeKCd3mTTi-i7MgfRXbULW5-2Vi-Mhe6t05DXHRSdmlaO4TZkIfQ9jC7wFREwT-MoVTU-BTzHgHD1JLIWs4jFuTcjb67RU78Mz3a0ABFOjzWLfQ78iJ8xCZkxzd1OHgIYlkfin628SAN1dBoXI462v6YbLrKyT9ADFrbUow14gP0HDw6bk6eVO-9iFj-vdW7T9vIGTmr05_lJGU9_Fua9pSG0QEWXFIJDGtwdSAqsqOIx-fGIYcHQkEifXdpqY9Y7Z5JtE-0ufhXj180s1DxnXLqG6v5-s2036LogHAmPFPLlMDGN6niA06I-C0HOvkD51hl9QSUmGODpG6Pos6wKgvHdcbJ8eYIEViFV7RDc-RcdPXedRSi8TKVu6AA7-vq4N_wctAdPKEjPTsg7ryVo0qM0dXqKXQlDjsQP3xZ7p4CVUY9TBXUc2ofs19ce944GVSgfSBfJv06RdAaFUf3gMse9I-HZFh8W_1C8zxdVprHXpXRNPXvT-f2blhsHVljWyF5oT8YdJRfg5Be_AgZKEqy8inDM26qLUbxdWhAZN5-VWI39_OhxW1LWYyxRid8qGhhCEcRMcIzvjFUgvVrLZGLZ66DUAElTYW_U-Big6nS0KuRUYfgKyDOaeNUE7QCpvdbQQpoZ74vPJHonvLVJga6f1xNIPgWcDgCn9BaUkSObPO3HPT3QmRQFP6fNRD6ClsD2VlfXO9IIeigNxshI2PIIkUTmT5DyBTZ19gpL26PLr9VmgMZQ_1Q2ZnYpZ2QRSnarD_CzCqAMlItznvFWIUJYaUo_Sv1GwbRKkxL5g3-il178X6vnnkucd5SHuuZFhdVmYmEiyGQSvPH-3oY8Cq-8_oK_K8K8xJk0LBCWOOclN6ofJ9GUpX4xpXlV3fzP7-nb1oZ0kliikNYIO05z3wICGYxWAH1w2bhh9wJ5EBTn-UJ8sT7hCru7kKtKmoKdQSpmhg3layUbdwB61Nn3w8ygZ3m0-g0d1oArPRahdiI0q7SwgVermuEShR8gXGKItzfkTmnRQlsBfu-r6gjyVvTbRpZ3cOKLkqcPZhcpsBKDg5A_arKWi7lb_NR6ON5xpQgqBV8fjdbrqSXv4n-kQ6Iy2rs6Fe-ZD38y2g_YtxTtdDjogDLlShlPpkMUbXdFynYlftaeHM-2BnE6jTT9cCGvSSmT30DWJiEJUQZ7rEUstp5aNZb1YSmkz3vX-p66t8_DBBrhLp31eVx1MtIWg7aVTJRhEFdkdnCTsRVyZ0TvcSCNzDl0n7XId2-bqm6RgpizuKPuS6KDb-vD0Cx5X6qXPpxGXiqYIHXp-woAnZwCROUYGbJLzJzNNTetEQiLYskFvqRIIXyn9L-352LtH3ZrcfOuAcvyml4wvA7FLfPCDpoIA_6dyutPzaDwa_xOxuygA8Eb1QZuWRQTk-D2W2ncvZRV7c4Pw45ZYQC16ta09u6OY2yk_fyc-0cICHvDv5J5ZN5IvxmOD1HMdv-deqeu5Gs0C5uIre5EYg6kPZiomOwr7L6p16fOUOq0gdI0bOLg4XXKcjRm5ctcc4NMPuDiy-ddXonnSoEOrQBuOcZO5hKDOTUWd2vn0e236a6rLFZvj9p4glldxbJCQ5i4l_fkBTzpkdBxUpf6gQoaunjB-14zN5JzbBeOTmFLSgFFppWKKZ3EBDgxguopksbVMkymMsMC7hCQ4VLGURbK02efR0AYCYstQVS0OluXE-NNLIai_WnjIXQ8GXGiqpj4D-HzmKaNprHPGemymAxoLfadELdnHbcLJJH-J8WZEqbk37EXZHhzHeuOFMFoFi5qBpFW9emunCdJr06dzhT26egqgWucPF_rM2Yft-GH3Afe2gklgRkvki65oX_4tywnl9Bfo4H4Ufy1JmvjggGATU_hdfvlkR5D6c-0h9ywMavg6BwZkTHhu9ZDzW4EcICb6RvL0K9-jweDlyKv4wEVSd4lMDv5cIID_TyV9DveMNBZtNSm77w1dXtw5JYq2EpDXNTE7MdXb_Gr8AeOdhK3ibCwVUZjOcIlbxxNQHbqvsF2_iJfArfnihOvmQoDT9z2deMTijGkEO-_QqKdUgUfjF73bCuii1hAXiYgqf3YlBk13SHTlmymrp0UG_Nw10dXYGa4FTn9Rt7CGm7DOAhlzOqKnQdRndL_xLX6wVe7nn2qHHetdkvoSuvJ8_ts6dfs4GEwzrX0g9tCLsD1_wViq-k3fVB9tcUmiMOh_4NgXcKN42PS_mwkSiSD6hRJcHt219BPu7lalU2zk2iqRgeEjF1GtHmXRkbGPdi76CbBOqwcmBMvJY7OVz657PLgMhc_g5XEvty3DoAqUwbM0AYdop8iTd0ui6wQBLGD6N5v7w2qCH4Eq0sJdXGc-zw8KCnv6qhDkBKYR2pWcShsgBOJq0UZmttQy3hoNcqFLk0Dhr0Ay8j1Fir8LMQSW8hAuh9SXrEpun_NVdruE-FWZAJNo2Oi10ToAEm2UZedlojdn9jYlSPUbW8kM8zX616hktr6bjdyiKBsW4bok__9XgO83WnPbfmkaaTBG1uOFkbi0-tG5lWMIi0_DKMomoMGjoK5AMxu5PV1Ai7_A64LdQzk6haqtemyj_38cDlpfZWpf3ZxEuzq2bd651idZEqJjZES60V-KQot6U4rZh8M4BguOP65Vvi3x4QE6YJUx7Gfh6o0cpcXF4oifXzDctBEijjrOTU-nk12pl-eyN6RnRjNMHwpDycqd1-28J5sZU247dJn6QsxYN-NRS3_9vA4xWcBzTE7SMmQUA8UQR1e1QUky1o3RJONtv5pbJ_AMCVxuM5qrELufX7oftBNYmel6Bwxx5bMIA_k-O2nDReLYBFA-uSJhxLUCgzoHP7lx6pGr7Pe0mAUdOpSWkVYL_aCsHL4xbHkL5cp8KjwrxY4jA3l_fpMpTMCRB0btqGtsQOS40rjc2XDx9tj3RnVTq2JboVPLbuu6GTiCkm52ab-mhnFxsCW645q4Zgn-vMVtuJuJc4fTgKD_5J6-zo56VuuPKhrZ8reYmPP8HLzaw8YLA-TZFR_KW7_u1jDcFFjrQZV1sBQpEVSmeuD78VuIdxmjZiwSzt8M3EV48Y1hQaSYAIHg_KbGIVcTyjR7lmh-c5wQAhWDivnGSbeXdqz4Ebu8M7PVKn8k5iR-EMsZwfvLQ7sUNmGKebvoPF6-bTpJPpna-hvwnkTV0V5IghzUH-dwBU7XlFZvH3HfoDI89d8KxHSSJa9IVpZXOpKi5MRMN-LHQv1uGewkimhkix7Yofe5Ce7bN_Fm4NwkPGmkhs2sQfYOcVSPWeoBuLb1q0xGPi3-YNW4PrCdMnHchq-Jg7ClVnZueEvftRt-p5Ya0fVeBktw-ga1dHXPLynYB6ROYAI0-oGBmEImeEVmiE6ihbNVw5PnCFUbKvsOdgBwcC2PhWZj6wVINf2CNwkgrBomh4Yuc6oajWygxA9AvLLcvK8ZNrweJalpoc-y05mLzcJKAoveOSXF02Ix-6oLXYV1TfNHZf3bJjHX08TEQzPGI8mEhi1_WJzvZxakiFoEnkU_gcp9a-mGXQjIbcTBWUwxEwkQcTMH7h3NeulcmeY7Y80buAKZgauM_wU5e93F-olJBXChu99mCLv--plEtN5RVMhm1VERikE8Gp3SvdrFm5w5xdt-Ud0LuSAfld1xyeeOwezCznEXQ4HdAM-0GBdt6ofwBHazloKWdyQ6y1fnSmZkGoFtiZktUbxPd5tRRnUSg7aeDfsEAuQuGWUnbDAoNs3EWyS2-vODRzvEma-8bwg7uedG4UQ4-0k-jG08rex6hYohh01YrnjutCGsri6yqe6q6s9GsYvwblMXQyaF_-KgRbDyDW6QfJVakdsVxBHOwq3hYdXuAGqd_GNM3NQRB1Tk2PXcGYILgN0RbdLp3PRIDEjdYglpjQT8mWXZW7DBxV8E4uhJLJFPFY-4IohhuzG4rsHMi1s1y9GiDbS1q_RB-1h7I58Sy8Ci_cyO_EDzhkVF8-FO5JSEPX20O0BpSR7Vhg2xp3b9sBO3trQmqfWSCkrZ-6arnJoJGrb3rAD6QPYQQw_vmbPnyDRkC0eSyAeiXCNpv4dT_85KsEDqcok69fa8InMJ3wNqtSHnOkfCQqdPLciQ7A_DGtJefxLhIraty0HBLwtGRBa3xgUgSu_af7xgoVfaAo-k1wp2_Q9QgGsbVx5yodvlNVtxbPh_RwJvsqY2SzrahbGssdoSro-URDI__PzmyoKcYSLNlK_FQ_7GcjrXhPA2SP99mphw_7QbPvPby2qj7IdxRui48tRdwoWU9zC-jRHs-Wh_kL8MQlEQQD9h7nOryLweaxx42zshy8waog0zqLqmqqeotwxTQXQrYcAH3tq7_GrAe2orRJrfEu2D9cPTlJQoA08Yq6necpnyqjHY0mOC5sHEDeMwKzbpSj0EqL8iJhddCdIQgRRH7cIf0qNXflKQ5E6E0_Spc8U6qJ95nFNE3wEJlYGi2mBl2v00jYfglB8v3yujBn8Hnrg_vYR9btbMChA0aUg0CHZedukLNzqhPoSpnvTc8EAM1Wt5vn02szrweOvYRloew2zQUU5BXbMtilgaD1Xo-xPeLC5aXyS90p8qqH5bWCeyv10R1cRt9-gwg5XgRHK-xsCrZA0wHZlCPItbrK7d9p3vGG7vhNDeEzEEIdBub2asejfuvCSm1AwkX45IQFZKlCRNu4avdPMcNkFtH1WhJZmyOzlsCoGARs2gyrIFre6_l3nfbysK9KpU4ACGAo5F9WzdGclBZbtcueCYvxez1qRh7Vmuhq5akw8S-w4oVcQd0RySTad6UaB3v-3DAmlknJLygU0_zWm1GvKkJC5PuW1289FJvIdNXzT8I9A8nDRO54JdkavAxJoZemrEA0dPAoZIBtjHC1w9C68KmS-w8gR2KVZTUvpbqFa5fBuDUVOIAmp0_mOnFSxHJutpRnPZdySYURRIEdiTOgxotaXXsVDMN9zP9nbUU_0bBJb7m8JRI5bMKFtiv5lu_he1QlBDpJRiadIeYgJvoHAj6pCfb696XOWZvotgla9zeuMlIa2o9CWELksccsko9oRlReX03Rl_Lf3S6YL1SWWy4QpKFhulFb45d0CE7oTZbRr82eUOJxGmlsbEH5DpOAfTg9A6H94HhBfgVIlor_SV8AHzu0aW7U5JJIIETQei271aENKCwhVxIFeeNqmDJtNwBDXdHWCLpwUxMu0f108YEm0qnlM2N6-OJ0iMeaDUv2Dg5u_hRT4Uc6nxy7EAf1dhhaHl2lazpshKJKZx3zWLeMQV-uHnQVYZ6-FHa_lDFsr6mkQ3yK3T5efnWa89Rn2YxEnrT67w6zZDR38f3cGOIY9sOgj4-jJfkSaZKEUoTh_IiX1liNafRDCa1i739gFvwjDLnGBSaZXyt-4Yt3251Z3yqUZ-xSMwVsm2OWHyq91f4rDfg3tlwRvDy_79lKd7Q2135A9M0wEYyacpW6bbYVLKP1IJkqg913_fEYqmbgeLlVicEQaMNBfBpea5vQynBlak5reEvJvknl1sESgBTf5IRgr5Ww3MpIt_fYxrFM0EOXFMK4EBgBTBGl2ReVdOAsMHs362OC0CWq1C0Fp-6h_ditV2zU1xUxsEcpBQ8nQVXHhPZDk0cELMf63r-I5PRI6zL5aZHJ1yOrJ8MtgRaG1Xj-N2lnhQDQtOuk7AKhyik2kky08szAjrRhg2-EdwgW8QwGnRAjgAR_zm2fkiU1OokO1ZJW3UyVPnaarHMV6BvHJqZiFTKYTpVUhMHvIrw3J_zCGhgkgT92528BavyMwMpVPfd-3tyUG8z14ebwWaJ-J1U7SHcryECn-58IrXwFBOxiyJdwbNYzDrX9pkwuLVVrWMDEZvmGLVQg3dsqmpn0D18SpuY3w7u6AUJlGZxXnnrxnt4euyNInYy6JEVjnvRxvL0BGbgxMGUfMMDthUFuxcgIM8fLVAJSTijx3Thl5U4XTfy0a-LLVe1qbIeCxp_amuoedUTIoT4hoS7OO4LDyxxtkKxC0CBDSOzF1ZQfiOfPjYc3bs-TiKs35filIQBqEGvkoJVEqtQuN5qAHqTdVJ1rM8rs3Xr9-zc9UJgeekquRLy4WDLVmlyGo4Bz19lIUxyWJkjrllWmAoJldnZ-2wxaicfgxCX7cUSxv4gEoIOce5-qu0JyNs-ZLpQO2dP0RIx6djq6GVczvKNSLPcKTMHVyBIlV3qtEoz3FtQpXy7_DrSDrVvahWvLpbKFWRIKWVHNqYfp64d3Lu9bEF6zyKBwQE-GxB0c7aVtsDgWSEOY6yo2SuRENKZXVl1x1ZSvITI2c0ryCO1aKThaunIhbw1vCXSYZJWaA7QxRDQAbD3wFQGNE5z0cisqeMQkVXD758593rrozWsaH5-WkwyjUitIOeMLbEi_HlIeO0hHsA5nQ_64dCHacG1I7nSoRKEkVDbkqabrGAmyu1vwiZj5429GqB-KOTY_ok7KJxxl0rNJ3XDBtxOamEbhAbvEc9GfMNMOjbjrrFTfVxKMx6-sTZcK0wcHZsm8ElDsxdhm5XXcCWqFIUFn6aw9UcFmS0RQFOyZrL036dOsfhjHa1g1K94xaJ2DRjNBU4nYNDRV0ghzLoT1S7rIru3RlLsdZr7p9ytM0i8D5VNNfI3YvGn_N42Cr2Qz-HEw8epBldQScAnb67egTH1-aT4kXUcVnoKXbnnAS3hvaXAy1NCFNh6B2dllyD6hYmP-4NIXJhABl8GCVyoie7UjenE3AcOBOrAxTeJyRvrtJ3sGKSLvEWOHZn-efGxUV9R5AfeoPHACc972-9SHwVEc8luPQaaw3PG4Uas_dj5MMypaRGGHm91QoFo6iw0EIDMG4pRPwXQ3HKXufcXFU7dopeceoCT63T_Y4mS7Pi-p-jTDJltnzHI0h0Vbc9RfRA-MzWZH4gBUMg-uuY1LlUu5ebej6zZysuRhnKsTwmfn08_5HR6TVKpSp37l5szlJggsPMQXDMRck2osTgIpxt5iKW4SIg-yunJWv0T5Jx7dn5h6ky03KhOiJTc_ysf9N3CfastCW6AXxjIdLVpREOZrFPnRxXkw3wxiEL9uCjLA9YDJfJHX0BTY-rtqKJ7X_ZIUdq4z5vwYfWsFQlS8bPBgCziQCpGgIqHfnTWCVQuq-5N5B_mtP06ol3dkOd8AS_sJaVgDYchl53WDlzKC2rgweJFJUni9wK13eybkDkOFCzwCHO3P6i7kwNELKDRHNQJjbWQbWtAXSVdbZtuxn0Ek-gQ0t-EHVsx43mXjGGU8J-gDmIGIWdZ0xy_oH8PtmX-OH9HFpywEme7mboAXuN5UjhInMk_vo2Q2GNjCXR02gKqoaW-j9eNuekK74nJlnXcSvXrIkXQJ0qqhhbfChuLoEetDWumP1Aa6sIDmTJXncR2Hp7C4m8w6ZSTUleFW71mwS2-0JWgBlBNzS1DDwHpC9gPjEqNHTKAeN0WYIW5UnxHXMhcuq1ZbNyqE9DA_d6jAoXaRvaQTsLQuvJ8DMuzkVxjcaEyQfnWZrlXNE9r5wspILrt5_HzcaMA-kwjciZ2QrPx-7eRXDNDICkyLpuKtN6VOd3R5RHmXUpKsFeCYbTqT5Nf30lshmCn8ipGwy8VjCTQz66wpsA6LGxK_Byx6E8uC3_nr8CAWH2dEja1BDUECaKGpzDpwckaqggXezuvcVAtUGAg1IULq_qeUVEz5hj_RWF8cyAM2GMkbQ5jkLuuY2dtjQFW7VMhGm5scx0IVhLLsGDhISRYcOTSbLEvIwO0TozdcICZ2n0JfBzcppsvkJgRJxIEm84OM0FRv4nJ8masEp7BiT0A1rVWwDIVzz-pLcZ1Q2fetabPA_cUNoTUg4kjA6X8Xc44Hl--FPD66Qmsvu7g6oHW_v7CI2N51H4cJeiGM-xMEyaFPuu4RZwX0K4yMjNKJFMQddwUcQSv2uttnPbgpNTO30n6Tqzlo7oPweKA80hzuIQMChOf1H4UvJuSp5Of-wS4V0liIHuFhxrAiWBwWmqaJdTMZZIqC7taJQ6maUQlbIHy1S8WZ3jSq2AELTE9r6RCtwWCCqZzyZWLi8RQJB45Dv-c_dx4B_HyixYx0lKjukJCHr7UGW_75Lvu4j4CQo3fAkP_7fE_3w73-8ngbSWTTvktONQ1ukdcikh6uM7hsi4Lm0wD2drv490WRY4ohrRH9BWZLteOYF1tAAShapD0lscYi7rwLqxyq0PgRTsUpDj_7OvGKQ94oiMO9MAYe7-_wqmISvreTJ2PWtcwZ05EYubwKegzYNyYta1WZAPc73gGHW6WbbuLubWKolwYXVk0tTG8IpDIz2M9lxvBG5XLdxhC73S4Gnf0KZz7mbCzvgj334jdDnH3XgJKJd4rfpnEu2cFjPlRy4prclBwlCyvLK-DRhBN75denaRwlGXwl8mNak6BD2ipuOUdsRqLpIgZBFjOsb1DV_ZJasAwSRyYGNH--DZsBmzvPzdE9q-jVyrJPKyEgEeH7TGif7_yG_umQCfCF6KVGp5ZiwtQNYN4o3YrdyyRCyA_TXCIL_5M7cIKnc3VOxxFiQZRP1bLajKCACZAvMkmi3ecOHsRC2JHrUzIrsdbArapnTvNKYW1lyT4Z-nR75SbVYuBIrgQsCqBsR-GiBWAVImlLh6whfKqy9MJLE1C_eDGIcWH20HPx2ruTtSCS_SW7EdPLrcrSLD4jVXn-VVCVLevQCWAoEvYkSwcCs2RvjVfleSKrGogOJvYXZr4lc8ajw7vm9Vmhb5Y6C21Zw5Q464sGO5xIJ3U4SDYwEuuUTNUVM9Mb2bk9LJGlfPc2p-M0ODCJzhyQkwqhh9g44bk4hcmql8AvS2eMjGPX4dl47NcFP-xVh62hnOZgBfLtMXDM2eDe_wrX1FCSaq4WJFsV7jyPGWhgX-VjRrIKmL9UdfC6Tt1EzMcwyV7La9jfuo-l9yJ2oEVPHb_5b3UXO4_IYeo47vxkSfvIlPE0L2P7fP_n4nmtvaThjONDHfKiLFUIWoy0jRNJ-c_txqzvXAzBCDrrpDBd3WakAyrjhVESjACYsKf_efA9VyOPOrmnwhuBLf1hiaAmz04dL5ZTD0WhTk62VkAtGeyuckFtyvDdcUvNqpOGIKtlQTsCa0xWQyWtqTGXzl1m6Q4L82be8hlYsWVoX7A71Mrp-2aev28HMo1GhRTP7potnffUmez8z1c2uhoItm0PnSVwNS2dcwYtAEM7UvxBxxAljNATdRPh9zpuoDC72t_RD2T2isv_wRII8dMRXIS4LOao2ahwMH9IsPzElngYq_pntpdpegpnJF84YAsQUXR4BttPs8zX-BW6a86MhrYwc2TsWY-PBk0E17y-dPBiki2kHlgkBEvTxUEIN26KjAR1RucpJRKE6brfVpra2aHbFpCnBw6ccTlJPsYg1hwuiaZtoe8zEDvfKxzbWr1j2k1AuZY2o0xGBwXC8yjBZhsnK9aTdlfCzXTEnrkW4egKXVj2sylKpFAksAaib6puwCYBL2QFYrbA21-nhPgCB-ODojfysA_oDSG7LoDh68hiTKyfCu7Z0GImqsVM9vi9kpX7cggV3oGvTCMOAgIt1u5ZVwVuI2bP55IegqbJGRQ10DYrwEAhpz5RXdE4ILjPm6ZUeBoAT4e63DrTU8ShUfZzr5Vf2JRVNNemZ9SClqA7daJH3YGNzCXF8AVteYH_HdoeYXlDYeIT2cRiNsUwgCkJo8_EwveC3wnc_iQaa4g5cvCkDgvVA9ek3d0-LQKGOQKS5IpWKuOuYjazfVmP03B3TQqiwwJQB9AJpfYIaYRDO4UFdYSE2sW5GU61SprgZpmy4RzBlIZdwO85TpelR24voShZw-tWYrW9S9nK-SgVDjAe-xgqyNJeWHw5-_9aIzklqoFwVIPgtWahQDVfBsXNDLuk8hJRP77GORkzbkAAap58OcI0cwYvNziHJ1SgjPiTrcaK36OUX2E_sWHchV7yCY_tbp088Hh4XXOKGTxFugIutCn2ajtYd_iRlJurhEEi9DuEsQ2X1FVUOH36aIgUnmop7N43rkDWhNLwRzgTsgoCh3kaI67L7nGyVHc8Ob-Vj0sS8_bx_2quiBG6MuJH7rnrmjRvFxy_vreXjmRLCn3M8-2W5-0JoQjapUhKo574qR1D42N68xUD9zCRs0z2kAfwvNpWJ3E55z2JBBQ1w93K5zt_xBB8EG14aE3-32GK6M3CbEM3d6VqicmAy-4Gmmns-3ozoKHallXDibxEg4qJ8qMBBLQwNibA1naQ1rEc8lieGyIfmN4mbs1QeiZ7RvRU0juO5HSzWDhQItBN7wa8U8TE9U_FDLZFRievjI1wbDzWwZ3PRDzV-KQZf7necTmiqjJg1xuynz01cqQ8exaBs4ajpurABZyF-TGvAa96exVNn0NhQsfBWQP3pOgfQ2FJQNOG0XRdYwAIyeAbBDaBl0yn8v9OqzTccZdih8OOxxkAd7wRMkRsgXBjhT_AI9nCvegnbBdtYPbMdDwv76wlLdyD3oTHp8w4OsxjOw9gSVJLR1HFToBSbqwc8COcSly1s9IC-OsIiLh1DKg4qFxCYv4HbqjgJ3DpHF-XT-hvOqEoe9Whpd_0GJjO6MIUvoVpEl4_u2dHgMybOHg-UYXpAog0dkkfktuBEwLp_JtOF28JwACwLewfJmaQmuft1PknMs3BaMAFvJh4LTxgm1QdE0dkg017ASrfhbQOqjvLidJGcbNWSOrf9ppe12HOY2lVkUY1OXKgos5XCkgAmHhe_1nGGLY8qX5hEgID7qhhg1TU2R_VptvDjNIXWyyU-GWIqGaUnuhmLUDrvDBTdLU663KWSOPIpxKSZ41b3xyYVzXKN41t5UlGKnr-Z6pHriFmhN-J3nIZpXYCv-BMl_6nkNqCXnV91xCLb2F93ogV3GSn_hLZ88rgCyBD8hT2FskUdcTYDdPImpHJjvQG1KS5Yh_c9n75JS3jrKT6rI-siYIeeW-sFHHJ4PXkVoWU6bsQ_8axVKMTrzNHWHQxq4Ot72Nepx1audwUR9m_07uaO957bFzAj6WQSAjXYwnELrEjuu8JgYiiALUnI-gEERzsNFfB2-Gn5Wjd_xQUmlTIrsi1uDnH49PrE-Xbg-GFSOnH2Jn2J_NmXNVA1Owh3cPoNer_Uh3MBw6KOOoLpUhS1l0VdHDghJXQKKX7LCZJTtxpkkJnGRun1WbZgvQSx5kO1in-rmBi8Hb_NXUylVcKVk-CxCGgVpR4okx7XyasvWJwQChpGzYLlO-YODxlFSnWu3ZosGg0Ekhqusgy7UOntRnISffv-Iqo8yivNYeOHdM49LVMawI1g6ko78RETxuIOMY0rhmpPW3DVRbl85-nq_pl6SH0To0FBFvKFr9YEK47uy2rLEnJzr8HNCAN2q5J8SXJJeZJetUpvpmqrcTmJtJ-olvY4xlpqLyrQSCb-sFxPuPJcmT2HYSVP2xS_WxclxyZEE4cNL7mXp2EckDcMI2xXRGqjgwgxgsgTxeHaOaaes07OkQw3ctXTtRSEsU8gXyuclunfd4AJKvyQ6gs2Sv7BR2WDErsPTw9bdHoeuNqaag1AYaa4snLfjRkhqipOiWkPx8IvrZ3QCblPM8KKBvngEkRWelk-Olf9cnbAwHeNPIJN8W9Eb9O2_wgFdOzQZZ_vrsbqdH2mcC0jH9hNAgIDxxng0dJwQBHvBPDPgibef84R_RaFl1KfrQLaXwVMmfSFVyWkBGEjGqwGtcOKsf1-JZ4BEe8jnm14LrCgOUBVbIYclVscdUrb4RL5fLWrDwm5MN5x1pIJ4nrXcLSwLLn2IiXDjxloi223cT15Y0-E83z5c6WHo6pFQAeT2fy5OiFeSzW7GcgyrQpbrf-i0ydkA8mDb11J2xJs5h-WoeNwHV1rVaCW_n56ownlwq12v6pW8RFHrUVFLwuElph47dKxLT97lp8hgop8sH49QlSxY1hVbIN8JAH85RQVc_1lDy8rcfjsdQtAIu-5X82fRvSohtwYSLPmIWHZnqEb9yAvDQroHKHRI5qBOBDaryzXY84gloil-oX1XKhrb2lR7kNjPsLtdu1Dkbd9vTbULZ2jeaR2g4HV7ljmzxYWW8fBxmRTtOIQR9CwLKFFfl2LBu9S10MCpRJa_sWpjSmVotyL1BfiP2e1SRMQOwfyFERUP7LGna-r52m-c4s6U7eksY-o5RODDu2eckOO1e7f9HlsigXvMLQM3it8lgzKQzrH4jPOt47G2Olil033mgoIVi2MXOEVn4j9X80_evaMzeDhczIBkM8Zu1m5pAH8fMUfIAmNvmrOupfDC-khkT4_ZvYZyO67MlBk6ooy4w_conrNASj0IOA93-Mi3QhzG-sW-LUqGkntkBVV3Gezsu37jyn8zBoksBiVjLa1TI_iqHPO9KIwoVp4S_YxuQ22RTxuzTLXHjodRSfeopObALmk0sAKtJSMo76Z0-rn4VRha5CkCjqhBOplLSX_igWIG5sBrfxLpXL_MAnqFy-VIuLyfsjQVH2yxG8nW2L271C2oomjc2GVLDupFGUQdhOHaHTErV34K_sIMW_cEVCpQvGkS51t0rIzmYe0onqy43tTygOjWMEZH75FFa8fAQ9ohtH57v3rWIXAIS0dVLFad_IcystDJAka4zh-7jXA0ZiPJrjSm_rYV3kjCzYtjwSTPez7l4c8R7VK8_NZEhiczu5t9j7VFYk26w8CirsmcIoRJmgSWwiuRwkJcV_TmwlEQBPjow-b0lfHKt7zxCURrr-XpPHznzkje_AQmsBnsh98hsYKY8lvfN4VmIbVLAINdpslg-qTsWGY57nZS6xg0KeSmVBOLSH0d_i3nqiVm1gV8Poz9uDCZECXK3-2ORe3wG6MXUd3uBfTHFvJ6fH0vhCl2RzZOATHmuolEScNdgljUVz-kBHtXFjcVlXo0gIBpPuSBzRouX5Gp399_rWgp_vuEMqJQmqBV7kEAsUdVtfSRlY3TNR7KA93gGolrxd0LxCgJoJOOFi86YXYNtmvBGeRWOH41SMM-sql0oxQDc-iRX95GGszuvudOxcu7gf1qahp7Y-Hnz3qzhoVhYs4yPsWNTA-SXEsiUKEfobCFNJ-ssr8e85HbjZuj7Qp7hCQt6rh4266D3Z39fzGeX5ImBz1HBQRk6kkl3vzvan9mIV3Tw2YgjgJFMr8kL9dwAc4gMZCZQpYuAqg2rSovui8n1yu314H9l3RCnjTAY3le19kdFJPA9YEyfGnSZv8Tgwhpid_qNiHhY0VysBQW2ENqRwYz2rJTAvOEGRH9LmtfyAhsOkQ5pXaSzOCT34BBBTmswLIGmL2oRj7kqUANKAAJlsrUOVfVEMQ5rawZLUpJ5WxX4oBDPbxUIBCTFXAMRD01rJ5H4EjN3181ILKDp3CjC5ggXz0-2_GSqJQo8GB4J8ucYlkt2lM-VpzDGGGjQRWbyr7SQjh365_MNsHSSGbxaDSR4zMmimR68DwLcbAG46SF-p83wNrODfmMAtUvxnLiJqpalymTzicqVhRHGh4KN2KsGw3G5hbS2uAL4guL7hKpYd8LGZ0Or_gL1Qpig9W1NjoKvfZVV7q5obp__CuQM5IqTqplQDJ8XZ4Y-Ot_TBoVc4010qt0Liv8eYQwgAbZXQVP2fd6h0NOQHbtLzyHR5qtn1jH8ImVZqbosmXmnQKE4GHM2SBlZU_4xa66QPEWUKaZzDQ513rnH5ka6TYWZPbHuspulf_WuReK_RpahbHB-iuuC5GxmCBpTGivQ0bidt39Kde_WEoBwM510MyFftwhgk_d4etTdH0TVffZcAH1PsaeaKzl43NQVZ95hEW3QCwppLY3vRhg3odrQiLV1fSysh8KJluDV6rfuJJskS-bU6UpFMQZ0I2LIecQBYR6cpHdU9QAx8OEi_0zMhtpbD8GSlOio4wYZh9u0iA1NU_HtE-I6h6fhxwG3FqPgZ8P4c06bEcOs7KYZjPUtyqhwd3iOGzUyokict11P-udV04Nzv-LhTT3KaUNYF1RRLtqBOsa_K9u2JxTd_ZEy5VBvA6Jq7_T0-ZBsrlnNW9tZCo6cWsVXw9a22Q6TeAlgMyu8mcfXilIZW8AjuyBy8ko55xWdScIQOsWZWVScYuz09ePxY9pyOrhoL5GiAaegcy4mAtY76fvzmbk6EgXD1lV7fX1vLgJxYcUTuv2zLsFZ851U8dOvoda_nCz6PX4wcoKXxTsGDjp55T3bI8btWrepqgObN57NKxABcLFkt70qZRVDUpUcqP88jCh7fgSAFEnp3JkGnlbXa6NHv6xzrLc_NwCtXHabEHPwvbJvpgljPNp_xZpd-VpQc1e9kH1QSswLEjV17W9HdEv37VW1OHDTd3gbHZRaZEWX9Vd0hpsE6OZChtgZu8OKUbwNswexaWSeovjdA0q7nhiNJQAVZIeFNIxulMgobHILvHmtc5UwEZcZam8x1xDV-oH_eAXhaPBX0cK63Bj2rJ-8DwmDGDcQJAFvtV6fUiqvL-JIT6XQRGl1jlgXRdAap5dfqZ3A726nA0AHC-j__b8K4iuMBDyiKTc8Vg06etaPIxKZJWth6ehUa5uffzNW1SYHt8BgwAg0rfG_mcicam9vw0R6BQ01W_NfHYmPfA5XOs-QF_7LM9be3hEQpqlYMi8-mCcRE4qS3WNzN0hrCr8Ef3cqJ9DfOP1bImC4UQ3u3jj9Krsrf37mF2pbK-sgNS2fEFYRPQKRabpT9XAuZooqgmyccZ2ga8oLPgMsY9C_u0UFRGdBaiWjzqwaGIxTn0BpICtAcVDqOMhYneXYJr86eeu8xzrmANsNeagZLjqEikN4hlqThvkqNSoN3Nn3N5yZoW9Ai3Ts71l54tJts-moqRbrk8tq3lxcjMQXulYNliFooH-DFGSP8AT9Iy13pa_GzpWgNyaKvYopj7a9QsRB0seu4sml4y4Kc1xXOIGB-hiGlNz8YBHKyQcbi19-ktJzX4ig9OlToUkIyYAdy9sqT-LwfDbWbnyesEHm_4bSE2ygeJl02kHLhVTRU8JeLchHO_0gbgIDd73PcP6xwjwzFS5NumXKriQoHkc7He2taehEld2gKotoacerPjhwEJEbk4xRSa1wU5qpIEJD4pIwt5FjHRgnh6fmKudKcCVn8UOvlq8K7s3BCsmpgwISFNDoatwwGdNt1kizw_RZBpZsCmiRDPtknGZZXMSE4qBt1SEyq_Fykv8eqplvWtbfGyOYGItxk_prMNBLL-td-u-_UsLuec0F82uL4O66pZ5PBVXoIu2nP0jR_wFIJMZgXI4NGNqA3OqAU6HKWtXH3OwQxLL-5cSrJNoar875P5Hko7o6sIcx_vaqo3izMKC2IH7xH4uRRhAGs2VPnqOll-vzaay9VsIsQ1ndYd1TsUEqahr6yNm06yq3nr_nzI-UV0Ma3LEQiXwt1hFTnh8Q2EUfpkufvXAzC-O1tccwb7nOZ3E7XRcQi5-Vjdc2vFZllBRDWqbwpqLrveWWSb_T-rMLidnop1VIRHeYN-0oosjLAB70Ft-2Gm62lQz6p6g2UuD40VKxOTzrbK6dCrSDkA0F8ORPOrkGNpTBLVDP8-Genmf_kIt_Q2tOCMIcyaOOFVlpiJmBfKNvNul8KDIv28-PnPvkDghVeLA2Rmvn1dFroGtenc3Y3tGcLu461L1VkBa4sBSBUueJYMrYyiTA5MqVho_sLN8aLZVw0oI4cKaPMac4UdT-wbZd5zVB3eyJJ_UZ-2sArFnSqqCh-PDvF5oVMmjh6pksIhuntReGNm8kpM72PREXEUw4pVkh3T7xa0oqNlhRF0inL2xZCFyS53SqCZsEXlwDR7k-xqqV8KmyJkD8mXH4fkHVAXnlkHm2Y-46HzNw5NiJPZamhIO1vHIIMSHpb3sA2rp4k--KLod1VDhivN5wtWgS6XqGOnamJOsHa5rhRr1NRjd_bWZUnO9x1NUs2414zfBqhDkrkFVbp4Zl88sgmEGNrV5Utsjrt2EMk6WAAjNywRjtp6k5axHzvKlOXQc64V_JcBhSYa2-wF8gi66Lu5h8u-j_taZefZ2jexiAYOxbJdHfPodcmu9UuVjlxeOzY9zHBCoUryR4vHACP6IppKaWkPrVDc8Aa6UqcPRg4yHdZjDZE8WOQ6ooFoj7TMxfk9l6Jp7d4wlj9OlOo3jivlvgoRKQ4kQHz4u_fGuRW1k0E5xbtfbTIiwIgmvQ9WuLOAogpk3iEs2H0AFcsDQ2Jtv-kOZE-_N_BF2XaSoQsbu9o0XNn9RJNI3MLRJkgHLydikBU6u4QUD8ja7fhineiryBJiyqYVxW202uds5g3R1SL5_xuQXC1mOsdgEtXsDz08hBOXpkYi7l3tagMDtogzF13t83BaoR_YIVnLggnu79esID5kqJ0B_86wtO8Qtc-spWZ2U7gZ65PbtGa2czbBl2xI4fsNoYScx8Yw7wAWalNjh8oauLtKEdnHtrKGkY2gvWrShtEs2AQWBIPZm4wt3f3whnfiHDQkWPxM9gYDm5Ne6x18uj8sSREzeEyauBZUWALbhvojMiuf6DvfQsH-kEjQ8tLP9CCeFDnP-BHiDDJMC2rgtJOelJCI0wiDbDgzPW3RfA7KLJiluXnV4-H9eJfcAHnqDKPuiOrckwmTASn_ai9Vw5lPsU28aosUhJo5f3nzj4hxIn48hpYvgL_WpjdHlPWdwhMP2mTksA7gK4QREuIkpeqjir01DmACHov8crNAs_2kL9jq8iAzUk_ZawBXbJCsl0l2_vhMJRSaEi73WBKWeT6Eoufs3K3RiuBwBZCB7gdFOYswfzO6cwzac6kXWi_LL4bEjva3JRHxlc4xhzmSTi7BMF8KdEPc1e2FYv926an6tiaG1fLPoBbpZ8z_VZZbnb4iSx7qaAOR8x4E1JWznMHSjGkgj4tC5_m2piCYmLCW6hD0qd9IZXq1d_OzW-GtfOZVMiEVIAimvrRovhFHy95OiPDUpoebInpfhGn8e7Q3ggLJ3vxtUAMRRGpXpCNvaES_VgfDWBLwn_CrxWdun_Yhtv9PhyQva_Jy1lEBTOYQahvBQP9c1LVekKXBIAof0abnMwXINwDgWQe7eyzN3kngvuO9ps3JDA6OOhUh5h_0RDDwQ_BS9xV6YclozrviZRhTLNmXxwtAtOgEV0B029SPNbbJyAOU-tuqibgjTcx1Bjo8kDicsZG5cf1DSNC7AyIZdXV10gCKH4Q3VWIjaFJiXTBsq_EaKUnfN2Q28jxBQn4Rh01AuVj3bnHRc90JAs9vD6VgkgGMweyMWzO02_5o4Cy10oY9is6VpMQhyN_o8ggzizYog2i1BcTOUBA6NSiK5k0SJQKud3BLBSw7iE5ND_b_-V24KS5eKjGgYmUgr3XSddUK0rG4OYYJ7oaMo5AJ3JnSghFif4JBrM9XZEHH-l0SuiRNkfDb4TcCREx65YNnDVwXc4kyRt4huXHhni7wBRHyuhhuoQ3fZKoHJTJ3bS-_G1IXxr7pwQqSNWCYsb0fMxalgezVcSaibLYjbhAAc7rB-Q7XXWygHuMYyuzSTRP7971luW3Idn-Ac9Rrx-Adda0VCYBLwR0DkmlEvoulje1hnhmOKuFQsBhhyFtlc_yoj7s8sCstf5tmnsfqeXS0fNtwBouzT6ivcDn09cpjOCz53BEm2wsyFl_ZxzkxtqgMTGJ2-xLwDK8AqRrfAnqI-91A9h4xp1bVZPlpN81QlbLQoQ6uDy9uLmvNgLniIVyEsxvpryTh9bd_VAjfByxufslFc6sU88r_zBSb_dUoSQpoSwaN9WNliCOGMaJ_Q4TT2FP57vTYyMxHVgJS3zDWLwrYhWdIByBget1HVWAxausPrwZd7y8aBFbut4BFQqqbi8U-7VBkQAFJt5GDOEq___42UQo98cW7j-CNge-LKN46aBKiERbcGozfeem9q3HfRNiTumSDY3vvDUA1UGy76Z_0dF_PUxKUDFWuCsV6dLSLzwHlHg2xa6p_qzYr77YO63LLXTsFiWCX-rV51Idy_HT1FVjVb9sSVOnOMH8YHoyZTAxZZdU-wbbjssW2QdMmeUqczBkEmI2vFZkK_-fvyjwvTOv_SV8IokG1I6rh94j-8wCPOHyizgme9ZrSqFT6vG2-Aj4na8IRIAneczFrvq3I1dAO36VyofzVHp5KbB4YGxbWp9Ael1TvA5XvrnhE7RDjiOAJSjwYP73HWp1R0Ps8fl1CBNviYafiSvDoy_lJ-AmShw1PDz5ruPRBfbFKWCXJyBIPl0KuiZvYW9F-tvzn62mF-CiU4jupulGNvK29-AIHSVr9i6M4JdIbX-ESLdffWT0_bFI37bxSmbm3tVr1EywzvAbjydkKgbrtNFmnyRCocYjNzTOvWKwPfCWHFeO92Vn65rVyf1NL7c45UlF3y__iUlWcU6ZOjTQd5lMa6RAcOBl_Nyc_5LDtHEvYPpBanuuuFLxoSM-RGZ_RfasOgGVgo06qkOQmAxz54S0JGhLWW2HKlBDByQJX9l1zjg_BdTYW4xPJTTSiKUhGSiBu3l5KcArp2lCyJn-3D_U1UQ7qpzokTo3lTXCyekWd1vW7dD7AzE8ppunDSQOCR1_onsC3lBG5fZfQ2kcun5S86hnjd4vlmeHW-6cskf4EkMVPk6gmd5baOz-Wjf3776wWhNSvxzYY-uwmSXXdbED7axklzSMOm77LWe9n2X7HDfkLSlL2qbjEzWgH0Y0lE5TJT6Vyqb0PfMw_x_UY9AJI5QdQplcSOJFxo45fMGGT16WMcYYh3bKo7vc7_sTzX5irFQj5AorIqy24M-yLl4iNyQX4I0AJQloobw0dBLuj2Vn0hhomk2FZ0oXY2gbKgPnpqjgD2nUmYUPrMPnmzMJ0-AxCerAbZn_IbecmQE6zHwj0Y8Drxk7nCUpi6_egqo3lID2qkcNXIFttC17LVb0qIhDyuLjexb_lfoPfPB8fR3R52_fxpGFeeDYXScNC_qLWt92Dqvey79jdJmstP7Pv9RXvi5ENDYmBWZjDFQBc5-MH8PIc5Oh61gzePoh302xB__mgQ6bfLIy9MvAJ8L15OxHbRix3itZ7ZHm3tAdzPxQR8u2IIzAyB96oVPZytixEB3li8qO-IdPg_1AOZULvPQs1sPxLLJfwMjDgDeZSQoYUqAIwyoNjUrrB8zQX0JoZFKurI5tlIkRYTOq3lxRNfwZL1I7x-Df8JJgOYnxmxNYmpxLo9obiLERSluisGrSevOA12OBulAYfWIZP9TxOAxODepmhfQKnTwwuZaYILkg6Mezqe25vpkO2gUVX_xuCYA7v70UNcszDlhYVnsD59AQ2k1ryiQx2QOm9K6Yx222_X5uG7RQhz7lXvhjBW5McXgF4OCSq2CtowA0nPYlq4wupbfABWXpuvBA9lVrsGZ2SDNEzII9rkz1QgOENgA-Q2mcgczv2X8zkxqBwRdEPtwadleBDU5OGRpzIM5EODbJdrA7miA5wc7_GrPnA3ldg1ZhCIrtz2XvOqWEIStBWKgceYjvrU1xUM6MNOrr7vG8LzzIV-el7f3CC9JGiS5rlXKyspjjzaXLQyrxyuQTKrBXKdIK1QnrAQ3f346TVwiGGAWlAL6_PzO70EPQIV06mcLpqhNd-F-rYkWtWPyw0PwglJefcybs6BMLz1lRp_HrfTw4IPMrnP_LwcV-oFIVIy9a5xEzojef7V-H2bqotBQcYfR_dBAMM5g7ymFBOBYWws6YRTCeRyv3oUwNpQ2ekbecvx4nM3isf8IuUGjwvuw2jtRy0UhiIsD2MTXHJWWtFRNcuNuWd2LH5vrgjjmXvZJOWBC7myYrp23jtuNh0ww2PZ4NlpQVCGUCVfEQm_w_aDmprQObA-FmhPD1ujNi-EkuJJi_aXudQaOn3an3VLwT67WLmiBkXs2zpjd2MyZELuu-RsblQk_Iz_wqQrNWHl_dPhtEDaGcEmn6KmQ6w-AdQ3cJODaZi4ya9entFekCDtl2nszJQGk_9IFKIJJqLk_X0f-M0yV3MYBMdfQZnJBThrRWTPQBuQzR3HUJNSoDK8D32komHdDPmTrikXT3fFrd1slKqZiEqia3lqso96BZxQMDUpQT7DC3UXMs0OwPPLnZYfZyS747Y51xVVq_vJi9mMNkKJl5DI9TW2Bn6_xL4M4TijuCSmg_IIyPGbjMhz7nengGOCpJ0M18NwUNCCX-wKgJITmOEFDaljLCuUBmfBnDPE6n1IuD_85CfzpnDuwVySAVEiVCHZfApo0K5k3rKCCC-jGq3sn9u8JVkhgGIYz37n9asOBqsP-ea4ILc0422gc_xtBt4jLG1Y-5rH5gMhNCvqWcosI5FEJGBtgj20Xkp39hcZipd31ES_CXiGu7Tompj7Ro8eML-JuXu88qgoMmieAuAmRKrX7D1Fw25t02cKT9ZXjl8Jjb04Ynu6pv83-3KCoOfsLjZtuj3LOX-mRaibcUse9-ZNm0axA0u6dJf-pegBxaLXpub9ebyt73JqLEOZ5wNL_w8djkw03RNzXOcYAUuzHAYxpbGZROn8WUE1CWcZgKoEWtg8Lah5WhUH6F4KwDtOAnZgDLphwEH6qRrIjVJV62Gx_UUbgqKitI7kpJDByTCu-2naKed9byVCj1WdZiNLMqQbB-qxM74ywHwSoe2ZFMgdwQfNRl__idkHJlBNxd3VAi62_yeP2z8f92exB8kX1nD7lbh4TlvUpQm3K5HzGS6ECJXVwbFICOH_rKlMkSRqpXpmET1hLCHLWW6sFVOj8ndro0SCGq-XJD2Ka4sIJKD4UR4MQXiMZU7oIpnAEDi1MnHZ6bZzA5PJG5UqfgsqHfvnBOZeB-xZLP4KEABseN_AY0wLAo_mE06UkPZ8IL1o7bcFTwhFNLqVgl4UZ-lWHukZz9lNEcXTMEMb7tgdw4H4Lv-1QjLEzo1IgMrTDf8QA5VrSY66kbndBhX4O2n293D88tCwYC85M030raR8i48tEJiRQqdX3F4QRPWfm5XoW49yDOSdd3CCiEhWiPbGzZFtqNCAeq14zDeWcZbxsAHx5ZHwwIEaBleIwKh3sSw9DfUErb8pwtYl8t4n8PF1RpHDqMqLoI_IlY6-Ae9LQEVifgFkguiVwo_5n14qlKICTEpo5MjO9tjkRgdKhaErILLm5oPRLpVNZzLGW42OFtN58uhFRjuln0mdy_vNe8fyXDTE9H8tn14XdElpdfkegq8TFJQUpqfnFVWSydRpUZcKFTRSgAUU8hg5cufdUTstIOA28ZNb5j5MBlCaZjm8N4HHbYRbcx7gTe8yH0vale_on0c4BOedK61YHS_yovVzrqPmWDC8u-MG3UwNEaosfiQzgoXDSrJz3hJvXBLh90K_O32BBl6BCUl15EeMrjS4JuMgFJA6tn19aI78w7YHPsGqrOxvCe_4dIqAo6CYJgFt88GHAZBu9uybi1aKgkFFgsXlboNSxjDZeAtRZ7bLcMczI28eOy0k0iNhAp-LgzP4kuFUQOX3pKAk3FHKmtk4bsENawMgx3eewXE5Votk3mdJaCHi1trsCpMqhRyBp8oyc3W0w-RbBgOJyM-q7JSAINBUNM3KYcrCrs773PNt1nS7ZiGTo2DQWNvUlBztSHlNMqx0go7KFANMR0UbLqCCx71gMkWyTR9pWITcJqoWVpCpHzSMShAVQs7T7zZ89oaFrcVfAoo2_iVwdzzXQYnVxLMRJHXCug_JTKcU5CRC_K1yBAMgeaou8rT5MqFBx6NO3J4JgBgvVySi9c_vJNH8YViPqPFLDHtoWSMAZlUvCnG32aj-4RR32RyPf_fxBZX-kQhYBcYKiin5ugTn4x5cQ19AiTEehwqtTKf71mvoXYxq54CZYQh1Rje3QxF1lDUpTZjMgd_lJ3okAAy7i8q2z2iUdvHdKXkMLyXOywbhtHZYjI8KKVJaFW5EH2SJOAj-QdYFAtPoXp73bMowWkFnmSYE1tmLKUq2-YPiHQ6H3_pCagemYOT3gmQZdOriYn8lXhn6wc380S-ICerpVxfmncqxkil8jjaW_1Tzc0puVjvyrDbq6qiHeHw6zOPamQqy4BNrAclwMqne12SH6Iiyq_VRaqVjGSYAAlqq1ZFoTRfUfNQn07I0_7tJrBt1llZhBuCUAPNknrZXfQ28x6T0lydzQCgv0roaRM_8anRTBh3zGE9tCiyjoIhZEcgkOO66VX0PRkrsvSSg6AJ3u-HiQDcEliAJEHXBDlaKnxZeq76U-feb96l6RMqkaqHeQIrzScMJQQZhV_kBHSLHq_wKfnevzslGowHUKt8-GP7txCACVZFZ07yOF8WJwpQnsE5z4VUy-YDEwMo3xl03YI6mlaaz9RsfS8cObUKNz2ZeMAmdB1BKSOyJifGdDlBN6D5zFglSF0EESuPUtFJBhGWTwjnmXT5aR9Hk4Shd5SzLuiZsV8jxzGT2iMEfe-r47kJQynNwja9AjuBwbR_SYyPIkVpR0rht01qEDS2qM6e1CYcilenp84W5GclCzO0L5E92Jbuu5HQBAKNxrW5nhBWt7EH8SC7dLMuzCfcGdY9WPIAWaBw7WKsaKU_I9bq67OlIzBBhSbV1QqcsQNf15ABxvpxLbtvL9mFDQFHWEfBNLLkkADKt-c6TFbSF_7iVj3gfO5k7F9uiAQRolzABT13wmKfXJMbSks1O3szT2ohWlbns-fv6rdk2RwIFlBhOkWmjFAq-C3GFiUKTrKSOvSvw-DbWJn8pddRgjqh0jvzy1y-jW2QUkCVDPfQhwD_ApwQBWe072rfmBkEFS04xUI9Oco_Yq43LvE-b5wPFXqdYRUOZ9Z8GgxRSTpQV4APjUOoC93I2bo56GuJEXRlK_I2WC9rx3HaI5k1O0qdth2MfB9jJiZJywjffAwZEvgOeGo236BlT3Ai6P5BBAlTkdXUPLh_wOEBSBusWMgpr5tfy3TmBXFckHGNyCC09vRkz0ASFdYMZboq4_qXqw0booTgAhjXa_4BkzygUrbtmg2N3Yj95NoIUmjGWfBrFWl6TSub4RifRyZIRK0ANAQHRlVvLMB2S-rzyK0PsdSzcPZk1VJAx03b-L8W4UOghKJ-j9Fo6q31aemNiNHj6y0Gl4w5v_7hNadClcvC76q6ZepzNxSjE8ajap7uf1RV9OF7jpFQzJ8ZgRnVUzxq4mQEDEY6LlrzKylUpI1-U9iBOPDlw873zNlBErkttDbiFpHrD_gaH9Y17ymScLPSTGpJBBG0xoAab7jPExKHPUXrVFZOLiYZIy8xgDvBe_FiVfzNWM8B8HCPhg3G_76ex89LBAlfmU7xkJVgN-n2E7vZpaK-MkXWnfj80rEuwOCJy_76hugvYr5tk-PZvW2XJ6-kqQdBPydmWbdU1xSRosI1HwuRhbh_iAoKEtVt_wh-AALe0rItBfXAFlD_LIvDLZ4QkQQFluoIQAtwQoPrm5KuPcnLOjUpQzLEbnrBIWJWOe-qHxbHDiOu4GsiWnHzmIP5-q4RAeIhyNbm_zADGbZfEplaIKQcxycSKb8nxOhdYT4AvzkYcfffIqQkQCChhhe-fhQEAgkotdPofD-Buei45ZuH_9Da-g6jF8LXiHAE1NnILOkZG_ZBn2OSfUVZ8I00g6mRAsfu-yStTSl9ZG_iuO5kegPNB0YHZXV4Qy6XnFw3GrSnTxA1tKDZRDfOy23KVAv7BAxiG60u_OhKP29nxaDSnFysxlZ0EgH1Z1dKp_9Zo9GnsROJ_qRSFvGBMGUKLZqm1g4HusVBRop0Ds0PTe6OK-rs09ruXBAahmJkiKt4XPzRJm4qPpnatyfg5HEgztY3SAQHp6iSx9lHIVEuXL7pNAjwWaraZIJSmY4FF-7fdO5a0Jj64zs9AmZuJaCjE-mxxRgDi5Myv_8MRg7CidjPYZ7BxYT61qFpV1AIYDrsng43CSi4ZVhrl-9lZZkWipX_qQgEB5mMCOoeEUczBcqSBWGZvqYQGhEmTUsyvn5lakWVMAlpYTnxLzNC10OwExmdW_TdClSW22qZgIPOR1hb1JNmVPwKYWXSBt_U_pdbPYwpwpsBq2JdTJmdQI1_IF_UYCWWBAEVNn_Rt0XrWzgsxEH1CUXnRrR4coC64A0lfYmi7OBMHmaK-Qm6mgbOpxGy1KRQ_wRZM2bwtwGWwcadAinL0TQcRzipNKICt8IkUuRfZILEcfzi_yVxn_B6OwAwna0-sAQENRPgwQcuF17iR9mgoZMPU2aHoXSLEvqshH6afBK5fuYzJrD6OiR8iY4J7eJ8OJkL_a6zxpt0zhj3BYFUNr8fqYN8RaqYawgfLTlQlLTgd-GqGwPeonzTU5QB0ygmsD0EGDeChwjSAg_rbbpiO_9U6s75uG5b-BDr2ucturQl7XFOpoXwa839Cf1kPBzlgx1xAfhXOevlieSRyI9zVza5Up-a7d2K6VEuSSK4OhuDZ7lGDebIMXPg4VlSPv_cIF7wBBII0sBlmmoIW3AeVSGGTKMHDPE1XPqXHwtIbwKF1hD9qS7iK-GyJoaw20sHgLdLvxhb0RHgby3uF0iZDG0vuXF48g1zGAcfPqigFx2ZUIjhEzopIC2ZdF1ZBvrrdTlu4QQKx4LF-XKMbse1f9HL_UOXm4voC-2i7AH7JiU6IiFjgicobOORDJhADyN7kk5L598Lc67irJ2X-RiJ6XNFHMi1BetmrHsn2yv5oNV6xLcsMqS7GIDZtBhba3gcPFidNCgEGACpaGEga7_ykSxc1RhxFzhxC_dSDhOFu8BXb-5vJCV8KScQwKoLWEmm236AO8cFBEVn5hpE2m1b1IiHHOFkQUiYNT66AUTa7ldPiIJiJjDiSxVX9AxUDrp5bAHML47qBBJeEMQDFDWl4HKWlyXV_5CERlt1sxjlXq5beQzRckI7dIUbf3P1JehPO6-nJSCqrhlHftERyDgz3mK3FceNdte_5u_EgbZZOo7Dqun2wU7ysUE_zsx84sifIxsjVK2cegQN6FsumFW2fZIJV6ttlCd9DN6DWPiyQHEJ4d6aXLosBXgJ_WjYo6HO2BeWvxii_voQ2K47nE-6v3hcieR5umDbb9GhSZEchgk8zNOFsQRGOtWHvV27qJYojX5OJWQjnyEEAUbfeJ1f1jY0Vqsg0v66pzmvOWMvsw_bs6wE1xldY46hBva20GRIR8ZA7RZeBVnLB9Sexfc3ZVvl7RypOrtXexseZWHfplBs6KsPev4-BkLoHreI6N1n4pi0ltSaDXJkBAgIOnozhl4s1ux44BpY0sPpuPtnT-2f8KqUSfnBlgwIoBWrNMaPzBBWZn4k1IZ4JRSbGpMtOlb8FTaiK778bU-5YdCYTL8xQM3w_4eecIpCVGqEUStLQ1PN_AWSNOwuZwQTYu59TJXfY20N5tPLQ1oiKEq0gwqyvnLQPa-4BUViHTMIewSm5O55rZ-FHfHjN-AZv3aOrV_ivwMuEfa9shVrSJHnA8t42-hLotH3RTlCoQcey7r2bAtMbLqlqKy7Y-kECVXCrbi1AGDHRrASqAL9uqHtiGmkpoZKwJtAjknSfeUkZIAuxmQ53disAyn56ojqDbYO3t8AF-i176odpqBb4rtHYw6E-vobB57Rn-3J0fcMYW2-hFeqPcDEbYsJJCYtBA1y8vlOkUjbRdweR3OzobLsjZNvzzX3u-7cSOJh21jUv_I2imnEVrqJ73sQzS5yCQciKyhZ4fvS2FcNU2UHClDSgsrCg8kzp_ZLuAXmycw-KrYCaZe5LlC-4YkmVj5HbAQVfFbG8Owcleu4FKcfP84VT04p8yyqK9EyfnndL1DsYOATCWTNcFIpY-DZS2oZS_4FEVPVtBc_kavxq0GVK6T4y1IRZDnCyLAhXk-HvWapk4uCrK8Zx7c_AH6mmEdft0YECghFSgdkIGc7IbdpzxNjErR3334JaxuxSVCR8ciHJ71uPWEAJDaQauyPTJBMef8mCeF5oJ65BOw4cDW907f7x1qecx_zTvxTRvhNEoY5glkqYsPPcKa-peSNAp4wLXyYBBTF3VtTIEWB6X7moNOa_np_wDX4cW6bZdaQKVuBpzlZ8P-L-hHS63H3MSibafkqkgIMHR7T_EkCBACLIFqbcvjBf4ZfQm0ytgM0iSW-kQs02IstztE4l1lWagSfqpwWXgQLlv0z0_M_azQiGBrk3aQOeMjJlFEk76zjk4sPS0s8qP6vBnfCIOMHEM7J9ZX17BkRvcHcfkB57S97fdIvJ6Po-b6IP5upXasIFOaxZUlwDfrrcV1xiH-Egijk_PWY3yAEFTYNrnmnx2XC8Wu5VSYMHafE47CvaDIbX2mRjZpECPV5KKh9CH5haRa6q_jShM31COo1e8Zwnw-SpCxouQdqps1AmmnxyOqR3pwlrWldNhTbLo1gGR0t6VajxQgqYkbVBAWnOkk9Ga0b6tHgZy-SysFORQlBQYpqldaVLqoAKJ4s3JG5GqRlIV2EROuuRDcF5hlCAmDouXixNeRV8cAXyRvm_COUOCEUEAlz_f2isffManR2t5vZpui3iKrSbi1dvwQDISGhoD24ws8_JeVmGT4tHlrUAcSoIcVRDeicuV88filJWFaWqHZQx0kRjG4hYx0Z7wO5y8ifwBYu5SCZIpVptwPH5kZaErk3w5p9obRUiUVt4Nd0hERZOuyqEP2VCaAEA2sqRhrAYnPO6CBYweIw1XuZDzznh9LnVJxF_JSibt5K8LcR1DN9Av1Vyd1VvREwDZ1VlRwQSqfkgE9u5tlbPLyh0oGfKjnBIAkgEr78sZwT7tG5grn7INPqAxZ_s8eaBArf6h-pgNE7u_8v6KtmPkEYvu6N1fRYaZRQbDKkoyjrnA39O9AEqqAn7N9d5fPj6AmKKGkIG9VBOZpUmZ_HwlFL43KU_OvH8Ih20C6Rzuqs4tfvaQNIei33IWOgvVVNAwQVdS76TgK1epNca7ojRDLjTm9apjNEGM-9HUxI6X02WyflxBcJC-U-XIV292yZQlUOKsz_-p1roX6qJ88ZSzdNVBkXyeqWWEBxS_sV1G24waGmfu4p7vrq6LGAgBVYJ_YEFUYCuqctS7IkNEoPS6zoBXAAWoS7CPtgnM0wcG4obl1Nw7z3fE34SsuTEdqcwaaSAR8bjkiTg7l-T-my9QX9iEKhKs42CFc7oMmNQgqmk7p7QjC5hE_NP56ygXTxHVoTBAS2aqL-7vyDnIWNzyGB4x3l_na9B5Nrt6HvdVLI6IkfnhH-xeIc8FofRmAboc0FOxN8UoFSg4ZMCGNsCDJsvY02crol-RRSZWTzi5pGXJAvqqBYtY5lS0MlJyzHKRWaHgQZ37VEqz6vhc41otZ1P9T1xQtp9ktg_0mGtytHIcjvdTfzGC-gOX_7ssuSeXx30aMFE0zLDmENrwQH57W7IVQ6D9V6Z0bbhd1biSjbeBups0ZncczeEUOqLhOosOPytDAEAD6lrEIjl0S0ehopDbp8tXPKtH49jDRLoTon4CMhJn3vKXevlW2Ei8Hpz84CmUBpCnGzXq_6oN1PTrbCKPlzu7Q0dojK81cxNWPkBtbeVEP7ZKVzYA0YjduC29_hb3aRBBVLwHcHpV6_YxIJm_r7mKsI-OAH_Df8wJ1tIQ6Ik5EkjFk7DBUPqaSLdo6agd80jAcWlEP2JwhChzIzgE29jNzTN59MpjTZ3y-YKF2bQuNhgnKT4Ut0aiRVSAdrq5izrwQGAIEO58d0NqNCRix3twBPQWJwgL0-ti38dmZTGkrv3-9HRnudVlBmuR1Gd671mLUUSTfdrEHWg77-sfE3mtHs0XKkhL40qha5rZEbTt_gGsGJBtJzcreOXpflB37fivwEGUjoeoQGpIffFQWboZJ8ckC6GBhVFJzTzG-kUErhHY3D6yLDtcx3FN93ExpQ2azzD79Tbm4e-M4taKYGvTUGOW58exVvFnGShqCQ-mq3RdvnGT5GdcEhgSZW0lFuop9rBAPVAwg-UrY3H60kt_CyblfrcNLaquWHVW_siKpZd4MpVhpiT10MY-l-3k3i2pBqwgYnnNrHceFyZHmMsP7tyJuRRqEYJqeilMqoSEX05srt0cPRG7eaBFAWXK7G18E4iAQJsyVd-gd6HaXX-iMcjJ174FXOwaN4fs6g0_Eilj5mmuZFHieo1-9vVozXFiVxD7oPEQOjRN9cDnIPYht0n51Aofc9g0e0pecWX5B-4M4it2NU1ISY9pE7v7TVF5SVxIIEEOjpGRBvvyK0VexUg8IlmqbIEh0TlKcR_2ft5eCRuQeqDZVWyEhI9F2Ls1zHYayoF1WVbQYuThlA-4VuvkmeQZi2rAmgYAglSA78cON4eF57zgiKbCxK34YpTp3pTdUaBBm0xtO0si7HcS6n8RyDk7NfqAz-YDVPI0C3vXR5RIoD-Udf8HdVNFeqnArpIJcAsxmjpFNTZYoKhvznVKKrNbnkgxsWdgL1AY9LWymzprhEI8yWfaoq2I1R4YfrpTNKQAQBfMp_qSu1APjHtkcSmSkL_974eBnRguSMTxCPqxjUqkjU5nEECgYPZUrsao_ZGVIXuC38Zd9jCMgKSUGFY2OTVdgXmgjwg-jOgUSGHKKbB1HG8qj3TwE3hMVg4_LwLzcEGDDZ1Nz0q4m60FR-ZnJ5LjuIqirQMtcWti_kUdAtYyg5n3ysBYuYJQVb-jucR3kGAsVxobMqWrdAU0GVkzovJP2nRBuDPEBUDxKXZO-iHWbMkvaTYTruz329Aj6dr7GwBAmqbBghhnKBwQpRDHyId-fXfsQCVrgshT0CoOU-JrvdE05QSyr3L2HXp9tS17MlIhFzL0uLQ0XsdaKbrSwJ1IyL6izKv734ivfSlzLiKilkgZ-3IBr_RLz4Mr4e1alxSAQWVQTM-l9oegft7X09QqSAZ1ztFmLzKboSTu6_O0zOPdXQ2sGoqQqJNWg_4kfWm6sU1bz1oklYBaLEV6lGph9GSxwf0DG_j3rzAtBqxhZkCeBtk6pur53xb8J4VE-q4lAEGD-SWIjZZPMJtRrtcarK5efjYC5tOIrogQmmqHWzPvz0D_yKRnVSWA6Rh1QeOX8wBrq4jDk6eDJJwMM28HVu5oLpi6s6hJsU-EWOxXiA_j-ygxhEtrgJkAZx8EMopjFwBAqjRlNs1IvCbpznbOgEk1ofh4XpoMTIZqQmf-VPsXirWyJ_qOvDzI1x-967N_tvrRlbL-oC1FaOlQXlnOxc18arrQQ8aJ4RaVr06l4zwkQGsOyz8QfenD5TfDCV2_qhxgQEqsknmhc-psCwkg5pjreAbvB0PouH9TY4n5jj1qvhnC-P68hZZO6lIAsADTzrVLEQRD_3I5arUAqxAzm6Gm3ghES-QUyiPzifIp-jOLAKi4a-m4iTLo2Ob154gjthAngEA58zYmlt2a9vd8-_FrgaQAvLNv2i5Uhm8_4hQlN-2av582RelN-B6AUuIh_SMk4yDb1MVXOsdOOm2akMayZT035kldKtXcYasur8jOUkE7W5hL2esSDhB6eYOz1o99aCBA67QQmnbvpmvKCDiS97rfaCZqr4U0DCy9e0ylMcBqDlX-K0IxhDNhiiqRFMYbatqBGCGcwNAc7B6c1YYar6fVkqCA7jYFZZyYt3yCND6JkM2BTfpAiakknT03vY2P6-WgQOGRCN4mQttSdsajcySvOyW2ohNP_nwEHD2lEjzsgOI8jjh7WaJf8-8Oh-X_zNgnMJUfvMgwVfHFNOIAPX_zj1y2tVJMpAnD9eSUBsSG90ghPI0hS-IKPnxppjsWrMD28EGPCKVlP22usiIj8Y2sZeGKCyX7xm4GCI3TBDqI_tZ0MNZdLVzIv3CbQND9H7xyoCB_CIE6G9nQMfirWanfFwhgOKxWDUL5YjAPnn_FeT4J601JO3Bf3gNCbMSzAPwdkMBAkeNIIko2D1zcVyxiluQEsv88fDOxLgV3MjuXVG6mmc34E8bZUJwz3UrUBl91CMEAzfEPwxc_AEH9oaPJN_hANs5rwQMi8TIHPwETYV_VYIJKKon9CO3xKTZym0GJlrxgQVr2UhK2y7r_jnJgPromEPEYZTwqWC2kcXNJ41WLgrW9WQKa8VBSDTd7SQmj3r35oRVTI6U_3_d0OOqMHR8gitL93r9-xmIx9WljoJwuyPoS7BMjQssv_hK7MFXR8tXeIEBBxHxkVMUNPn5q_TWsjtcVYbQ8iGJCFZHBXkDljFQXnvvktOr9xx28qN-6fgNDmmA6KU9lKSXqypZ10DUL0Y-BWyubg0h3xLirUdxXHiZQnkxp5_NdWwRc_0GO1ioJNHBBjGRtlYTJlAMKux4uXiI1gSDuJ-bBUO43BAg012ryQxUsaYowT7Db_j0skDXMfO_hJu6tgnJF-oGjdH0OdHkoOdWsOZ3vINMY7U0EfYxqyT5fjT4BV54DKY0axWEpB8ywQMTD8k5Arj-DQCo-RziCOE3ISGh8ocX5AB8CX9zK15cZ1VjvLa1H_pS_X-pNpWqdQZB7mdFK6ZTWwC2EOXwnaghzLTaFWr39TLB7fSEETalvxPelrwtW6RzwUeXDSGboYEDBopTOJ4gGFGy3kj03mOE6eqZ8vKCwGE44S63NIgJWy6M5m3fgYJC-k1rH5CvWDFAlMtqrarDZbZi_R3ENGATY222Tun66K4cVEi1ytWm_566aJD8G_yvO5v_K829cE4"
            },
            "purposes": [
              "assertionMethod",
              "authentication",
              "keyAgreement",
              "capabilityInvocation",
              "capabilityDelegation"
            ]
        }
    ]
    }
    "##;
}
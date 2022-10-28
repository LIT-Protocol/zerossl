use serde::{Deserialize, Serialize};
use crate::client::validation::{ValidationOptions, ValidationType};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCertificateReq {
    certificate_domains: Vec<String>,
    certificate_csr: Vec<u8>,
    certificate_validity_days: Option<u8>,
    strict_domains: Option<u8>,
}

impl CreateCertificateReq {
    pub fn new(
        certificate_domains: Vec<String>,
        certificate_csr: Vec<u8>,
        certificate_validity_days: Option<u8>,
        strict_domains: bool,
    ) -> Self {
        let strict_domains = if strict_domains {
            Some(1 as u8)
        } else {
            None
        };

        Self {
            certificate_domains,
            certificate_csr,
            certificate_validity_days,
            strict_domains
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCertificateRes {
    id: String,
    #[serde(rename = "type")]
    typ: u8,
    common_name: String,
    additional_domains: String,
    created: String,
    expires: String,
    status: String,
    validation_type: Option<ValidationType>,
    validation_emails: Option<String>,
    replacement_for: Option<String>,
    validation: Option<ValidationOptions>,
}
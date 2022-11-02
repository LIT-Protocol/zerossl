use openssl::pkey::{PKey, Private};
use serde::{Deserialize, Serialize};
use crate::certs::csr::{Csr, generate_csr};

use crate::client::result::{ErrorMsg, Resp, ResultStatus};
use crate::client::validation::{ValidationOptions, ValidationType};

// Create Certificate

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCertificateReq {
    certificate_domains: String,
    certificate_csr: String,
    certificate_validity_days: Option<u8>,
    strict_domains: Option<u8>,
}

impl CreateCertificateReq {
    pub fn new(
        certificate_domains: Vec<String>,
        certificate_csr: String,
    ) -> Self {
        Self {
            certificate_domains: certificate_domains.join(","),
            certificate_csr,
            certificate_validity_days: None,
            strict_domains: None,
        }
    }

    pub fn from_csr(pkey: &PKey<Private>, csr: &Csr) -> crate::error::Result<Self> {
        let x509_req = generate_csr(&pkey, &csr)
            .map_err(|e| crate::error::openssl(e, None))?;

        let csr_pem = x509_req.to_pem()
            .map_err(|e| crate::error::openssl(e, None))?;
        let csr_pem_str = String::from_utf8(csr_pem)
            .map_err(|e| crate::error::openssl(e,
                                               Some("failed to convert PEM to String".to_string())))?;

        Ok(Self::new(csr.all_names(), csr_pem_str))
    }

    pub fn with_certificate_validity_days(&mut self, days: u8) -> &mut Self {
        self.certificate_validity_days = Some(days);
        self
    }

    pub fn with_strict_domains(&mut self, strict_domains: bool) -> &mut Self {
        let strict_domains = if strict_domains {
            Some(1 as u8)
        } else {
            None
        };

        self.strict_domains = strict_domains;
        self
    }

    // Accessors


}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCertificateRes {
    // For errors (no, they only return status 200???
    #[serde(flatten)]
    pub(crate) result_status: ResultStatus,

    // Actual response
    #[serde(flatten)]
    pub(crate) certificate: Certificate,
}

impl CreateCertificateRes {
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }
}

impl Resp for CreateCertificateRes {
    fn is_ok(&self) -> bool {
        return self.result_status.is_ok();
    }

    fn err_msg(&self) -> Option<ErrorMsg> {
        return self.result_status.err_msg();
    }
}

// List Certificates

#[derive(Debug, Serialize, Deserialize)]
pub struct ListCertificatesReq {
    certificate_status: Option<String>,
    certificate_type: Option<String>,
    search: Option<String>,
    limit: Option<u32>,
    page: Option<u32>,
}

impl ListCertificatesReq {
    pub fn default() -> Self {
        Self {
            certificate_status: None,
            certificate_type: None,
            search: None,
            limit: None,
            page: None
        }
    }

    pub fn new(certificate_status: Option<String>,
               certificate_type: Option<String>,
               search: Option<String>,
               limit: Option<u32>,
               page: Option<u32>
    ) -> Self {
        Self {
            certificate_status,
            certificate_type,
            search, limit, page,
            ..Self::default()
        }
    }

    pub fn for_search(search: String) -> Self {
        Self {
            search: Some(search),
            ..Self::default()
        }
    }

    pub fn with_status(&mut self, status: Vec<&str>) -> &mut Self {
        self.certificate_status = Some(status.join(","));
        self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListCertificatesRes {
    #[serde(flatten)]
    pub(crate) result_status: ResultStatus,

    // Actual response
    pub(crate) results: Vec<Certificate>,
}

impl ListCertificatesRes {
    pub fn results(&self) -> &Vec<Certificate> {
        &self.results
    }
}

impl Resp for ListCertificatesRes {
    fn is_ok(&self) -> bool {
        return self.result_status.is_ok();
    }

    fn err_msg(&self) -> Option<ErrorMsg> {
        return self.result_status.err_msg();
    }
}

// Common

#[derive(Debug, Serialize, Deserialize)]
pub struct Certificate {
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub cert_type: Option<String>,
    pub common_name: Option<String>,
    pub additional_domains: Option<String>,
    pub created: Option<String>,
    pub expires: Option<String>,
    pub status: Option<String>,
    pub validation_type: Option<ValidationType>,
    pub validation_emails: Option<String>,
    pub replacement_for: Option<String>,
    pub validation: Option<ValidationOptions>,
}

impl Certificate {
    pub fn file_validation(&self, domain: &String) -> Option<(String, Vec<String>)> {
        if let Some(validation) = self.validation.as_ref() {
            return validation.file_validation(domain);
        }

        None
    }
}
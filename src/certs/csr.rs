use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::{Rsa};
use openssl::stack::Stack;
use openssl::x509::{X509Name, X509Req};
use openssl::x509::extension::{KeyUsage, SubjectAlternativeName};

pub fn generate_rsa_2048_priv_key() -> Result<PKey<Private>, ErrorStack> {
    PKey::from_rsa(Rsa::generate(2048)?)
}

pub struct Csr {
    common_name: String,
    alt_names: Option<Vec<String>>,
    alt_name_is_ip: bool,
    country: Option<String>,
    org_name: Option<String>,
    org_unit: Option<String>,
}

impl Csr {
    pub fn default() -> Self {
        Self {
            common_name: "".to_string(),
            alt_names: None,
            alt_name_is_ip: false,
            country: None,
            org_name: None,
            org_unit: None,
        }
    }

    pub fn new(common_name: String) -> Self {
        Self {
            common_name,
            ..Csr::default()
        }
    }

    pub fn with_alt_names(&mut self, alt_names: Vec<String>, is_ip: bool) -> &mut Self {
        self.alt_names = Some(alt_names);
        self.alt_name_is_ip = is_ip;
        self
    }

    pub fn with_country(&mut self, country: String) -> &mut Self {
        self.country = Some(country);
        self
    }

    pub fn with_org_name(&mut self, org_name: String) -> &mut Self {
        self.org_name = Some(org_name);
        self
    }

    pub fn with_org_unit(&mut self, org_unit: String) -> &mut Self {
        self.org_unit = Some(org_unit);
        self
    }

    // Accessors
    pub fn common_name(&self) -> String {
        self.common_name.clone()
    }

    pub fn alt_names(&self) -> Option<Vec<String>> {
        self.alt_names.clone()
    }

    pub fn alt_name_is_ip(&self) -> bool {
        self.alt_name_is_ip
    }

    pub fn all_names(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();

        names.push(self.common_name.clone());

        if let Some(alt_names) = self.alt_names.as_ref() {
            for name in alt_names.iter() {
                if !name.eq_ignore_ascii_case(self.common_name.as_ref()) {
                    names.push(name.clone());
                }
            }
        }

        names
    }

    pub fn country(&self) -> Option<String> {
        self.country.clone()
    }

    pub fn org_name(&self) -> Option<String> {
        self.org_name.clone()
    }

    pub fn org_unit(&self) -> Option<String> {
        self.org_unit.clone()
    }
}

pub fn generate_csr(
    pkey: &PKey<Private>,
    csr: &Csr
) -> Result<X509Req, ErrorStack>{
    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, csr.common_name.as_str())?;

    if let Some(country) = csr.country.as_ref() {
        name.append_entry_by_nid(Nid::COUNTRYNAME, country.as_str())?;
    }
    if let Some(org_name) = csr.org_name.as_ref() {
        name.append_entry_by_nid(Nid::ORGANIZATIONNAME, org_name.as_str())?;
    }
    if let Some(org_unit) = csr.org_unit.as_ref() {
        name.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, org_unit.as_str())?;
    }

    let name = name.build();

    let mut builder = X509Req::builder()?;
    builder.set_version(0)?;
    builder.set_subject_name(&name)?;
    builder.set_pubkey(&pkey)?;

    let mut extensions = Stack::new()?;
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()?;
    extensions.push(key_usage).unwrap();

    if let Some(alt_names) = csr.alt_names.as_ref() {
        for alt in alt_names {
            let mut subject_alternative_name = SubjectAlternativeName::new();
            if csr.alt_name_is_ip {
                subject_alternative_name.ip(alt);
            } else {
                subject_alternative_name.dns(alt);
            }

            let subject_alternative_name = subject_alternative_name
                .build(&builder.x509v3_context(None))?;

            extensions.push(subject_alternative_name)?;
        }
    }
    builder.add_extensions(&extensions)?;

    builder.sign(&pkey, MessageDigest::sha256())?;

    Ok(builder.build())
}


#[cfg(test)]
mod tests {
    use crate::certs::csr::{Csr, generate_csr, generate_rsa_2048_priv_key};

    #[test]
    fn generate_rsa_2048_priv_key_test() {
        let _ = generate_rsa_2048_priv_key().unwrap();
    }

    #[test]
    fn generate_csr_ip_test() {
        let pkey = generate_rsa_2048_priv_key().unwrap();

        let mut alt_names: Vec<String> = Vec::new();
        alt_names.push("172.33.33.33".to_string());
        alt_names.push("172.33.33.34".to_string());

        let mut csr = Csr::new("172.33.33.33".to_string());
        let csr = csr.with_alt_names(alt_names, true)
            .with_country("AU".to_string())
            .with_org_name("Lit".to_string())
            .with_org_unit("Node Devs".to_string());

        let csr = generate_csr(&pkey, &csr).unwrap();

        // TODO: Verify more
        let csr_pem = csr.to_pem().unwrap();

        assert!(csr_pem.len() > 0);
    }

    #[test]
    fn generate_csr_dns_test() {
        let pkey = generate_rsa_2048_priv_key().unwrap();

        let mut alt_names: Vec<String> = Vec::new();
        alt_names.push("www.example.com".to_string());
        alt_names.push("www2.example.com".to_string());

        let mut csr = Csr::new("example.com".to_string());
        let csr = csr.with_alt_names(alt_names, false)
            .with_country("AU".to_string())
            .with_org_name("Lit".to_string())
            .with_org_unit("Node Devs".to_string());

        let csr = generate_csr(&pkey, &csr).unwrap();

        // TODO: Verify more
        let csr_pem = csr.to_pem().unwrap();

        assert!(csr_pem.len() > 0);
    }
}
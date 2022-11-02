use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationType {
    Email,
    CnameCsrHash,
    HttpCsrHash,
    HttpsCsrHash
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationOptions {
    pub email_validation: Option<HashMap<String, Vec<String>>>,
    pub other_methods: Option<HashMap<String, OtherValidation>>,
}

impl ValidationOptions {
    pub fn file_validation(&self, domain: &String) -> Option<(String, Vec<String>)> {
        if let Some(other_methods) = self.other_methods.as_ref() {
            if let Some(other_validation) = other_methods.get(domain) {
                return other_validation.file_validation();
            }
        }

        None
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OtherValidation {
    pub file_validation_url_http: Option<String>,
    pub file_validation_url_https: Option<String>,
    pub file_validation_content: Option<Vec<String>>,
    pub cname_validation_p1: Option<String>,
    pub cname_validation_p2: Option<String>
}

impl OtherValidation {
    pub fn file_validation(&self) -> Option<(String, Vec<String>)> {
        if let Some(file_validation_url_https) = self.file_validation_url_https.as_ref() {
            if let Some(file_validation_content) = self.file_validation_content.as_ref() {
                let parts: Vec<&str> = file_validation_url_https.split("/").collect();
                if parts.len() > 0 {
                    let id_part = parts.last().unwrap();
                    let parts: Vec<&str> = id_part.split(".").collect();
                    if parts.len() > 0 {
                        return Some((parts.first().unwrap().to_string(), file_validation_content.clone()))
                    }
                }
            }
        }

        None
    }
}
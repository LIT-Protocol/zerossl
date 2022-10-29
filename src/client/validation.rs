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

#[derive(Debug, Serialize, Deserialize)]
pub struct OtherValidation {
    pub file_validation_url_http: Option<String>,
    pub file_validation_url_https: Option<String>,
    pub file_validation_content: Option<Vec<String>>,
    pub cname_validation_p1: Option<String>,
    pub cname_validation_p2: Option<String>
}


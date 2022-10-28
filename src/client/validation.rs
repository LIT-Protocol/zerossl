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
    email_validation: Option<HashMap<String, Vec<String>>>,
    other_methods: Option<HashMap<String, OtherValidation>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OtherValidation {
    file_validation_url_http: Option<String>,
    file_validation_url_https: Option<String>,
    file_validation_content: Option<Vec<String>>,
    cname_validation_p1: Option<String>,
    cname_validation_p2: Option<String>
}


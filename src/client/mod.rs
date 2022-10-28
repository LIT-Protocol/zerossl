use crate::client::certificates::{CreateCertificateReq, CreateCertificateRes};

pub mod certificates;
pub mod validation;

static ZEROSSL_API_URL: &str = "https://api.zerossl.com";

pub struct Client {
    api_key: String,
    api_url: String,
}

impl Client {
    pub fn default() -> Self {
        Client {
            api_key: "".to_string(),
            api_url: ZEROSSL_API_URL.to_string(),
        }
    }

    pub fn new(api_key: String) -> Self {
        Client {
            api_key,
            ..Client::default()
        }
    }

    fn prepare(&self, method: reqwest::Method, uri: &str) -> reqwest::RequestBuilder {
        let client = reqwest::Client::new();

        client.request(method, format!("{}{}", self.api_url, uri))
            .query(&[("access_key", self.api_key.clone())])
    }

    fn post(&self, uri: &str) -> reqwest::RequestBuilder {
        self.prepare(reqwest::Method::POST, uri)
    }

    // Actions
    pub async fn create_certificate(&self, req: &CreateCertificateReq) -> Result<CreateCertificateRes, reqwest::Error> {
        let mut r = self.post("/certificates");
        let res = r.form(req)
            .send().await?;

        let res = res
            .json::<CreateCertificateRes>()
            .await?;

        Ok(res)
    }
}
use reqwest::{Response, StatusCode};

use crate::client::certificates::{CreateCertificateReq, CreateCertificateRes, ListCertificatesReq, ListCertificatesRes};
use crate::client::result::{Resp, ResultStatus, ResultStatusAlt};
use crate::error as error;
use crate::error::Result;

pub mod certificates;
pub mod validation;
pub mod result;

pub static API_URL: &str = "https://api.zerossl.com";

pub static PENDING_STATUS: [&str;2] = ["draft", "pending_validation"];

pub struct Client {
    api_key: String,
    api_url: String,
}

impl Client {
    pub fn default() -> Self {
        Client {
            api_key: "".to_string(),
            api_url: API_URL.to_string(),
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

    fn get(&self, uri: &str) -> reqwest::RequestBuilder {
        self.prepare(reqwest::Method::GET, uri)
    }

    fn post(&self, uri: &str) -> reqwest::RequestBuilder {
        self.prepare(reqwest::Method::POST, uri)
    }

    // Error handling
    async fn res_to_err(&self, res: Response) -> error::Error {
        return error::request(format!("request failed"),
                                  Some(res.text()
                                      .await.unwrap_or("no body returned".to_string())))
    }

    // Actions
    pub async fn create_certificate(&self, req: &CreateCertificateReq) -> Result<CreateCertificateRes> {
        let res = self.post("/certificates")
            .form(req)
            .send().await
            .map_err(|e| error::request(e, None))?;

        if res.status() != StatusCode::OK {
            return Err(self.res_to_err(res).await);
        }

        let res = res.json::<CreateCertificateRes>()
            .await
            .map_err(|e| error::request(e, None))?;

        // Apparently even error's produce Status 200 (???)
        if !res.is_ok() {
            return Err(res.to_err());
        }

        Ok(res)
    }

    pub async fn get_certificates(&self, req: &ListCertificatesReq) -> Result<ListCertificatesRes> {
        let res = self.get("/certificates")
            .query(req)
            .send().await
            .map_err(|e| error::request(e, None))?;

        if res.status() != StatusCode::OK {
            return Err(self.res_to_err(res).await);
        }

        let res = res.json::<ListCertificatesRes>()
            .await
            .map_err(|e| error::request(e, None))?;

        // Apparently even error's produce Status 200 (???)
        if !res.is_ok() {
            return Err(res.to_err());
        }

        Ok(res)
    }

    pub async fn get_pending_certificates(&self, domain: String) -> Result<ListCertificatesRes> {
        let mut cert_search_req = ListCertificatesReq::for_search(domain);
        cert_search_req.with_status(PENDING_STATUS.to_vec());

        self.get_certificates(&cert_search_req).await
    }

    pub async fn purge_pending_certificates(&self, domain: String) -> Result<()> {
        let mut cert_search_req = ListCertificatesReq::for_search(domain);
        cert_search_req.with_status(PENDING_STATUS.to_vec());

        let res = self.get_certificates(&cert_search_req).await?;

        for rec in res.results.iter() {
            if let Some(id) = rec.id.as_ref() {
                self.cancel_certificate(id.clone()).await?;
            }
        }

        Ok(())
    }

    pub async fn cancel_certificate(&self, id: String) -> Result<ResultStatusAlt> {
        let res = self.post(format!("/certificates/{}/cancel", id).as_str())
            .send().await
            .map_err(|e| error::request(e, None))?;

        if res.status() != StatusCode::OK {
            return Err(self.res_to_err(res).await);
        }

        let res = res.json::<ResultStatusAlt>()
            .await
            .map_err(|e| error::request(e, None))?;

        // Apparently even error's produce Status 200 (???)
        if !res.is_ok() {
            return Err(res.to_err());
        }

        Ok(res)
    }

}

#[cfg(test)]
mod tests {
    use std::env;
    use crate::certs::csr::{Csr, generate_rsa_2048_priv_key};
    use crate::client::certificates::{CreateCertificateReq, ListCertificatesReq};
    use crate::client::Client;

    #[tokio::test]
    /*
    async fn dummy_test() {
        //let test_domain = "107.178.100.155".to_string();
        //let is_ip = true;
        let test_domain = "dev.getlit.sh".to_string();
        let is_ip = false;

        let client = Client::new(env::var("API_KEY").unwrap().as_str());

        let pkey = generate_rsa_2048_priv_key().unwrap();

        let mut domains: Vec<String> = Vec::new();
        domains.push(test_domain.clone());

        let mut csr = Csr::new(test_domain);
        let csr = csr.with_alt_names(domains.clone(), is_ip)
            .with_country("AU".to_string())
            .with_org_name("Lit".to_string())
            .with_org_unit("Node Devs".to_string());

        let cert_req = CreateCertificateReq::from_csr(&pkey, &csr)
            .expect("failed to make cert req");

        let cert_res = client.create_certificate(&cert_req).await
            .expect("failed to get cert");

        println!("OUT: {:#?}", cert_res);

        assert!(false);
    }

     */
    async fn dummy_test() {
        // TODO: REMOVE
        let test_domain = "dev.getlit.sh".to_string();
        let api_key = env::var("API_KEY").unwrap();
        let client = Client::new(api_key);

        client.purge_pending_certificates(test_domain).await
            .expect("failed to get certs");

        assert!(false);
    }
}
use std::sync::Arc;

use account::NewAccountRequest;
use api::DirectoryUrl;
use bytes::Bytes;
use error::AcmeResult;

use serde_json::{json, Value};
use tokio::sync::Mutex;

use self::api::Directory;
use self::utils::base64;

pub use account::*;
pub use authorization::*;
pub use error::*;
pub use key::*;
pub use order::*;

mod account;
mod api;
mod authorization;
mod error;
mod key;
mod order;
mod utils;

#[derive(Debug, Clone)]
struct AcmeRequest<'a> {
    url: &'a str,
    kid: Option<&'a str>,
    private_key: &'a key::PrivateKey,
    payload: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct AcmeClient {
    directory_url: DirectoryUrl,
    inner: Arc<AcmeClientInner>,
}

#[derive(Debug)]
pub(crate) struct AcmeClientInner {
    http: reqwest::Client,
    directory: api::Directory,
    next_nonce: Mutex<Option<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct AcmeClientBuilder {
    http_client: reqwest::Client,
}

pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";

impl AcmeClientBuilder {
    pub fn http_client(self, http_client: reqwest::Client) -> Self {
        Self { http_client }
    }

    pub async fn build_lets_encrypt_staging(self) -> AcmeResult<AcmeClient> {
        self.build_with_directory_url(LETS_ENCRYPT_STAGING).await
    }

    pub async fn build_lets_encrypt_production(self) -> AcmeResult<AcmeClient> {
        self.build_with_directory_url(LETS_ENCRYPT_PRODUCTION).await
    }

    pub async fn build_with_directory_url(
        self,
        url: impl Into<DirectoryUrl>,
    ) -> AcmeResult<AcmeClient> {
        let url = url.into();
        let directory = self.http_client.get(&url.0).send().await?;
        let directory = directory.json::<Directory>().await?;
        Ok(AcmeClient::new(url, directory, self.http_client))
    }
}

impl AcmeClientInner {
    async fn send_request(
        &self,
        request: impl Into<AcmeRequest<'_>>,
    ) -> AcmeResult<http::Response<Bytes>> {
        let request = request.into();

        let res = loop {
            let jwk = if request.kid.is_none() {
                Some(request.private_key.jwk()?)
            } else {
                None
            };

            let protected = base64(
                json!({
                    "alg": request.private_key.alg(),
                    "url": request.url,
                    "nonce": self.nonce().await?,
                    "kid": request.kid,
                    "jwk": jwk,
                })
                .to_string(),
            );

            let payload = base64(
                request
                    .payload
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_default(),
            );

            let signature = request
                .private_key
                .sign(format!("{protected}.{payload}").as_bytes())?;

            let body = json!({
                "protected": protected,
                "payload": payload,
                "signature": signature,
            });

            let mut nonce = self.next_nonce.lock().await;

            let res = self
                .http
                .post(request.url)
                .body(body.to_string())
                .header("Content-Type", "application/jose+json")
                .send()
                .await?;

            if let Some(next_nonce) = res
                .headers()
                .get("replay-nonce")
                .and_then(|nonce| nonce.to_str().ok())
            {
                nonce.replace(next_nonce.to_owned());
                drop(nonce);
            };

            if res.status().is_client_error() || res.status().is_server_error() {
                let error = res.json::<api::ServerError>().await?;

                if !error.is_bad_nonce() {
                    return Err(error.into());
                };
            } else {
                break res;
            }
        };

        let mut http_res = http::Response::builder()
            .status(res.status())
            .version(res.version());
        *http_res.headers_mut().unwrap() = res.headers().clone();

        Ok(http_res.body(res.bytes().await?).unwrap())
    }

    async fn nonce(&self) -> AcmeResult<String> {
        match self.next_nonce.lock().await.take() {
            Some(nonce) => Ok(nonce),
            None => self
                .http
                .get(&self.directory.new_nonce)
                .send()
                .await?
                .headers()
                .get("replay-nonce")
                .and_then(|nonce| nonce.to_str().ok())
                .map(|nonce| nonce.to_string())
                .ok_or_else(|| "Failed to generate nonce".into()),
        }
    }
}

impl AcmeClient {
    pub fn builder() -> AcmeClientBuilder {
        AcmeClientBuilder::default()
    }

    pub async fn from_directory_url(url: impl AsRef<str>) -> AcmeResult<AcmeClient> {
        let http = reqwest::Client::default();
        let directory = http.get(url.as_ref()).send().await?;
        let directory = directory.json::<Directory>().await?;
        Ok(Self::new(url.as_ref().into(), directory, http))
    }

    fn new(directory_url: DirectoryUrl, directory: Directory, http: reqwest::Client) -> Self {
        AcmeClient {
            directory_url,
            inner: Arc::new(AcmeClientInner {
                directory,
                http,
                next_nonce: Mutex::new(None),
            }),
        }
    }

    pub fn directory_url(&self) -> &str {
        self.directory_url.0.as_str()
    }

    pub fn directory(&self) -> &Directory {
        &self.inner.directory
    }

    pub fn new_account(&self) -> NewAccountRequest {
        NewAccountRequest::new(self.inner.clone(), &self.directory().new_account)
    }

    pub async fn existing_account_from_private_key(
        &self,
        private_key: impl TryInto<key::PrivateKey>,
    ) -> AcmeResult<Account> {
        self.new_account()
            .private_key(private_key)
            .only_return_existing(true)
            .send()
            .await
    }
}

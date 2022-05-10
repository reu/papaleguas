use std::sync::Arc;

use futures::future::try_join_all;
use openssl::pkey::{PKey, Private};
use serde_json::json;

use crate::{
    account::{Account, AccountInner},
    api,
    authorization::Authorization,
    csr::generate_csr,
    error::AcmeResult,
    utils::{self, add_field},
    AcmeClientInner, AcmeRequest,
};

pub use api::OrderStatus;

#[derive(Debug, Clone)]
pub struct Order {
    pub(crate) acme: Arc<AcmeClientInner>,
    pub(crate) account: Arc<AccountInner>,
    pub(crate) url: String,
    pub(crate) order: api::Order,
}

impl Order {
    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn status(&self) -> &OrderStatus {
        &self.order.status
    }

    pub fn expires(&self) -> Option<&str> {
        self.order.expires.as_deref()
    }

    pub fn not_before(&self) -> Option<&str> {
        self.order.expires.as_deref()
    }

    pub fn not_after(&self) -> Option<&str> {
        self.order.expires.as_deref()
    }

    pub fn error(&self) -> Option<&api::ServerError> {
        self.order.error.as_ref()
    }

    pub async fn authorizations(&self) -> AcmeResult<Vec<Authorization>> {
        let auths = self
            .order
            .authorizations
            .iter()
            .map(|auth| AcmeRequest {
                url: auth,
                kid: Some(&self.account.kid),
                private_key: &self.account.key,
                payload: None,
            })
            .map(|req| async {
                let res = self.acme.send_request(req).await?;
                Ok(Authorization {
                    acme: self.acme.clone(),
                    account: self.account.clone(),
                    authorization: serde_json::from_slice(&res.into_body())?,
                })
            });

        try_join_all(auths).await
    }

    pub async fn finalize(self, private_key: &PKey<Private>) -> AcmeResult<Self> {
        let domains = self
            .order
            .identifiers
            .iter()
            .map(|i| i.value.as_str())
            .collect::<Vec<&str>>();

        let csr = generate_csr(private_key, &domains)?;

        let res = self
            .acme
            .send_request(AcmeRequest {
                url: &self.order.finalize,
                kid: Some(&self.account.kid),
                private_key: &self.account.key,
                payload: Some(json!({ "csr": utils::base64(&csr.to_der()?) })),
            })
            .await?;

        let order = serde_json::from_slice(&res.into_body())?;

        Ok(Self {
            acme: self.acme,
            account: self.account,
            url: self.url,
            order,
        })
    }

    pub async fn certificate(&self) -> AcmeResult<String> {
        let res = self
            .acme
            .send_request(AcmeRequest {
                url: self
                    .order
                    .certificate
                    .as_ref()
                    .ok_or("Order is not in a valid state to fetch the certificate")?,
                kid: Some(&self.account.kid),
                private_key: &self.account.key,
                payload: None,
            })
            .await?;

        Ok(std::str::from_utf8(&res.into_body())?.to_owned())
    }
}

pub enum OrderIdentifier {
    Dns(String),
    Other(String, String),
}

impl<T: Into<String>> From<T> for OrderIdentifier {
    fn from(dns: T) -> Self {
        OrderIdentifier::Dns(dns.into())
    }
}

pub struct NewOrderRequest<'a> {
    pub(crate) account: &'a Account,
    pub(crate) identifiers: Vec<OrderIdentifier>,
}

impl<'a> NewOrderRequest<'a> {
    pub(crate) fn new(account: &'a Account) -> Self {
        NewOrderRequest {
            account,
            identifiers: Default::default(),
        }
    }

    add_field!(identifiers, Vec<OrderIdentifier>);

    pub fn dns(self, dns: impl Into<String>) -> Self {
        let mut identifiers = self.identifiers;
        identifiers.push(dns.into().into());
        Self {
            identifiers,
            ..self
        }
    }

    pub fn identifier(self, identifier: impl Into<OrderIdentifier>) -> Self {
        let mut identifiers = self.identifiers;
        identifiers.push(identifier.into());
        Self {
            identifiers,
            ..self
        }
    }

    pub async fn send(self) -> AcmeResult<Order> {
        let acme = self.account.inner.acme.clone();
        let account = self.account.inner.clone();

        let identifiers = self
            .identifiers
            .into_iter()
            .map(|identifier| match identifier {
                OrderIdentifier::Dns(dns) => json!({ "type": "dns", "value": dns }),
                OrderIdentifier::Other(r#type, value) => {
                    json!({ "type": r#type, "value": value })
                }
            })
            .collect::<Vec<_>>();

        let res = acme
            .send_request(AcmeRequest {
                url: &acme.directory.new_order,
                kid: Some(self.account.kid()),
                private_key: &self.account.inner.key,
                payload: Some(json!({ "identifiers": identifiers })),
            })
            .await?;

        let url = res
            .headers()
            .get(http::header::LOCATION)
            .and_then(|kid| kid.to_str().map(|kid| kid.to_owned()).ok())
            .ok_or("Failed to get order url")?;

        Ok(Order {
            acme,
            account,
            url,
            order: serde_json::from_slice(&res.into_body())?,
        })
    }
}

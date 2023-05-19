use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{
    api,
    error::AcmeResult,
    key,
    order::{NewOrderRequest, Order},
    utils::add_field,
    AcmeClientInner, AcmeRequest,
};

#[derive(Debug, Clone)]
pub struct Account {
    pub(crate) inner: Arc<AccountInner>,
}

#[derive(Debug)]
pub(crate) struct AccountInner {
    pub(crate) acme: Arc<AcmeClientInner>,
    pub(crate) kid: String,
    pub(crate) key: key::PrivateKey,
    pub(crate) account: api::Account,
}

impl Account {
    fn new(
        acme: Arc<AcmeClientInner>,
        kid: String,
        key: key::PrivateKey,
        account: api::Account,
    ) -> Self {
        Account {
            inner: Arc::new(AccountInner {
                acme,
                kid,
                account,
                key,
            }),
        }
    }

    pub fn kid(&self) -> &str {
        self.inner.kid.as_str()
    }

    pub fn key(&self) -> &key::PrivateKey {
        &self.inner.key
    }

    pub fn new_order(&self) -> NewOrderRequest {
        NewOrderRequest::new(self)
    }

    pub async fn find_order(&self, url: impl Into<String>) -> AcmeResult<Order> {
        let url = url.into();

        let res = self
            .inner
            .acme
            .send_request(AcmeRequest {
                url: &url,
                kid: Some(self.kid()),
                private_key: &self.inner.key,
                payload: None,
            })
            .await?;

        Ok(Order {
            acme: self.inner.acme.clone(),
            account: self.inner.clone(),
            url,
            order: serde_json::from_slice(&res.into_body())?,
        })
    }

    pub async fn orders_urls(&self) -> AcmeResult<Vec<String>> {
        #[derive(Deserialize)]
        struct Orders {
            orders: Vec<String>,
        }

        match &self.inner.account.orders {
            Some(orders) => {
                let res = self
                    .inner
                    .acme
                    .send_request(AcmeRequest {
                        url: orders,
                        kid: Some(self.kid()),
                        private_key: &self.inner.key,
                        payload: None,
                    })
                    .await?;

                Ok(serde_json::from_slice::<Orders>(&res.into_body())?.orders)
            }
            None => Ok(Vec::new()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccountRequest<'a> {
    #[serde(skip)]
    acme: Arc<AcmeClientInner>,
    #[serde(skip)]
    url: &'a str,
    #[serde(skip)]
    private_key: Option<key::PrivateKey>,
    contacts: Vec<&'a str>,
    terms_of_service_agreed: bool,
    only_return_existing: bool,
}

impl<'a> NewAccountRequest<'a> {
    pub(crate) fn new(acme: Arc<AcmeClientInner>, url: &'a str) -> Self {
        Self {
            acme,
            url,
            private_key: None,
            contacts: Vec::with_capacity(1),
            terms_of_service_agreed: false,
            only_return_existing: false,
        }
    }

    add_field!(contacts, Vec<&'a str>);
    add_field!(terms_of_service_agreed, bool);
    add_field!(only_return_existing, bool);

    pub fn private_key(self, key: impl TryInto<key::PrivateKey>) -> Self {
        Self {
            private_key: key.try_into().ok(),
            ..self
        }
    }

    pub fn contact(self, email: &'a str) -> Self {
        let mut contacts = self.contacts;
        contacts.push(email);
        Self { contacts, ..self }
    }

    #[cfg(feature = "rsa")]
    pub fn with_auto_generated_rsa_key(self) -> Self {
        Self {
            private_key: Some(key::PrivateKey::random_rsa_key(rand::thread_rng())),
            ..self
        }
    }

    pub fn with_auto_generated_ec_key(self) -> Self {
        Self {
            private_key: Some(key::PrivateKey::random_ec_key(rand::thread_rng())),
            ..self
        }
    }

    pub async fn send(self) -> AcmeResult<Account> {
        let payload = serde_json::to_value(&self)?;
        let key = self.private_key.ok_or("Invalid private key")?;

        let res = self
            .acme
            .send_request(AcmeRequest {
                url: self.url,
                private_key: &key,
                kid: None,
                payload: Some(payload),
            })
            .await?;

        let kid = res
            .headers()
            .get(http::header::LOCATION)
            .and_then(|kid| kid.to_str().map(|kid| kid.to_owned()).ok())
            .ok_or("Failed to parse account key id")?;

        let account = serde_json::from_slice(&res.into_body())?;

        Ok(Account::new(self.acme, kid, key, account))
    }
}

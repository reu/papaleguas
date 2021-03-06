use std::sync::Arc;

use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
};

use serde::{Deserialize, Serialize};

use crate::{
    api,
    error::AcmeResult,
    jose,
    order::{NewOrderRequest, Order},
    utils::{add_field, add_optional_field},
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
    pub(crate) key: jose::Key,
    pub(crate) account: api::Account,
}

impl Account {
    fn new(acme: Arc<AcmeClientInner>, kid: String, key: jose::Key, account: api::Account) -> Self {
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

    pub fn key(&self) -> &jose::Key {
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
    private_key: Option<PKey<Private>>,
    contacts: Vec<String>,
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

    add_optional_field!(private_key, PKey<Private>);
    add_field!(contacts, Vec<String>);
    add_field!(terms_of_service_agreed, bool);
    add_field!(only_return_existing, bool);

    pub fn contact(self, email: impl Into<String>) -> Self {
        let mut contacts = self.contacts;
        contacts.push(email.into());
        Self { contacts, ..self }
    }

    pub fn with_auto_generated_rsa_key(self) -> Self {
        let private_key = Rsa::generate(2048).and_then(PKey::from_rsa).ok();
        Self {
            private_key,
            ..self
        }
    }

    pub fn with_auto_generated_ec_key(self) -> Self {
        let private_key = EcGroup::from_curve_name(Nid::SECP384R1)
            .and_then(|group| EcKey::generate(&group))
            .and_then(PKey::from_ec_key)
            .ok();

        Self {
            private_key,
            ..self
        }
    }

    pub async fn send(self) -> AcmeResult<Account> {
        let payload = serde_json::to_value(&self)?;
        let key = self.private_key.ok_or("Missing private key")?.try_into()?;

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

        let account = serde_json::from_slice::<api::Account>(&res.into_body())?;

        Ok(Account::new(self.acme, kid, key, account))
    }
}

use std::sync::Arc;

use serde_json::json;

use crate::error::AcmeResult;
use crate::{account::AccountInner, api, AcmeClientInner, AcmeRequest};

pub use api::AuthorizationStatus;
pub use api::ChallengeStatus;

#[derive(Debug, Clone)]
pub struct Authorization {
    pub(crate) acme: Arc<AcmeClientInner>,
    pub(crate) account: Arc<AccountInner>,
    pub(crate) authorization: api::Authorization,
}

impl Authorization {
    pub fn status(&self) -> &AuthorizationStatus {
        &self.authorization.status
    }

    pub fn expires(&self) -> Option<&str> {
        self.authorization.expires.as_deref()
    }

    pub fn wildcard(&self) -> bool {
        self.authorization.wildcard.unwrap_or(false)
    }

    pub fn challenges(&self) -> Vec<Challenge> {
        self.authorization
            .challenges
            .iter()
            .filter_map(|challenge| match challenge {
                api::Challenge::Http01(challenge) => Some(challenge),
                api::Challenge::Dns01(challenge) => Some(challenge),
                api::Challenge::TlsAlpn01(challenge) => Some(challenge),
                _ => None,
            })
            .cloned()
            .map(|challenge| Challenge {
                acme: self.acme.clone(),
                account: self.account.clone(),
                challenge,
            })
            .collect()
    }

    pub fn http01_challenge(&self) -> Option<Challenge> {
        self.authorization
            .challenges
            .iter()
            .find_map(|challenge| match challenge {
                api::Challenge::Http01(challenge) => Some(challenge),
                _ => None,
            })
            .cloned()
            .map(|challenge| Challenge {
                acme: self.acme.clone(),
                account: self.account.clone(),
                challenge,
            })
    }

    pub fn dns01_challenge(&self) -> Option<Challenge> {
        self.authorization
            .challenges
            .iter()
            .find_map(|challenge| match challenge {
                api::Challenge::Dns01(challenge) => Some(challenge),
                _ => None,
            })
            .cloned()
            .map(|challenge| Challenge {
                acme: self.acme.clone(),
                account: self.account.clone(),
                challenge,
            })
    }

    pub fn tls_alpn01_challenge(&self) -> Option<Challenge> {
        self.authorization
            .challenges
            .iter()
            .find_map(|challenge| match challenge {
                api::Challenge::TlsAlpn01(challenge) => Some(challenge),
                _ => None,
            })
            .cloned()
            .map(|challenge| Challenge {
                acme: self.acme.clone(),
                account: self.account.clone(),
                challenge,
            })
    }
}

#[derive(Debug, Clone)]
pub struct Challenge {
    pub(crate) acme: Arc<AcmeClientInner>,
    pub(crate) account: Arc<AccountInner>,
    pub(crate) challenge: api::TokenChallenge,
}

impl Challenge {
    pub fn url(&self) -> &str {
        &self.challenge.url
    }

    pub fn status(&self) -> &ChallengeStatus {
        &self.challenge.status
    }

    pub fn validated(&self) -> Option<&str> {
        self.challenge.validated.as_deref()
    }

    pub fn token(&self) -> &str {
        &self.challenge.token
    }

    pub fn key_authorization(&self) -> AcmeResult<String> {
        Ok(self.account.key.authorize_token(self.token())?)
    }

    pub async fn validate(self) -> AcmeResult<Self> {
        let res = self
            .acme
            .send_request(AcmeRequest {
                url: &self.challenge.url,
                kid: Some(&self.account.kid),
                private_key: &self.account.key,
                payload: Some(json!({})),
            })
            .await?;

        let challenge = serde_json::from_slice(&res.into_body())?;

        Ok(Challenge {
            acme: self.acme,
            account: self.account,
            challenge,
        })
    }
}

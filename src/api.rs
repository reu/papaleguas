use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryUrl(pub(crate) String);

impl<T: AsRef<str>> From<T> for DirectoryUrl {
    fn from(url: T) -> Self {
        DirectoryUrl(url.as_ref().to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub revoke_cert: String,
    pub key_change: String,
    pub meta: Option<DirectoryMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    pub caa_identities: Option<Vec<String>>,
    pub external_account_required: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct Account {
    pub status: String,
    pub orders: Option<String>,
    pub key: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Identifier {
    pub r#type: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    pub status: OrderStatus,
    #[serde(default, with = "time::serde::iso8601::option")]
    pub expires: Option<OffsetDateTime>,
    pub identifiers: Vec<Identifier>,
    #[serde(default, with = "time::serde::iso8601::option")]
    pub not_before: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::iso8601::option")]
    pub not_after: Option<OffsetDateTime>,
    pub error: Option<ServerError>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Authorization {
    pub identifier: Identifier,
    pub status: AuthorizationStatus,
    #[serde(default, with = "time::serde::iso8601::option")]
    pub expires: Option<OffsetDateTime>,
    pub challenges: Vec<Challenge>,
    pub wildcard: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type")]
pub enum Challenge {
    #[serde(rename = "http-01")]
    Http01(TokenChallenge),
    #[serde(rename = "dns-01")]
    Dns01(TokenChallenge),
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01(TokenChallenge),
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TokenChallenge {
    pub url: String,
    pub status: ChallengeStatus,
    pub validated: Option<String>,
    pub error: Option<ServerError>,
    pub token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, thiserror::Error)]
#[error("ServerError({}): {}", r#type, detail.clone().unwrap_or_default())]
pub struct ServerError {
    #[serde(default = "default_type")]
    pub r#type: String,
    pub title: Option<String>,
    pub status: Option<u16>,
    pub detail: Option<String>,
    pub subproblems: Option<Vec<ServerError>>,
}

fn default_type() -> String {
    "about:blank".into()
}

impl ServerError {
    pub fn http_status(&self) -> Option<http::StatusCode> {
        http::StatusCode::from_u16(self.status?).ok()
    }

    pub(crate) fn is_bad_nonce(&self) -> bool {
        self.r#type == "urn:ietf:params:acme:error:badNonce"
    }
}

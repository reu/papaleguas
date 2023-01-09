use crate::{api, jose};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("validation error: {0}")]
    Validation(&'static str),

    #[error(transparent)]
    Server(#[from] api::ServerError),

    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

pub type AcmeResult<T> = Result<T, Error>;

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self::Other(err.into())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::Other(err.into())
    }
}

impl From<jose::JoseError> for Error {
    fn from(err: jose::JoseError) -> Self {
        Self::Other(err.into())
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::Other(err.into())
    }
}

impl From<&'static str> for Error {
    fn from(err: &'static str) -> Self {
        Self::Validation(err)
    }
}

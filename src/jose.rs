use std::str::FromStr;

use p256::SecretKey as EcdsaPrivateKey;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand::{CryptoRng, Rng};
use rsa::{PublicKeyParts, RsaPrivateKey};
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};
use signature::Signer;

use crate::utils::base64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey(Key);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Key {
    Rsa(Box<RsaPrivateKey>),
    Ec(EcdsaPrivateKey),
}

#[derive(Debug, thiserror::Error)]
pub enum JoseError {
    #[error("pkcs8 encoding error")]
    Pkcs8Error(#[from] pkcs8::Error),

    #[error("signature error {0}")]
    SignatureError(String),

    #[error("encoding error {0}")]
    EncodingError(String),

    #[error("decoding error {0}")]
    DecodingError(String),
}

impl From<serde_json::Error> for JoseError {
    fn from(err: serde_json::Error) -> Self {
        JoseError::EncodingError(err.to_string())
    }
}

type JoseResult<T> = Result<T, JoseError>;

impl PrivateKey {
    pub fn random_rsa_key(mut rng: impl Rng + CryptoRng) -> Self {
        RsaPrivateKey::new(&mut rng, 2048).unwrap().into()
    }

    pub fn random_ec_key(rng: impl Rng + CryptoRng) -> Self {
        EcdsaPrivateKey::random(rng).into()
    }

    pub(crate) fn sign(&self, buf: &[u8]) -> JoseResult<String> {
        let signature = match &self.0 {
            Key::Rsa(key) => {
                let digest = Sha256::new().chain_update(buf).finalize();
                let padding = rsa::PaddingScheme::new_pkcs1v15_sign::<Sha256>();
                key.sign(padding, &digest)
                    .map_err(|err| JoseError::SignatureError(err.to_string()))?
            }
            Key::Ec(key) => {
                let signing_key = ecdsa::SigningKey::from(key);
                let signature = signing_key.sign(buf);
                signature.to_vec()
            }
        };
        Ok(base64(signature))
    }

    pub(crate) fn authorize_token(&self, token: &str) -> JoseResult<String> {
        Ok(format!("{token}.{}", base64(self.jwk_digest()?)))
    }

    pub(crate) fn alg(&self) -> String {
        match &self.0 {
            Key::Rsa(key) => format!("RS{}", key.size()),
            Key::Ec(_) => "ES256".into(),
        }
    }

    pub(crate) fn jwk(&self) -> JoseResult<Json> {
        match &self.0 {
            Key::Rsa(rsa) => Ok(json!({
                "e": base64(rsa.e().to_bytes_be()),
                "kty": "RSA",
                "n": base64(rsa.n().to_bytes_be()),
            })),

            Key::Ec(ec) => Ok(serde_json::to_value(ec.public_key().to_jwk())?),
        }
    }

    pub(crate) fn jwk_digest(&self) -> JoseResult<[u8; 32]> {
        let digest = Sha256::new()
            .chain_update(serde_json::to_vec(&self.jwk()?)?)
            .finalize();
        Ok(digest.into())
    }

    pub fn from_pem(pem: &str) -> JoseResult<Self> {
        if let Ok(key) = EcdsaPrivateKey::from_pkcs8_pem(pem) {
            return Ok(key.into());
        }

        if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(pem) {
            return Ok(key.into());
        }

        Err(JoseError::DecodingError("Invalid PEM encoded key".into()))
    }

    pub fn from_der(der: &[u8]) -> JoseResult<Self> {
        if let Ok(key) = EcdsaPrivateKey::from_pkcs8_der(der) {
            return Ok(key.into());
        }

        if let Ok(key) = RsaPrivateKey::from_pkcs8_der(der) {
            return Ok(key.into());
        }

        Err(JoseError::DecodingError("Invalid DER encoded key".into()))
    }

    pub fn to_pem(&self) -> JoseResult<String> {
        let pem = match &self.0 {
            Key::Rsa(key) => key.to_pkcs8_pem(LineEnding::default())?,
            Key::Ec(key) => key.to_pkcs8_pem(LineEnding::default())?,
        };
        Ok(pem.to_string())
    }

    pub fn to_der(&self) -> JoseResult<Vec<u8>> {
        let der = match &self.0 {
            Key::Rsa(key) => key.to_pkcs8_der()?,
            Key::Ec(key) => key.to_pkcs8_der()?,
        };
        Ok(der.as_bytes().into())
    }

    pub(crate) fn csr(
        &self,
        domains: impl Into<Vec<String>>,
    ) -> Result<Vec<u8>, rcgen::RcgenError> {
        rcgen::Certificate::from_params({
            let mut params = rcgen::CertificateParams::new(domains);
            params.distinguished_name = rcgen::DistinguishedName::new();
            params.key_pair = match &self.0 {
                Key::Rsa(key) => Some(rcgen::KeyPair::from_der_and_sign_algo(
                    key.to_pkcs8_der().unwrap().as_bytes(),
                    &rcgen::PKCS_RSA_SHA256,
                )?),
                Key::Ec(key) => Some(rcgen::KeyPair::from_der_and_sign_algo(
                    key.to_pkcs8_der().unwrap().as_bytes(),
                    &rcgen::PKCS_ECDSA_P256_SHA256,
                )?),
            };
            params.alg = match self.0 {
                Key::Rsa(_) => &rcgen::PKCS_RSA_SHA256,
                Key::Ec(_) => &rcgen::PKCS_ECDSA_P256_SHA256,
            };
            params
        })
        .and_then(|cert| cert.serialize_request_der())
    }
}

impl From<RsaPrivateKey> for PrivateKey {
    fn from(key: RsaPrivateKey) -> Self {
        Self(Key::Rsa(Box::new(key)))
    }
}

impl From<EcdsaPrivateKey> for PrivateKey {
    fn from(key: EcdsaPrivateKey) -> Self {
        Self(Key::Ec(key))
    }
}

impl FromStr for PrivateKey {
    type Err = JoseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_pem(s)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rsa_pem_encoding() {
        let rng = rand::thread_rng();
        let key = PrivateKey::random_rsa_key(rng);
        let serialized = key.to_pem().unwrap();
        let deserialized = PrivateKey::from_pem(&serialized).unwrap();
        assert_eq!(key, deserialized);
    }

    #[test]
    fn test_ec_pem_encoding() {
        let rng = rand::thread_rng();
        let key = PrivateKey::random_ec_key(rng);
        let serialized = key.to_pem().unwrap();
        let deserialized = PrivateKey::from_pem(&serialized).unwrap();
        assert_eq!(key, deserialized);
    }

    #[test]
    fn test_rsa_der_encoding() {
        let rng = rand::thread_rng();
        let key = PrivateKey::random_rsa_key(rng);
        let serialized = key.to_der().unwrap();
        let deserialized = PrivateKey::from_der(&serialized).unwrap();
        assert_eq!(key, deserialized);
    }

    #[test]
    fn test_ec_der_encoding() {
        let rng = rand::thread_rng();
        let key = PrivateKey::random_ec_key(rng);
        let serialized = key.to_der().unwrap();
        let deserialized = PrivateKey::from_der(&serialized).unwrap();
        assert_eq!(key, deserialized);
    }
}

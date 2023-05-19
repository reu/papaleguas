use std::str::FromStr;

use p256::SecretKey as Ec256;
#[cfg(feature = "p384")]
use p384::SecretKey as Ec384;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand::{CryptoRng, Rng};
#[cfg(feature = "rsa")]
use rsa::{PublicKeyParts, RsaPrivateKey};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use signature::Signer;

use crate::utils::base64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey(Key);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Key {
    #[cfg(feature = "rsa")]
    Rsa(Box<RsaPrivateKey>),
    Ec256(Ec256),
    #[cfg(feature = "p384")]
    Ec384(Ec384),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("pkcs8 encoding error {0}")]
    Pkcs8Error(#[from] pkcs8::Error),

    #[error("signature error {0}")]
    SignatureError(String),

    #[error("encoding error {0}")]
    EncodingError(String),

    #[error("decoding error {0}")]
    DecodingError(String),
}

impl From<serde_json::Error> for KeyError {
    fn from(err: serde_json::Error) -> Self {
        KeyError::EncodingError(err.to_string())
    }
}

type Result<T> = std::result::Result<T, KeyError>;

impl PrivateKey {
    #[cfg(feature = "rsa")]
    pub fn random_rsa_key(mut rng: impl Rng + CryptoRng) -> Self {
        RsaPrivateKey::new(&mut rng, 2048).unwrap().into()
    }

    pub fn random_ec_key(rng: impl Rng + CryptoRng) -> Self {
        Ec256::random(rng).into()
    }

    pub(crate) fn sign(&self, buf: &[u8]) -> Result<String> {
        let signature = match &self.0 {
            #[cfg(feature = "rsa")]
            Key::Rsa(key) => {
                let digest = Sha256::new().chain_update(buf).finalize();
                let padding = rsa::PaddingScheme::new_pkcs1v15_sign::<Sha256>();
                key.sign(padding, &digest)
                    .map_err(|err| KeyError::SignatureError(err.to_string()))?
            }
            Key::Ec256(key) => {
                let signing_key = ecdsa::SigningKey::from(key);
                let signature = signing_key.sign(buf);
                signature.to_vec()
            }
            #[cfg(feature = "p384")]
            Key::Ec384(key) => {
                let signing_key = ecdsa::SigningKey::from(key);
                let signature = signing_key.sign(buf);
                signature.to_vec()
            }
        };
        Ok(base64(signature))
    }

    pub(crate) fn authorize_token(&self, token: &str) -> Result<String> {
        Ok(format!("{token}.{}", base64(self.jwk_digest()?)))
    }

    pub(crate) fn alg(&self) -> String {
        match &self.0 {
            #[cfg(feature = "rsa")]
            Key::Rsa(key) => format!("RS{}", key.size()),
            Key::Ec256(_) => "ES256".into(),
            #[cfg(feature = "p384")]
            Key::Ec384(_) => "ES384".into(),
        }
    }

    pub(crate) fn jwk(&self) -> Result<Json> {
        match &self.0 {
            #[cfg(feature = "rsa")]
            Key::Rsa(rsa) => Ok(serde_json::json!({
                "e": base64(rsa.e().to_bytes_be()),
                "kty": "RSA",
                "n": base64(rsa.n().to_bytes_be()),
            })),

            Key::Ec256(ec) => Ok(serde_json::to_value(ec.public_key().to_jwk())?),

            #[cfg(feature = "p384")]
            Key::Ec384(ec) => Ok(serde_json::to_value(ec.public_key().to_jwk())?),
        }
    }

    pub(crate) fn jwk_digest(&self) -> Result<[u8; 32]> {
        let digest = Sha256::new()
            .chain_update(serde_json::to_vec(&self.jwk()?)?)
            .finalize();
        Ok(digest.into())
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        if let Ok(key) = Ec256::from_pkcs8_pem(pem) {
            return Ok(key.into());
        }

        #[cfg(feature = "rsa")]
        if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(pem) {
            return Ok(key.into());
        }

        Err(KeyError::DecodingError("Invalid PEM encoded key".into()))
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        if let Ok(key) = Ec256::from_pkcs8_der(der) {
            return Ok(key.into());
        }

        #[cfg(feature = "p384")]
        if let Ok(key) = Ec384::from_pkcs8_der(der) {
            return Ok(key.into());
        }

        #[cfg(feature = "rsa")]
        if let Ok(key) = RsaPrivateKey::from_pkcs8_der(der) {
            return Ok(key.into());
        }

        Err(KeyError::DecodingError("Invalid DER encoded key".into()))
    }

    pub fn to_pem(&self) -> Result<String> {
        let pem = match &self.0 {
            #[cfg(feature = "rsa")]
            Key::Rsa(key) => key.to_pkcs8_pem(LineEnding::default())?,
            Key::Ec256(key) => key.to_pkcs8_pem(LineEnding::default())?,
            #[cfg(feature = "p384")]
            Key::Ec384(key) => key.to_pkcs8_pem(LineEnding::default())?,
        };
        Ok(pem.to_string())
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        let der = match &self.0 {
            #[cfg(feature = "rsa")]
            Key::Rsa(key) => key.to_pkcs8_der()?,
            Key::Ec256(key) => key.to_pkcs8_der()?,
            #[cfg(feature = "p384")]
            Key::Ec384(key) => key.to_pkcs8_der()?,
        };
        Ok(der.as_bytes().into())
    }

    pub(crate) fn csr(
        &self,
        domains: impl Into<Vec<String>>,
    ) -> std::result::Result<Vec<u8>, rcgen::RcgenError> {
        rcgen::Certificate::from_params({
            let mut params = rcgen::CertificateParams::new(domains);
            params.distinguished_name = rcgen::DistinguishedName::new();
            params.key_pair = match &self.0 {
                #[cfg(feature = "rsa")]
                Key::Rsa(key) => Some(rcgen::KeyPair::from_der_and_sign_algo(
                    key.to_pkcs8_der().unwrap().as_bytes(),
                    &rcgen::PKCS_RSA_SHA256,
                )?),
                Key::Ec256(key) => Some(rcgen::KeyPair::from_der_and_sign_algo(
                    key.to_pkcs8_der().unwrap().as_bytes(),
                    &rcgen::PKCS_ECDSA_P256_SHA256,
                )?),
                #[cfg(feature = "p384")]
                Key::Ec384(key) => Some(rcgen::KeyPair::from_der_and_sign_algo(
                    &key.to_sec1_der().unwrap(),
                    &rcgen::PKCS_ECDSA_P384_SHA384,
                )?),
            };
            params.alg = match self.0 {
                #[cfg(feature = "rsa")]
                Key::Rsa(_) => &rcgen::PKCS_RSA_SHA256,
                Key::Ec256(_) => &rcgen::PKCS_ECDSA_P256_SHA256,
                #[cfg(feature = "p384")]
                Key::Ec384(_) => &rcgen::PKCS_ECDSA_P384_SHA384,
            };
            params
        })
        .and_then(|cert| cert.serialize_request_der())
    }
}

#[cfg(feature = "rsa")]
impl From<RsaPrivateKey> for PrivateKey {
    fn from(key: RsaPrivateKey) -> Self {
        Self(Key::Rsa(Box::new(key)))
    }
}

impl From<Ec256> for PrivateKey {
    fn from(key: Ec256) -> Self {
        Self(Key::Ec256(key))
    }
}

#[cfg(feature = "p384")]
impl From<Ec384> for PrivateKey {
    fn from(key: Ec384) -> Self {
        Self(Key::Ec384(key))
    }
}

impl TryFrom<&Vec<u8>> for PrivateKey {
    type Error = KeyError;

    fn try_from(value: &Vec<u8>) -> std::result::Result<Self, Self::Error> {
        Self::from_der(&value[..])
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = KeyError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_der(value)
    }
}

impl TryFrom<&str> for PrivateKey {
    type Error = KeyError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::from_pem(value)
    }
}

impl TryFrom<String> for PrivateKey {
    type Error = KeyError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::from_pem(&value)
    }
}

impl FromStr for PrivateKey {
    type Err = KeyError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_pem(s)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(feature = "rsa")]
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

    #[cfg(feature = "rsa")]
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

    #[test]
    fn test_try_from_string() {
        let rng = rand::thread_rng();
        let key = PrivateKey::random_ec_key(rng);
        let serialized = key.to_pem().unwrap();

        let deserialized = PrivateKey::try_from(serialized.as_str()).unwrap();
        assert_eq!(key, deserialized);

        let deserialized = PrivateKey::try_from(serialized).unwrap();
        assert_eq!(key, deserialized);
    }

    #[test]
    fn test_try_from_byte_slice() {
        let rng = rand::thread_rng();
        let key = PrivateKey::random_ec_key(rng);
        let serialized = key.to_der().unwrap();
        let deserialized = PrivateKey::try_from(&serialized).unwrap();
        assert_eq!(key, deserialized);
    }

    #[test]
    fn test_ec256_from_pkcs8_der() {
        let mut rng = rand::thread_rng();
        let key = Ec256::random(&mut rng);
        let der = key.to_pkcs8_der().unwrap();
        let pkey = PrivateKey::from_der(der.as_bytes()).unwrap();
        assert_eq!(der.as_bytes(), pkey.to_der().unwrap());
    }

    #[cfg(feature = "p384")]
    #[test]
    fn test_ec384_from_pkcs8_der() {
        let mut rng = rand::thread_rng();
        let key = Ec384::random(&mut rng);
        let der = key.to_pkcs8_der().unwrap();
        let pkey = PrivateKey::from_der(der.as_bytes()).unwrap();
        assert_eq!(der.as_bytes(), pkey.to_der().unwrap());
    }
}

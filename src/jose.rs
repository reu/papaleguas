use p256::SecretKey as EcdsaPrivateKey;
use pkcs8::{EncodePrivateKey, LineEnding};
use rand::{CryptoRng, Rng};
use rsa::{pss::BlindedSigningKey, PublicKeyParts, RsaPrivateKey};
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};
use signature::{RandomizedSigner, Signer};

use crate::utils;

#[derive(Debug, Clone)]
pub enum Key {
    Rsa(RsaPrivateKey),
    Ec(EcdsaPrivateKey),
}

#[derive(Debug, thiserror::Error)]
pub enum PKeyError {
    #[error("unsupported key type: only RSA and EC keys are supported")]
    UnsupportedKey,
}

#[derive(Debug, thiserror::Error)]
pub enum JoseError {
    #[error(transparent)]
    OpenSsl(#[from] Box<dyn std::error::Error + Send + Sync>),
}

type JoseResult<T> = Result<T, JoseError>;

impl Key {
    pub fn random_rsa_key(mut rng: impl Rng + CryptoRng) -> Self {
       Key::Rsa(RsaPrivateKey::new(&mut rng, 2048).unwrap())
    }

    pub fn random_ec_key(rng: impl Rng + CryptoRng) -> Self {
       Key::Ec(EcdsaPrivateKey::random(rng))
    }

    pub fn sign(&self, buf: &[u8]) -> JoseResult<String> {
        let signature = match self {
            Key::Rsa(key) => {
                let signing_key = BlindedSigningKey::<Sha256>::new(key.clone());
                let signature = signing_key.sign_with_rng(rand::thread_rng(), buf);
                signature.to_vec()
            }
            Key::Ec(key) => {
                let signing_key = ecdsa::SigningKey::from(key);
                let signature = signing_key.sign(buf);
                signature.to_vec()
            }
        };
        Ok(utils::base64(signature))
    }

    pub fn authorize_token(&self, token: &str) -> JoseResult<String> {
        let fingerprint = utils::base64(self.jwk_digest()?);
        Ok(format!("{token}.{fingerprint}"))
    }

    pub(crate) fn alg(&self) -> String {
        match self {
            Key::Rsa(_key) => format!("RS{}", 256),
            Key::Ec(_) => "EC256".into(),
        }
    }

    pub fn jwk(&self) -> JoseResult<Json> {
        match self {
            Key::Rsa(rsa) => Ok(json!({
                "e": utils::base64(rsa.e().to_bytes_be()),
                "kty": "RSA",
                "n": utils::base64(rsa.n().to_bytes_be()),
            })),

            Key::Ec(ec) => Ok(serde_json::to_value(ec.to_jwk()).unwrap()),
        }
    }

    pub fn jwk_digest(&self) -> JoseResult<[u8; 32]> {
        let digest = Sha256::new()
            .chain_update(serde_json::to_vec(&self.jwk()?).unwrap())
            .finalize();
        Ok(digest.into())
    }

    pub fn to_pem(&self) -> JoseResult<Vec<u8>> {
        let pem = match self {
            Key::Rsa(key) => key.to_pkcs8_pem(LineEnding::default()).unwrap(),
            Key::Ec(key) => key.to_pkcs8_pem(LineEnding::default()).unwrap(),
        };
        Ok(pem.as_bytes().into())
    }
}

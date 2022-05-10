use openssl::{
    bn::{BigNum, BigNumContext},
    ec::EcKey,
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    sha::Sha256,
    sign::Signer,
};
use serde_json::{json, Value as Json};

use crate::utils;

#[derive(Debug, Clone)]
pub enum Key {
    Rsa(Rsa<Private>),
    Ec(EcKey<Private>),
}

impl TryFrom<PKey<Private>> for Key {
    type Error = PKeyError;

    fn try_from(key: PKey<Private>) -> Result<Self, Self::Error> {
        if let Ok(rsa) = key.rsa() {
            Ok(Key::Rsa(rsa))
        } else if let Ok(ec) = key.ec_key() {
            Ok(Key::Ec(ec))
        } else {
            Err(PKeyError::UnsupportedKey)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PKeyError {
    #[error("unsupported key type: only RSA and EC keys are supported")]
    UnsupportedKey,
}

#[derive(Debug, thiserror::Error)]
pub enum JoseError {
    #[error(transparent)]
    OpenSsl(#[from] ErrorStack),
}

type JoseResult<T> = Result<T, JoseError>;

impl Key {
    pub fn sign(&self, buf: &[u8]) -> JoseResult<String> {
        let key = self.pkey()?;
        let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
        signer.update(buf)?;
        Ok(utils::base64(signer.sign_to_vec()?))
    }

    pub(crate) fn alg(&self) -> String {
        match self {
            Key::Rsa(rsa) => format!("RS{}", rsa.size()),
            Key::Ec(ec) => format!("EC{}", ec.private_key().num_bits()),
        }
    }

    pub fn jwk(&self) -> JoseResult<Json> {
        match self {
            Key::Rsa(rsa) => Ok(json!({
                "e": utils::base64(rsa.e().to_vec()),
                "kty": "RSA",
                "n": utils::base64(rsa.n().to_vec()),
            })),

            Key::Ec(ec) => {
                let mut ctx = BigNumContext::new()?;
                let mut x = BigNum::new()?;
                let mut y = BigNum::new()?;

                let pub_key = ec.public_key();
                pub_key.affine_coordinates(ec.group(), &mut x, &mut y, &mut ctx)?;

                let bits = ec.private_key().num_bits();

                Ok(json!({
                    "crv": format!("P-{bits}"),
                    "kty": "EC",
                    "x": utils::base64(x.to_vec()),
                    "y": utils::base64(y.to_vec()),
                }))
            }
        }
    }

    pub fn jwk_digest(&self) -> JoseResult<[u8; 32]> {
        let mut digest = Sha256::new();
        digest.update(&serde_json::to_vec(&self.jwk()?).unwrap());
        Ok(digest.finish())
    }

    pub fn to_pem(&self) -> JoseResult<Vec<u8>> {
        let pem = self.pkey()?.private_key_to_pem_pkcs8()?;
        Ok(pem)
    }

    fn pkey(&self) -> Result<PKey<Private>, ErrorStack> {
        match self {
            Key::Rsa(rsa) => PKey::from_rsa(rsa.clone()),
            Key::Ec(ec) => PKey::from_ec_key(ec.clone()),
        }
    }
}

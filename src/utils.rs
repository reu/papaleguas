use base64ct::{Base64UrlUnpadded as Base64, Encoding};

macro_rules! add_field {
    ($n:ident, $t:ty) => {
        pub fn $n<T: Into<$t>>(self, val: T) -> Self {
            Self {
                $n: val.into(),
                ..self
            }
        }
    };
}

macro_rules! add_optional_field {
    ($n:ident, $t:ty) => {
        pub fn $n<T: Into<$t>>(self, val: T) -> Self {
            Self {
                $n: Some(val.into()),
                ..self
            }
        }
    };
}

pub(crate) use add_field;
pub(crate) use add_optional_field;

pub(crate) fn base64<T: AsRef<[u8]>>(data: T) -> String {
    Base64::encode_string(data.as_ref())
}

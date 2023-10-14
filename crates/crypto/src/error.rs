use hmac::digest::InvalidLength;

#[derive(Debug, PartialEq)]
pub struct CryptError(String);

impl CryptError {
    pub fn invalid_hdpath() -> CryptError {
        CryptError("Invalid hdpath".to_owned())
    }

    pub fn depth_exceeded() -> CryptError {
        CryptError("Exceeded depth".to_owned())
    }

    pub fn wrong_length_bytes() -> CryptError {
        CryptError("Wrong length bytes".to_owned())
    }

    pub fn cannot_hardened() -> CryptError {
        CryptError("Public key can not derive hardened key".to_owned())
    }

    pub fn invalid_format(target: &str) -> CryptError {
        CryptError(format!("Invalid bytes format for {target}"))
    }

    pub fn type_missmatched() -> CryptError {
        CryptError("Type miss-matched".to_owned())
    }

    pub fn unsupported_version() -> CryptError {
        CryptError("unsupported version".to_owned())
    }
}

impl From<InvalidLength> for CryptError {
    fn from(src: InvalidLength) -> Self {
        Self(src.to_string())
    }
}
impl From<elliptic_curve::Error> for CryptError {
    fn from(src: elliptic_curve::Error) -> Self {
        Self(src.to_string())
    }
}

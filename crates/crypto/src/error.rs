use hmac::digest::InvalidLength;
use std::fmt::Display;

#[derive(Clone, Debug, PartialEq)]
pub struct CryptoError(String);

impl CryptoError {
    pub fn invalid_hdpath() -> CryptoError {
        CryptoError("Invalid hdpath".to_owned())
    }

    pub fn depth_exceeded() -> CryptoError {
        CryptoError("Exceeded depth".to_owned())
    }

    pub fn wrong_length_bytes() -> CryptoError {
        CryptoError("Wrong length bytes".to_owned())
    }

    pub fn cannot_hardened() -> CryptoError {
        CryptoError("Public key can not derive hardened key".to_owned())
    }

    pub fn invalid_format(target: &str) -> CryptoError {
        CryptoError(format!("Invalid bytes format for {target}"))
    }

    pub fn type_missmatched() -> CryptoError {
        CryptoError("Type miss-matched".to_owned())
    }

    pub fn unsupported_version() -> CryptoError {
        CryptoError("unsupported version".to_owned())
    }

    pub fn too_many_commitment_parts(got: usize) -> CryptoError {
        CryptoError(format!("Too many commitment parts: {}", got))
    }

    pub fn commitment_part_too_large(got: usize) -> CryptoError {
        CryptoError(format!("Commitment part too large: {}", got))
    }

    pub fn secrets_too_few(got: usize) -> CryptoError {
        CryptoError(format!("Secrets too few: {}", got))
    }

    pub fn secrets_too_large(got: usize) -> CryptoError {
        CryptoError(format!("Secrets too large: {}", got))
    }

    pub fn secrets_invalid_part_length<A: Display>(got: A) -> CryptoError {
        CryptoError(format!("Secrets invalid part length: {}", got))
    }
}

impl From<InvalidLength> for CryptoError {
    fn from(src: InvalidLength) -> Self {
        Self(src.to_string())
    }
}
impl From<elliptic_curve::Error> for CryptoError {
    fn from(src: elliptic_curve::Error) -> Self {
        Self(src.to_string())
    }
}

use crate::CryptoError;
use bytes::Bytes;
use num_bigint::BigUint;

pub fn from_biguint(x: &BigUint) -> Bytes {
    x.to_bytes_be().into()
}

pub fn to_biguint(bs: &Bytes) -> crate::Result<BigUint> {
    if bs.is_empty() {
        Err(CryptoError::message_malformed())
    } else {
        Ok(BigUint::from_bytes_be(bs))
    }
}

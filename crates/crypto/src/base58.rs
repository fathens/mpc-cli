use crate::extend_key::ecdsa_key::KEY_SIZE;
use crate::fixed_bytes::{fixed_bytes, FixedBytes};
use crate::CryptError;
use crate::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use core::fmt;
use core::str::FromStr;
use once_cell::sync::Lazy;
use std::collections::HashMap;

pub const ENCODED_BYTE_SIZE: usize = 78;
pub const MAX_BASE58_SIZE: usize = 112;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Prefix([u8; 4]);
fixed_bytes!(Prefix);

static PREFIX_PAIRS: Lazy<HashMap<Prefix, Prefix>> = Lazy::new(|| {
    vec![(Prefix::XPRV, Prefix::XPUB), (Prefix::TPRV, Prefix::TPUB)]
        .into_iter()
        .collect()
});

impl Prefix {
    pub const XPRV: Prefix = Prefix([0x04, 0x88, 0xad, 0xe4]);
    pub const XPUB: Prefix = Prefix([0x04, 0x88, 0xB2, 0x1E]);
    pub const TPRV: Prefix = Prefix([0x04, 0x35, 0x83, 0x94]);
    pub const TPUB: Prefix = Prefix([0x04, 0x35, 0x87, 0xCF]);

    pub fn is_public(&self) -> bool {
        !self.is_private()
    }

    pub fn is_private(&self) -> bool {
        PREFIX_PAIRS.contains_key(self)
    }

    pub fn get_public(&self) -> Result<Self> {
        PREFIX_PAIRS
            .get(self)
            .map(|v| v.clone())
            .ok_or(CryptError::unsupported_version())
    }

    pub fn validate(&self) -> Result<()> {
        if PREFIX_PAIRS.contains_key(self) {
            return Ok(());
        }
        PREFIX_PAIRS
            .values()
            .find(|a| a == &self)
            .map(|_| ())
            .ok_or(CryptError::unsupported_version())
    }
}

pub struct DecodedExtKey {
    pub prefix: Prefix,
    pub depth: Bytes,
    pub parent: Bytes,
    pub child_number: Bytes,
    pub chain_code: Bytes,
    pub key: Bytes,
}

pub fn encode(src: &DecodedExtKey) -> String {
    let mut buf = BytesMut::with_capacity(ENCODED_BYTE_SIZE);
    buf.put(src.prefix.as_ref());
    buf.put(src.depth.as_ref());
    buf.put(src.parent.as_ref());
    buf.put(src.child_number.as_ref());
    buf.put(src.chain_code.as_ref());

    let bs = src.key.as_ref();
    if KEY_SIZE == bs.len() {
        buf.put_u8(0);
    }
    buf.put(bs);

    bs58::encode(&buf).with_check().into_string()
}

pub fn decode(src: &str) -> Result<DecodedExtKey> {
    let mut buf: Bytes = bs58::decode(src)
        .with_check(None)
        .into_vec()
        .map_err(|err| CryptError::invalid_format(&err.to_string()))?
        .into();
    if buf.len() != ENCODED_BYTE_SIZE {
        return Err(CryptError::wrong_length_bytes());
    }

    let prefix: Prefix = buf.split_to(4).try_into()?;
    prefix.validate()?;

    let depth = buf.split_to(1);
    let parent = buf.split_to(4);
    let child_number = buf.split_to(4);
    let chain_code = buf.split_to(KEY_SIZE);

    if prefix.is_private() {
        // Drop first byte
        let zero = buf.split_to(1).get_u8();
        if zero != 0 {
            return Err(CryptError::invalid_format("extend key"));
        }
    }
    let key = buf.into();

    let result = DecodedExtKey {
        prefix,
        depth,
        parent,
        child_number,
        chain_code,
        key,
    };

    Ok(result)
}

impl fmt::Display for DecodedExtKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = encode(self);
        f.write_str(s.as_str())
    }
}

impl FromStr for DecodedExtKey {
    type Err = CryptError;

    fn from_str(src: &str) -> std::result::Result<Self, Self::Err> {
        decode(src)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    fn to_bytes<const N: usize>(bs: [u8; N]) -> Bytes {
        Bytes::copy_from_slice(&bs)
    }

    #[test]
    fn bip32_test_vector_1_xprv() {
        let xprv_base58 = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPP\
             qjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

        let xprv: DecodedExtKey = xprv_base58.parse().unwrap();
        assert_eq!(xprv.prefix, Prefix::XPRV);
        assert_eq!(xprv.depth, to_bytes([0u8; 1]));
        assert_eq!(xprv.parent, to_bytes([0; 4]));
        assert_eq!(xprv.child_number, to_bytes([0; 4]));
        assert_eq!(
            xprv.chain_code,
            to_bytes(hex!(
                "873DFF81C02F525623FD1FE5167EAC3A55A049DE3D314BB42EE227FFED37D508"
            ))
        );
        assert_eq!(
            xprv.key,
            to_bytes(hex!(
                "E8F32E723DECF4051AEFAC8E2C93C9C5B214313817CDB01A1494B917C8436B35"
            ))
        );
        assert_eq!(&xprv.to_string(), xprv_base58);
    }

    #[test]
    fn bip32_test_vector_1_xpub() {
        let xpub_base58 = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhe\
             PY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

        let xpub: DecodedExtKey = xpub_base58.parse().unwrap();
        assert_eq!(xpub.prefix, Prefix::XPUB);
        assert_eq!(xpub.depth, to_bytes([0; 1]));
        assert_eq!(xpub.parent, to_bytes([0; 4]));
        assert_eq!(xpub.child_number, to_bytes([0; 4]));
        assert_eq!(
            xpub.chain_code,
            to_bytes(hex!(
                "873DFF81C02F525623FD1FE5167EAC3A55A049DE3D314BB42EE227FFED37D508"
            ))
        );
        assert_eq!(
            xpub.key,
            to_bytes(hex!(
                "0339A36013301597DAEF41FBE593A02CC513D0B55527EC2DF1050E2E8FF49C85C2"
            ))
        );
        assert_eq!(&xpub.to_string(), xpub_base58);
    }
}

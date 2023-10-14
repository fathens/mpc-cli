use crate::base58;
use crate::extend_key::ecdsa_key::{
    Fingerprint, KeyBytes, PrvKey, PrvKeyBytes, PubKey, PubKeyBytes, KEY_SIZE,
};
use crate::fixed_bytes::{fixed_bytes, FixedBytes};
use crate::hdpath::node::Node;
use crate::hdpath::path::HDPath;
use crate::CryptoError;
use crate::Result;
use bytes::Bytes;
use core::fmt;
use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainCode([u8; KEY_SIZE]);
fixed_bytes!(ChainCode);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Depth([u8; 1]);
fixed_bytes!(Depth);

impl Depth {
    fn increment(&self) -> Result<Self> {
        let next = self.0[0]
            .checked_add(1)
            .ok_or(CryptoError::depth_exceeded())?;
        Ok(Self([next]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChildNumber([u8; 4]);
fixed_bytes!(ChildNumber);

impl From<u32> for ChildNumber {
    fn from(v: u32) -> Self {
        Self(v.to_be_bytes())
    }
}

//----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtKey<A> {
    pub prefix: base58::Prefix,
    pub parent: Fingerprint,
    pub chain_code: ChainCode,
    pub key: A,
    pub depth: Depth,
    pub child_number: ChildNumber,
}

impl ExtKey<PrvKeyBytes> {
    pub fn from_seed(prefix: base58::Prefix, seed: Bytes) -> Result<Self> {
        if prefix.is_public() {
            return Err(CryptoError::type_missmatched());
        }
        let mut hash = HmacSha512::new_from_slice("Bitcoin seed".as_bytes())?;
        hash.update(&seed);
        let hashed = &hash.finalize().into_bytes();
        let (child_key, chain_code) = hashed.split_at(hashed.len() / 2);
        let result = ExtKey {
            prefix,
            parent: [0, 0, 0, 0].as_ref().try_into()?,
            chain_code: chain_code.try_into()?,
            key: child_key.try_into()?,
            depth: [0].as_ref().try_into()?,
            child_number: 0.into(),
        };
        Ok(result)
    }

    pub fn get_key(&self) -> &PrvKeyBytes {
        &self.key
    }
}

impl ExtKey<PubKeyBytes> {
    pub fn get_key(&self) -> &PubKeyBytes {
        &self.key
    }
}

impl<A: KeyBytes> ExtKey<A> {
    fn mk_child<K: AsRef<[u8]>>(
        &self,
        prefix: base58::Prefix,
        parent: Fingerprint,
        child_number: ChildNumber,
        key: &K,
    ) -> Result<Self> {
        let key_bytes = key.as_ref();
        let padding = vec![0; (KEY_SIZE + 1) - key_bytes.len()];

        let mut hash = HmacSha512::new_from_slice(self.chain_code.as_ref())?;
        hash.update(&padding);
        hash.update(key_bytes);
        hash.update(child_number.as_ref());
        let hashed = &hash.finalize().into_bytes();

        let (child_key, chain_code) = hashed.split_at(hashed.len() / 2);
        let next = ExtKey {
            prefix,
            parent,
            chain_code: chain_code.try_into()?,
            key: self.key.new_child(child_key)?,
            depth: self.depth.increment()?,
            child_number,
        };
        Ok(next)
    }
}

impl<A: PubKey> ExtKey<A> {
    pub fn get_child_normal_only(&self, node: Node) -> Result<Self> {
        if node.is_hardened() {
            return Err(CryptoError::cannot_hardened());
        }
        self.mk_child(
            self.prefix.clone(),
            self.key.fingerprint(),
            node.raw_index().into(),
            &self.key,
        )
    }
}

impl<A, B> ExtKey<A>
where
    A: PrvKey<Public = B>,
    B: PubKey,
{
    pub fn get_child(&self, node: Node) -> Result<Self> {
        let fp = self.key.get_public()?.fingerprint();
        if node.is_hardened() {
            self.mk_child(self.prefix.clone(), fp, node.raw_index().into(), &self.key)
        } else {
            self.mk_child(
                self.prefix.clone(),
                fp,
                node.raw_index().into(),
                &self.key.get_public()?,
            )
        }
    }

    pub fn derive_child(&self, path: HDPath) -> Result<Self> {
        if let [head, tail @ ..] = path.nodes() {
            tail.iter().fold(self.get_child(*head), |prev, node| {
                prev.and_then(|parent| parent.get_child(*node))
            })
        } else {
            Err(CryptoError::invalid_hdpath())
        }
    }

    pub fn get_public(&self) -> Result<ExtKey<B>> {
        let r = ExtKey {
            prefix: self.prefix.get_public()?,
            parent: self.parent.clone(),
            chain_code: self.chain_code.clone(),
            key: self.key.get_public()?,
            depth: self.depth.clone(),
            child_number: self.child_number.clone(),
        };
        Ok(r)
    }
}

//----------------------------------------------------------------

impl<A: KeyBytes> From<&ExtKey<A>> for base58::DecodedExtKey {
    fn from(src: &ExtKey<A>) -> Self {
        base58::DecodedExtKey {
            prefix: src.prefix.clone(),
            depth: src.depth.copy_bytes(),
            parent: src.parent.copy_bytes(),
            child_number: src.child_number.copy_bytes(),
            chain_code: src.chain_code.copy_bytes(),
            key: src.key.copy_bytes(),
        }
    }
}

impl<A> TryFrom<base58::DecodedExtKey> for ExtKey<A>
where
    A: KeyBytes,
    A: TryFrom<Bytes, Error = CryptoError>,
{
    type Error = CryptoError;

    fn try_from(src: base58::DecodedExtKey) -> std::result::Result<Self, Self::Error> {
        let r = Self {
            prefix: src.prefix.clone(),
            depth: src.depth.try_into()?,
            parent: src.parent.try_into()?,
            child_number: src.child_number.try_into()?,
            chain_code: src.chain_code.try_into()?,
            key: src.key.try_into()?,
        };
        Ok(r)
    }
}

impl<A: KeyBytes> fmt::Display for ExtKey<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d: base58::DecodedExtKey = self.into();
        d.fmt(f)
    }
}

//----------------------------------------------------------------

#[cfg(test)]
mod test {
    use hex_literal::hex;

    use super::*;

    type ExtPrvKey = ExtKey<PrvKeyBytes>;

    fn check(seed: Bytes, expected: &str) {
        let actual = ExtPrvKey::from_seed(base58::Prefix::XPRV, seed).unwrap();
        assert_eq!(expected, actual.to_string().as_str());
    }

    #[test]
    fn seed_vector1() {
        check(
            hex!("000102030405060708090a0b0c0d0e0f").as_ref().into(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        );
    }

    #[test]
    fn seed_vector2() {
        check(
            hex!("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").as_ref().into(),
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
        );
    }

    #[test]
    fn seed_vector3() {
        check(
            hex!("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be").as_ref().into(),
            "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
        );
    }

    #[test]
    fn seed_vector4() {
        check(
            hex!("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678").as_ref().into(),
            "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"
        );
    }
}

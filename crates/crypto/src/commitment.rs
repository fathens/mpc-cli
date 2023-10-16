use crate::hash::{hash_sha512_256i, Hash256};
use crate::{CryptoError, Result};
use bytes::Bytes;
use common::slice::multibytes_to_bigints;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{ToPrimitive, Zero};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Secrets(Vec<BigUint>);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HashCommitment(Hash256);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HashDeCommitment {
    salt: BigUint,
    secrets: Secrets,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HashCommitDecommit {
    pub commitment: HashCommitment,
    pub decommitment: HashDeCommitment,
}

impl HashDeCommitment {
    pub fn commit(&self) -> HashCommitment {
        let mut parts = self.secrets.to_vec();
        parts.insert(0, self.salt.clone());
        let hash = hash_sha512_256i(&parts);
        HashCommitment(hash)
    }
}

impl From<&[Bytes]> for HashDeCommitment {
    fn from(marshalled: &[Bytes]) -> Self {
        let parts = multibytes_to_bigints(marshalled);
        if let Some((salt, secrets)) = parts.split_first() {
            Self {
                salt: salt.clone(),
                secrets: secrets.into(),
            }
        } else {
            Self {
                salt: BigUint::zero(),
                secrets: Secrets(vec![]),
            }
        }
    }
}

impl HashCommitDecommit {
    pub fn new(secrets: Secrets) -> Self {
        let mut rng = rand::thread_rng();
        let salt = rng.gen_biguint(Hash256::BIT_LENGTH);
        let decommitment = HashDeCommitment { salt, secrets };
        let commitment = decommitment.commit();
        Self {
            commitment,
            decommitment,
        }
    }

    fn verify(&self) -> bool {
        let hash = self.decommitment.commit();
        hash == self.commitment
    }

    pub fn decommit(&self) -> Option<Secrets> {
        if self.verify() {
            let dc = self.decommitment.secrets.clone();
            Some(dc)
        } else {
            None
        }
    }
}

impl From<Vec<BigUint>> for Secrets {
    fn from(secrets: Vec<BigUint>) -> Self {
        Self(secrets.clone())
    }
}

impl From<&[BigUint]> for Secrets {
    fn from(secrets: &[BigUint]) -> Self {
        Self(secrets.to_vec())
    }
}

impl AsRef<[BigUint]> for Secrets {
    fn as_ref(&self) -> &[BigUint] {
        self.0.as_ref()
    }
}

impl Secrets {
    const PARTS_CAP: usize = 3;
    const MAX_PART_SIZE: usize = 1 * 1024 * 1024; // 1 MB

    pub fn to_vec(&self) -> Vec<BigUint> {
        self.0.clone()
    }

    pub fn build(parts: &[&[BigUint]]) -> Result<Secrets> {
        if parts.len() > Self::PARTS_CAP {
            return Err(CryptoError::too_many_commitment_parts(parts.len()));
        }
        let secrets: Vec<_> = parts
            .iter()
            .flat_map(|ps| {
                let part_len = ps.len();
                if part_len > Self::MAX_PART_SIZE {
                    return Err(CryptoError::commitment_part_too_large(part_len));
                }
                let mut vs = ps.to_vec();
                vs.insert(0, BigUint::from(part_len));
                Ok(vs)
            })
            .flatten()
            .collect();

        Ok(secrets.into())
    }

    pub fn parse(&self) -> Result<Vec<Vec<BigUint>>> {
        if self.0.len() < 2 {
            return Err(CryptoError::secrets_too_few(self.0.len()));
        }

        let mut ss = self.0.clone();
        let mut parts = Vec::new();
        while !ss.is_empty() {
            if parts.len() >= Self::PARTS_CAP {
                return Err(CryptoError::too_many_commitment_parts(parts.len() + 1));
            }
            let first = ss.remove(0);
            let part_len = first
                .to_usize()
                .ok_or(CryptoError::secrets_invalid_part_length(first))?;
            if part_len > Self::MAX_PART_SIZE {
                return Err(CryptoError::secrets_too_large(part_len));
            }
            if part_len > ss.len() {
                return Err(CryptoError::secrets_invalid_part_length(part_len));
            }
            let part = ss.drain(..part_len);
            parts.push(part.collect());
        }
        Ok(parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_vec<N>(parts: &[&[N]]) -> Vec<Vec<BigUint>>
    where
        N: Copy,
        BigUint: From<N>,
    {
        parts
            .into_iter()
            .map(|ps| ps.into_iter().map(|p| BigUint::from(*p)).collect())
            .collect()
    }

    #[test]
    fn test_verify() {
        let s1 = BigUint::from(1_u8);
        let s2 = BigUint::from(2_u8);
        let secrets = &[s1, s2][..];
        let hcd = HashCommitDecommit::new(secrets.into());
        let d = hcd.decommit().unwrap();
        assert_eq!(secrets, d.as_ref());
        let mut bad = hcd.clone();
        bad.decommitment.salt += 1_u8;
        assert_eq!(false, bad.decommit().is_some());
    }

    #[test]
    fn test_commit() {
        let salt = BigUint::from(28_u8);
        let s1 = BigUint::from(1_u8);
        let s2 = BigUint::from(2_u8);
        let secrets = &[s1.clone(), s2.clone()][..];
        let d = HashDeCommitment {
            salt: salt.clone(),
            secrets: secrets.into(),
        };
        let c = d.commit();
        let hash = hash_sha512_256i(&[salt, s1, s2][..]);
        assert_eq!(c.0, hash);
    }

    #[test]
    fn secrets_build_success() {
        let check = |parts: &[&[u8]], expected: &[u8]| {
            let parts = to_vec(parts);
            let parts: Vec<&[BigUint]> = parts.iter().map(|ps| ps.as_ref()).collect();
            let actual = Secrets::build(parts.as_ref()).unwrap();
            let expected: Vec<_> = expected.iter().map(|e| BigUint::from(*e)).collect();
            assert_eq!(actual.0, expected);
        };

        check(&[], &[]);
        check(&[&[]], &[0]);
        check(&[&[], &[]], &[0, 0]);
        check(&[&[1]], &[1, 1]);
        check(&[&[1], &[2], &[3]], &[1, 1, 1, 2, 1, 3]);
        check(&[&[1], &[1, 2], &[1, 2, 3]], &[1, 1, 2, 1, 2, 3, 1, 2, 3])
    }

    #[test]
    fn secrets_build_failure() {
        let r = Secrets::build(&[&[], &[], &[], &[]]);
        assert!(r.is_err());
        assert_eq!(r.err().unwrap(), CryptoError::too_many_commitment_parts(4));
    }

    #[test]
    fn secrets_parse_success() {
        let check = |secrets: &[u8], expected: &[&[u8]]| {
            let secrets: Vec<BigUint> = secrets.iter().map(|s| BigUint::from(*s)).collect();
            let secrets = Secrets(secrets);
            let actual = secrets.parse();
            assert_eq!(actual.clone().err(), None);
            let expected = to_vec(expected);
            assert_eq!(actual, Ok(expected));
        };

        check(&[0, 0], &[&[], &[]]);
        check(&[1, 1, 1, 1], &[&[1], &[1]]);
        check(&[1, 1, 1, 2, 1, 3], &[&[1], &[2], &[3]]);
        check(&[1, 1, 2, 1, 2, 3, 1, 2, 3], &[&[1], &[1, 2], &[1, 2, 3]]);
    }

    #[test]
    fn secrets_parse_failure() {
        let check = |secrets: &[u8], err: CryptoError| {
            let secrets: Vec<BigUint> = secrets.iter().map(|s| BigUint::from(*s)).collect();
            let secrets = Secrets(secrets);
            let actual = secrets.parse();
            assert_eq!(actual, Err(err));
        };

        check(&[], CryptoError::secrets_too_few(0));
        check(&[0], CryptoError::secrets_too_few(1));
        check(&[0, 0, 0, 0], CryptoError::too_many_commitment_parts(4));
        check(&[2, 0], CryptoError::secrets_invalid_part_length(2));
        check(&[3, 1, 2], CryptoError::secrets_invalid_part_length(3));
    }
}

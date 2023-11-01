use crate::fixed_bytes::{fixed_bytes, FixedBytes};
use num_bigint::BigUint;
use num_traits::Zero;
use sha2::{Digest, Sha512_256};

const HASH_INPUT_DELIMITER: [u8; 1] = ['$' as u8];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hash256([u8; 32]);
fixed_bytes!(Hash256);

impl Hash256 {
    pub const BIT_LENGTH: u64 = 256;
}

fn sha512_256(tag: Option<&[u8]>, src_list: &[&[u8]]) -> Hash256 {
    let mut hasher = Sha512_256::new();
    if let Some(tag) = tag {
        let hashed_tag = sha512_256(None, &[tag]);
        hasher.update(hashed_tag.as_ref());
        hasher.update(hashed_tag);
    }
    let in_len_bz = (src_list.len() as u64).to_le_bytes();
    hasher.update(&in_len_bz);
    for src in src_list {
        let len64 = (src.len() as u64).to_le_bytes();
        hasher.update(src);
        hasher.update(&HASH_INPUT_DELIMITER);
        hasher.update(&len64);
    }
    Hash256(hasher.finalize().into())
}

fn sha512_256i(tag: Option<&[u8]>, src_list: &[BigUint]) -> Hash256 {
    let bs_list: Vec<_> = src_list
        .iter()
        .map(|x| if x.is_zero() { vec![] } else { x.to_bytes_be() })
        .collect();
    let bss: Vec<_> = bs_list.iter().map(|x| x.as_slice()).collect();
    sha512_256(tag, bss.as_slice())
}

pub fn hash_sha512_256(src_list: &[&[u8]]) -> Hash256 {
    sha512_256(None, src_list)
}

pub fn hash_sha512_256i(src_list: &[BigUint]) -> Hash256 {
    sha512_256i(None, src_list)
}

pub fn hash_sha512_256i_tagged(tag: &[u8], src_list: &[BigUint]) -> Hash256 {
    sha512_256i(Some(tag), src_list)
}

pub fn rejection_sample(q: &BigUint, hash: &Hash256) -> BigUint {
    let eh = BigUint::from_bytes_be(hash.as_ref());
    eh % q
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_integer::Integer;
    use num_traits::ToPrimitive;

    #[test]
    fn hash_bytes() {
        let one = hash_sha512_256(&["one".as_bytes()]);
        assert_eq!(
            [
                155, 131, 203, 249, 98, 196, 229, 70, 2, 28, 211, 87, 227, 190, 237, 33, 234, 222,
                237, 187, 64, 76, 128, 71, 25, 78, 154, 136, 22, 45, 51, 41
            ],
            one.0
        );
        let two = hash_sha512_256(&["hello".as_bytes(), "world".as_bytes()]);
        assert_eq!(
            [
                123, 126, 124, 145, 206, 51, 245, 169, 8, 47, 212, 46, 66, 170, 66, 11, 82, 160,
                117, 28, 8, 114, 142, 122, 134, 191, 158, 155, 65, 179, 239, 4
            ],
            two.0
        );
    }

    #[test]
    fn hash_bigint() {
        let one = hash_sha512_256i(&[BigUint::from(12345678_u32)]);
        assert_eq!(
            [
                67, 219, 167, 235, 231, 133, 107, 20, 13, 26, 137, 209, 227, 44, 166, 243, 178,
                187, 225, 8, 188, 216, 190, 110, 158, 214, 125, 4, 251, 94, 93, 188
            ],
            one.0
        );
        let two = hash_sha512_256i(&[BigUint::from(12345678_u32), BigUint::from(34567890_u32)]);
        assert_eq!(
            [
                204, 108, 54, 96, 23, 83, 16, 141, 6, 196, 205, 169, 56, 190, 16, 86, 190, 140,
                255, 179, 57, 7, 138, 28, 226, 9, 15, 169, 24, 135, 190, 32
            ],
            two.0
        );
        let three = hash_sha512_256i(&[
            BigUint::from(12345678_u32),
            BigUint::from(0_u32),
            BigUint::from(34567890_u32),
        ]);
        assert_eq!(
            [
                139, 229, 38, 79, 150, 188, 146, 98, 69, 214, 76, 111, 80, 122, 155, 236, 73, 128,
                40, 100, 24, 163, 191, 55, 178, 177, 13, 12, 133, 150, 138, 209
            ],
            three.0
        );
    }

    #[test]
    fn hash_bigint_tagged() {
        let one = hash_sha512_256i_tagged("tag-a".as_bytes(), &[BigUint::from(12345678_u32)]);
        assert_eq!(
            [
                62, 229, 129, 172, 169, 125, 219, 131, 105, 95, 195, 233, 170, 196, 197, 213, 236,
                163, 114, 155, 156, 196, 165, 198, 67, 235, 246, 30, 140, 248, 88, 95
            ],
            one.0
        );
        let two = hash_sha512_256i_tagged(
            "tag-b".as_bytes(),
            &[BigUint::from(12345678_u32), BigUint::from(34567890_u32)],
        );
        assert_eq!(
            [
                27, 182, 159, 219, 92, 228, 45, 221, 84, 231, 52, 154, 154, 33, 20, 84, 83, 190,
                12, 89, 205, 95, 64, 217, 176, 132, 5, 157, 75, 168, 73, 38
            ],
            two.0
        );
        let three = hash_sha512_256i_tagged(
            "tag-c".as_bytes(),
            &[
                BigUint::from(12345678_u32),
                BigUint::from(0_u32),
                BigUint::from(34567890_u32),
            ],
        );
        assert_eq!(
            [
                213, 63, 56, 234, 196, 75, 69, 74, 68, 71, 105, 213, 75, 149, 4, 237, 211, 185, 20,
                151, 149, 84, 187, 218, 108, 208, 171, 58, 202, 185, 168, 189
            ],
            three.0
        );
    }

    #[test]
    fn test_rejection_sample() {
        let q = BigUint::from(16_u8);
        let hash = hash_sha512_256(&["hello".as_bytes(), "world".as_bytes()]);
        let x = rejection_sample(q, hash);
        assert_eq!(Some(4_u64), x.to_u64());
    }

    fn rejection_sample(q: BigUint, hash: Hash256) -> BigUint {
        let x = BigUint::from_bytes_be(hash.as_ref());
        x.mod_floor(&q)
    }
}

use num_bigint::BigUint;
use sha2::{Digest, Sha512_256};

const HASH_INPUT_DELIMITER: [u8; 1] = ['$' as u8];

fn sha512_256(src_list: &[&[u8]]) -> [u8; 32] {
    if src_list.is_empty() {
        return [0; 32];
    }
    let mut hasher = Sha512_256::new();
    let in_len_bz = (src_list.len() as u64).to_le_bytes();
    hasher.update(&in_len_bz);
    for src in src_list {
        let len64 = (src.len() as u64).to_le_bytes();
        hasher.update(src);
        hasher.update(&HASH_INPUT_DELIMITER);
        hasher.update(&len64);
    }
    hasher.finalize().into()
}

fn sha512_256i(src_list: &[BigUint]) -> BigUint {
    let bs_list: Vec<_> = src_list.iter().map(|x| x.to_bytes_be()).collect();
    let bss: Vec<_> = bs_list.iter().map(|x| x.as_slice()).collect();
    let hash = sha512_256(bss.as_slice());
    BigUint::from_bytes_be(&hash)
}

macro_rules! sha512_256 {
    ($($src:expr),+) => {{
        let src_list = [$($src),+];
        sha512_256(&src_list)
    }};
}

macro_rules! sha512_256i {
    ($($src:expr),+) => {{
        let src_list = [$($src),+];
        sha512_256i(&src_list)
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_bytes() {
        let one = sha512_256!("one".as_bytes());
        assert_eq!(
            [
                155, 131, 203, 249, 98, 196, 229, 70, 2, 28, 211, 87, 227, 190, 237, 33, 234, 222,
                237, 187, 64, 76, 128, 71, 25, 78, 154, 136, 22, 45, 51, 41
            ],
            one
        );
        let two = sha512_256!("hello".as_bytes(), "world".as_bytes());
        assert_eq!(
            [
                123, 126, 124, 145, 206, 51, 245, 169, 8, 47, 212, 46, 66, 170, 66, 11, 82, 160,
                117, 28, 8, 114, 142, 122, 134, 191, 158, 155, 65, 179, 239, 4
            ],
            two
        );
    }

    #[test]
    fn hash_bigint() {
        let one = sha512_256i!(BigUint::from(12345678_u32));
        assert_eq!(
            vec![
                67, 219, 167, 235, 231, 133, 107, 20, 13, 26, 137, 209, 227, 44, 166, 243, 178,
                187, 225, 8, 188, 216, 190, 110, 158, 214, 125, 4, 251, 94, 93, 188
            ],
            one.to_bytes_be()
        );
        let two = sha512_256i!(BigUint::from(12345678_u32), BigUint::from(34567890_u32));
        assert_eq!(
            vec![
                204, 108, 54, 96, 23, 83, 16, 141, 6, 196, 205, 169, 56, 190, 16, 86, 190, 140,
                255, 179, 57, 7, 138, 28, 226, 9, 15, 169, 24, 135, 190, 32
            ],
            two.to_bytes_be()
        );
    }
}

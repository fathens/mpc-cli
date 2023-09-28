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

macro_rules! sha512_256 {
    ($($src:expr),+) => {{
        let src_list = [$($src),+];
        sha512_256(&src_list)
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_hash() {
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
}

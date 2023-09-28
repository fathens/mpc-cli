use sha2::{Digest, Sha512_256};

const HASH_INPUT_DELIMITER: [u8; 1] = ['$' as u8];

fn sha512_256(src_list: &[[u8]]) -> [u8; 32] {
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

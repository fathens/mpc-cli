use num_bigint::BigUint;
use num_integer::Integer;

fn rejection_sample(q: BigUint, hash: crate::hash::Hash256) -> BigUint {
    let x = BigUint::from_bytes_be(hash.as_ref());
    x.mod_floor(&q)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_sha512_256;
    use num_traits::{Num, ToPrimitive};

    #[test]
    fn test_rejection_sample() {
        let q = BigUint::from_str_radix("10", 16).unwrap();
        let hash = hash_sha512_256(&["hello".as_bytes(), "world".as_bytes()]);
        let x = rejection_sample(q, hash);
        assert_eq!(Some(4_u64), x.to_u64());
    }
}

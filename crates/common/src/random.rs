use crate::{CommonError, Result};
use num_bigint::BigUint;
use rand::RngCore;
use std::ops::RangeInclusive;

const RANDOM_BITS_RANGE: RangeInclusive<u32> = 1..=5000;

pub fn get_random_int(bits: u32) -> Result<BigUint> {
    if !RANDOM_BITS_RANGE.contains(&bits) {
        return Err(CommonError::invalid_random_bits_length(
            bits,
            RANDOM_BITS_RANGE,
        ));
    }

    let bs_len = (bits + 7) / 8;
    let mut buf = vec![0_u8; bs_len as usize];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(buf.as_mut_slice());
    let mut r = BigUint::from_bytes_be(&buf);
    for bit_pos in bits..(bs_len * 8) {
        r.set_bit(bit_pos as u64, false);
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;

    #[test]
    fn get_random_int_success() {
        let check = |bits: u32| {
            let r = get_random_int(bits).unwrap();
            let ceiling = BigUint::one() << bits;
            assert_eq!(true, r < ceiling);
        };

        for bits in RANDOM_BITS_RANGE {
            for _ in 0..10 {
                check(bits);
            }
        }
    }

    #[test]
    fn get_random_int_failure() {
        let err = get_random_int(0).unwrap_err();
        assert_eq!(
            CommonError::invalid_random_bits_length(0, RANDOM_BITS_RANGE),
            err
        );

        let err = get_random_int(5001).unwrap_err();
        assert_eq!(
            CommonError::invalid_random_bits_length(5001, RANDOM_BITS_RANGE),
            err
        );
    }
}

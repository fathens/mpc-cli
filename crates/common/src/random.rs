use crate::{CommonError, Result};
use num_bigint::{BigUint, RandBigInt};
use num_prime::nt_funcs::is_safe_prime;
use num_traits::Zero;
use std::ops::RangeInclusive;

const RANDOM_BITS_RANGE: RangeInclusive<u64> = 1..=5000;

fn check_bits_range(bits: u64) -> Result<()> {
    if !RANDOM_BITS_RANGE.contains(&bits) {
        return Err(CommonError::invalid_random_bits_length(
            bits,
            RANDOM_BITS_RANGE,
        ));
    }
    Ok(())
}

pub fn get_random_int(bits: u64) -> Result<BigUint> {
    check_bits_range(bits)?;

    let mut rng = rand::thread_rng();
    let r = rng.gen_biguint(bits);
    Ok(r)
}

pub fn get_random_int_cap(ceiling: &BigUint) -> Result<BigUint> {
    check_bits_range(ceiling.bits())?;

    let mut rng = rand::thread_rng();
    let r = rng.gen_biguint_below(ceiling);
    Ok(r)
}

pub fn get_random_prime_int(bits: u64) -> Result<BigUint> {
    check_bits_range(bits)?;

    let mut rnd = rand::thread_rng();
    let mut r = BigUint::zero();
    while r.is_zero() || !is_safe_prime(&r).probably() {
        r = rnd.gen_biguint(bits);
        r.set_bit(0, true);
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;

    #[test]
    fn get_random_int_success() {
        let check = |bits: u64| {
            let r = get_random_int(bits).unwrap();
            let ceiling = BigUint::one() << bits;
            assert_eq!(
                true,
                r < ceiling,
                "r: {}, ceiling(bits): {}({})",
                r,
                ceiling,
                bits
            );
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

    #[test]
    fn get_random_int_cap_success() {
        let check = |ceiling_bits: u32| {
            let ceiling = BigUint::one() << ceiling_bits;
            let r = get_random_int_cap(&ceiling).unwrap();
            assert_eq!(true, r < ceiling);
        };

        for ceiling_bits in 1..100 {
            for _ in 0..100 {
                check(ceiling_bits);
            }
        }
    }

    #[test]
    fn get_random_prime_int_success() {
        let check = |bits: u64| {
            let r = get_random_prime_int(bits).unwrap();
            assert_eq!(
                true,
                r.bits() <= bits,
                "r: {}({}), bits: {}",
                r,
                r.bits(),
                bits
            );
        };

        for _ in 0..10 {
            check(128);
        }
    }
}

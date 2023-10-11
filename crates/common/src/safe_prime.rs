use num_bigint::BigUint;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GermainSafePrime {
    q: BigUint,
    p: BigUint, // 2q + 1
}

impl GermainSafePrime {
    pub fn prime(&self) -> &BigUint {
        &self.q
    }

    pub fn safe_prime(&self) -> &BigUint {
        &self.p
    }

    pub fn generate(bits: u64) -> Self {
        let (q, p) = generator::safe_prime(bits - 1);
        Self { q, p }
    }
}

mod generator {
    use crate::miller_rabin;
    use num_bigint::{BigUint, RandBigInt};
    use num_prime::{nt_funcs, PrimalityTestConfig};
    use num_traits::{One, ToPrimitive};
    use once_cell::sync::Lazy;
    use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
    use std::iter::repeat_with;

    const CONFIG_STRICT: Lazy<PrimalityTestConfig> = Lazy::new(|| PrimalityTestConfig::strict());
    const CONFIG_NORMAL: Lazy<PrimalityTestConfig> = Lazy::new(|| PrimalityTestConfig::default());

    const SMALL_PRIMES: [u8; 15] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

    const SMALL_PRIMES_PRODUCT: Lazy<BigUint> = Lazy::new(|| {
        SMALL_PRIMES
            .iter()
            .fold(1_u128, |acc, p| acc * (*p as u128))
            .into()
    });

    fn check_by_small_primes(v: &BigUint) -> bool {
        let m = (v % &*SMALL_PRIMES_PRODUCT).to_u128().unwrap();
        SMALL_PRIMES.into_iter().all(|p| {
            let prime = p as u128;
            m == prime || m % prime != 0
        })
    }

    const DELTA_BITS: u64 = 20;
    fn with_delta(origin: &BigUint) -> Option<(BigUint, BigUint)> {
        let mut q = origin.clone();
        let times = 1_u32 << (DELTA_BITS - 1);
        for _ in 1..times {
            if check_by_small_primes(&q) && !(&q % 3_u8).is_one() {
                let mut p = q.clone();
                p <<= 1;
                p += 1_u8;
                if check_by_small_primes(&p) {
                    return Some((q, p));
                }
            }
            q += 2_u8;
        }
        None
    }

    pub fn safe_prime(bits: u64) -> (BigUint, BigUint) {
        let mut rng = rand::thread_rng();
        let mut do_gen = || {
            let mut v = rng.gen_biguint(bits - 1);
            v.set_bit(bits - 1, true);
            v.set_bit(bits - 2, true);
            v.set_bit(0, true);
            v
        };
        let two = &BigUint::from(2_u8);

        let check = |(q, p): &(BigUint, BigUint)| {
            if q.bits() != bits || !is_prime(q, false) {
                return false;
            }
            let e = two.modpow(&(p - 1_u8), p);
            if !e.is_one() {
                return false;
            }
            return is_prime(q, true) && is_prime(p, true);
        };

        loop {
            let trials: Vec<_> = repeat_with(|| do_gen()).take(100).collect();
            if let Some((q, p)) = trials.par_iter().filter_map(with_delta).find_any(check) {
                return (q, p);
            }
        }
    }

    fn is_prime(v: &BigUint, is_strict: bool) -> bool {
        if is_strict {
            nt_funcs::is_prime(v, Some(*CONFIG_STRICT)).probably()
        } else {
            miller_rabin::is_prime(v, 20)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_prime::nt_funcs::is_prime;
    use num_prime::PrimalityTestConfig;

    #[test]
    fn generator_safe_prime() {
        let bits = 1024;
        let (q, p) = generator::safe_prime(bits - 1);
        let config = Some(PrimalityTestConfig::strict());
        assert_eq!(q.clone() * 2_u32 + 1_u32, p.clone());
        assert!(is_prime(&q, config).probably());
        assert!(is_prime(&p, config).probably());
        assert_eq!(q.bits(), bits - 1);
        assert_eq!(p.bits(), bits);
    }
}

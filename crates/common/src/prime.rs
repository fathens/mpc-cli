use num_bigint::BigUint;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GermainSafePrime {
    pub prime: BigUint,
    pub safe_prime: BigUint, // 2q + 1
}

impl GermainSafePrime {
    pub fn generate(bits: u64) -> Self {
        let (q, p) = safe_prime::gen_qp(bits - 1);
        Self {
            prime: q,
            safe_prime: p,
        }
    }
}

pub mod safe_prime {
    use super::{miller_rabin, simple_check};
    use num_bigint::{BigUint, RandBigInt};
    use num_prime::{nt_funcs, PrimalityTestConfig};
    use num_traits::One;
    use rayon::iter::ParallelIterator;
    use rayon::prelude::IntoParallelIterator;

    const CONCURRENT_NUM: usize = 100;

    pub fn is_prime(v: &BigUint) -> bool {
        let config = PrimalityTestConfig::strict();
        nt_funcs::is_prime(v, Some(config)).probably()
    }

    pub(super) fn gen_qp(bits: u64) -> (BigUint, BigUint) {
        let do_gen = || {
            let mut v = rand::rngs::ThreadRng::default().gen_biguint(bits - 2);
            v.set_bit(bits - 1, true);
            v.set_bit(bits - 2, true);
            v.set_bit(0, true);
            v
        };
        let two = &BigUint::from(2_u8);

        let check = |(q, p): &(BigUint, BigUint)| {
            if q.bits() != bits || !miller_rabin::is_prime(q, None) {
                return false;
            }
            let e = two.modpow(&(p - 1_u8), p);
            if !e.is_one() {
                return false;
            }
            is_prime(q) && is_prime(p)
        };

        (0..)
            .find_map(|_| {
                (0..CONCURRENT_NUM).into_par_iter().find_map_any(|_| {
                    let g = do_gen();
                    with_delta(g).filter(check)
                })
            })
            .unwrap()
    }

    const DELTA_BITS: u64 = 20;

    fn with_delta(mut q: BigUint) -> Option<(BigUint, BigUint)> {
        let times = 1_u32 << (DELTA_BITS - 1);
        for _ in 1..times {
            if simple_check::is_prime(&q) && !(&q % 3_u8).is_one() {
                let mut p = q.clone();
                p <<= 1;
                p += 1_u8;
                if simple_check::is_prime(&p) {
                    return Some((q, p));
                }
            }
            q += 2_u8;
        }
        None
    }
}

pub mod simple_check {
    use num_bigint::BigUint;
    use num_traits::ToPrimitive;
    use once_cell::sync::Lazy;

    const SMALL_PRIMES: [u8; 15] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

    static SMALL_PRIMES_PRODUCT: Lazy<BigUint> = Lazy::new(|| {
        SMALL_PRIMES
            .iter()
            .fold(1_u128, |acc, p| acc * (*p as u128))
            .into()
    });

    pub fn is_prime(v: &BigUint) -> bool {
        let m = (v % &*SMALL_PRIMES_PRODUCT).to_u128().unwrap();
        SMALL_PRIMES.into_iter().all(|p| {
            let prime = p as u128;
            m == prime || m % prime != 0
        })
    }
}

pub mod miller_rabin {
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::One;
    use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

    const DEFAULT_REPS: usize = 20;

    pub fn is_prime(n: &BigUint, reps: Option<usize>) -> bool {
        let reps = reps.unwrap_or(DEFAULT_REPS);
        let nm1 = n - 1_u8;
        let k = nm1.trailing_zeros().unwrap_or(0);
        let q = &nm1 >> k;
        let nm3 = &nm1 - 2_u8;

        let mut rng = rand::thread_rng();
        let samples: Vec<_> = (1..=reps)
            .map(|idx| {
                if idx == reps {
                    BigUint::from(2_u8)
                } else {
                    let a = rng.gen_biguint_below(&nm3);
                    a + 2_u8
                }
            })
            .collect();

        samples.par_iter().all(|x| {
            let mut y = x.modpow(&q, n);
            if y.is_one() || y == nm1 {
                return true;
            }

            for _ in 1..k {
                y = y.sqrt() % n;
                if y == nm1 {
                    return true;
                }
                if y.is_one() {
                    return false;
                }
            }
            false
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::time;
    use num_prime::nt_funcs::is_prime;
    use num_prime::PrimalityTestConfig;
    use std::time::Duration;

    #[test]
    fn generator_safe_prime() {
        let check = || {
            let bits = 128;
            let (gsp, dur) = time(|| GermainSafePrime::generate(bits));
            let q = &gsp.prime;
            let p = &gsp.safe_prime;
            let config = Some(PrimalityTestConfig::strict());
            assert_eq!(&(q * 2_u32 + 1_u32), p);
            assert!(is_prime(q, config).probably());
            assert!(is_prime(p, config).probably());
            assert_eq!(q.bits(), bits - 1);
            assert_eq!(p.bits(), bits);
            dur
        };

        let n = 10;
        let ts: Duration = (0..n).map(|_| check()).sum();
        let average = ts / n;
        let secs = (average.as_millis() as f32) / 1000_f32;
        println!("average {}", secs);
    }
}

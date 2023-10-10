use crate::miller_rabin;
use crate::random::get_random_int;
use crate::time::time;
use crate::Result;
use num_bigint::BigUint;
use num_prime::buffer::NaiveBuffer;
use num_prime::PrimalityTestConfig;
use num_traits::{One, ToPrimitive};
use rand::prelude::ThreadRng;

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

    pub fn generate(bits: u64) -> Result<Self> {
        let gen = Generator::init();
        let (q, p) = gen.safe_prime(bits - 1)?;
        Ok(Self { q, p })
    }
}

struct Generator {
    one: BigUint,
    two: BigUint,
    three: BigUint,

    small_primes_product: BigUint,

    config: Option<PrimalityTestConfig>,
    native_buffer: NaiveBuffer,

    rng: ThreadRng,
}

impl Generator {
    const TEST_NUM: usize = 30;

    const SMALL_PRIMES: [u8; 15] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

    fn init() -> Self {
        Self {
            one: BigUint::one(),
            two: BigUint::from(2_u8),
            three: BigUint::from(3_u8),

            small_primes_product: Generator::SMALL_PRIMES
                .iter()
                .fold(1_u64, |acc, p| acc * (*p as u64))
                .into(),

            config: Some(PrimalityTestConfig::bpsw()),
            native_buffer: NaiveBuffer::new(),

            rng: rand::thread_rng(),
        }
    }

    fn check_by_small_primes(&self, v: &BigUint) -> bool {
        let m = (v % &self.small_primes_product).to_u64().unwrap();
        Generator::SMALL_PRIMES.into_iter().all(|p| {
            let prime = p as u64;
            m == prime || m % prime != 0
        })
    }

    fn with_delta(&self, origin: &BigUint, delta_bits: u64) -> Option<(BigUint, BigUint)> {
        let mut q = origin.clone();
        let times = 1_u32 << (delta_bits - 1);
        for _ in 1..times {
            if self.check_by_small_primes(&q) && !(&q % &self.three).is_one() {
                let mut p = q.clone();
                p <<= 1;
                p += 1_u8;
                if self.check_by_small_primes(&p) {
                    return Some((q, p));
                }
            }
            q += &self.two;
        }
        None
    }

    fn safe_prime(&self, bits: u64) -> Result<(BigUint, BigUint)> {
        let must_bits = &self.one << (bits - 1) | &self.one << (bits - 2) | &self.one;
        let do_gen = || {
            let mut v = get_random_int(bits - 1)?;
            v |= &must_bits;
            Ok(v)
        };

        loop {
            let origin = do_gen()?;
            if let Some((q, p)) = self.with_delta(&origin, 20) {
                if q.bits() == bits && self.is_prime(20, &q) {
                    let e = self.two.modpow(&(&p - &self.one), &p);
                    if e.is_one()
                        && self.is_prime(Self::TEST_NUM, &q)
                        && self.is_prime(Self::TEST_NUM, &p)
                    {
                        return Ok((q, p));
                    }
                }
            }
        }
    }

    fn is_prime(&self, num: usize, v: &BigUint) -> bool {
        let (r, duration) = time(|| miller_rabin::is_prime(v, num));
        println!("is_prime: {} ns", duration.as_nanos());
        return r;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_prime::nt_funcs::is_prime;

    #[test]
    fn generator_safe_prime() {
        let bits = 1024;
        let (q, p) = Generator::init().safe_prime(bits - 1).unwrap();
        let config = Some(PrimalityTestConfig::strict());
        assert_eq!(q.clone() * 2_u32 + 1_u32, p.clone());
        assert!(is_prime(&q, config).probably());
        assert!(is_prime(&p, config).probably());
        assert_eq!(q.bits(), bits - 1);
        assert_eq!(p.bits(), bits);
    }
}

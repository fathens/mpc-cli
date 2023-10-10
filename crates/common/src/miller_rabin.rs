use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use once_cell::sync::Lazy;
use rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::iter::Iterator;

const SMALL_PRIMES: [u8; 18] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
];

const PRIMES_A_MEMBERS: [u8; 9] = [3, 5, 7, 11, 13, 17, 19, 23, 37];
const PRIMES_A: Lazy<u32> =
    Lazy::new(|| PRIMES_A_MEMBERS.iter().fold(1, |acc, p| acc * (*p as u32)));
const PRIMES_B_MEMBERS: [u8; 6] = [29, 31, 41, 43, 47, 53];
const PRIMES_B: Lazy<u32> =
    Lazy::new(|| PRIMES_B_MEMBERS.iter().fold(1, |acc, p| acc * (*p as u32)));
const PRIMES_AB: Lazy<u64> = Lazy::new(|| {
    let ab = (*PRIMES_A as u128) * (*PRIMES_B as u128);
    let mask = (1 << 64) - 1;
    (ab & mask) as u64
});

pub fn is_prime(x: &BigUint, reps: usize) -> bool {
    probably_prime_miller_rabin(x, reps)
}

pub fn probably_by_small_primes(x: &BigUint) -> bool {
    if x.bits() <= 6 {
        let v = x.to_u8().unwrap();
        return SMALL_PRIMES.contains(&v);
    } else if x.is_even() {
        return false;
    }

    let r = (x % *PRIMES_AB).to_u64().unwrap();
    let r_a = (r % (*PRIMES_A as u64)) as u32;
    let r_b = (r % (*PRIMES_B as u64)) as u32;

    let by_a = PRIMES_A_MEMBERS
        .into_par_iter()
        .any(|m| (r_a % (m as u32)).is_zero());
    let by_b = PRIMES_B_MEMBERS
        .into_par_iter()
        .any(|m| (r_b % (m as u32)).is_zero());

    by_a || by_b
}

fn probably_prime_miller_rabin(n: &BigUint, reps: usize) -> bool {
    let nm1 = n - 1_u8;
    let k = nm1.trailing_zeros().unwrap_or(0);
    let q = &nm1 >> k;
    let nm3 = &nm1 - 2_u8;

    let mut rng = rand::thread_rng();
    let samples: Vec<_> = (1..=reps)
        .into_iter()
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
        return false;
    })
}

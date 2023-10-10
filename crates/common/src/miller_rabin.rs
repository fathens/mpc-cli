use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use once_cell::sync::Lazy;
use rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::iter::Iterator;

const PRIMES_AS_BIT_MASK: u64 = 1 << 2
    | 1 << 3
    | 1 << 5
    | 1 << 7
    | 1 << 11
    | 1 << 13
    | 1 << 17
    | 1 << 19
    | 1 << 23
    | 1 << 29
    | 1 << 31
    | 1 << 37
    | 1 << 41
    | 1 << 43
    | 1 << 47
    | 1 << 53
    | 1 << 59
    | 1 << 61;

const PRIMES_A_MEMBERS: [u8; 9] = [3, 5, 7, 11, 13, 17, 19, 23, 37];
static PRIMES_A: Lazy<u32> =
    Lazy::new(|| PRIMES_A_MEMBERS.iter().fold(1, |acc, p| acc * (*p as u32)));
const PRIMES_B_MEMBERS: [u8; 6] = [29, 31, 41, 43, 47, 53];
static PRIMES_B: Lazy<u32> =
    Lazy::new(|| PRIMES_B_MEMBERS.iter().fold(1, |acc, p| acc * (*p as u32)));
static PRIMES_AB: Lazy<u64> = Lazy::new(|| {
    let ab = (*PRIMES_A as u128) * (*PRIMES_B as u128);
    let mask = (1 << 64) - 1;
    (ab & mask) as u64
});

pub fn is_prime(x: &BigUint, reps: usize) -> bool {
    if x.bits() <= 6 {
        let v = x.to_u64().unwrap();
        return PRIMES_AS_BIT_MASK & (1 << v) != 0;
    } else if x.is_even() {
        return false;
    }

    let r = (x % *PRIMES_AB).to_u64().unwrap();
    let r_a = (r % (*PRIMES_A as u64)) as u32;
    let r_b = (r % (*PRIMES_B as u64)) as u32;

    if PRIMES_A_MEMBERS
        .into_par_iter()
        .any(|m| (r_a % (m as u32)).is_zero())
        || PRIMES_B_MEMBERS
            .into_par_iter()
            .any(|m| (r_b % (m as u32)).is_zero())
    {
        return false;
    }

    probably_prime_miller_rabin(x, reps)
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

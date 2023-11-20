pub mod ecdsa;

use crate::CryptoError;
use crate::Result;
use common::prime::miller_rabin::is_prime;
use common::random::get_random_generator_of_the_quadratic_residue;
use num_bigint::BigUint;

pub struct NTildei {
    pub n: BigUint,
    pub v1: BigUint,
    pub v2: BigUint,
}

impl NTildei {
    pub fn generate(prime1: BigUint, prime2: BigUint) -> Result<Self> {
        if !is_prime(&prime1, Some(30)) || !is_prime(&prime2, Some(30)) {
            return Err(CryptoError::need_primes());
        }
        let n = prime1 * prime2;
        let v1 = get_random_generator_of_the_quadratic_residue(&n).map_err(CryptoError::from)?;
        let v2 = get_random_generator_of_the_quadratic_residue(&n).map_err(CryptoError::from)?;
        Ok(NTildei { n, v1, v2 })
    }
}

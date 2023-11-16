use crate::CryptoError;
use crate::Result;
use common::prime::miller_rabin::is_prime;
use common::random::get_random_generator_of_the_quadratic_residue;
use elliptic_curve::sec1::{ModulusSize, ToEncodedPoint};
use elliptic_curve::{Curve, FieldBytesSize};
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

/// Returns the x and y coordinates of the point.
/// If the point is at infinity, returns (0, 0).
pub fn point_xy<A, C>(point: &A) -> (BigUint, BigUint)
where
    A: ToEncodedPoint<C>,
    C: Curve,
    FieldBytesSize<C>: ModulusSize,
{
    let ep = point.to_encoded_point(false);

    let x = ep
        .x()
        .map(|x| BigUint::from_bytes_be(x))
        .unwrap_or_default();
    let y = ep
        .y()
        .map(|y| BigUint::from_bytes_be(y))
        .unwrap_or_default();
    (x, y)
}

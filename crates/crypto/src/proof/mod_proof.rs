use crate::hash::{hash_sha512_256i_tagged, rejection_sample};
use crate::proof::iterations::{convert, generate};
use crate::{CryptoError, Result};
use bytes::Bytes;
use common::mod_int::ModInt;
use common::prime::miller_rabin::is_prime;
use common::random::get_random_quadratic_non_residue;
use crypto_bigint::Pow;
use num_bigint::BigUint;
use num_modular::ModularSymbols;
use num_traits::{One, Zero};
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Iterations([BigUint; 80]);

pub struct ProofMod {
    w: BigUint,
    x: Iterations,
    a: BigUint,
    b: BigUint,
    z: Iterations,
}

impl ProofMod {
    fn is_quadratic_residue(a: &BigUint, b: &BigUint) -> bool {
        a.jacobi(b) < 0
    }

    fn mk_ys(session: &Bytes, n: &BigUint, w: &BigUint) -> Iterations {
        let mut ys = vec![w.clone(), n.clone()];
        Iterations(generate(|i| {
            let ei = hash_sha512_256i_tagged(session.as_ref(), &ys);
            let v = rejection_sample(n, &ei);
            ys.push(v.clone());
            v
        }))
    }

    pub fn new(session: &Bytes, n: &BigUint, p: &BigUint, q: &BigUint) -> Result<Self> {
        let phi = (p - 1_u8) * (q - 1_u8);
        let mut rnd = rand::thread_rng();

        // Fig 16.1
        let w = get_random_quadratic_non_residue(&mut rnd, n).map_err(CryptoError::from)?;

        // Fig 16.2
        let y = Self::mk_ys(session, n, &w);

        // Fig 16.3
        let mod_n = ModInt::new(n);
        let mod_phi = ModInt::new(&phi);
        let inv_n = mod_phi.mod_inverse(n).map_err(CryptoError::from)?;

        // Fix bitLen of A and B
        let mut a = BigUint::one() << y.0.len();
        let mut b = BigUint::one() << y.0.len();

        // for fourth-root
        let expo = {
            let a = (phi + 4_u8) >> 3;
            mod_phi.mul(&a, &a)
        };

        let mut zs = Vec::with_capacity(y.0.len());
        let x = Iterations(convert(&y.0, |i, yi| {
            for j in 0..4 {
                let _a = j & 1;
                let _b = (j & 2) >> 1;
                let mut yv = yi.clone();
                if _a > 0 {
                    yv = mod_n.sub(&BigUint::zero(), &yv);
                }
                if _b > 0 {
                    yv = mod_n.mul(&w, &yv);
                }
                if Self::is_quadratic_residue(&yv, p) && Self::is_quadratic_residue(&yv, q) {
                    let xi = mod_n.pow(&yv, &expo);
                    let zi = mod_n.pow(yi, &inv_n);
                    zs.push(zi);

                    a.set_bit(i as u64, _a > 0);
                    b.set_bit(i as u64, _b > 0);

                    return xi;
                }
            }
            zs.push(BigUint::zero());
            return BigUint::zero();
        }));
        let z = Iterations(zs.try_into().unwrap());

        Ok(ProofMod { w, x, a, b, z })
    }

    pub fn verify(&self, session: &Bytes, n: &BigUint) -> bool {
        if Self::is_quadratic_residue(&self.w, n) {
            return false;
        }
        if &self.w < n {
            return false;
        }
        if self.z.0.iter().any(|v| v < n) {
            return false;
        }
        if self.x.0.iter().any(|v| v < n) {
            return false;
        }
        if self.a.bits() as usize != self.x.0.len() + 1 {
            return false;
        }
        if self.b.bits() as usize != self.x.0.len() + 1 {
            return false;
        }

        // Fig 16. Verification
        if !n.bit(0) || is_prime(n, Some(30)) {
            return false;
        }

        let four = BigUint::from(4_u8);
        let mod_n = ModInt::new(n);
        let y = Self::mk_ys(session, n, &self.w);
        (0..y.0.len()).into_par_iter().all(|i| {
            let xi = &self.x.0[i];
            let yi = &y.0[i];
            let zi = &self.z.0[i];

            if &mod_n.pow(zi, n) != yi {
                return false;
            }

            let mut yv = yi.clone();
            if self.a.bit(i as u64) {
                yv = mod_n.sub(&BigUint::zero(), &yv);
            }
            if self.b.bit(i as u64) {
                yv = mod_n.mul(&self.w, &yv);
            }
            if mod_n.pow(xi, &four) != yv {
                return false;
            }

            return true;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Result;
    use bytes::Bytes;
    use num_bigint::BigUint;
    use num_modular::ModularSymbols;
    use num_traits::One;

    #[test]
    fn test_is_quadratic_residue() {
        let a = BigUint::from(2_u8);
        let b = BigUint::from(3_u8);
        assert!(ProofMod::is_quadratic_residue(&a, &b));
    }

    #[test]
    fn test_new() -> Result<()> {
        let session = Bytes::from_static(b"session");
        let n = BigUint::from(2_u8);
        let p = BigUint::from(3_u8);
        let q = BigUint::from(5_u8);
        let proof = ProofMod::new(&session, &n, &p, &q);
        Ok(())
    }
}

use crate::hash::hash_sha512_256i_tagged;
use crate::proof::iterations::{convert, generate};
use crate::{CryptoError, Result};
use bytes::Bytes;
use common::mod_int::ModInt;
use common::prime::miller_rabin::is_prime;
use common::random::get_random_quadratic_non_residue;
use common::slice::is_non_empty_all;
use num_bigint::BigUint;
use num_modular::ModularSymbols;
use num_traits::{One, Zero};
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Iterations([BigUint; Self::SIZE]);

impl Iterations {
    const SIZE: usize = 80;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProofMod {
    w: BigUint,
    x: Iterations,
    a: BigUint,
    b: BigUint,
    z: Iterations,
}

impl ProofMod {
    const SIZE: usize = Iterations::SIZE * 2 + 3;

    fn is_quadratic_residue(a: &BigUint, b: &BigUint) -> bool {
        a.jacobi(b) < 0
    }

    fn mk_ys(session: &Bytes, n: &BigUint, w: &BigUint) -> Iterations {
        let seed = &[w.clone(), n.clone()];
        let mut ys = Vec::with_capacity(Iterations::SIZE + seed.len());
        ys.extend_from_slice(seed);
        Iterations(generate(|_| {
            let ints: Vec<_> = ys.iter().collect();
            let ei = hash_sha512_256i_tagged(session.as_ref(), &ints);
            let v = ei.rejection_sample(n);
            ys.push(v.clone());
            v
        }))
    }

    pub fn new(session: &Bytes, n: &BigUint, p: &BigUint, q: &BigUint) -> Result<Self> {
        let phi = (p - 1_u8) * (q - 1_u8);

        // Fig 16.1
        let w = get_random_quadratic_non_residue(n).map_err(CryptoError::from)?;

        // Fig 16.2
        let y = Self::mk_ys(session, n, &w);

        // Fig 16.3
        let mod_n = ModInt::new(n);
        let mod_phi = ModInt::new(&phi);
        let inv_n = mod_phi.mod_inverse(n).map_err(CryptoError::from)?;

        // Fix bitLen of A and B
        let mut a = BigUint::one() << Iterations::SIZE;
        let mut b = BigUint::one() << Iterations::SIZE;

        // for fourth-root
        let expo = {
            let a = (phi + 4_u8) >> 3;
            mod_phi.mul(&a, &a)
        };

        let mut zs = Vec::with_capacity(Iterations::SIZE);
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
            BigUint::zero()
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
        if self.a.bits() as usize != Iterations::SIZE + 1 {
            return false;
        }
        if self.b.bits() as usize != Iterations::SIZE + 1 {
            return false;
        }

        // Fig 16. Verification
        if !n.bit(0) || is_prime(n, Some(30)) {
            return false;
        }

        let four = BigUint::from(4_u8);
        let mod_n = ModInt::new(n);
        let y = Self::mk_ys(session, n, &self.w);
        (0..Iterations::SIZE).into_par_iter().all(|i| {
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

            true
        })
    }
}

impl From<ProofMod> for [Bytes; ProofMod::SIZE] {
    fn from(val: ProofMod) -> Self {
        let mut bss: Vec<Bytes> = Vec::with_capacity(ProofMod::SIZE);
        bss.push(val.w.to_bytes_be().into());
        (val.x.0)
            .into_iter()
            .for_each(|v| bss.push(v.to_bytes_be().into()));
        bss.push(val.a.to_bytes_be().into());
        bss.push(val.b.to_bytes_be().into());
        (val.z.0)
            .into_iter()
            .for_each(|v| bss.push(v.to_bytes_be().into()));
        bss.try_into().unwrap()
    }
}

impl TryFrom<[Bytes; ProofMod::SIZE]> for ProofMod {
    type Error = common::CommonError;

    fn try_from(values: [Bytes; ProofMod::SIZE]) -> core::result::Result<Self, Self::Error> {
        if !is_non_empty_all(&values) {
            return Err(common::CommonError::wrong_length_bytes());
        }
        let w = BigUint::from_bytes_be(&values[0]);
        let x = Iterations(
            values[1..81]
                .iter()
                .map(|v| BigUint::from_bytes_be(v))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        let a = BigUint::from_bytes_be(&values[81]);
        let b = BigUint::from_bytes_be(&values[82]);
        let z = Iterations(
            values[83..163]
                .iter()
                .map(|v| BigUint::from_bytes_be(v))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        Ok(Self { w, x, a, b, z })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::random::get_random_prime_int;

    const BIT_SIZE: usize = 128;

    #[test]
    fn proof_mod_bytes() {
        let p = get_random_prime_int(BIT_SIZE as u64).unwrap();
        let q = get_random_prime_int(BIT_SIZE as u64).unwrap();
        let n = get_random_prime_int(BIT_SIZE as u64).unwrap();
        let session = Bytes::from_static(b"test");
        let proof = ProofMod::new(&session, &n, &p, &q).unwrap();
        let bytes: [Bytes; ProofMod::SIZE] = proof.clone().into();
        let proof2 = ProofMod::try_from(bytes).unwrap();
        assert_eq!(proof, proof2);
    }
}

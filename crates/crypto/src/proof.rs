use crate::commitment::Secrets;
use crate::hash::hash_sha512_256i;
use crate::{CryptoError, Result};
use bytes::Bytes;
use common::mod_int::ModInt;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Iterations([BigUint; Iterations::LENGTH]);

impl Iterations {
    const LENGTH: usize = 128;

    fn values(&self) -> &[BigUint; Self::LENGTH] {
        &self.0
    }

    fn generate<F>(mut f: F) -> Self
    where
        F: FnMut(u8) -> BigUint,
    {
        let mut bs = Vec::with_capacity(Self::LENGTH);
        for i in 0..Self::LENGTH {
            bs.push(f(i as u8));
        }
        Self(bs.try_into().unwrap())
    }

    fn gen_random(ceiling: &BigUint) -> Self {
        let mut rng = rand::thread_rng();
        Self::generate(|_| rng.gen_biguint_below(ceiling))
    }

    fn convert<F>(&self, mut f: F) -> Self
    where
        F: FnMut(&BigUint, u8) -> BigUint,
    {
        Self::generate(|i| f(&self.0[i as usize], i))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Proof {
    alpha: Iterations,
    t: Iterations,
}

impl Proof {
    pub fn new(
        (h1, h2): (&BigUint, &BigUint),
        x: &BigUint,
        (p, q): (&BigUint, &BigUint),
        n: &BigUint,
    ) -> Proof {
        let mod_n = ModInt::new(n);
        let mod_qp = ModInt::new(&(p * q));
        let randoms = Iterations::gen_random(n);
        let alpha = randoms.convert(|r, _| mod_n.pow(h1, r));
        let mut msg = vec![h1.clone(), h2.clone(), n.clone()];
        alpha.values().iter().for_each(|a| msg.push(a.clone()));
        let c = hash_sha512_256i(msg.as_ref());
        let t = randoms.convert(|v, i| {
            let bi = if c.get_bit(i) {
                BigUint::one()
            } else {
                BigUint::zero()
            };
            mod_qp.add(v, &mod_qp.mul(&bi, x))
        });
        Proof { alpha, t }
    }

    pub fn unmarshal(bzs: &[Bytes]) -> Result<Self> {
        let bis: Vec<_> = bzs.iter().map(|bs| BigUint::from_bytes_be(bs)).collect();
        let secrets: Secrets = bis.into();
        let parsed = secrets.parse()?;
        if parsed.len() != 2 {
            return Err(CryptoError::dln_proof_invalid_length(parsed.len()));
        }
        let to_its = |bis: Vec<BigUint>| -> Result<Iterations> {
            let bs = bis
                .clone()
                .try_into()
                .map_err(|_| CryptoError::dln_proof_invalid_length(bis.len()))?;
            Ok(Iterations(bs))
        };
        Ok(Proof {
            alpha: to_its(parsed[0].clone())?,
            t: to_its(parsed[1].clone())?,
        })
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn unmarshal_success() {
        assert!(true);
    }
}

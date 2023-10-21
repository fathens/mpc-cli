use crate::commitment::Secrets;
use crate::hash::hash_sha512_256i;
use crate::{CryptoError, Result};
use bytes::Bytes;
use common::mod_int::ModInt;
use num_bigint::{BigUint, RandBigInt};

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
        let hash_bits = &BigUint::from_bytes_be(c.as_ref());
        let t = randoms.convert(|r, i| {
            if hash_bits.bit(i as u64) {
                r.clone()
            } else {
                mod_qp.add(r, x)
            }
        });
        Proof { alpha, t }
    }

    pub fn unmarshal(bzs: &[Bytes]) -> Result<Self> {
        let parse = |bis: Vec<BigUint>| -> Result<[Vec<BigUint>; 2]> {
            let secrets: Secrets = bis.into();
            let parsed = secrets.parse()?;
            parsed
                .try_into()
                .map_err(|org: Vec<Vec<BigUint>>| CryptoError::dln_proof_invalid_length(org.len()))
        };
        let [b0, b1] = parse(bzs.iter().map(|bs| BigUint::from_bytes_be(bs)).collect())?;
        let to_its = |bis: Vec<BigUint>| -> Result<Iterations> {
            let bs = bis
                .clone()
                .try_into()
                .map_err(|_| CryptoError::dln_proof_invalid_length(bis.len()))?;
            Ok(Iterations(bs))
        };
        Ok(Proof {
            alpha: to_its(b0)?,
            t: to_its(b1)?,
        })
    }

    pub fn marshal(&self) -> Result<Vec<Bytes>> {
        let secrets = Secrets::build(&[self.alpha.values(), self.t.values()])?;
        let bss = secrets
            .to_vec()
            .iter()
            .map(|x| Bytes::from(x.to_bytes_be()))
            .collect();
        Ok(bss)
    }
}

#[cfg(test)]
mod test {
    use crate::proof::Proof;
    use num_bigint::BigUint;

    #[test]
    fn unmarshal_success() {
        let sample = Proof::new(
            (&BigUint::from(10123_u16), &BigUint::from(20123_u16)),
            &BigUint::from(30123_u16),
            (&BigUint::from(40123_u16), &BigUint::from(50123_u16)),
            &BigUint::from(60123_u16),
        );
        let bzs = sample.marshal().unwrap();
        let actual = Proof::unmarshal(&bzs).unwrap();
        assert_eq!(actual, sample);
    }
}

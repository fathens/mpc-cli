use crate::hash::hash_sha512_256i_tagged;
use crate::utils::NTildei;
use bytes::Bytes;
use common::mod_int::ModInt;
use common::random;
use common::slice::is_non_empty_all;
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProofFac {
    p: BigUint,
    q: BigUint,
    a: BigUint,
    b: BigUint,
    t: BigUint,
    sigma: BigUint,
    z1: BigUint,
    z2: BigUint,
    w1: BigUint,
    w2: BigUint,
    v: BigInt,
}

pub struct VerifyParam {
    pub session: Bytes,
    pub curve_n: BigUint,
    pub n0: BigUint,
    pub n_tildei: NTildei,
}

impl VerifyParam {
    pub fn mul_st(&self, m: &ModInt, ns: Option<&BigUint>, a: &BigUint, b: &BigUint) -> BigUint {
        let x = m.pow(ns.unwrap_or(&self.n_tildei.v1), a);
        let y = m.pow(&self.n_tildei.v2, b);
        m.mul(&x, &y)
    }

    pub fn e_hash(
        &self,
        p: &BigUint,
        q: &BigUint,
        a: &BigUint,
        b: &BigUint,
        t: &BigUint,
        sigma: &BigUint,
    ) -> BigUint {
        let list = [
            self.n0.clone(),
            self.n_tildei.n.clone(),
            self.n_tildei.v1.clone(),
            self.n_tildei.v2.clone(),
            p.clone(),
            q.clone(),
            a.clone(),
            b.clone(),
            t.clone(),
            sigma.clone(),
        ];
        let eh = hash_sha512_256i_tagged(&self.session, &list);
        eh.rejection_sample(&self.curve_n)
    }
}

impl ProofFac {
    const SIZE: usize = 11;

    pub fn new(
        vp: &VerifyParam,
        n0p: &BigUint,
        n0q: &BigUint,
    ) -> Result<Self, common::CommonError> {
        let q3 = &vp.curve_n.pow(3);
        let ncap = &vp.n_tildei.n;
        let q_ncap = &(&vp.curve_n * ncap);
        let n0 = &vp.n0;
        let q_n0_ncap = &(q_ncap * n0);
        let q3_ncap = &(q3 * ncap);
        let q3_n0_ncap = &(q3_ncap * n0);
        let q3_sqrt_n0 = &(q3 * n0.sqrt());

        // Fig 28.1 sample
        let mut rnd = rand::thread_rng();
        let alpha = &rnd.gen_biguint_below(q3_sqrt_n0);
        let beta = &rnd.gen_biguint_below(q3_sqrt_n0);
        let mu = &rnd.gen_biguint_below(q_ncap);
        let nu = &rnd.gen_biguint_below(q_ncap);
        let sigma = rnd.gen_biguint_below(q_n0_ncap);
        let r = &random::get_random_positive_relatively_prime_int(&mut rnd, q3_n0_ncap)?;
        let x = &rnd.gen_biguint_below(q3_ncap);
        let y = &rnd.gen_biguint_below(q3_ncap);

        // Fig 28.1 compute
        let m = &ModInt::new(ncap);

        let p = vp.mul_st(m, None, n0p, mu);
        let q = vp.mul_st(m, None, n0q, nu);
        let a = vp.mul_st(m, None, alpha, x);
        let b = vp.mul_st(m, None, beta, y);
        let t = vp.mul_st(m, Some(&q), alpha, r);

        // Fig 28.2 e
        let e = &vp.e_hash(&p, &q, &a, &b, &t, &sigma);

        // Fig 28.3
        let z1 = e * n0p + alpha;
        let z2 = e * n0q + beta;
        let w1 = e * mu + x;
        let w2 = e * nu + y;
        let v = e.to_bigint().unwrap()
            * (sigma.to_bigint().unwrap() - (nu * n0p).to_bigint().unwrap())
            + r.to_bigint().unwrap();

        Ok(Self {
            p,
            q,
            a,
            b,
            t,
            sigma,
            z1,
            z2,
            w1,
            w2,
            v,
        })
    }

    pub fn verify(&self, vp: &VerifyParam) -> bool {
        let q3 = &vp.curve_n.pow(3);
        let sqrt_n0 = vp.n0.sqrt();
        let q3_sqrt_n0 = &(q3 * &sqrt_n0);

        // Fig 28. Range Check
        if q3_sqrt_n0 <= &self.z1 {
            return false;
        }
        if q3_sqrt_n0 <= &self.z2 {
            return false;
        }

        let e = &vp.e_hash(&self.p, &self.q, &self.a, &self.b, &self.t, &self.sigma);

        // Fig 28. Equality Check
        let m = &ModInt::new(&vp.n_tildei.n);
        {
            let a = vp.mul_st(m, None, &self.z1, &self.w1);
            let b = m.mul(&self.a, &m.pow(&self.p, e));
            if a != b {
                return false;
            }
        }

        {
            let a = vp.mul_st(m, None, &self.z2, &self.w2);
            let b = m.mul(&self.b, &m.pow(&self.q, e));
            if a != b {
                return false;
            }
        }

        if let Ok(y) = m.powi(&vp.n_tildei.v2, &self.v) {
            let x = m.pow(&self.q, &self.z1);
            let a = m.mul(&x, &y);

            let r = vp.mul_st(m, None, &vp.n0, &self.sigma);
            let b = m.mul(&self.t, &m.pow(&r, e));
            if a != b {
                return false;
            }
        } else {
            return false;
        }

        true
    }
}

impl TryFrom<[Bytes; ProofFac::SIZE]> for ProofFac {
    type Error = common::CommonError;

    fn try_from(values: [Bytes; ProofFac::SIZE]) -> Result<Self, Self::Error> {
        if !is_non_empty_all(&values) {
            return Err(common::CommonError::wrong_length_bytes());
        }
        let r = Self {
            p: BigUint::from_bytes_be(&values[0]),
            q: BigUint::from_bytes_be(&values[1]),
            a: BigUint::from_bytes_be(&values[2]),
            b: BigUint::from_bytes_be(&values[3]),
            t: BigUint::from_bytes_be(&values[4]),
            sigma: BigUint::from_bytes_be(&values[5]),
            z1: BigUint::from_bytes_be(&values[6]),
            z2: BigUint::from_bytes_be(&values[7]),
            w1: BigUint::from_bytes_be(&values[8]),
            w2: BigUint::from_bytes_be(&values[9]),
            v: BigInt::from_signed_bytes_be(&values[10]),
        };
        Ok(r)
    }
}

impl From<ProofFac> for [Bytes; ProofFac::SIZE] {
    fn from(val: ProofFac) -> Self {
        [
            val.p.to_bytes_be().into(),
            val.q.to_bytes_be().into(),
            val.a.to_bytes_be().into(),
            val.b.to_bytes_be().into(),
            val.t.to_bytes_be().into(),
            val.sigma.to_bytes_be().into(),
            val.z1.to_bytes_be().into(),
            val.z2.to_bytes_be().into(),
            val.w1.to_bytes_be().into(),
            val.w2.to_bytes_be().into(),
            val.v.to_signed_bytes_be().into(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::random::get_random_prime_int;
    use crypto_bigint::Encoding;
    use k256::Secp256k1;
    use num_traits::ToPrimitive;
    use rand::rngs::ThreadRng;

    const BIT_SIZE: u64 = 128;

    fn gen_proof_fac(rnd: &mut ThreadRng) -> (VerifyParam, (BigUint, BigUint)) {
        let n_tildei = NTildei::generate(
            get_random_prime_int(rnd, BIT_SIZE).unwrap(),
            get_random_prime_int(rnd, BIT_SIZE).unwrap(),
        )
        .unwrap();

        let n0p = get_random_prime_int(rnd, BIT_SIZE).unwrap();
        let n0q = get_random_prime_int(rnd, BIT_SIZE).unwrap();
        let n0 = &n0p * &n0q;

        let bs: Vec<_> = (0..rnd.gen_biguint(8).to_u8().unwrap())
            .flat_map(|_| rnd.gen_biguint(8).to_bytes_be())
            .collect();

        let curve_n = elliptic_curve::ScalarPrimitive::<Secp256k1>::MODULUS.to_be_bytes();

        let vp = VerifyParam {
            session: bs.into(),
            curve_n: BigUint::from_bytes_be(&curve_n),
            n0,
            n_tildei,
        };

        (vp, (n0p, n0q))
    }

    #[test]
    fn proof_fac_verify() {
        let mut rnd = rand::thread_rng();
        for _ in 0..8 {
            let (vp, (n0q, n0p)) = gen_proof_fac(&mut rnd);
            for _ in 0..8 {
                let sample = ProofFac::new(&vp, &n0p, &n0q).unwrap();
                let ok = sample.verify(&vp);
                assert!(ok);
            }
        }
    }

    #[test]
    fn proof_fac_bytes() {
        let mut rnd = rand::thread_rng();
        let (vp, (n0q, n0p)) = gen_proof_fac(&mut rnd);
        let sample = ProofFac::new(&vp, &n0p, &n0q).unwrap();

        let bytes: [Bytes; ProofFac::SIZE] = sample.clone().into();
        let sample2 = ProofFac::try_from(bytes).unwrap();
        assert_eq!(sample, sample2);
    }
}

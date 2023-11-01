use crate::hash::{hash_sha512_256i_tagged, rejection_sample};
use bytes::Bytes;
use common::mod_int::ModInt;
use common::random;
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
    pub curve_n: BigUint,
    pub n0: BigUint,
    pub n_cap: BigUint,
    pub s: BigUint,
    pub t: BigUint,
}

impl VerifyParam {
    pub fn mul_st(&self, m: &ModInt, ns: Option<&BigUint>, a: &BigUint, b: &BigUint) -> BigUint {
        let x = m.pow(ns.unwrap_or(&self.s), a);
        let y = m.pow(&self.t, b);
        m.mul(&x, &y)
    }

    pub fn e_hash(
        &self,
        session: &Bytes,
        p: &BigUint,
        q: &BigUint,
        a: &BigUint,
        b: &BigUint,
        t: &BigUint,
        sigma: &BigUint,
    ) -> BigUint {
        let list = [
            self.n0.clone(),
            self.n_cap.clone(),
            self.s.clone(),
            self.t.clone(),
            p.clone(),
            q.clone(),
            a.clone(),
            b.clone(),
            t.clone(),
            sigma.clone(),
        ];
        let eh = hash_sha512_256i_tagged(session, &list);
        rejection_sample(&self.curve_n, &eh)
    }
}

impl ProofFac {
    pub fn new(
        session: &Bytes,
        vp: &VerifyParam,
        n0p: &BigUint,
        n0q: &BigUint,
    ) -> Result<Self, common::CommonError> {
        let q3 = &vp.curve_n.pow(3);
        let ncap = &vp.n_cap;
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
        let m = &ModInt::new(&ncap);

        let p = vp.mul_st(m, None, n0p, mu);
        let q = vp.mul_st(m, None, n0q, nu);
        let a = vp.mul_st(m, None, alpha, x);
        let b = vp.mul_st(m, None, beta, y);
        let t = vp.mul_st(m, Some(&q), alpha, r);

        // Fig 28.2 e
        let e = &vp.e_hash(session, &p, &q, &a, &b, &t, &sigma);

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

    pub fn verify(&self, session: &Bytes, vp: &VerifyParam) -> bool {
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

        let e = &vp.e_hash(
            session,
            &self.p,
            &self.q,
            &self.a,
            &self.b,
            &self.t,
            &self.sigma,
        );

        // Fig 28. Equality Check
        let m = &ModInt::new(&vp.n_cap);
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

        {
            let x = m.pow(&self.q, &self.z1);
            let mi = m.module().to_bigint().unwrap();
            let y = vp.t.to_bigint().unwrap().modpow(&self.v, &mi);
            let a = (x.to_bigint().unwrap() * &y) % &mi;

            let r = vp.mul_st(m, None, &vp.n0, &self.sigma);
            let b = m.mul(&self.t, &m.pow(&r, e));
            if a != b.to_bigint().unwrap() {
                return false;
            }
        }

        return true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_fac_verify() {
        let vp = VerifyParam {
            curve_n: BigUint::from(2_u8),
            n0: BigUint::from(3_u8),
            n_cap: BigUint::from(4_u8),
            s: BigUint::from(5_u8),
            t: BigUint::from(6_u8),
        };
        let session = BigUint::from(1_u8).to_bytes_be().into();

        let sample =
            ProofFac::new(&session, &vp, &BigUint::from(10_u8), &BigUint::from(11_u8)).unwrap();

        let ok = sample.verify(&session, &vp);
        assert!(ok);
    }
}

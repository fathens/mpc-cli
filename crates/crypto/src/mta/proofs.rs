use crate::hash::hash_sha512_256i_tagged;
use crate::utils::ecdsa;
use crate::Result;
use crate::{paillier, CryptoError};
use bytes::Bytes;
use common::mod_int::ModInt;
use common::random::{get_random_positive_int, get_random_positive_relatively_prime_int};
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, FieldBytesSize};
use num_bigint::{BigUint, RandBigInt};

pub struct ProofBob {
    z: BigUint,
    z_prm: BigUint,
    t: BigUint,
    v: BigUint,
    w: BigUint,
    s: BigUint,
    s1: BigUint,
    s2: BigUint,
    t1: BigUint,
    t2: BigUint,
}

pub struct ProofBobWC<C>
where
    C: CurveArithmetic,
{
    bob: ProofBob,
    u: C::AffinePoint,
}

impl ProofBob {
    const NUM_PARTS: usize = 10;
    const NUM_PARTS_WITH_POINT: usize = ProofBob::NUM_PARTS + 2;

    pub fn new<C>(
        session: &[u8],
        pk: &paillier::PublicKey,
        n_tilde: &BigUint,
        hc: &((BigUint, BigUint), (BigUint, BigUint)),
        xy: &(BigUint, BigUint),
        r: &BigUint,
        point: Option<&C::AffinePoint>,
    ) -> Result<ProofBob>
    where
        C: CurveArithmetic,
        C::AffinePoint: ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let ((h1, h2), (c1, c2)) = hc;
        let (x, y) = xy;
        let n2 = &pk.n().pow(2);
        let q = &ecdsa::curve_n::<C>();
        let q3 = &q.pow(3);
        let q7 = &(q3.pow(2) * q);

        let q_n_tilde = &(q * n_tilde);
        let q3_n_tilde = &(q3 * n_tilde);

        // steps are numbered as shown in Fig. 10, but diverge slightly for Fig. 11
        // 1.
        let alpha = &get_random_positive_int(q3).map_err(CryptoError::from)?;

        // 2.
        let rho = &get_random_positive_int(q_n_tilde).map_err(CryptoError::from)?;
        let sigma = &get_random_positive_int(q_n_tilde).map_err(CryptoError::from)?;
        let tau = &get_random_positive_int(q3_n_tilde).map_err(CryptoError::from)?;

        // 3.
        let rho_prm = &get_random_positive_int(q3_n_tilde).map_err(CryptoError::from)?;

        // 4.
        let beta = &get_random_positive_relatively_prime_int(pk.n()).map_err(CryptoError::from)?;
        let gamma = &get_random_positive_int(q7).map_err(CryptoError::from)?;

        // 6.
        let mod_n_tilde = ModInt::new(n_tilde);
        let z = mod_n_tilde.mul(&mod_n_tilde.pow(h1, x), &mod_n_tilde.pow(h2, rho));

        // 7.
        let z_prm = mod_n_tilde.mul(&mod_n_tilde.pow(h1, alpha), &mod_n_tilde.pow(h2, rho_prm));

        // 8.
        let t = mod_n_tilde.mul(&mod_n_tilde.pow(h1, y), &mod_n_tilde.pow(h2, sigma));

        // 9.
        let pk_gamma = &(pk.n() + 1_u8);
        let mod_n2 = ModInt::new(n2);
        let v = {
            let a = &mod_n2.pow(c1, alpha);
            let b = &mod_n2.pow(pk_gamma, gamma);
            let c = &mod_n2.pow(beta, pk.n());
            mod_n2.mul(&mod_n2.mul(a, b), c)
        };

        // 10.
        let w = mod_n_tilde.mul(&mod_n_tilde.pow(h1, gamma), &mod_n_tilde.pow(h2, tau));

        // 11-12. e'
        let e = {
            let list = point
                .map(|point| {
                    let (px, py) = ecdsa::point_xy(point);
                    // 5.
                    let u = ecdsa::point_mul::<C>(alpha);
                    let (ux, uy) = ecdsa::point_xy(&u);
                    [
                        pk.n().clone(),
                        pk_gamma.clone(),
                        px,
                        py,
                        c1.clone(),
                        c2.clone(),
                        ux,
                        uy,
                        z.clone(),
                        z_prm.clone(),
                        t.clone(),
                        v.clone(),
                        w.clone(),
                    ]
                    .to_vec()
                })
                .unwrap_or_else(|| {
                    [
                        pk.n().clone(),
                        pk_gamma.clone(),
                        c1.clone(),
                        c2.clone(),
                        z.clone(),
                        z_prm.clone(),
                        t.clone(),
                        v.clone(),
                        w.clone(),
                    ]
                    .to_vec()
                });
            let hash = hash_sha512_256i_tagged(session, &list);
            &hash.rejection_sample(q)
        };

        // 13.
        let mod_n = ModInt::new(pk.n());
        let s = mod_n.mul(&mod_n.pow(r, e), beta);

        // 14.
        let s1 = e * x + alpha;

        // 15.
        let s2 = e * rho + rho_prm;

        // 16.
        let t1 = e * y + gamma;

        // 17.
        let t2 = e * sigma + tau;

        Ok(ProofBob {
            z,
            z_prm,
            t,
            v,
            w,
            s,
            s1,
            s2,
            t1,
            t2,
        })
    }
}

impl TryFrom<&[Bytes; ProofBob::NUM_PARTS]> for ProofBob {
    type Error = CryptoError;

    fn try_from(value: &[Bytes; ProofBob::NUM_PARTS]) -> Result<Self> {
        let to_biguint = |bs: &Bytes| {
            if bs.len() == 0 {
                Err(CryptoError::message_malformed())
            } else {
                Ok(BigUint::from_bytes_be(&bs))
            }
        };

        Ok(ProofBob {
            z: to_biguint(&value[0])?,
            z_prm: to_biguint(&value[1])?,
            t: to_biguint(&value[2])?,
            v: to_biguint(&value[3])?,
            w: to_biguint(&value[4])?,
            s: to_biguint(&value[5])?,
            s1: to_biguint(&value[6])?,
            s2: to_biguint(&value[7])?,
            t1: to_biguint(&value[8])?,
            t2: to_biguint(&value[9])?,
        })
    }
}

impl<C> ProofBobWC<C>
where
    C: CurveArithmetic,
{
    pub fn new(bob: ProofBob) -> Self {
        let q = ecdsa::curve_n::<C>();
        let q3 = q.pow(3);
        let alpha = rand::thread_rng().gen_biguint_below(&q3);
        let u = ecdsa::point_mul::<C>(&alpha);

        Self { bob, u }
    }
}

impl<C> TryFrom<&[Bytes; ProofBob::NUM_PARTS_WITH_POINT]> for ProofBobWC<C>
where
    C: CurveArithmetic,
    C::AffinePoint: FromEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    type Error = CryptoError;

    fn try_from(value: &[Bytes; ProofBob::NUM_PARTS_WITH_POINT]) -> Result<Self> {
        let bs: Vec<_> = value
            .to_vec()
            .into_iter()
            .take(ProofBob::NUM_PARTS)
            .collect();
        let bob = ProofBob::try_from(&bs.try_into().unwrap())?;
        let x = BigUint::from_bytes_be(&value[10]);
        let y = BigUint::from_bytes_be(&value[11]);
        let u = ecdsa::xy_point::<C>(&x, &y).ok_or(CryptoError::message_malformed())?;
        Ok(Self { bob, u })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use k256::Secp256k1;
    use num_traits::Num;
    use std::collections::HashMap;
}

use crate::hash::hash_sha512_256i_tagged;
use crate::utils::ecdsa;
use crate::Result;
use crate::{paillier, CryptoError};
use bytes::Bytes;
use common::mod_int::ModInt;
use common::random::{get_random_positive_int, get_random_positive_relatively_prime_int};
use elliptic_curve::ops::MulByGenerator;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, FieldBytesSize};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;

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
    ) -> Result<Self>
    where
        C: CurveArithmetic,
        C::AffinePoint: ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let wc = ProofBobWC::<C>::new(session, pk, n_tilde, hc, xy, r, None)?;
        Ok(wc.bob)
    }

    pub fn verify<C>(
        &self,
        session: &[u8],
        pk: &paillier::PublicKey,
        n_tilde: &BigUint,
        hc: &((BigUint, BigUint), (BigUint, BigUint)),
    ) -> bool
    where
        C: CurveArithmetic,
        C::AffinePoint: ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        self.verify_with_wc::<C>(session, pk, n_tilde, hc, None)
    }

    fn verify_with_wc<C>(
        &self,
        session: &[u8],
        pk: &paillier::PublicKey,
        n_tilde: &BigUint,
        hc: &((BigUint, BigUint), (BigUint, BigUint)),
        xu: Option<(C::AffinePoint, C::AffinePoint)>,
    ) -> bool
    where
        C: CurveArithmetic,
        C::AffinePoint: ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let ((h1, h2), (c1, c2)) = hc;

        let n2 = &pk.n().pow(2);
        let q = &ecdsa::curve_n::<C>();
        let q3 = &q.pow(3);
        let q7 = &(q3.pow(2) * q);

        if [
            (&self.z, n_tilde),
            (&self.z_prm, n_tilde),
            (&self.t, n_tilde),
            (&self.v, n2),
            (&self.w, n_tilde),
            (&self.s, pk.n()),
        ]
        .into_iter()
        .any(|(a, b)| a >= b)
        {
            return false;
        }

        if [
            (&self.z, n_tilde),
            (&self.z_prm, n_tilde),
            (&self.t, n_tilde),
            (&self.v, n2),
            (&self.w, n_tilde),
            (&self.s, pk.n()),
            (&self.v, pk.n()),
        ]
        .into_iter()
        .any(|(a, b)| !a.gcd(b).is_one())
        {
            return false;
        }

        if [&self.s1, &self.s2, &self.t1, &self.t2]
            .into_iter()
            .any(|a| a < q)
        {
            return false;
        }

        // 3.
        if &self.s1 > q3 || &self.t1 > q7 {
            return false;
        }

        // 1-2. e'
        let e = {
            let list = xu
                .map(|(x, u)| {
                    let (xp_x, xp_y) = ecdsa::point_xy(&x);
                    let (up_x, up_y) = ecdsa::point_xy(&u);
                    [
                        pk.n().clone(),
                        pk.n().clone() + 1_u8,
                        xp_x,
                        xp_y,
                        c1.clone(),
                        c2.clone(),
                        up_x,
                        up_y,
                        self.z.clone(),
                        self.z_prm.clone(),
                        self.t.clone(),
                        self.v.clone(),
                        self.w.clone(),
                    ]
                    .to_vec()
                })
                .unwrap_or_else(|| {
                    [
                        pk.n().clone(),
                        pk.n().clone() + 1_u8,
                        c1.clone(),
                        c2.clone(),
                        self.z.clone(),
                        self.z_prm.clone(),
                        self.t.clone(),
                        self.v.clone(),
                        self.w.clone(),
                    ]
                    .to_vec()
                });
            let hash = hash_sha512_256i_tagged(session, &list);
            &hash.rejection_sample(q)
        };

        // 4.
        if xu.iter().any(|(x, u)| {
            let e = ecdsa::to_scalar::<C>(e);
            let s1 = ecdsa::to_scalar::<C>(&self.s1);
            C::ProjectivePoint::mul_by_generator(&s1) != (C::ProjectivePoint::from(*x) * e + u)
        }) {
            return false;
        }

        let mod_n_tilde = ModInt::new(n_tilde);

        // 5.
        if mod_n_tilde.mul(
            &mod_n_tilde.pow(h1, &self.s1),
            &mod_n_tilde.pow(h2, &self.s2),
        ) != mod_n_tilde.mul(&mod_n_tilde.pow(&self.z, e), &self.z_prm)
        {
            return false;
        }

        // 6.
        if mod_n_tilde.mul(
            &mod_n_tilde.pow(h1, &self.t1),
            &mod_n_tilde.pow(h2, &self.t2),
        ) != mod_n_tilde.mul(&mod_n_tilde.pow(&self.t, e), &self.w)
        {
            return false;
        }

        // 7.
        let mod_n2 = ModInt::new(n2);
        let c1_exp_s1 = mod_n2.pow(c1, &self.s1);
        let s_exp_n = mod_n2.pow(&self.s, pk.n());
        let gamma_exp_t1 = mod_n2.pow(&(pk.n() + 1_u8), &self.t1);
        let left = mod_n2.mul(&mod_n2.mul(&c1_exp_s1, &s_exp_n), &gamma_exp_t1);
        let c2_exp_e = mod_n2.pow(c2, e);
        let right = mod_n2.mul(&c2_exp_e, &self.v);
        if left != right {
            return false;
        }

        true
    }
}

impl TryFrom<&[&Bytes; ProofBob::NUM_PARTS]> for ProofBob {
    type Error = CryptoError;

    fn try_from(value: &[&Bytes; ProofBob::NUM_PARTS]) -> Result<Self> {
        Ok(ProofBob {
            z: to_biguint(value[0])?,
            z_prm: to_biguint(value[1])?,
            t: to_biguint(value[2])?,
            v: to_biguint(value[3])?,
            w: to_biguint(value[4])?,
            s: to_biguint(value[5])?,
            s1: to_biguint(value[6])?,
            s2: to_biguint(value[7])?,
            t1: to_biguint(value[8])?,
            t2: to_biguint(value[9])?,
        })
    }
}

impl<C> ProofBobWC<C>
where
    C: CurveArithmetic,
{
    pub fn new(
        session: &[u8],
        pk: &paillier::PublicKey,
        n_tilde: &BigUint,
        hc: &((BigUint, BigUint), (BigUint, BigUint)),
        xy: &(BigUint, BigUint),
        r: &BigUint,
        point: Option<&C::AffinePoint>,
    ) -> Result<Self>
    where
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
        let u = ecdsa::generate_mul::<C>(alpha);

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

        let bob = ProofBob {
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
        };
        Ok(Self { bob, u })
    }

    pub fn verify(
        &self,
        session: &[u8],
        pk: &paillier::PublicKey,
        n_tilde: &BigUint,
        hc: &((BigUint, BigUint), (BigUint, BigUint)),
        x: C::AffinePoint,
    ) -> bool
    where
        C::AffinePoint: ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        self.bob
            .verify_with_wc::<C>(session, pk, n_tilde, hc, Some((x, self.u)))
    }
}

impl<C> TryFrom<&[&Bytes; ProofBob::NUM_PARTS_WITH_POINT]> for ProofBobWC<C>
where
    C: CurveArithmetic,
    C::AffinePoint: FromEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    type Error = CryptoError;

    fn try_from(value: &[&Bytes; ProofBob::NUM_PARTS_WITH_POINT]) -> Result<Self> {
        let bob = ProofBob::try_from(&[
            value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
            value[8], value[9],
        ])?;
        let x = to_biguint(value[10])?;
        let y = to_biguint(value[11])?;
        let u = ecdsa::xy_point::<C>(&x, &y).ok_or(CryptoError::message_malformed())?;
        Ok(Self { bob, u })
    }
}

fn to_biguint(bs: &Bytes) -> Result<BigUint> {
    if bs.is_empty() {
        Err(CryptoError::message_malformed())
    } else {
        Ok(BigUint::from_bytes_be(bs))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use k256::Secp256k1;
    use num_traits::Num;
    use std::collections::HashMap;
}

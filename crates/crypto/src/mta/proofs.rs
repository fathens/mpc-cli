use crate::{CryptoError, Result};
use crypto_bigint::{CheckedMul, Encoding};
use elliptic_curve::group::Curve;
use elliptic_curve::{CurveArithmetic, Group, ScalarPrimitive};
use num_bigint::{BigUint, RandBigInt};
use rand::prelude::ThreadRng;
use std::ops::Mul;

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

impl ProofBob {}

impl<C> ProofBobWC<C>
where
    C: CurveArithmetic,
{
    pub fn new(bob: ProofBob, rnd: &mut ThreadRng) -> Result<Self> {
        let q = C::ORDER;
        let q2: Option<C::Uint> = q.checked_mul(&q).into();
        let q2 = q2.ok_or(CryptoError::point_overflow())?;
        let q3: Option<C::Uint> = q2.checked_mul(&q).into();
        let q3 = q3.ok_or(CryptoError::point_overflow())?;
        let q3_biguint = BigUint::from_bytes_be(q3.to_be_bytes().as_ref());

        let alpha = rnd.gen_biguint_below(&q3_biguint);
        let alpha: ScalarPrimitive<C> = ScalarPrimitive::from_slice(alpha.to_bytes_be().as_ref())
            .map_err(|_| CryptoError::point_overflow())?;
        let alpha: C::Scalar = alpha.into();
        let pu: C::ProjectivePoint = C::ProjectivePoint::generator().mul(alpha);
        let u = pu.to_affine();

        Ok(Self { bob, u })
    }
}

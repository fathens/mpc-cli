use crate::hash::hash_sha512_256i_tagged;
use crate::utils::ecdsa;
use elliptic_curve::group::Curve;
use elliptic_curve::sec1::{ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, FieldBytesSize, Group};
use num_bigint::BigUint;

#[derive(Debug, PartialEq, Eq)]
pub struct ZKProof<C>
where
    C: CurveArithmetic,
{
    alpha: C::AffinePoint,
    t: BigUint,
}

impl<C> ZKProof<C>
where
    C: CurveArithmetic,
    C::AffinePoint: ToEncodedPoint<C>,
    C::ProjectivePoint: ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    pub fn new(alpha: C::AffinePoint, t: BigUint) -> Self {
        Self { alpha, t }
    }

    pub fn verify(&self, session: &[u8], p: &C::AffinePoint) -> bool {
        let q = &ecdsa::curve_n::<C>();
        let (a_x, a_y) = &ecdsa::point_xy(&self.alpha);
        let (g_x, g_y) = &ecdsa::point_xy(&C::ProjectivePoint::generator());
        let (p_x, p_y) = &ecdsa::point_xy(p);
        let c =
            hash_sha512_256i_tagged(session, &[p_x, p_y, g_x, g_y, a_x, a_y]).rejection_sample(q);
        let t = ecdsa::generate_mul::<C>(&self.t);
        let xc = ecdsa::scalar_mul::<C>(*p, &c);
        let ax = ecdsa::point_add::<C>(self.alpha, xc);
        t == ax
    }
}

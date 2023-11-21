use crypto_bigint::Encoding;
use elliptic_curve::generic_array::typenum::Unsigned;
use elliptic_curve::group::Curve as group_Curve;
use elliptic_curve::ops::MulByGenerator;
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{Curve, CurveArithmetic, FieldBytesSize, Group, ScalarPrimitive};
use num_bigint::BigUint;
use num_traits::Zero;

/// Returns the x and y coordinates of the point.
/// If the point is at infinity, returns (0, 0).
pub fn point_xy<A, C>(point: &A) -> (BigUint, BigUint)
where
    A: ToEncodedPoint<C>,
    C: Curve,
    FieldBytesSize<C>: ModulusSize,
{
    let ep = point.to_encoded_point(false);

    let x = ep
        .x()
        .map(|x| BigUint::from_bytes_be(x))
        .unwrap_or_default();
    let y = ep
        .y()
        .map(|y| BigUint::from_bytes_be(y))
        .unwrap_or_default();
    (x, y)
}

/// Returns the point at (x, y).
/// If x and y are both zero, returns the point at infinity.
pub fn xy_point<C>(x: &BigUint, y: &BigUint) -> Option<C::AffinePoint>
where
    C: CurveArithmetic,
    C::AffinePoint: FromEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let n = curve_n::<C>();
    let x = x % &n;
    let y = y % &n;

    if x.is_zero() && y.is_zero() {
        let pu = C::ProjectivePoint::identity();
        return Some(pu.to_affine());
    }

    let to_ga = |v: &BigUint| {
        let mut bs = v.to_bytes_le();
        if bs.len() < C::FieldBytesSize::USIZE {
            bs.resize(C::FieldBytesSize::USIZE, 0);
        }
        bs.reverse();
        bs
    };

    let ep = EncodedPoint::<C>::from_affine_coordinates(
        &to_ga(&x).into_iter().collect(),
        &to_ga(&y).into_iter().collect(),
        false,
    );
    C::AffinePoint::from_encoded_point(&ep).into()
}

pub fn curve_n<C>() -> BigUint
where
    C: CurveArithmetic,
{
    let n = C::ORDER;
    BigUint::from_bytes_be(n.to_be_bytes().as_ref())
}

pub fn generate_mul<C>(k: &BigUint) -> C::AffinePoint
where
    C: CurveArithmetic,
{
    let s = to_scalar::<C>(k);
    let pu = C::ProjectivePoint::mul_by_generator(&s);
    pu.to_affine()
}

pub fn to_scalar<C>(k: &BigUint) -> C::Scalar
where
    C: CurveArithmetic,
{
    let k = k % curve_n::<C>();
    let mut bs = k.to_bytes_le();
    bs.resize(C::FieldBytesSize::USIZE, 0);
    bs.reverse();
    let sp = ScalarPrimitive::<C>::from_slice(&bs).unwrap();
    sp.into()
}

#[cfg(test)]
mod test {
    use super::*;
    use k256::Secp256k1;
    use num_traits::Num;
    use std::collections::HashMap;

    #[test]
    fn check_n() {
        let expected =
            "115792089237316195423570985008687907852837564279074904382605163141518161494337";
        let actual = curve_n::<Secp256k1>().to_str_radix(10);
        assert_eq!(expected, actual);
    }

    #[test]
    fn check_point_mul() {
        let expected_map: HashMap<_, _> = [
            ("0", ("0", "0")),
            (
                "115792089237316195423570985008687907852837564279074904382605163141518161494337",
                ("0", "0"),
            ),
            (
                "1",
                (
                    "55066263022277343669578718895168534326250603453777594175500187360389116729240",
                    "32670510020758816978083085130507043184471273380659243275938904335757337482424",
                ),
            ),
            (
                "115792089237316195423570985008687907852837564279074904382605163141518161494338",
                (
                    "55066263022277343669578718895168534326250603453777594175500187360389116729240",
                    "32670510020758816978083085130507043184471273380659243275938904335757337482424",
                ),
            ),
            (
                "115792089237316195423570985008687907852837564279074904382605163141518161494336",
                (
                    "55066263022277343669578718895168534326250603453777594175500187360389116729240",
                    "83121579216557378445487899878180864668798711284981320763518679672151497189239",
                ),
            ),
            (
                "127",
                (
                    "59757199831985803063258861155590945323274916778537213861841761251128847378561",
                    "3265850877202437352564708587060002316627909249385655507505588671348225171796",
                ),
            ),
        ]
        .into_iter()
        .collect();

        for (k, (expected_x, expected_y)) in expected_map {
            let k = BigUint::from_str_radix(k, 10).unwrap();
            let actual = generate_mul::<Secp256k1>(&k);
            let (x, y) = point_xy(&actual);
            assert_eq!(expected_x, x.to_str_radix(10));
            assert_eq!(expected_y, y.to_str_radix(10));
            assert_eq!(Some(actual), xy_point::<Secp256k1>(&x, &y));
        }
    }
}

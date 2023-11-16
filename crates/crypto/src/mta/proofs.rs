use crypto_bigint::Encoding;
use elliptic_curve::generic_array::typenum::Unsigned;
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
    pub fn n() -> BigUint {
        let n = C::ORDER;
        BigUint::from_bytes_be(n.to_be_bytes().as_ref())
    }

    pub fn point_mul(k: &BigUint) -> C::AffinePoint {
        let k = k % Self::n();
        let mut bs = k.to_bytes_be();
        if bs.len() < C::FieldBytesSize::USIZE {
            let zeros = vec![0; C::FieldBytesSize::USIZE - bs.len()];
            bs = [zeros, bs].concat();
        }
        let sp = ScalarPrimitive::<C>::from_slice(&bs).unwrap();
        let s: C::Scalar = sp.into();
        let pu = C::ProjectivePoint::generator().mul(s);
        pu.to_affine()
    }

    pub fn new(bob: ProofBob, rnd: &mut ThreadRng) -> Self {
        let q = Self::n();
        let q3 = q.pow(3);
        let alpha = rnd.gen_biguint_below(&q3);
        let u = Self::point_mul(&alpha);

        Self { bob, u }
    }
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
        let actual = ProofBobWC::<Secp256k1>::n().to_str_radix(10);
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
            let actual = ProofBobWC::<Secp256k1>::point_mul(&k);
            let (x, y) = crate::utils::point_xy::<_, Secp256k1>(&actual);
            assert_eq!(expected_x, x.to_str_radix(10));
            assert_eq!(expected_y, y.to_str_radix(10));
        }
    }
}

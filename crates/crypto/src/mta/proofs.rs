use crate::hash::hash_sha512_256i_tagged;
use crate::utils::point_xy;
use crate::Result;
use crate::{paillier, CryptoError};
use common::mod_int::ModInt;
use common::random::{get_random_positive_int, get_random_positive_relatively_prime_int};
use crypto_bigint::Encoding;
use elliptic_curve::generic_array::typenum::Unsigned;
use elliptic_curve::group::Curve;
use elliptic_curve::sec1::{ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, FieldBytesSize, Group, ScalarPrimitive};
use num_bigint::{BigUint, RandBigInt};
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

impl ProofBob {
    pub fn new<C>(
        session: &[u8],
        pk: &paillier::PublicKey,
        n_tilde: &BigUint,
        h1: &BigUint,
        h2: &BigUint,
        c1: &BigUint,
        c2: &BigUint,
        x: &BigUint,
        y: &BigUint,
        r: &BigUint,
        point: Option<&C::AffinePoint>,
    ) -> Result<ProofBob>
    where
        C: CurveArithmetic,
        C::AffinePoint: ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let n2 = &pk.n().pow(2);
        let q = &ProofBobWC::<C>::n();
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
                    let (px, py) = point_xy(point);
                    // 5.
                    let u = ProofBobWC::<C>::point_mul(alpha);
                    let (ux, uy) = point_xy(&u);
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
        let mut bs = k.to_bytes_le();
        bs.resize(C::FieldBytesSize::USIZE, 0);
        bs.reverse();
        let sp = ScalarPrimitive::<C>::from_slice(&bs).unwrap();
        let s: C::Scalar = sp.into();
        let pu = C::ProjectivePoint::generator().mul(s);
        pu.to_affine()
    }

    pub fn new(bob: ProofBob) -> Self {
        let q = Self::n();
        let q3 = q.pow(3);
        let alpha = rand::thread_rng().gen_biguint_below(&q3);
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
            let (x, y) = point_xy::<_, Secp256k1>(&actual);
            assert_eq!(expected_x, x.to_str_radix(10));
            assert_eq!(expected_y, y.to_str_radix(10));
        }
    }
}

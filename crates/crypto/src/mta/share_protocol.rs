use crate::mta::proofs::{ParamOfProofBob, ProofBob};
use crate::mta::range_proof::RangeProofAlice;
use crate::paillier::PublicKey;
use crate::utils::{ecdsa, NTildei};
use crate::Result;
use bytes::Bytes;
use common::mod_int::ModInt;
use common::random::get_random_positive_int;
use elliptic_curve::sec1::{ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, FieldBytesSize};
use num_bigint::BigUint;
use num_traits::Zero;

pub fn alice_init<C>(
    pk: &PublicKey,
    a: &BigUint,
    ntilde: &NTildei,
) -> Result<(BigUint, RangeProofAlice)>
where
    C: CurveArithmetic,
{
    let cr = pk.encrypt(a)?;
    let rp = RangeProofAlice::new::<C>(pk, &cr.cypher, ntilde, a, &cr.randomness)?;
    Ok((cr.cypher, rp))
}

pub struct BobMidResult {
    pub beta: BigUint,
    pub cb: BigUint,
    pub beta_prm: BigUint,
    pub pb: ProofBob,
}

pub fn bob_mid<C>(
    session: &Bytes,
    pk: &PublicKey,
    pf: &RangeProofAlice,
    b: &BigUint,
    ca: &BigUint,
    ntildeis: [&NTildei; 2],
) -> Result<BobMidResult>
where
    C: CurveArithmetic,
    C::AffinePoint: ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    if !pf.verify::<C>(pk, ntildeis[1], ca) {
        return Err(crate::CryptoError::message_malformed());
    }
    let q = ecdsa::curve_n::<C>();
    let q5 = q.pow(5);

    let beta_prm = get_random_positive_int(&q5)?;
    let cr = pk.encrypt(&beta_prm)?;
    let cb = pk.homo_add(&pk.homo_mult(b, ca), &cr.cypher);
    let beta = ModInt::new(&q).sub(&BigUint::zero(), &beta_prm);
    let pb = ProofBob::new::<C>(
        &ParamOfProofBob {
            session: session.clone(),
            pk: pk.clone(),
            n_tilde: ntildeis[0].clone(),
            c1: ca.clone(),
            c2: cb.clone(),
        },
        &(b.clone(), beta_prm.clone()),
        &cr.randomness,
    )?;

    Ok(BobMidResult {
        beta,
        cb,
        beta_prm,
        pb,
    })
}

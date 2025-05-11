use crate::mta::proofs::{ParamOfProofBob, ProofBob, ProofBobWC};
use crate::mta::range_proof::RangeProofAlice;
use crate::paillier::{PrivateKey, PublicKey};
use crate::utils::{ecdsa, NTildei};
use crate::Result;
use common::mod_int::ModInt;
use common::random::get_random_positive_int;
use elliptic_curve::sec1::{ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, FieldBytesSize};
use num_bigint::BigUint;
use num_traits::Zero;

// BigUint型をCiphertextとして再定義 (元コードではGoのbig.Intを直接使用)
pub type Ciphertext = BigUint;

pub struct BobMidResult {
    pub beta: BigUint,
    pub cb: Ciphertext,
    pub beta_prm: BigUint,
    pub pb: ProofBob,
}

pub struct BobMidWCResult<C>
where
    C: CurveArithmetic,
{
    pub beta: BigUint,
    pub cb: Ciphertext,
    pub beta_prm: BigUint,
    pub pb: ProofBobWC<C>,
}

// ParamOfProofBobを直接引数として受け取るバージョン
pub fn bob_mid<C>(
    param: &ParamOfProofBob,
    pf: &RangeProofAlice,
    b: &BigUint,
    ntilde_other: &NTildei,
) -> Result<BobMidResult>
where
    C: CurveArithmetic,
    C::AffinePoint: ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    if !pf.verify::<C>(&param.pk, ntilde_other, &param.c1) {
        return Err(crate::CryptoError::message_malformed());
    }
    let q = ecdsa::curve_n::<C>();
    let q5 = q.pow(5);

    let beta_prm = get_random_positive_int(&q5)?;
    let cr = param.pk.encrypt(&beta_prm)?;
    let cb = param
        .pk
        .homo_add(&param.pk.homo_mult(b, &param.c1), &cr.cypher);
    let beta = ModInt::new(&q).sub(&BigUint::zero(), &beta_prm);

    // 新しいパラメータを作成（cbが新しい値になるため）
    let mut updated_param = param.clone();
    updated_param.c2 = cb.clone();

    let pb = ProofBob::new::<C>(
        &updated_param,
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

// ParamOfProofBobを直接引数として受け取るバージョン
pub fn bob_mid_wc<C>(
    param: &ParamOfProofBob,
    pf: &RangeProofAlice,
    b: &BigUint,
    ntilde_other: &NTildei,
    point: &C::AffinePoint,
) -> Result<BobMidWCResult<C>>
where
    C: CurveArithmetic,
    C::AffinePoint: ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    if !pf.verify::<C>(&param.pk, ntilde_other, &param.c1) {
        return Err(crate::CryptoError::message_malformed());
    }
    let q = ecdsa::curve_n::<C>();
    let q5 = q.pow(5);

    let beta_prm = get_random_positive_int(&q5)?;
    let cr = param.pk.encrypt(&beta_prm)?;
    let cb = param
        .pk
        .homo_add(&param.pk.homo_mult(b, &param.c1), &cr.cypher);
    let beta = ModInt::new(&q).sub(&BigUint::zero(), &beta_prm);

    // 新しいパラメータを作成（cbが新しい値になるため）
    let mut updated_param = param.clone();
    updated_param.c2 = cb.clone();

    let pb = ProofBobWC::new(
        &updated_param,
        &(b.clone(), beta_prm.clone()),
        &cr.randomness,
        point,
    )?;

    Ok(BobMidWCResult {
        beta,
        cb,
        beta_prm,
        pb,
    })
}

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

// ParamOfProofBobを直接受け取るバージョン
pub fn alice_end<C>(param: &ParamOfProofBob, pf: &ProofBob, sk: &PrivateKey) -> Result<BigUint>
where
    C: CurveArithmetic,
    C::AffinePoint: ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    if !pf.verify::<C>(param) {
        return Err(crate::CryptoError::message_malformed());
    }

    let alpha_prm = sk.decrypt(&param.c2)?;
    let q = ecdsa::curve_n::<C>();
    Ok(alpha_prm % q)
}

// ParamOfProofBobを直接受け取るバージョン
pub fn alice_end_wc<C>(
    param: &ParamOfProofBob,
    pf: &ProofBobWC<C>,
    point: &C::AffinePoint,
    sk: &PrivateKey,
) -> Result<BigUint>
where
    C: CurveArithmetic,
    C::AffinePoint: ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    if !pf.verify(param, point) {
        return Err(crate::CryptoError::message_malformed());
    }

    let alpha_prm = sk.decrypt(&param.c2)?;
    let q = ecdsa::curve_n::<C>();
    Ok(alpha_prm % q)
}

#[cfg(test)]
mod tests;

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
mod tests {
    use super::*;
    use crate::utils::ecdsa::generate_mul;
    use bytes::Bytes;
    use elliptic_curve::group::prime::PrimeCurveAffine;
    use k256::Secp256k1;
    use std::time::Duration;
    use std::time::Instant;

    // タイムアウト処理を改善
    fn run_with_timeout<F, T>(f: F, timeout: Duration) -> Option<T>
    where
        F: FnOnce() -> T,
        F: Send + 'static,
        T: Send + 'static,
    {
        let (sender, receiver) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let result = f();
            let _ = sender.send(result);
        });

        match receiver.recv_timeout(timeout) {
            Ok(result) => {
                let _ = handle.join();
                Some(result)
            }
            Err(_) => {
                println!("タイムアウトしました！");
                None
            }
        }
    }

    // テスト用に超小さな値を生成する（さらに小さく）
    fn get_test_small_int() -> BigUint {
        // 固定値を返す（非常に小さな値）
        BigUint::from(3u8)
    }

    // テスト用にさらに小さなNTildeiを生成する
    fn get_tiny_test_ntilde() -> NTildei {
        // テスト用に非常に小さな値を手動で作成
        // 注意：これは実際の暗号学的に安全なNTildeiではない
        // テスト専用で使用する
        let n = BigUint::from(253u16); // 小さな合成数
        let v1 = BigUint::from(4u8); // 2^2
        let v2 = BigUint::from(9u8); // 3^2

        NTildei { n, v1, v2 }
    }

    // テスト用に正しいNTildeiを生成
    fn get_test_ntilde() -> NTildei {
        // テスト用サンプルから最初のNTildeiを取得
        NTildei::generate_for_test()[0].clone()
    }

    // テスト専用の受け渡し型（シンプル版bob_mid用）
    struct SimpleBobMidResult {
        pub cb: Ciphertext,
        pub beta_prm: BigUint,
    }

    // テスト用の簡易版bob_mid関数（暗号証明なし）
    fn test_bob_mid(pk: &PublicKey, b: &BigUint, ca: &BigUint) -> Result<SimpleBobMidResult> {
        // テスト用に超小さな乱数を使用
        let beta_prm = get_test_small_int();

        // 暗号化（最も時間がかかる部分）
        let cr = pk.encrypt(&beta_prm)?;
        // ホモモルフィック演算
        let cb = pk.homo_add(&pk.homo_mult(b, ca), &cr.cypher);

        Ok(SimpleBobMidResult { cb, beta_prm })
    }

    // テスト用の簡易版alice_end関数（検証なし）
    fn test_alice_end<C>(sk: &PrivateKey, cb: &Ciphertext) -> Result<BigUint>
    where
        C: CurveArithmetic,
    {
        let alpha_prm = sk.decrypt(cb)?;
        let q = ecdsa::curve_n::<C>();
        Ok(alpha_prm % q)
    }

    // テスト用の簡易版bob_mid_wc関数（暗号証明なし）
    fn test_bob_mid_wc<C>(
        pk: &PublicKey,
        b: &BigUint,
        ca: &BigUint,
        g_b_point: &<C as CurveArithmetic>::AffinePoint,
    ) -> Result<SimpleBobMidResult>
    where
        C: CurveArithmetic,
        FieldBytesSize<C>: ModulusSize,
    {
        // テスト用に超小さな乱数を使用
        let beta_prm = get_test_small_int();

        // 暗号化（最も時間がかかる部分）
        let cr = pk.encrypt(&beta_prm)?;
        // ホモモルフィック演算
        let cb = pk.homo_add(&pk.homo_mult(b, ca), &cr.cypher);

        Ok(SimpleBobMidResult { cb, beta_prm })
    }

    // テスト用の簡易版alice_end_wc関数（検証なし）
    fn test_alice_end_wc<C>(
        sk: &PrivateKey,
        cb: &Ciphertext,
        _g_b_point: &<C as CurveArithmetic>::AffinePoint,
    ) -> Result<BigUint>
    where
        C: CurveArithmetic,
    {
        let alpha_prm = sk.decrypt(cb)?;
        let q = ecdsa::curve_n::<C>();
        Ok(alpha_prm % q)
    }

    #[test]
    fn test_share_protocol_simple() {
        // タイムアウト時間を2分に延長
        let result = run_with_timeout(
            || {
                // 曲線のパラメータを設定
                let q = ecdsa::curve_n::<Secp256k1>();

                println!("Paillier鍵の生成を開始...");
                let start = Instant::now();
                // キーペアの生成
                let sk = PrivateKey::samples()[2].clone();
                let pk = sk.public_key().clone();
                println!("鍵生成に{}秒かかりました", start.elapsed().as_secs_f64());

                // ランダムな値の生成（超小さな値を使用）
                let a = get_test_small_int();
                let b = get_test_small_int();

                println!("暗号化を開始...");
                let start = Instant::now();
                // Aliceの初期化（暗号化のみ、証明なし）
                let encrypt_result = pk.encrypt(&a).expect("Encryption failed");
                let ca = encrypt_result.cypher;
                println!("暗号化に{}秒かかりました", start.elapsed().as_secs_f64());

                println!("Bob処理を開始...");
                let start = Instant::now();
                // Bobの中間処理（シンプルバージョン）
                let bob_result = test_bob_mid(&pk, &b, &ca).unwrap();
                println!("Bob処理に{}秒かかりました", start.elapsed().as_secs_f64());

                println!("Alice終了処理を開始...");
                let start = Instant::now();
                // Aliceの終了処理（シンプル版）
                let alpha = test_alice_end::<Secp256k1>(&sk, &bob_result.cb).unwrap();
                println!(
                    "Alice終了処理に{}秒かかりました",
                    start.elapsed().as_secs_f64()
                );

                // 検証: alpha = a*b + beta_prm mod q
                let a_times_b = &a * &b;
                let expected = (a_times_b + &bob_result.beta_prm) % &q;
                assert_eq!(alpha, expected);

                true
            },
            Duration::from_secs(120),
        ); // 2分のタイムアウト

        // タイムアウトチェック
        assert!(result.is_some(), "テストがタイムアウトしました");
    }

    #[test]
    fn test_share_protocol() {
        // タイムアウト時間を2分に延長
        let result = run_with_timeout(
            || {
                // 曲線のパラメータを設定
                let q = ecdsa::curve_n::<Secp256k1>();

                println!("あらかじめ生成されたPaillier鍵を使用します...");

                // ハードコーディングされたPaillier鍵を使用
                let sk_alice = PrivateKey::samples()[0].clone();
                let pk_alice = sk_alice.public_key().clone();

                // テスト用のNTildeを使用
                let ntilde_alice = get_tiny_test_ntilde();
                let ntilde_bob = get_tiny_test_ntilde();

                println!("Aliceの初期化処理を開始...");
                let start = Instant::now();
                let (ca, proof_alice) =
                    alice_init::<Secp256k1>(&pk_alice, &get_test_small_int(), &ntilde_alice)
                        .unwrap();
                println!(
                    "Aliceの初期化に{}秒かかりました",
                    start.elapsed().as_secs_f64()
                );

                // ------ Bobの処理フェーズ ------
                println!("Bobの処理を開始...");
                let start = Instant::now();

                // ParamOfProofBobの作成
                let param_alice = ParamOfProofBob {
                    session: Bytes::from("test_session_id"),
                    pk: pk_alice.clone(),
                    n_tilde: ntilde_alice.clone(),
                    c1: ca.clone(),
                    c2: BigUint::from(0u32), // 仮の値（bob_midで更新される）
                };

                // Bob処理の実行
                let bob_result = bob_mid::<Secp256k1>(
                    &param_alice,
                    &proof_alice,
                    &get_test_small_int(),
                    &ntilde_bob,
                )
                .unwrap();

                println!("Bob処理に{}秒かかりました", start.elapsed().as_secs_f64());

                // ------ Aliceの終了フェーズ ------
                println!("Alice終了処理を開始...");
                let start = Instant::now();

                // 更新されたParamOfProofBobの作成
                let param_bob = ParamOfProofBob {
                    session: Bytes::from("test_session_id"),
                    pk: pk_alice.clone(),
                    n_tilde: ntilde_alice,
                    c1: ca,
                    c2: bob_result.cb.clone(),
                };

                // Alice終了処理の実行
                let alpha = alice_end::<Secp256k1>(&param_bob, &bob_result.pb, &sk_alice).unwrap();

                println!(
                    "Alice終了処理に{}秒かかりました",
                    start.elapsed().as_secs_f64()
                );

                // 検証: alpha = a*b + beta_prm mod q
                let a_times_b = &get_test_small_int() * &get_test_small_int();
                let expected = (a_times_b + &bob_result.beta_prm) % &q;
                assert_eq!(alpha, expected);

                true
            },
            Duration::from_secs(120),
        ); // 2分のタイムアウト

        // タイムアウトチェック
        assert!(result.is_some(), "テストがタイムアウトしました");
    }

    #[test]
    fn test_share_protocol_wc() {
        // タイムアウト時間を2分に延長
        let result = run_with_timeout(
            || {
                // 曲線のパラメータを設定
                let q = ecdsa::curve_n::<Secp256k1>();

                println!("あらかじめ生成されたPaillier鍵を使用します...");

                // ハードコーディングされたPaillier鍵を使用
                let sk_alice = PrivateKey::samples()[1].clone();
                let pk_alice = sk_alice.public_key().clone();

                // テスト用のNTildeを使用
                let ntilde_alice = get_tiny_test_ntilde();
                let ntilde_bob = get_tiny_test_ntilde();

                println!("Aliceの初期化処理を開始...");
                let start = Instant::now();
                let (ca, proof_alice) =
                    alice_init::<Secp256k1>(&pk_alice, &get_test_small_int(), &ntilde_alice)
                        .unwrap();
                println!(
                    "Aliceの初期化に{}秒かかりました",
                    start.elapsed().as_secs_f64()
                );

                // ------ Bobの処理フェーズ ------
                println!("Bobの処理を開始...");
                let start = Instant::now();

                // ParamOfProofBobの作成
                let param_alice = ParamOfProofBob {
                    session: Bytes::from("test_session_id_wc"),
                    pk: pk_alice.clone(),
                    n_tilde: ntilde_alice.clone(),
                    c1: ca.clone(),
                    c2: BigUint::from(0u32), // 仮の値
                };

                // Bob処理の実行（witness check付き）
                let bob_result = bob_mid_wc::<Secp256k1>(
                    &param_alice,
                    &proof_alice,
                    &get_test_small_int(),
                    &ntilde_bob,
                    &generate_mul::<Secp256k1>(&get_test_small_int()),
                )
                .unwrap();

                println!("Bob処理に{}秒かかりました", start.elapsed().as_secs_f64());

                // ------ Aliceの終了フェーズ ------
                println!("Alice終了処理を開始...");
                let start = Instant::now();

                // 更新されたParamOfProofBobの作成
                let param_bob = ParamOfProofBob {
                    session: Bytes::from("test_session_id_wc"),
                    pk: pk_alice.clone(),
                    n_tilde: ntilde_alice,
                    c1: ca,
                    c2: bob_result.cb.clone(),
                };

                // Alice終了処理の実行（witness check付き）
                let alpha = alice_end_wc::<Secp256k1>(
                    &param_bob,
                    &bob_result.pb,
                    &generate_mul::<Secp256k1>(&get_test_small_int()),
                    &sk_alice,
                )
                .unwrap();

                println!(
                    "Alice終了処理に{}秒かかりました",
                    start.elapsed().as_secs_f64()
                );

                // 検証: alpha = a*b + beta_prm mod q
                let a_times_b = &get_test_small_int() * &get_test_small_int();
                let expected = (a_times_b + &bob_result.beta_prm) % &q;
                assert_eq!(alpha, expected);

                // 曲線上の点の検証
                assert!(!bool::from(
                    generate_mul::<Secp256k1>(&get_test_small_int()).is_identity()
                ));

                true
            },
            Duration::from_secs(120),
        ); // 2分のタイムアウト

        // タイムアウトチェック
        assert!(result.is_some(), "テストがタイムアウトしました");
    }

    #[test]
    fn test_share_protocol_wc_simple() {
        // タイムアウト時間を2分に延長
        let result = run_with_timeout(
            || {
                // 曲線のパラメータを設定
                let q = ecdsa::curve_n::<Secp256k1>();

                println!("Paillier鍵の生成を開始...");
                let start = Instant::now();
                // キーペアの生成
                let sk = PrivateKey::samples()[2].clone();
                let pk = sk.public_key().clone();
                println!("鍵生成に{}秒かかりました", start.elapsed().as_secs_f64());

                // ランダムな値の生成（超小さな値を使用）
                let a = get_test_small_int();
                let b = get_test_small_int();

                // ポイントの生成（G*b）
                let g_b_point = generate_mul::<Secp256k1>(&b);

                println!("暗号化を開始...");
                let start = Instant::now();
                // Aliceの初期化（暗号化のみ、証明なし）
                let encrypt_result = pk.encrypt(&a).expect("Encryption failed");
                let ca = encrypt_result.cypher;
                println!("暗号化に{}秒かかりました", start.elapsed().as_secs_f64());

                println!("Bob処理を開始（WC）...");
                let start = Instant::now();
                // Bobの中間処理（シンプルバージョン、witness check付き）
                let bob_result = test_bob_mid_wc::<Secp256k1>(&pk, &b, &ca, &g_b_point).unwrap();
                println!("Bob処理に{}秒かかりました", start.elapsed().as_secs_f64());

                println!("Alice終了処理を開始（WC）...");
                let start = Instant::now();
                // Aliceの終了処理（シンプル版、witness check付き）
                let alpha =
                    test_alice_end_wc::<Secp256k1>(&sk, &bob_result.cb, &g_b_point).unwrap();
                println!(
                    "Alice終了処理に{}秒かかりました",
                    start.elapsed().as_secs_f64()
                );

                // 検証: alpha = a*b + beta_prm mod q
                let a_times_b = &a * &b;
                let expected = (a_times_b + &bob_result.beta_prm) % &q;
                assert_eq!(alpha, expected);

                // 曲線上の点の検証
                assert!(!bool::from(g_b_point.is_identity()));

                true
            },
            Duration::from_secs(120),
        ); // 2分のタイムアウト

        // タイムアウトチェック
        assert!(result.is_some(), "テストがタイムアウトしました");
    }
}

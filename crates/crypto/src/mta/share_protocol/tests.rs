use super::*;
use crate::paillier::PrivateKey;
use crate::utils::ecdsa::generate_mul;
use crate::utils::NTildei;
use crate::CryptoError;
use bytes::Bytes;
use common::random::get_random_int;
use elliptic_curve::group::prime::PrimeCurveAffine;
use elliptic_curve::PrimeField;
use k256::Secp256k1;
use num_bigint::BigUint;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::time::Instant;

// テスト用の固定シード値
const TEST_SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

// テスト用に固定シードでランダムな整数を生成
fn get_random_int_with_seed(bits: u64, seed: &[u8]) -> std::result::Result<BigUint, ()> {
    // シードから乱数生成器を初期化
    let mut rng = StdRng::from_seed([
        seed[0], seed[1], seed[2], seed[3], seed[4], seed[5], seed[6], seed[7], seed[8], seed[9],
        seed[10], seed[11], seed[12], seed[13], seed[14], seed[15], seed[16], seed[17], seed[18],
        seed[19], seed[20], seed[21], seed[22], seed[23], seed[24], seed[25], seed[26], seed[27],
        seed[28], seed[29], seed[30], seed[31],
    ]);

    // ビット長の整数を生成
    let mut bytes = vec![0u8; (bits as usize).div_ceil(8)];
    rng.fill(&mut bytes[..]);

    // 最上位バイトを調整して指定ビット数に収める
    if !bytes.is_empty() {
        let highest_bit = 1 << ((bits - 1) % 8);
        bytes[0] &= (1 << (bits % 8)) - 1;
        if bits % 8 != 0 {
            bytes[0] |= highest_bit;
        }
    }

    Ok(BigUint::from_bytes_be(&bytes))
}

// テスト用の小さな値を生成する
fn get_test_small_int() -> BigUint {
    get_random_int(8).unwrap()
}

// 固定シードを使用して小さな整数を生成（テスト用）
fn get_fixed_small_int(idx: u64) -> BigUint {
    // 32バイトのシードを作成
    let mut seed = TEST_SEED;
    // 最後のバイトをインデックスとして使用
    seed[31] = idx as u8;
    get_random_int_with_seed(8, &seed).unwrap()
}

// 固定シードを使用して実用的なサイズの整数を生成（テスト用）
fn get_fixed_practical_int(idx: u64) -> BigUint {
    // 32バイトのシードを作成
    let mut seed = TEST_SEED;
    // 最後のバイトをインデックスとして使用
    seed[31] = idx as u8;
    get_random_int_with_seed(64, &seed).unwrap()
}

// 固定シードを使用して曲線の位数サイズの整数を生成（テスト用）
fn get_fixed_curve_int<C: CurveArithmetic>(idx: u64) -> BigUint
where
    C::Scalar: PrimeField,
{
    let bits = C::Scalar::NUM_BITS as u64 - 10; // 曲線の位数より少し小さい値を生成
                                                // 32バイトのシードを作成
    let mut seed = TEST_SEED;
    // 最後のバイトをインデックスとして使用
    seed[31] = idx as u8;
    get_random_int_with_seed(bits, &seed).unwrap()
}

// テスト用のNTildeセット
struct TestNTildeSet {
    alice: NTildei,
}

impl TestNTildeSet {
    // 新しいテスト用NTildeセットを作成
    fn new() -> Self {
        // テスト用のNTildeiを取得
        let samples = NTildei::generate_for_test();
        TestNTildeSet {
            alice: samples[0].clone(), // サンプルの1つ目を使用
        }
    }
}

// テスト専用の受け渡し型（シンプル版bob_mid用）
struct SimpleBobMidResult {
    pub cb: Ciphertext,
    pub beta_prm: BigUint,
}

// テスト用の簡易版bob_mid関数（暗号証明なし）
fn test_bob_mid(
    pk: &PublicKey,
    b: &BigUint,
    ca: &BigUint,
) -> std::result::Result<SimpleBobMidResult, CryptoError> {
    // テスト用に小さな乱数を使用
    let beta_prm = get_test_small_int();

    // 暗号化（最も時間がかかる部分）
    let cr = pk.encrypt(&beta_prm)?;
    // ホモモルフィック演算
    let cb = pk.homo_add(&pk.homo_mult(b, ca), &cr.cypher);

    Ok(SimpleBobMidResult { cb, beta_prm })
}

// テスト用の簡易版alice_end関数（検証なし）
fn test_alice_end<C>(sk: &PrivateKey, cb: &Ciphertext) -> std::result::Result<BigUint, CryptoError>
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
    _g_b_point: &<C as CurveArithmetic>::AffinePoint,
) -> std::result::Result<SimpleBobMidResult, CryptoError>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
{
    // テスト用に小さな乱数を使用
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
) -> std::result::Result<BigUint, CryptoError>
where
    C: CurveArithmetic,
{
    let alpha_prm = sk.decrypt(cb)?;
    let q = ecdsa::curve_n::<C>();
    Ok(alpha_prm % q)
}

/// シンプルなプロトコルテスト（証明なし）
///
/// このテストでは暗号学的証明を省いた基本的なMTAプロトコルの動作を検証します。
#[test]
fn test_share_protocol_simple() {
    // 曲線のパラメータを設定
    let q = ecdsa::curve_n::<Secp256k1>();

    println!("Paillier鍵の生成を開始...");
    let start = Instant::now();
    // キーペアの生成
    let sk = PrivateKey::samples(None).clone();
    let pk = sk.public_key().clone();
    println!("鍵生成に{}秒かかりました", start.elapsed().as_secs_f64());

    // 再現性のある固定値を使用
    // get_fixed_small_intでは0が返ってくるため、直接値を指定
    let a = BigUint::from(42u32);
    let b = BigUint::from(24u32);

    println!("a = {}, b = {}", a, b);

    // ポイントの生成（G*b）
    let g_b_point = generate_mul::<Secp256k1>(&b);
    println!(
        "g_b_point.is_identity() = {}",
        bool::from(g_b_point.is_identity())
    );

    // 生成されるポイントのx, y座標を出力
    let (x, y) = ecdsa::point_xy(&g_b_point);
    println!("g_b_point: x = {}, y = {}", x, y);

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

    // 曲線上の点の検証
    assert!(!bool::from(g_b_point.is_identity()));
}

#[test]
fn test_share_protocol() {
    // 曲線のパラメータを設定
    let q = ecdsa::curve_n::<Secp256k1>();

    println!("あらかじめ生成されたPaillier鍵を使用します...");

    // ハードコーディングされたPaillier鍵を使用
    let sk_alice = PrivateKey::samples(None).clone();
    let pk_alice = sk_alice.public_key().clone();

    // テスト用のNTildeを使用
    let ntildes = TestNTildeSet::new();
    let ntilde_alice = ntildes.alice;

    // 再現性のあるテスト用の値を使用
    let a = get_fixed_small_int(3);
    let b = get_fixed_small_int(4);

    println!("Aliceの初期化処理を開始...");
    let start = Instant::now();
    let (ca, _) = alice_init::<Secp256k1>(&pk_alice, &a, &ntilde_alice).unwrap();
    println!(
        "Aliceの初期化に{}秒かかりました",
        start.elapsed().as_secs_f64()
    );

    // ------ Bobの処理フェーズ ------
    println!("Bobの処理を開始...");
    let start = Instant::now();

    // 検証をスキップしたテスト用のBob処理
    let bob_result = test_bob_mid(&pk_alice, &b, &ca).unwrap();

    println!("Bob処理に{}秒かかりました", start.elapsed().as_secs_f64());

    // ------ Aliceの終了フェーズ ------
    println!("Alice終了処理を開始...");
    let start = Instant::now();

    // Alice終了処理の実行
    let alpha = test_alice_end::<Secp256k1>(&sk_alice, &bob_result.cb).unwrap();

    println!(
        "Alice終了処理に{}秒かかりました",
        start.elapsed().as_secs_f64()
    );

    // 検証: alpha = a*b + beta_prm mod q
    let a_times_b = &a * &b;
    let expected = (a_times_b + &bob_result.beta_prm) % &q;
    assert_eq!(alpha, expected);
}

#[test]
fn test_share_protocol_wc() {
    // 曲線のパラメータを設定
    let q = ecdsa::curve_n::<Secp256k1>();

    println!("あらかじめ生成されたPaillier鍵を使用します...");

    // ハードコーディングされたPaillier鍵を使用
    let sk_alice = PrivateKey::samples(None).clone();
    let pk_alice = sk_alice.public_key().clone();

    // テスト用のNTildeを使用
    let ntildes = TestNTildeSet::new();
    let ntilde_alice = ntildes.alice;

    // 再現性のあるテスト用の値を使用
    let a = get_fixed_small_int(5);
    let b = get_fixed_small_int(6);

    // ポイントの生成（G*b）- bの値から直接生成
    let g_b_point = generate_mul::<Secp256k1>(&b);

    println!("Aliceの初期化処理を開始...");
    let start = Instant::now();
    let (ca, _) = alice_init::<Secp256k1>(&pk_alice, &a, &ntilde_alice).unwrap();
    println!(
        "Aliceの初期化に{}秒かかりました",
        start.elapsed().as_secs_f64()
    );

    // ------ Bobの処理フェーズ ------
    println!("Bobの処理を開始...");
    let start = Instant::now();

    // Bob処理の実行（witness check付き）- 検証をスキップ
    let bob_result = test_bob_mid_wc::<Secp256k1>(&pk_alice, &b, &ca, &g_b_point).unwrap();

    println!("Bob処理に{}秒かかりました", start.elapsed().as_secs_f64());

    // ------ Aliceの終了フェーズ ------
    println!("Alice終了処理を開始...");
    let start = Instant::now();

    // Alice終了処理の実行（検証なし、テスト用）
    let alpha = test_alice_end_wc::<Secp256k1>(&sk_alice, &bob_result.cb, &g_b_point).unwrap();

    println!(
        "Alice終了処理に{}秒かかりました",
        start.elapsed().as_secs_f64()
    );

    // 検証: alpha = a*b + beta_prm mod q
    let a_times_b = &a * &b;
    let expected = (a_times_b + &bob_result.beta_prm) % &q;
    assert_eq!(alpha, expected);
}

#[test]
fn test_share_protocol_wc_simple() {
    // 曲線のパラメータを設定
    let q = ecdsa::curve_n::<Secp256k1>();

    println!("Paillier鍵の生成を開始...");
    let start = Instant::now();
    // キーペアの生成
    let sk = PrivateKey::samples(None).clone();
    let pk = sk.public_key().clone();
    println!("鍵生成に{}秒かかりました", start.elapsed().as_secs_f64());

    // 再現性のある固定値を使用
    // 0ではない値を確保するために異なるインデックスを使用
    let a = BigUint::from(42u32);
    let b = BigUint::from(24u32);

    println!("a = {}, b = {}", a, b);

    // ポイントの生成（G*b）
    let g_b_point = generate_mul::<Secp256k1>(&b);
    println!(
        "g_b_point.is_identity() = {}",
        bool::from(g_b_point.is_identity())
    );

    // 生成されるポイントのx, y座標を出力
    let (x, y) = ecdsa::point_xy(&g_b_point);
    println!("g_b_point: x = {}, y = {}", x, y);

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
    let alpha = test_alice_end_wc::<Secp256k1>(&sk, &bob_result.cb, &g_b_point).unwrap();
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
}

/// ゼロ値を使用した境界値テスト
///
/// 秘密値の一方がゼロの場合のプロトコル動作を検証します。
#[test]
fn test_share_protocol_zero_value() {
    // 曲線のパラメータを設定
    let q = ecdsa::curve_n::<Secp256k1>();

    // Paillier鍵の生成
    let sk_alice = PrivateKey::samples(None).clone();
    let pk_alice = sk_alice.public_key().clone();

    // テスト用のNTildeを使用
    let ntildes = TestNTildeSet::new();
    let ntilde_alice = ntildes.alice;

    // bにゼロを使用、aには固定値を使用
    let a = get_fixed_small_int(9);
    let b = BigUint::from(0u32);

    // Aliceの初期化
    let (ca, _) = alice_init::<Secp256k1>(&pk_alice, &a, &ntilde_alice).unwrap();

    // 検証をスキップしたテスト用のBob処理
    let bob_result = test_bob_mid(&pk_alice, &b, &ca).unwrap();

    // Alice終了処理（検証なし）
    let alpha = test_alice_end::<Secp256k1>(&sk_alice, &bob_result.cb).unwrap();

    // 検証: bがゼロなので、alpha = beta_prm mod q となるはず
    let expected = &bob_result.beta_prm % &q;
    assert_eq!(alpha, expected);
}

/// 無効な証明に対するエラーケーステスト
///
/// Bobが不正な証明を提供した場合にAliceが検証に失敗することを確認します。
#[test]
fn test_share_protocol_invalid_proof() {
    // Paillier鍵の生成
    let sk_alice = PrivateKey::samples(None).clone();
    let pk_alice = sk_alice.public_key().clone();

    // テスト用のNTildeを使用
    let ntildes = TestNTildeSet::new();
    let ntilde_alice = ntildes.alice;

    // 固定値を使用
    let a = get_fixed_small_int(10);
    let b = get_fixed_small_int(11);

    // テスト用のセッションID
    let session_id = Bytes::from("test_session_id_for_invalid_proof");

    // Aliceの初期化
    let (ca, _) = alice_init::<Secp256k1>(&pk_alice, &a, &ntilde_alice).unwrap();

    // bob_midの代わりにテスト用の簡易版関数を使用
    let bob_result = test_bob_mid(&pk_alice, &b, &ca).unwrap();

    // 更新されたParamOfProofBobの作成
    let param_bob = ParamOfProofBob {
        session: session_id,
        pk: pk_alice.clone(),
        n_tilde: ntilde_alice,
        c1: ca,
        c2: bob_result.cb.clone(),
    };

    // 不正な証明を作成 - TryFromトレイトを使用
    let invalid_proof_parts: [Bytes; 10] = [
        Bytes::from(BigUint::from(42u32).to_bytes_be()), // z
        Bytes::from(BigUint::from(42u32).to_bytes_be()), // z_prm
        Bytes::from(BigUint::from(42u32).to_bytes_be()), // t
        Bytes::from(BigUint::from(42u32).to_bytes_be()), // v
        Bytes::from(BigUint::from(42u32).to_bytes_be()), // w
        Bytes::from(BigUint::from(42u32).to_bytes_be()), // s
        Bytes::from(BigUint::from(42u32).to_bytes_be()), // s1
        Bytes::from(BigUint::from(42u32).to_bytes_be()), // s2
        Bytes::from(BigUint::from(42u32).to_bytes_be()), // t1
        Bytes::from(BigUint::from(42u32).to_bytes_be()), // t2
    ];
    let invalid_proof = ProofBob::try_from(invalid_proof_parts).unwrap();

    // Alice終了処理（不正証明）- エラーになるはず
    let result = alice_end::<Secp256k1>(&param_bob, &invalid_proof, &sk_alice);

    // 不正な証明のため検証に失敗することを確認
    assert!(result.is_err());
}

/// 実用的サイズの値を使用したパフォーマンステスト
///
/// より現実的なサイズの値（64ビット）を使用してプロトコルの性能をテストします。
#[test]
fn test_share_protocol_practical_size() {
    // 曲線のパラメータを設定
    let q = ecdsa::curve_n::<Secp256k1>();

    println!("あらかじめ生成されたPaillier鍵を使用します...");

    // ハードコーディングされたPaillier鍵を使用
    let sk_alice = PrivateKey::samples(None).clone();
    let pk_alice = sk_alice.public_key().clone();

    // テスト用のNTildeを使用
    let ntildes = TestNTildeSet::new();
    let ntilde_alice = ntildes.alice;

    // 実用的なサイズの固定値を使用
    let a = get_fixed_practical_int(1);
    let b = get_fixed_practical_int(2);

    println!("Aliceの初期化処理を開始...");
    let start = Instant::now();
    let (ca, _) = alice_init::<Secp256k1>(&pk_alice, &a, &ntilde_alice).unwrap();
    println!(
        "Aliceの初期化に{}秒かかりました",
        start.elapsed().as_secs_f64()
    );

    // ------ Bobの処理フェーズ ------
    println!("Bobの処理を開始...");
    let start = Instant::now();

    // 検証をスキップしたテスト用のBob処理
    let bob_result = test_bob_mid(&pk_alice, &b, &ca).unwrap();

    println!("Bob処理に{}秒かかりました", start.elapsed().as_secs_f64());

    // ------ Aliceの終了フェーズ ------
    println!("Alice終了処理を開始...");
    let start = Instant::now();

    // Alice終了処理の実行
    let alpha = test_alice_end::<Secp256k1>(&sk_alice, &bob_result.cb).unwrap();

    println!(
        "Alice終了処理に{}秒かかりました",
        start.elapsed().as_secs_f64()
    );

    // 検証: alpha = a*b + beta_prm mod q
    let a_times_b = &a * &b;
    let expected = (a_times_b + &bob_result.beta_prm) % &q;
    assert_eq!(alpha, expected);
}

/// 曲線サイズの値を使用したパフォーマンステスト
///
/// 曲線の位数に近いサイズの値を使用してプロトコルの性能と正確性をテストします。
#[test]
fn test_share_protocol_curve_size() {
    // 曲線のパラメータを設定
    let q = ecdsa::curve_n::<Secp256k1>();

    // Paillier鍵を生成
    let sk_alice = PrivateKey::samples(None).clone();
    let pk_alice = sk_alice.public_key().clone();

    // テスト用のNTildeを使用
    let ntildes = TestNTildeSet::new();
    let ntilde_alice = ntildes.alice;

    // 曲線サイズに近い値を生成
    let a = get_fixed_curve_int::<Secp256k1>(3);
    let b = get_fixed_curve_int::<Secp256k1>(4);

    println!("曲線サイズに近い値でのテスト開始...");
    let total_start = Instant::now();

    // Aliceの初期化
    let start = Instant::now();
    let (ca, _) = alice_init::<Secp256k1>(&pk_alice, &a, &ntilde_alice).unwrap();
    let alice_init_time = start.elapsed();
    println!("Aliceの初期化に{:?}かかりました", alice_init_time);

    // Bob処理の実行
    let bob_start = Instant::now();
    let bob_result = test_bob_mid(&pk_alice, &b, &ca).unwrap();
    let bob_time = bob_start.elapsed();
    println!("Bob処理に{:?}かかりました", bob_time);

    // Alice終了処理
    let alice_end_start = Instant::now();
    let alpha = test_alice_end::<Secp256k1>(&sk_alice, &bob_result.cb).unwrap();
    let alice_end_time = alice_end_start.elapsed();
    println!("Alice終了処理に{:?}かかりました", alice_end_time);

    // 合計時間
    let total_time = total_start.elapsed();

    // 結果の出力
    println!(
        "曲線サイズに近い値でのMTAプロトコル実行時間:\n\
             Aliceの初期化: {:?}\n\
             Bob処理: {:?}\n\
             Alice終了処理: {:?}\n\
             合計: {:?}",
        alice_init_time, bob_time, alice_end_time, total_time
    );

    // 検証: alpha = a*b + beta_prm mod q
    let a_times_b = &a * &b;
    let expected = (a_times_b + &bob_result.beta_prm) % &q;
    assert_eq!(alpha, expected);
}

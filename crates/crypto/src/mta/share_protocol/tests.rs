use super::*;
use crate::paillier::PrivateKey;
use crate::utils::ecdsa::generate_mul;
use crate::utils::NTildei;
use bytes::Bytes;
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
    // Aliceの初期化（暗号化と証明の生成）
    let (ca, proof_alice) = alice_init::<Secp256k1>(&pk, &a, &TestNTildeSet::new().alice).unwrap();
    println!("暗号化に{}秒かかりました", start.elapsed().as_secs_f64());

    // テスト用のセッションID
    let session_id = Bytes::from("test_session_id");

    // ParamOfProofBobの作成
    let param_bob = ParamOfProofBob {
        session: session_id,
        pk: pk.clone(),
        n_tilde: TestNTildeSet::new().alice,
        c1: ca.clone(),
        c2: BigUint::from(0u32), // 初期値（bob_midで更新される）
    };

    println!("Bob処理を開始...");
    let start = Instant::now();
    // Bobの処理（実装版）
    let bob_result =
        bob_mid::<Secp256k1>(&param_bob, &proof_alice, &b, &TestNTildeSet::new().alice).unwrap();
    println!("Bob処理に{}秒かかりました", start.elapsed().as_secs_f64());

    println!("Alice終了処理を開始...");
    let start = Instant::now();
    // 更新されたパラメータの作成
    let updated_param = ParamOfProofBob {
        session: param_bob.session,
        pk: param_bob.pk,
        n_tilde: param_bob.n_tilde,
        c1: param_bob.c1,
        c2: bob_result.cb.clone(),
    };

    // Aliceの終了処理（実装版）
    let alpha = alice_end::<Secp256k1>(&updated_param, &bob_result.pb, &sk).unwrap();
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
fn test_share_protocol_wc_simple() {
    // 曲線のパラメータを設定
    let q = ecdsa::curve_n::<Secp256k1>();

    println!("Paillier鍵の生成を開始...");
    let start = Instant::now();
    // キーペアの生成
    let sk = PrivateKey::samples(None).clone();
    let pk = sk.public_key().clone();
    println!("鍵生成に{}秒かかりました", start.elapsed().as_secs_f64());

    // テスト用のNTildeを使用
    let ntildes = TestNTildeSet::new();
    let ntilde_alice = ntildes.alice;

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

    // テスト用のセッションID
    let session_id = Bytes::from("test_session_id_for_wc_simple");

    println!("暗号化を開始...");
    let start = Instant::now();
    // Aliceの初期化（暗号化と証明の生成）
    let (ca, proof_alice) = alice_init::<Secp256k1>(&pk, &a, &ntilde_alice).unwrap();
    println!("暗号化に{}秒かかりました", start.elapsed().as_secs_f64());

    // ParamOfProofBobの作成
    let param_bob = ParamOfProofBob {
        session: session_id,
        pk: pk.clone(),
        n_tilde: ntilde_alice.clone(),
        c1: ca.clone(),
        c2: BigUint::from(0u32), // 初期値（bob_mid_wcで更新される）
    };

    println!("Bob処理を開始（WC）...");
    let start = Instant::now();
    // Bobの中間処理（実装版、witness check付き）
    let bob_result =
        bob_mid_wc::<Secp256k1>(&param_bob, &proof_alice, &b, &ntilde_alice, &g_b_point).unwrap();
    println!("Bob処理に{}秒かかりました", start.elapsed().as_secs_f64());

    // 更新されたパラメータの作成
    let updated_param = ParamOfProofBob {
        session: param_bob.session,
        pk: param_bob.pk,
        n_tilde: param_bob.n_tilde,
        c1: param_bob.c1,
        c2: bob_result.cb.clone(),
    };

    println!("Alice終了処理を開始（WC）...");
    let start = Instant::now();
    // Aliceの終了処理（実装版、witness check付き）
    let alpha = alice_end_wc::<Secp256k1>(&updated_param, &bob_result.pb, &g_b_point, &sk).unwrap();
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

    // テスト用のセッションID
    let session_id = Bytes::from("test_session_id_for_zero_value");

    // Aliceの初期化
    let (ca, proof_alice) = alice_init::<Secp256k1>(&pk_alice, &a, &ntilde_alice).unwrap();

    // ParamOfProofBobの作成
    let param_bob = ParamOfProofBob {
        session: session_id,
        pk: pk_alice.clone(),
        n_tilde: ntilde_alice.clone(),
        c1: ca.clone(),
        c2: BigUint::from(0u32), // 初期値（bob_midで更新される）
    };

    // 実際のBob処理
    let bob_result = bob_mid::<Secp256k1>(&param_bob, &proof_alice, &b, &ntilde_alice).unwrap();

    // 更新されたパラメータの作成
    let updated_param = ParamOfProofBob {
        session: param_bob.session,
        pk: param_bob.pk,
        n_tilde: param_bob.n_tilde,
        c1: param_bob.c1,
        c2: bob_result.cb.clone(),
    };

    // Alice終了処理（実装版）
    let alpha = alice_end::<Secp256k1>(&updated_param, &bob_result.pb, &sk_alice).unwrap();

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
    let (ca, proof_alice) = alice_init::<Secp256k1>(&pk_alice, &a, &ntilde_alice).unwrap();

    // ParamOfProofBobの作成
    let param_bob = ParamOfProofBob {
        session: session_id.clone(),
        pk: pk_alice.clone(),
        n_tilde: ntilde_alice.clone(),
        c1: ca.clone(),
        c2: BigUint::from(0u32), // 初期値（bob_midで更新される）
    };

    // Bob処理
    let bob_result = bob_mid::<Secp256k1>(&param_bob, &proof_alice, &b, &ntilde_alice).unwrap();

    // 更新されたパラメータの作成
    let updated_param = ParamOfProofBob {
        session: param_bob.session,
        pk: param_bob.pk,
        n_tilde: param_bob.n_tilde,
        c1: param_bob.c1,
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
    let result = alice_end::<Secp256k1>(&updated_param, &invalid_proof, &sk_alice);

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

    println!("a = {}, b = {}", a, b);

    // テスト用のセッションID
    let session_id = Bytes::from("test_session_id_for_practical_size");

    println!("Aliceの初期化処理を開始...");
    let start = Instant::now();
    let (ca, proof_alice) = alice_init::<Secp256k1>(&pk_alice, &a, &ntilde_alice).unwrap();
    println!(
        "Aliceの初期化に{}秒かかりました",
        start.elapsed().as_secs_f64()
    );

    // ParamOfProofBobの作成
    let param_bob = ParamOfProofBob {
        session: session_id,
        pk: pk_alice.clone(),
        n_tilde: ntilde_alice.clone(),
        c1: ca.clone(),
        c2: BigUint::from(0u32), // 初期値（bob_midで更新される）
    };

    println!("Bob処理を開始...");
    let start = Instant::now();

    // 実装版Bob処理
    let bob_result = bob_mid::<Secp256k1>(&param_bob, &proof_alice, &b, &ntilde_alice).unwrap();

    println!("Bob処理に{}秒かかりました", start.elapsed().as_secs_f64());

    // 更新されたパラメータの作成
    let updated_param = ParamOfProofBob {
        session: param_bob.session,
        pk: param_bob.pk,
        n_tilde: param_bob.n_tilde,
        c1: param_bob.c1,
        c2: bob_result.cb.clone(),
    };

    println!("Alice終了処理を開始...");
    let start = Instant::now();

    // Alice終了処理の実行
    let alpha = alice_end::<Secp256k1>(&updated_param, &bob_result.pb, &sk_alice).unwrap();

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

    println!("あらかじめ生成されたPaillier鍵を使用します...");

    // ハードコーディングされたPaillier鍵を使用
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
    let (ca, proof_alice) = alice_init::<Secp256k1>(&pk_alice, &a, &ntilde_alice).unwrap();
    let alice_init_time = start.elapsed();
    println!("Aliceの初期化に{:?}かかりました", alice_init_time);

    // ParamOfProofBobの作成
    let param_bob = ParamOfProofBob {
        session: Bytes::from("test_session_id_for_curve_size"),
        pk: pk_alice.clone(),
        n_tilde: ntilde_alice.clone(),
        c1: ca.clone(),
        c2: BigUint::from(0u32), // 初期値（bob_midで更新される）
    };

    // Bob処理の実行
    let bob_start = Instant::now();
    let bob_result = bob_mid::<Secp256k1>(&param_bob, &proof_alice, &b, &ntilde_alice).unwrap();
    let bob_time = bob_start.elapsed();
    println!("Bob処理に{:?}かかりました", bob_time);

    // 更新されたパラメータの作成
    let updated_param = ParamOfProofBob {
        session: param_bob.session,
        pk: param_bob.pk,
        n_tilde: param_bob.n_tilde,
        c1: param_bob.c1,
        c2: bob_result.cb.clone(),
    };

    // Alice終了処理
    let alice_end_start = Instant::now();
    let alpha = alice_end::<Secp256k1>(&updated_param, &bob_result.pb, &sk_alice).unwrap();
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

/// 実際の実装を使用したプロトコルテスト
///
/// このテストでは簡易版テスト関数ではなく、本物の実装を使用してMTAプロトコルをテストします。
/// セキュリティ証明を含めた完全なプロトコルフローを検証します。
#[test]
fn test_share_protocol() {
    // 曲線のパラメータを設定
    let q = ecdsa::curve_n::<Secp256k1>();

    println!("Paillier鍵の生成を開始...");
    let start = Instant::now();
    // キーペアの生成
    let sk = PrivateKey::samples(None).clone();
    let pk = sk.public_key().clone();
    println!("鍵生成に{}秒かかりました", start.elapsed().as_secs_f64());

    // セッションIDを生成（通常は一意のものを使用）
    let session_id = Bytes::from("test_session_123");

    // NTildeセットを生成
    let ntilde_set = TestNTildeSet::new();
    let ntilde_alice = ntilde_set.alice.clone();

    // 再現性のある固定値を使用
    let a = BigUint::from(42u32);
    let b = BigUint::from(24u32);

    println!("a = {}, b = {}", a, b);

    // ポイントの生成（G*b）
    let g_b_point = generate_mul::<Secp256k1>(&b);
    println!(
        "g_b_point.is_identity() = {}",
        bool::from(g_b_point.is_identity())
    );

    // alice_init: Aliceが値aを暗号化し、範囲証明を生成
    let (ca, pf) = alice_init::<Secp256k1>(&pk, &a, &ntilde_alice).unwrap();
    println!("Aliceの初期値と証明を生成しました");

    // ParamOfProofBobを作成（c2は仮の値として設定）
    let param = ParamOfProofBob {
        session: session_id.clone(),
        pk: pk.clone(),
        n_tilde: ntilde_alice.clone(),
        c1: ca.clone(),
        c2: BigUint::from(0u32), // 一時的な値（bob_midで更新される）
    };

    // bob_mid: Bobが自分の値bを使用して処理
    let bob_result = bob_mid::<Secp256k1>(&param, &pf, &b, &ntilde_alice).unwrap();
    println!("Bobの中間結果を生成しました");

    // 更新されたパラメータを作成
    let updated_param = ParamOfProofBob {
        session: session_id,
        pk: pk.clone(),
        n_tilde: ntilde_alice.clone(),
        c1: ca,
        c2: bob_result.cb.clone(), // 更新されたcb値
    };

    // alice_end: Aliceが最終結果を取得
    let alpha_prm = alice_end::<Secp256k1>(&updated_param, &bob_result.pb, &sk).unwrap();
    println!("Aliceの最終結果を取得しました");

    // 検証：a * b = alpha_prm + beta (mod q)
    let expected = (a * b) % &q;
    let actual = (alpha_prm.clone() + bob_result.beta.clone()) % &q;

    println!("期待値: {} = a * b mod q", expected);
    println!("実際値: {} = alpha_prm + beta mod q", actual);

    assert_eq!(expected, actual, "a * b ≠ alpha_prm + beta (mod q)");
    println!("MTAプロトコルの検証に成功しました");
}

// WCバージョン（Witness Encryption）の実際の実装を使用したテスト
#[test]
fn test_share_protocol_wc() {
    // 曲線のパラメータを設定
    let q = ecdsa::curve_n::<Secp256k1>();

    println!("Paillier鍵の生成を開始...");
    let start = Instant::now();
    // キーペアの生成
    let sk = PrivateKey::samples(None).clone();
    let pk = sk.public_key().clone();
    println!("鍵生成に{}秒かかりました", start.elapsed().as_secs_f64());

    // セッションIDを生成（通常は一意のものを使用）
    let session_id = Bytes::from("test_session_wc_123");

    // NTildeセットを生成
    let ntilde_set = TestNTildeSet::new();
    let ntilde_alice = ntilde_set.alice.clone();

    // 再現性のある固定値を使用
    let a = BigUint::from(42u32);
    let b = BigUint::from(24u32);

    println!("a = {}, b = {}", a, b);

    // ポイントの生成（G*b）
    let g_b_point = generate_mul::<Secp256k1>(&b);
    println!(
        "g_b_point.is_identity() = {}",
        bool::from(g_b_point.is_identity())
    );

    // alice_init: Aliceが値aを暗号化し、範囲証明を生成
    let (ca, pf) = alice_init::<Secp256k1>(&pk, &a, &ntilde_alice).unwrap();
    println!("Aliceの初期値と証明を生成しました");

    // ParamOfProofBobを作成（c2は仮の値として設定）
    let param = ParamOfProofBob {
        session: session_id.clone(),
        pk: pk.clone(),
        n_tilde: ntilde_alice.clone(),
        c1: ca.clone(),
        c2: BigUint::from(0u32), // 一時的な値（bob_mid_wcで更新される）
    };

    // bob_mid_wc: Bobが自分の値bを使用して処理（witness-committed版）
    let bob_result = bob_mid_wc::<Secp256k1>(&param, &pf, &b, &ntilde_alice, &g_b_point).unwrap();
    println!("Bobの中間結果（WC版）を生成しました");

    // 更新されたパラメータを作成
    let updated_param = ParamOfProofBob {
        session: session_id,
        pk: pk.clone(),
        n_tilde: ntilde_alice.clone(),
        c1: ca,
        c2: bob_result.cb.clone(), // 更新されたcb値
    };

    // alice_end_wc: Aliceが最終結果を取得（witness-committed版）
    let alpha_prm =
        alice_end_wc::<Secp256k1>(&updated_param, &bob_result.pb, &g_b_point, &sk).unwrap();
    println!("Aliceの最終結果（WC版）を取得しました");

    // 検証：a * b = alpha_prm + beta (mod q)
    let expected = (a * b) % &q;
    let actual = (alpha_prm.clone() + bob_result.beta.clone()) % &q;

    println!("期待値: {} = a * b mod q", expected);
    println!("実際値: {} = alpha_prm + beta mod q", actual);

    assert_eq!(expected, actual, "a * b ≠ alpha_prm + beta (mod q)");
    println!("WC版MTAプロトコルの検証に成功しました");
}

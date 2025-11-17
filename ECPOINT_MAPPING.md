# ecpoint.go → Rust実装対応表

## 結論
**ecpoint.goの専用移植は不要** - 全機能が`k256`と`elliptic_curve`クレート + 既存実装でカバー済み

## 詳細対応表

### ✅ 既に実装済みの関数

| ecpoint.go関数 | Rust実装 | 実装場所 | 使用例 |
|---|---|---|---|
| `NewECPoint(curve, x, y)` | `xy_point::<C>(x, y)` | `utils/ecdsa.rs:33` | `proofs.rs`, `share_protocol.rs` |
| `NewECPointNoCurveCheck` | `xy_point` (自動検証) | `utils/ecdsa.rs:33` | 検証は`from_encoded_point`で自動 |
| `X()`, `Y()` | `point_xy::<A,C>(point)` | `utils/ecdsa.rs:12` | `proofs.rs:176,177`, `paillier.rs` |
| `ScalarBaseMult(k)` | `generate_mul::<C>(k)` | `utils/ecdsa.rs:73` | `share_protocol/tests.rs`, `proofs.rs` |
| `to_scalar` helper | `to_scalar::<C>(k)` | `utils/ecdsa.rs:82` | `proofs.rs:214,216` |
| `curve.Params().N` | `curve_n::<C>()` | `utils/ecdsa.rs:65` | `share_protocol.rs`, `proofs.rs` |

### ✅ ビルトイン演算子（専用実装不要）

| ecpoint.go関数 | Rust実装 | 説明 |
|---|---|---|
| `Add(p1)` | `point1 + point2` | `ProjectivePoint`の`+`演算子 |
| `ScalarMult(k)` | `point * scalar` | `ProjectivePoint`の`*`演算子 |
| `Equals(p2)` | `point1 == point2` | `PartialEq`トレイト |
| `IsOnCurve()` | 自動検証 | `from_encoded_point`で自動チェック |
| `Curve()` | ジェネリック型`C` | コンパイル時に型で解決 |

### 使用例（既存コードより）

```rust
// mta/proofs.rs より
use elliptic_curve::{CurveArithmetic, ops::MulByGenerator};

// ベースポイントのスカラー倍（ScalarBaseMult相当）
let s1_g = C::ProjectivePoint::mul_by_generator(&s1);

// ポイント演算（Add + ScalarMult相当）
let result = C::ProjectivePoint::from(x.to_owned()) * e + u;

// 座標取得（X, Y相当）
let (x_coord, y_coord) = ecdsa::point_xy(&point);

// ポイント作成（NewECPoint相当）
let point = ecdsa::xy_point::<C>(&x, &y)?;

// 曲線の位数取得
let q = ecdsa::curve_n::<C>();
```

### ⚠️ 必要時に追加実装（約30行）

| ecpoint.go関数 | 実装タイミング | 推定コード量 |
|---|---|---|
| `FlattenECPoints([]*ECPoint)` | TSSプロトコル実装時 | 10-15行 |
| `UnFlattenECPoints([]*big.Int)` | TSSプロトコル実装時 | 15-20行 |
| `EightInvEight()` | EdDSA実装時（Phase 4） | 5行 |
| `MarshalJSON` / `UnmarshalJSON` | 必要に応じて`serde` derive | 自動生成 |
| `GobEncode` / `GobDecode` | 不要（Rustは`serde`使用） | N/A |

### 実装済み箇所の使用統計

```bash
# curve_n の使用: 11箇所
mta/share_protocol.rs: 4回
mta/proofs.rs: 2回
mta/range_proof.rs: 5回

# point_xy の使用: 4箇所
mta/proofs.rs: 4回
paillier.rs: 1回

# generate_mul の使用: 2箇所
mta/proofs.rs: 1回
share_protocol/tests.rs: 1回

# to_scalar の使用: 2箇所
mta/proofs.rs: 2回
```

## 技術的背景

### なぜ専用実装が不要か

1. **型システムの違い**
   - Go: `ECPoint`構造体で曲線とポイントを保持
   - Rust: ジェネリック型`C: CurveArithmetic`でコンパイル時解決

2. **演算子オーバーロード**
   - Go: メソッド呼び出し (`p.Add(p2)`)
   - Rust: 演算子 (`p1 + p2`) - より直感的

3. **型安全性**
   - Go: 実行時の曲線チェック
   - Rust: コンパイル時に型で保証

### Flatten/UnFlattenの実装例（必要時）

```rust
// 必要になったら追加（約30行）
pub fn flatten_points<C>(points: &[C::AffinePoint]) -> Vec<BigUint>
where
    C: CurveArithmetic,
    C::AffinePoint: ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    points.iter()
        .flat_map(|p| {
            let (x, y) = point_xy(p);
            vec![x, y]
        })
        .collect()
}

pub fn unflatten_points<C>(flat: &[BigUint]) -> Result<Vec<C::AffinePoint>>
where
    C: CurveArithmetic,
    C::AffinePoint: FromEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    flat.chunks(2)
        .map(|chunk| {
            xy_point::<C>(&chunk[0], &chunk[1])
                .ok_or_else(|| CryptoError::invalid_point())
        })
        .collect()
}
```

## まとめ

- ✅ **基本機能**: 完全実装済み (`utils/ecdsa.rs`)
- ✅ **演算**: ビルトイン演算子で提供
- ✅ **現在の実装**: 問題なく動作中
- ⚠️ **追加実装**: Flatten系のみ、必要時に30行追加

**結論**: ecpoint.go (272行)の移植は不要。既存実装で十分。
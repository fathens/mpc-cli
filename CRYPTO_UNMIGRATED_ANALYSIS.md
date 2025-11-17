# crypto未移植モジュール詳細分析

## 調査結果サマリー

| モジュール | 行数 | 既存実装 | 実装必要性 | 使用箇所 | 優先度 |
|---|---|---|---|---|---|
| **ecpoint.go** | 272行 | ✅ 代替済み | ❌ 不要 | `utils/ecdsa.rs`で完全代替 | - |
| **vss/feldman_vss.go** | 175行 | ❌ 未実装 | ✅ **必須** | ECDSA keygen (round 1, 3) | **高** |
| **schnorr/schnorr_proof.go** | 137行 | ❌ 未実装 | ✅ **必須** | ECDSA signing (round 4, 6) | **高** |

## 詳細分析

### 1. ✅ ecpoint.go (272行) - **移植不要**

#### 判定理由
- ✅ 全機能が`utils/ecdsa.rs`で実装済み
- ✅ `k256::ProjectivePoint`の演算子オーバーロードで代替
- ✅ 既に11箇所で使用中、正常動作

#### 実装状況
```rust
// utils/ecdsa.rs で提供
pub fn xy_point<C>(x, y) -> Option<C::AffinePoint>
pub fn point_xy<A,C>(point) -> (BigUint, BigUint)
pub fn generate_mul<C>(k) -> C::AffinePoint
pub fn to_scalar<C>(k) -> C::Scalar
pub fn curve_n<C>() -> BigUint

// ビルトイン演算
point1 + point2  // Add
point * scalar   // ScalarMult
```

#### 詳細
`ECPOINT_MAPPING.md`参照

---

### 2. ❌ vss/feldman_vss.go (175行) - **実装必須**

#### 判定理由
- ❌ 完全に未実装（グレップで0件）
- ✅ ECDSA鍵生成プロトコルの中核機能
- ✅ Phase 3の前提条件

#### 使用箇所
```go
// ecdsa/keygen/round_1.go
vs, shares, err := vss.Create(round.EC(), round.Threshold(), ui, ids, round.Rand())

// ecdsa/keygen/round_3.go
Vc := make(vss.Vs, round.Threshold()+1)
PjShare := vss.Share{...}
ok := share.Verify(...)
```

#### 必要な機能
```go
// feldman_vss.go の主要API
type Share struct {
    Threshold int
    ID, Share *big.Int
}
type Vs []*crypto.ECPoint
type Shares []*Share

// 必要な関数
func Create(ec, threshold, secret, indexes, rand) (Vs, Shares, error)
func (share *Share) Verify(ec, threshold, vs) bool
func (shares Shares) ReConstruct(ec) (*big.Int, error)
func CheckIndexes(ec, indexes) ([]*big.Int, error)
```

#### 実装の難易度
- **難易度**: 中
- **依存**: 既存のecdsa utilsのみ（新規依存なし）
- **推定工数**: 2-3日
- **コード量**: 約200-250行（テスト込み）

#### 実装の構造
```
crypto/src/vss/
├── mod.rs           // 公開API
├── feldman.rs       // Feldman VSSコア実装
└── polynomial.rs    // 多項式評価ヘルパー
```

---

### 3. ❌ schnorr/schnorr_proof.go (137行) - **実装必須**

#### 判定理由
- ❌ 完全に未実装（グレップで0件）
- ✅ ECDSA署名プロトコルで使用（round 4, 6）
- ✅ Phase 3の前提条件

#### 使用箇所
```go
// ecdsa/signing/round_4.go
piGamma, err := schnorr.NewZKProof(ContextI, round.temp.gamma, round.temp.pointGamma, round.Rand())

// ecdsa/signing/round_6.go
piAi, err := schnorr.NewZKProof(ContextI, round.temp.roi, round.temp.bigAi, round.Rand())
piV, err := schnorr.NewZKVProof(ContextI, round.temp.bigVi, round.temp.bigR, round.temp.si, round.temp.li, round.Rand())
```

#### 必要な機能
```go
// schnorr_proof.go の主要API
type ZKProof struct {
    Alpha *crypto.ECPoint
    T     *big.Int
}

type ZKVProof struct {
    Alpha *crypto.ECPoint
    T, U  *big.Int
}

// 必要な関数
func NewZKProof(Session, x, X, rand) (*ZKProof, error)
func (pf *ZKProof) Verify(Session, X) bool

func NewZKVProof(Session, V, R, s, l, rand) (*ZKVProof, error)
func (pf *ZKVProof) Verify(Session, V, R) bool
```

#### 実装の難易度
- **難易度**: 低-中
- **依存**: 既存のhash, ecdsa utilsのみ
- **推定工数**: 1-2日
- **コード量**: 約150-180行（テスト込み）

#### 実装の構造
```
crypto/src/schnorr/
├── mod.rs        // 公開API
├── zk_proof.rs   // ZKProof実装
└── zkv_proof.rs  // ZKVProof実装
```

---

## 実装優先順位と戦略

### Phase 1完了のための残タスク

#### 必須実装 (Phase 2に進む前に完了)
1. **VSS (Feldman)** - 175行 → 推定250行
   - ECDSA keygenの前提
   - 実装難易度: 中
   - 工数: 2-3日

2. **Schnorr proof** - 137行 → 推定180行
   - ECDSA signingの前提
   - 実装難易度: 低-中
   - 工数: 1-2日

#### 合計
- **実装必要**: 312行 → 約430行（テスト込み）
- **推定工数**: 3-5日
- **ecpoint.goは不要**: 272行削減

### 実装後のPhase 1完了率
```
Phase 1: 基盤暗号モジュール
├── ✅ common (100%)
├── ✅ crypto基盤 (100%)
├── ✅ proof系 (100%)
├── ✅ mta (100%)
├── ✅ ckd (100%)
├── ✅ utils/ecdsa (100%) ← ecpoint.goの代替
├── ⚠️ vss (0% → 実装必要)
└── ⚠️ schnorr (0% → 実装必要)

完了後: Phase 1 = 100%
```

## 推奨実装順序

### ステップ1: Schnorr proof（1-2日）
理由: より単純で、VSSの実装練習になる

1. `crypto/src/schnorr/mod.rs` - モジュール定義
2. `crypto/src/schnorr/zk_proof.rs` - ZKProof実装
3. `crypto/src/schnorr/zkv_proof.rs` - ZKVProof実装
4. テスト追加

### ステップ2: VSS (Feldman)（2-3日）
理由: より複雑だが、Schnorrの経験を活かせる

1. `crypto/src/vss/mod.rs` - モジュール定義
2. `crypto/src/vss/polynomial.rs` - 多項式ヘルパー
3. `crypto/src/vss/feldman.rs` - Feldman VSS実装
4. テスト追加

### ステップ3: Phase 2へ移行
VSS/Schnorr完了後、TSSコア実装に着手可能

---

## まとめ

### 現状
- ✅ **ecpoint.go**: 代替実装済み（移植不要）
- ❌ **VSS**: 未実装（ECDSA keygen必須）
- ❌ **Schnorr**: 未実装（ECDSA signing必須）

### Phase 1完了への道のり
```
残り実装: 2モジュール (312行 → 約430行)
推定工数: 3-5日
完了後: Phase 2 (TSSコア) 実装開始可能
```

### 技術的リスク
- **低**: 両モジュールとも既存の暗号プリミティブのみに依存
- **依存関係**: 新規クレート不要
- **テスト**: Go実装のテストケースを移植可能
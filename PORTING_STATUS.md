# tss-lib Rust移植プロジェクト進捗状況

## プロジェクト概要

このプロジェクトは、[bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) (
Go実装) をRustに移植するものです。tss-libはThreshold Signature Scheme (TSS)
を実装したライブラリで、ECDSAおよびEdDSA署名のための分散鍵生成と署名プロトコルを提供します。

## 統計情報

### コード規模

- **元のGoコード** (crypto + common): 約5,592行
- **移植済みRustコード**:
    - `crypto` crate: 約7,698行
    - `common` crate: 約884行
    - **合計**: 約8,582行

### プロジェクト構造

```
mpc-cli/
├── crates/
│   ├── common/     # 共通ユーティリティ
│   ├── crypto/     # 暗号プリミティブとプルーフ
│   ├── cli/        # CLIインターフェース
│   └── protobuf/   # Protobuf定義
```

## 移植完了モジュール

### ✅ common crate

元の `tss-lib/common` の機能を移植:

| 元のモジュール          | 移植先                     | 状態 | 説明                    |
|------------------|-------------------------|----|------------------------|
| `hash.go`        | `crypto/src/hash.rs`    | ✅  | ハッシュ関数ユーティリティ         |
| `hash_utils.go`  | `crypto/src/hash.rs`    | ✅  | ハッシュヘルパー関数 (含まれる)     |
| `random.go`      | `common/src/random.rs`  | ✅  | 安全な乱数生成               |
| `safe_prime.go`  | `common/src/prime.rs`   | ✅  | 安全素数生成                |
| `slice.go`       | `common/src/slice.rs`   | ✅  | スライスユーティリティ           |
| `int.go`         | `common/src/mod_int.rs` | ✅  | モジュラ演算                |
| `logger.go`      | -                       | ✅  | ロガー (slogで代替)         |
| `signature.pb.go` | `protobuf/`             | ✅  | Protobuf定義 (署名データ構造) |
| -                | `common/src/time.rs`    | ✅  | 時間ユーティリティ (新規追加)      |
| -                | `common/src/error.rs`   | ✅  | エラーハンドリング             |

**進捗**: 10/10 完了 (100%)

### ✅ crypto crate - 基本暗号プリミティブ

元の `tss-lib/crypto` の機能を移植:

| 元のモジュール                        | 移植先                         | 状態 | 説明                        |
|----------------------------------|-----------------------------|----|-----------------------------|
| `paillier/paillier.go`           | `crypto/src/paillier.rs`    | ✅  | Paillier準同型暗号 (101KB)     |
| `commitments/commitment.go`      | `crypto/src/commitment.rs`  | ✅  | コミットメントスキーム               |
| `commitments/commitment_builder.go` | `crypto/src/commitment.rs`  | ✅  | Builderパターン (含まれる)        |
| `utils.go`                       | `crypto/src/utils.rs`       | ✅  | 暗号ユーティリティ (NTildei生成)    |
| -                                | `crypto/src/base58.rs`      | ✅  | Base58エンコーディング            |
| -                                | `crypto/src/fixed_bytes.rs` | ✅  | 固定サイズバイト配列                |

**進捗**: 6/6 完了 (100%)

### ✅ crypto/proof - ゼロ知識証明

元の `tss-lib/crypto/*proof` の機能を移植:

| 元のモジュール            | 移植先                              | 状態 | 説明                  |
|----------------------|----------------------------------|----|---------------------|
| `dlnproof/proof.go`  | `crypto/src/proof/dln_proof.rs`  | ✅  | DLN証明 (832KB - 大規模) |
| `facproof/proof.go`  | `crypto/src/proof/fac_proof.rs`  | ✅  | Factoring証明         |
| `modproof/proof.go`  | `crypto/src/proof/mod_proof.rs`  | ✅  | Modulus証明           |
| -                    | `crypto/src/proof/iterations.rs` | ✅  | イテレーション設定           |

**進捗**: 4/4 完了 (100%)

### ✅ crypto/mta - Multiplicative-to-Additive

元の `tss-lib/crypto/mta` の機能を移植:

| 元のモジュール             | 移植先                                | 状態 | 説明             |
|---------------------|------------------------------------|----|----------------|
| `proofs.go`         | `crypto/src/mta/proofs.rs`         | ✅  | MTA証明 (35KB)   |
| `range_proof.go`    | `crypto/src/mta/range_proof.rs`    | ✅  | レンジプルーフ (21KB) |
| `share_protocol.go` | `crypto/src/mta/share_protocol.rs` | ✅  | シェアプロトコル       |

**進捗**: 3/3 完了 (100%)

### ✅ crypto/ckd - 鍵導出

元の `tss-lib/crypto/ckd` の機能を移植:

| 元のモジュール                   | 移植先                                  | 状態 | 説明     |
|---------------------------|--------------------------------------|----|--------|
| `child_key_derivation.go` | `crypto/src/extend_key/extkey.rs`    | ✅  | 拡張鍵    |
| -                         | `crypto/src/extend_key/ecdsa_key.rs` | ✅  | ECDSA鍵 |
| -                         | `crypto/src/hdpath/path.rs`          | ✅  | HD鍵パス  |
| -                         | `crypto/src/hdpath/node.rs`          | ✅  | HDノード  |

**進捗**: 4/4 完了 (100%)

### ✅ protobuf crate

元の `tss-lib/protob` のProtobuf定義を移植:

| 元のモジュール                  | 移植先                                       | 状態 | 説明        |
|--------------------------|-------------------------------------------|----|-----------|
| `message.proto`          | `protobuf/src/message.proto`              | ✅  | メッセージ定義   |
| `signature.proto`        | `protobuf/src/signature.proto`            | ✅  | 署名データ構造   |
| `ecdsa-keygen.proto`     | `protobuf/src/ecdsa-keygen.proto`         | ✅  | ECDSA鍵生成  |
| `ecdsa-signing.proto`    | `protobuf/src/ecdsa-signing.proto`        | ✅  | ECDSA署名   |
| `ecdsa-resharing.proto`  | `protobuf/src/ecdsa-resharing.proto`      | ✅  | ECDSA鍵再共有 |
| `eddsa-keygen.proto`     | `protobuf/src/eddsa-keygen.proto`         | ✅  | EdDSA鍵生成  |
| `eddsa-signing.proto`    | `protobuf/src/eddsa-signing.proto`        | ✅  | EdDSA署名   |
| `eddsa-resharing.proto`  | `protobuf/src/eddsa-resharing.proto`      | ✅  | EdDSA鍵再共有 |

**進捗**: 8/8 完了 (100%)

## 未移植モジュール

### ❌ crypto - 追加プロトコル

元の `tss-lib/crypto` の未移植モジュール:

| 元のモジュール                        | 行数   | 説明                     | 優先度 | 備考                           |
|--------------------------------|------|------------------------|-----|------------------------------|
| `vss/feldman_vss.go`           | 175行 | Feldman VSS (検証可能秘密分散) | 高   | TSSプロトコル実装に必須               |
| `schnorr/schnorr_proof.go`     | 137行 | Schnorr ZK証明           | 中   | 一部のプロトコルで使用                  |
| ~~`ecpoint.go`~~               | 272行 | ~~楕円曲線ポイント操作~~         | -   | ✅ `CurveArithmetic`で代替済み（移植不要） |

**未完了**: 2モジュール、約312行（ecpoint.goは移植不要）

### ❌ tss - TSSプロトコルコア

元の `tss-lib/tss` (TSSプロトコルの基盤):

| モジュール         | 説明          | 優先度 |
|---------------|-------------|-----|
| `curve.go`    | 楕円曲線設定      | 高   |
| `error.go`    | エラーハンドリング   | 高   |
| `message.go`  | メッセージルーティング | 高   |
| `params.go`   | プロトコルパラメータ  | 高   |
| `party.go`    | パーティ抽象化     | 高   |
| `party_id.go` | パーティID管理    | 高   |
| `peers.go`    | ピア管理        | 高   |
| `round.go`    | ラウンド抽象化     | 高   |
| `wire.go`     | ワイヤフォーマット   | 中   |

### ❌ ecdsa/keygen - ECDSA鍵生成プロトコル

元の `tss-lib/ecdsa/keygen` (分散鍵生成):

| モジュール             | 説明             | 優先度 |
|-------------------|----------------|-----|
| `local_party.go`  | パーティロジック       | 高   |
| `prepare.go`      | 初期化処理          | 高   |
| `round_1.go`      | ラウンド1: コミットメント | 高   |
| `round_2.go`      | ラウンド2: シェア配布   | 高   |
| `round_3.go`      | ラウンド3: プルーフ検証  | 高   |
| `round_4.go`      | ラウンド4: ファイナライズ | 高   |
| `save_data.go`    | 鍵データ保存         | 高   |
| `dln_verifier.go` | DLN検証          | 中   |
| `messages.go`     | メッセージ定義        | 高   |

### ❌ ecdsa/signing - ECDSA署名プロトコル

元の `tss-lib/ecdsa/signing` (分散署名生成):

| モジュール                       | 説明             | 優先度 |
|-----------------------------|----------------|-----|
| `local_party.go`            | パーティロジック       | 高   |
| `prepare.go`                | 署名準備           | 高   |
| `round_1.go` ~ `round_9.go` | 署名ラウンド (9ラウンド) | 高   |
| `finalize.go`               | 署名完成           | 高   |
| `key_derivation_util.go`    | 鍵導出ユーティリティ     | 中   |
| `messages.go`               | メッセージ定義        | 高   |

### ❌ ecdsa/resharing - 鍵再共有

元の `tss-lib/ecdsa/resharing` (鍵の再分散):

| モジュール | 説明        | 優先度 |
|-------|-----------|-----|
| (未調査) | 鍵再共有プロトコル | 中   |

### ❌ eddsa - EdDSAプロトコル

元の `tss-lib/eddsa` (Ed25519のTSS実装):

| モジュール        | 説明        | 優先度 |
|--------------|-----------|-----|
| `keygen/`    | EdDSA鍵生成  | 低   |
| `signing/`   | EdDSA署名   | 低   |
| `resharing/` | EdDSA鍵再共有 | 低   |

## 進捗率

### フェーズ別進捗

| フェーズ             | 状態    | 進捗率  | 説明              |
|------------------|-------|------|-----------------|
| **フェーズ1: 基盤**    | ✅ 完了  | 100% | 暗号プリミティブ、証明、MTA |
| **フェーズ2: TSSコア** | ❌ 未着手 | 0%   | プロトコル基盤、パーティ管理  |
| **フェーズ3: ECDSA** | ❌ 未着手 | 0%   | 鍵生成・署名プロトコル     |
| **フェーズ4: EdDSA** | ❌ 未着手 | 0%   | EdDSA実装 (オプション) |

### 全体進捗

```
完了: 基盤暗号モジュール (common + crypto基盤)
残り: TSSプロトコルコア + ECDSA/EdDSA実装

推定進捗: 25-30%
```

## 次のステップ

### 優先度: 高 (Phase 2)

1. **TSSコアの実装**
    - [ ] `tss/party.go` - パーティ抽象化
    - [ ] `tss/message.go` - メッセージルーティング
    - [ ] `tss/round.go` - ラウンド管理
    - [ ] `tss/params.go` - パラメータ管理
    - [ ] `tss/curve.go` - 曲線設定

2. **ECポイント操作**
    - [ ] `crypto/ecpoint.go` - 楕円曲線ポイント

3. **VSS実装**
    - [ ] `crypto/vss/` - 検証可能秘密分散

### 優先度: 高 (Phase 3)

4. **ECDSA Keygen実装**
    - [ ] 全4ラウンド + 準備・保存処理

5. **ECDSA Signing実装**
    - [ ] 全9ラウンド + 準備・ファイナライズ

### 優先度: 中

6. **Schnorr証明**
    - [ ] `crypto/schnorr/` 実装

7. **鍵再共有**
    - [ ] ECDSA resharing実装

### 優先度: 低

8. **EdDSA実装**
    - [ ] EdDSA keygen/signing/resharing

## 技術的考慮事項

### 依存クレート

- `num-bigint`: 大整数演算
- `k256`: secp256k1楕円曲線
- `sha2`, `ripemd`: ハッシュ関数
- `num-modular`: モジュラ演算
- `rand`: 乱数生成
- `rayon`: 並列処理

### テスト状況

```bash
cargo test --workspace --no-run  # ✅ コンパイル成功
```

## 参考情報

### 元のリポジトリ

- GitHub: https://github.com/bnb-chain/tss-lib
- ライセンス: MIT

### 関連ドキュメント

- GG20: https://eprint.iacr.org/2020/540.pdf (ECDSA TSS protocol)
- Paillier暗号: 準同型暗号方式
- Feldman VSS: 検証可能秘密分散スキーム

---

**最終更新**: 2025-11-13
**ステータス**: Phase 1完了、Phase 2準備中

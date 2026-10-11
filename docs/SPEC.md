# BHSS Consensus Specification

**BHSS** = *bitcoin-hardfork-stark-slhdsa*. Version 1, 2026-10-11.

> **日本語要約**: 本書は BHSS(Bitcoin の regtest/signet 向けハードフォーク)の
> コンセンサスルールの正本である。各ルールには ID(例 `TX-3`)が付き、Rust 実装
> (`crates/bhss-consensus` ほか)とテストはその ID を参照する。要点:
> (1) ハッシュはすべてタグ付き単一 SHA-256、(2) 署名は SLH-DSA-SHA2-128s のみ、
> (3) Bitcoin Script は廃止し固定の出力タイプのみ、(4) UTXO 集合は深さ 256 の
> SHA-256 スパース Merkle ツリー(SMT)でコミットし全入力に包含証明を要求、
> (5) 各ブロックは RISC Zero の STARK レシートで自身の有効性を証明し、ノードは
> それに加えてネイティブでも全ルールを再検証する(二重検証)、(6) スナップショット
> 由来の旧 UTXO(secp256k1)は、支出者が作る tx 単位の STARK(マイグレーション証明)
> でのみ消費できる。

This document is normative. Where the implementation and this document
disagree, the document wins and the implementation is a bug. "MUST" has its
RFC 2119 meaning. All integers are unsigned. `H(x)` is SHA-256 of `x`.

Design decisions and their rationale are in [`DECISIONS.md`](DECISIONS.md).

---

## 1. Overview

> **日本語要約**: ノードが受理するブロックの条件と、証明(STARK)が何を担保するかの全体像。

A BHSS chain is a sequence of blocks starting at a deterministic genesis
block (§13). Every block after genesis MUST satisfy all of:

1. the header rules (§9),
2. the body rules: structure, transactions, coinbase and state transition
   (§10–§12),
3. it carries a RISC Zero receipt whose journal commits exactly the state
   transition the node computed natively (§14).

Rule 3 is **in addition to**, never instead of, rules 1–2 (decision D3). A
node that cannot verify a receipt (because it is malformed or proves a
different transition) MUST reject the block even if everything else checks
out; a node whose native validation fails MUST reject the block even if the
receipt verifies. The single exception is the secp256k1 signature of a
legacy (snapshot) coin, which is verified only inside the migration guest
(§15): nodes verify the *receipt* of that guest, not the signature.

Consequently, a soundness failure of the proof system can at most allow
theft of **un-migrated legacy coins**; coins locked by SLH-DSA conditions
never depend on the proof system.

---

## 2. Hashing

> **日本語要約**: すべてのコンセンサス用ハッシュは `SHA256(tag || data)`。タグは
> 先頭 1 バイトで用途ごとに固定。二重 SHA-256 や RIPEMD-160 は新規構造では使わない。

* **HASH-1.** Every hash defined by this specification is a single
  SHA-256 whose first input byte is a domain tag. `H_t(a‖b‖…)` denotes
  `SHA256(t ‖ a ‖ b ‖ …)`.
* **HASH-2.** Tags (one byte each):

| Tag | Name | Used for |
|----:|------|----------|
| 0x00 | SmtLeaf | SMT leaf hash of a coin (SMT-3) |
| 0x01 | SmtNode | SMT inner node (SMT-4) |
| 0x02 | SmtKey | SMT key of an outpoint (SMT-2) |
| 0x03 | BlockHeader | block hash (HDR-2) |
| 0x04 | TxId | transaction id (TX-3) |
| 0x05 | TxCommit | Merkle leaf (TX-5) |
| 0x06 | Witness | witness hash (TX-4) |
| 0x07 | SigHash | SLH-DSA signing message (SIG-1) |
| 0x08 | MigrationMsg | legacy signing message (MIG-3) |
| 0x0A | Params | chain parameter hash (PAR-2) |
| 0x0B | MerkleNode | Merkle inner node (BLK-3) |
| 0x0C | GenesisState | reserved for genesis state digests |
| 0x0D | LegacyScript | script hash in migration journal (MIG-4) |
| 0x10 | SlhPubKey | SLH-DSA public key hash (OUT-1) |

Legacy Bitcoin constructions that BHSS must recognise structurally
(`HASH160`, `SHA256(witness_script)`) keep their original untagged
definitions (§15); they never appear in new BHSS structures.

---

## 3. Canonical encoding

> **日本語要約**: 整数はリトルエンディアン固定長、個数・長さは Bitcoin の
> CompactSize、バイト列は長さ接頭辞付き。デコードは厳格(非最小 CompactSize や
> 末尾の余りはエラー)。

* **ENC-1.** `u8/u16/u32/u64` are fixed-width little-endian.
* **ENC-2.** `bool` is one byte, `0x00` or `0x01`; any other value is invalid.
* **ENC-3.** Counts and lengths use Bitcoin CompactSize: `< 0xfd` one
  byte; `0xfd` + u16; `0xfe` + u32; `0xff` + u64.
* **ENC-4.** `bytes` = CompactSize length followed by the bytes.
  `vec<T>` = CompactSize count followed by the encoded elements.
* **ENC-5.** A CompactSize MUST be minimal (e.g. `0xfd 0x05 0x00` is invalid).
* **ENC-6.** Decoding a top-level object MUST consume the whole input;
  trailing bytes are invalid.
* **ENC-7.** No collection may declare more than 2²⁴ elements, nor more
  elements than can be represented by the remaining bytes.
* **ENC-8.** `enc(x)` denotes the canonical encoding of `x`. Encodings of
  each type are given with the type below.

---

## 4. Outputs and coins

> **日本語要約**: 出力は「値 + 種別」。種別は P2PK-SLH、k-of-n マルチシグ、
> タイムロック包装、データ、レガシー(スナップショット由来のみ)の 5 つ。
> Data は値 0 で SMT に入らない。Legacy は tx で作れない。

```
Output      = value:u64 ‖ kind:OutputKind
OutputKind  = tag:u8 ‖ body
  0x00 P2pkSlh      body = pkh:32
  0x01 MultisigSlh  body = k:u8 ‖ vec<pkh:32>
  0x02 Timelock     body = abs_height:u32 ‖ rel_blocks:u32 ‖ inner:OutputKind
  0x03 Data         body = bytes
  0x04 Legacy       body = script_pubkey:bytes
Coin        = output:Output ‖ height:u32 ‖ coinbase:bool
OutPoint    = txid:32 ‖ vout:u32
```

* **OUT-1.** `P2pkSlh.pkh = H_0x10(pubkey)` where `pubkey` is a 32-byte
  SLH-DSA-SHA2-128s public key.
* **OUT-2.** `MultisigSlh`: `1 ≤ k ≤ n = len(pkhs) ≤ 16`.
* **OUT-3.** `Timelock`: at least one of `abs_height`, `rel_blocks` is
  non-zero; `inner` MUST be `P2pkSlh` or `MultisigSlh` (no nesting).
* **OUT-4.** `Data.data` is at most 1 024 bytes.
* **OUT-5.** A `Data` output MUST have `value = 0`. Data outputs are never
  inserted into the UTXO set.
* **OUT-6.** A transaction MUST NOT create a `Legacy` output. Legacy
  outputs exist only in the genesis state (§13). Their script is 1 to
  10 000 bytes.
* **AMT-1.** Every value and every sum of values a rule computes MUST be
  `≤ MAX_MONEY = 21 000 000 × 10⁸`; arithmetic that would overflow `u64`
  is invalid.
* **COIN-1.** A coin records the output, the height of the block that
  created it and whether that transaction was the coinbase.

---

## 5. Transactions

> **日本語要約**: tx = version, 入力列(prevout + witness), 出力列, locktime, proofs。
> txid は witness と proofs を除いた「コア」のハッシュ。witness は別途
> `witness_hash` としてブロックにコミットされる。proofs(マイグレーション
> レシート)はコミットされない。

```
Transaction = version:u32 ‖ vec<Input> ‖ vec<Output> ‖ locktime:u32 ‖ vec<proof:bytes>
Input       = prevout:OutPoint ‖ witness:Witness
Witness     = tag:u8 ‖ body
  0x00 Slh       body = vec<Signer>;  Signer = index:u8 ‖ pubkey:32 ‖ signature:bytes
  0x01 Legacy    body = (empty)
  0x02 Coinbase  body = (empty)
```

* **TX-1.** `version = 1`; at least one input and one output.
* **TX-2.** The *core* encoding is
  `version ‖ CompactSize(len(inputs)) ‖ prevout₀ ‖ prevout₁ … ‖ vec<Output> ‖ locktime`
  (inputs contribute only their prevouts).
* **TX-3.** `txid = H_0x04(core)`.
* **TX-4.** `witness_hash = H_0x06(CompactSize(len(inputs)) ‖ witness₀ ‖ witness₁ …)`.
* **TX-5.** `tx_commit = H_0x05(txid ‖ witness_hash)`. This is what the
  block Merkle root commits to. `proofs` are committed by neither TX-3 nor
  TX-4; they are validated by content (MIG-2).
* **TX-6.** No two inputs of one transaction may have the same prevout.
* **TX-7.** Every output MUST satisfy OUT-2…OUT-6 and AMT-1.
* **TX-8.** If `locktime ≠ 0`, the transaction is valid only in a block of
  height `≥ locktime`. The coinbase MUST have `locktime = 0`.
* **TX-9.** `len(proofs)` MUST equal the number of inputs whose spent coin
  is `Legacy` (so zero for ordinary transactions and for the coinbase).
  `proofs[j]` belongs to the j-th input (which, by MIG-1, is input `j`).
* **TX-10.** The *committed size* of a transaction is the length of its
  encoding with `proofs` replaced by an empty vector.

---

## 6. Blocks

> **日本語要約**: ブロック = ヘッダ + tx 列 + ブロック witness(消費コインと SMT
> 証明) + レシート。Merkle root は tx_commit に対して計算し、奇数要素は複製せず
> そのまま持ち上げる。

```
Header       = version:u32 ‖ prev_hash:32 ‖ merkle_root:32 ‖ state_root:32 ‖ time:u32 ‖ bits:u32 ‖ nonce:u32
Block        = header:Header ‖ vec<Transaction> ‖ witness:BlockWitness ‖ receipt:bytes
BlockWitness = vec<Coin> ‖ vec<SmtProof>
SmtProof     = bitmap:32 ‖ vec<sibling:32>
```

* **BLK-1.** Block encoding as above. `receipt` is the serialized RISC
  Zero receipt (§14); `witness` and `receipt` are not committed by the
  header — they are validated by content.
* **BLK-2.** `witness.coins` lists, in block order, the coin spent by each
  input of every non-coinbase transaction. `witness.proofs` lists one SMT
  proof per state operation in the order of STATE-1.
* **BLK-3.** `merkle_root` is computed over `[tx_commit₀, tx_commit₁, …]`:
  while more than one element remains, replace each adjacent pair `(l, r)`
  by `H_0x0B(l ‖ r)`; an unpaired last element is carried up unchanged.
* **BLK-4.** At least one transaction.
* **BLK-5.** Transaction 0 is the coinbase (§11); no other transaction may
  be or contain a `Coinbase` witness.
* **BLK-6.** No two transactions in a block share a txid.
* **BLK-7.** `CompactSize(len(txs)) + Σ committed_size(tx)` MUST be
  `≤ max_block_tx_bytes` (default 131 072).
* **BLK-8.** The total number of SLH-DSA signatures verified in the block
  (sum of `len(signers)`) MUST be `≤ max_sig_checks` (default 16).
* **BLK-9.** The number of legacy inputs in the block MUST be
  `≤ max_migrations` (default 16).
* **BLK-10.** `len(witness.coins)` MUST equal the number of non-coinbase
  inputs.
* **BLK-11.** `len(witness.proofs)` MUST equal the number of state
  operations: every proof is consumed, none is left over.

---

## 7. Chain parameters

> **日本語要約**: ネットワーク固有の定数。`params_hash` が各ブロックの journal に
> 入るため、パラメータが違えば証明も互換しない。

```
ChainParams = name:bytes ‖ max_block_tx_bytes:u32 ‖ max_sig_checks:u32 ‖ max_migrations:u32
            ‖ coinbase_maturity:u32 ‖ subsidy_halving_interval:u32 ‖ initial_subsidy:u64
            ‖ pow_bits:u32 ‖ genesis_time:u32 ‖ genesis_state_root:32 ‖ require_real_proofs:bool
```

* **PAR-1.** Defaults (`bhrt`): 131 072 / 16 / 16 / 100 / 150 /
  5 000 000 000 / 0x207fffff / 1 760 000 000 / (computed) / false.
* **PAR-2.** `params_hash = H_0x0A(enc(ChainParams))`.
* **PAR-3.** `name` is also the bech32m human-readable part (ADDR-1).

---

## 8. The UTXO commitment (SMT)

> **日本語要約**: キー = `H(0x02‖txid‖vout)`、リーフ = `H(0x00‖enc(Coin))`、深さ
> 256 の二分木。空部分木のハッシュは下から `E[256]=0³²`, `E[d]=H(0x01‖E[d+1]‖E[d+1])`。
> 証明は非空の兄弟だけを bitmap 付きで持ち、空ハッシュを非空として送るのは無効。
> 同じ証明で「削除後 / 挿入後」の root も計算できる。

* **SMT-1.** The tree is a complete binary tree of depth 256. A key is a
  32-byte string; the path of a key is its bits most-significant first
  (bit 7 of byte 0 is depth 0); bit 0 = left child, 1 = right child.
* **SMT-2.** `key(outpoint) = H_0x02(txid ‖ vout:u32)`.
* **SMT-3.** `leaf(coin) = H_0x00(enc(Coin))`. The empty leaf is `0³²`.
* **SMT-4.** `node(l, r) = H_0x01(l ‖ r)`. Empty subtree hashes:
  `E[256] = 0³²`, `E[d] = node(E[d+1], E[d+1])`. The root of the empty set
  is `E[0]`.
* **SMT-5.** `SmtProof.bitmap` bit `i` (same bit order as keys) is set iff
  the sibling at depth `i` (a node at depth `i+1`) is non-empty;
  `siblings` lists exactly those hashes from depth 0 downward.
  `len(siblings)` MUST equal `popcount(bitmap)`.
* **SMT-6.** A listed sibling MUST differ from `E[i+1]`; a proof that lists
  an empty hash is invalid (proofs are canonical).
* **SMT-7.** `root(key, leaf, proof)`: `h ← leaf`; for `i` from 255 down to
  0: `s ← siblings[next] if bit i set else E[i+1]`;
  `h ← node(h, s)` if key bit `i` = 0 else `node(s, h)`. The result is the
  root implied by the proof. `proof` proves inclusion of `(key, leaf)`
  under `R` iff `root(key, leaf, proof) = R`; it proves non-inclusion of
  `key` iff `root(key, 0³², proof) = R`.
* **SMT-8.** The same siblings give the post-update root:
  deleting = `root(key, 0³², proof)`, inserting = `root(key, leaf, proof)`.

The in-memory tree in `crates/bhss-smt` is an implementation detail; only
SMT-1…SMT-8 are consensus.

---

## 9. Header rules

> **日本語要約**: version 1、prev_hash が親に一致、bits は固定、time は単調非減少、
> block_hash がターゲット以下、merkle_root と state_root(適用後 root)が一致。

* **HDR-1.** Encoding as in §6; `version = 1` (**HDR-4**).
* **HDR-2.** `block_hash = H_0x03(enc(Header))`.
* **HDR-3.** `state_root` MUST equal the SMT root *after* applying the
  block (§12).
* **HDR-5.** `prev_hash` MUST equal the hash of the parent block; the
  block's height is the parent's height + 1.
* **HDR-6.** `bits` MUST equal `params.pow_bits` (constant difficulty).
* **HDR-7.** `time` MUST be `≥` the parent's `time`.
* **POW-1.** `block_hash`, read as a 256-bit big-endian integer, MUST be
  `≤ target(bits)`.
* **POW-2.** `target(bits)`: exponent `e = bits >> 24`, mantissa
  `m = bits & 0x007fffff`; target `= m × 256^(e−3)` (Bitcoin's compact
  encoding, sign bit ignored).

---

## 10. Transaction rules (non-coinbase)

> **日本語要約**: 入力ごとに (a) 成熟・タイムロック、(b) witness の種別がコインの
> 種別に一致、(c) SLH 署名または移行レシートの検証、(d) SMT からの削除。出力は
> 非包含証明つきで挿入。入力合計 ≥ 出力合計、差額が手数料。

For input `i` of transaction `tx` spending coin `c` at block height `h`:

* **IN-1.** The witness type MUST match the coin: `Slh` for a coin whose
  kind (after unwrapping `Timelock`) is `P2pkSlh`/`MultisigSlh`; `Legacy`
  for a `Legacy` coin. A `Coinbase` witness is invalid here.
* **IN-2.** If `c.coinbase`, then `h ≥ c.height + coinbase_maturity`.
* **IN-3.** If `c.output.kind` is `Timelock{abs, rel, …}`: `h ≥ abs` and
  `h ≥ c.height + rel`.
* **SIG-1.** `sighash_i = H_0x07(genesis_hash ‖ txid ‖ i:u32 ‖ leaf(c))`.
  (`txid` already commits every prevout, output and locktime; `leaf(c)`
  commits the value and condition being spent; `genesis_hash` binds the
  network.)
* **SIG-2.** `P2pkSlh{pkh}`: exactly one signer with `index = 0`,
  `H_0x10(pubkey) = pkh`, and `SLH-DSA.Verify(pubkey, sighash_i, signature)`
  (CRYPTO-3) succeeds.
* **SIG-3.** `MultisigSlh{k, pkhs}`: exactly `k` signers with strictly
  increasing `index < len(pkhs)`; for each, `H_0x10(pubkey) = pkhs[index]`
  and the signature verifies over `sighash_i`.
* **MIG-1.** If any input spends a `Legacy` coin then *all* inputs MUST
  spend `Legacy` coins, and every output kind MUST be `P2pkSlh`,
  `MultisigSlh` or `Timelock` (a *migration transaction*).
* **MIG-2.** For each legacy input `i`, the verifier MUST accept a receipt
  for the migration guest image (§15) whose journal is exactly
  `enc(MigrationJournal{msg_i, script_hash})` with `msg_i` per MIG-3 and
  `script_hash = H_0x0D(script_pubkey)`. Natively the receipt is
  `tx.proofs[i]`; inside the block guest it is an assumption (PRF-4).
* **MIG-3.** `msg_i = H_0x08(genesis_hash ‖ txid ‖ i:u32 ‖ leaf(c))`.
* **AMT-2.** `Σ input values ≥ Σ output values`; the difference is the fee.
* **STATE-3.** Spending an outpoint that is not in the set, or whose
  committed coin differs from the witness coin, is invalid.
* **STATE-4.** Creating an outpoint that already exists is invalid.

---

## 11. Coinbase rules

> **日本語要約**: 入力 1 つ(prevout = (0, height), witness Coinbase)、出力合計 ≤
> 補助金 + 手数料、補助金は 150 ブロックごとに半減、成熟は 100 ブロック。

* **CB-1.** Exactly one input, with a `Coinbase` witness.
* **CB-2.** That input's prevout is `(0³², height)`.
* **CB-3.** `Σ outputs ≤ subsidy(height) + Σ fees of the block`, where
  `subsidy(h) = initial_subsidy >> (h / subsidy_halving_interval)` and 0
  once the shift reaches 64.
* **CB-4.** Coins created by the coinbase have `coinbase = true` and are
  subject to IN-2.
* **CB-5.** Coinbase outputs obey TX-7; `proofs` is empty; `locktime = 0`.

---

## 12. State transition

> **日本語要約**: 操作順序は固定: tx 順に「入力を削除 → 出力を挿入」、ただし
> coinbase の出力は最後(手数料確定後)。各操作に SMT 証明が 1 つ対応。

* **STATE-1.** Operations are applied in this order: for each non-coinbase
  transaction in block order — delete each input's key (input order), then
  insert each non-Data output `(txid, vout)` with
  `Coin{output, height, coinbase=false}` (vout order) — and finally insert
  the coinbase outputs with `coinbase = true`.
* **STATE-2.** A stateless verifier consumes `witness.proofs` in that
  order: a deletion requires `root(key, leaf(c), p) = current_root` and sets
  `current_root ← root(key, 0³², p)`; an insertion requires
  `root(key, 0³², p) = current_root` and sets `current_root ← root(key, leaf, p)`.
  A stateful verifier additionally checks every witness coin against its
  own UTXO set (STATE-3) and MUST reach the same root.
* **STATE-5.** The root before the block is the parent's `state_root`; the
  root after must equal `header.state_root` (HDR-3).

---

## 13. Genesis

> **日本語要約**: ジェネシスはパラメータから決定論的に生成。スナップショット由来の
> コインは height 0・coinbase false の Legacy として SMT に入り、その root が
> `genesis_state_root`。

* **GEN-1.** The genesis block has `prev_hash = 0³²`, one coinbase with
  prevout `(0³², 0)` and a single `Data{"BHSS genesis"}` output of value 0,
  `state_root = genesis_state_root`, `time = genesis_time`,
  `bits = pow_bits`, and the smallest `nonce` satisfying POW-1. It carries
  no receipt and is never validated by §9–§12.
* **GEN-2.** The genesis state is a set of `(OutPoint, Coin)`; its root is
  the SMT root after inserting every entry. Because SMT roots are
  order-independent, anyone can recompute it from the set.
* **GEN-3.** When importing a Bitcoin Core `dumptxoutset`, each coin
  becomes `Coin{Output{value, Legacy{script_pubkey}}, height = 0, coinbase = false}`
  under its original outpoint.
* **GEN-4.** Unspendable scripts (empty, or starting with `OP_RETURN`, or
  longer than 10 000 bytes) are not imported.
* **GEN-5.** `genesis_hash` (used by SIG-1, MIG-3 and the network handshake)
  is the hash of the genesis header.

---

## 14. Block proofs

> **日本語要約**: ブロックの guest(RISC Zero)は本仕様 §9–§12 をステートレスに
> 実行し、journal に (params_hash, height, block_hash, root_prev, root_next,
> migrate_image_id) を出力する。ノードはレシートを image ID と journal の完全一致で
> 検証し、`require_real_proofs=false` のチェーンでは dev-mode の偽レシートも受理する。

* **PRF-1.** The block guest is the RISC Zero program in
  `crates/bhss-methods/guest/src/bin/block.rs`; its image ID is
  consensus. Its private inputs are `enc(ChainParams)`, `genesis_hash`,
  `enc(PrevState)` (`height ‖ hash ‖ state_root ‖ time` of the parent),
  `enc(Block)` with an empty `receipt`, and the migration image ID.
* **PRF-2.** The guest runs §9–§12 with a proof-backed state (STATE-2),
  requires BLK-11, and commits the journal
  `enc(BlockJournal) = params_hash ‖ height:u32 ‖ block_hash ‖ root_prev ‖ root_next ‖ migrate_image_id`.
* **PRF-3.** A node accepts `block.receipt` iff it deserializes to a RISC
  Zero receipt that verifies for the block image ID and whose journal
  bytes equal `enc(BlockJournal)` built from the node's own native result
  (`root_prev` = parent `state_root`, `root_next` = header `state_root`,
  `migrate_image_id` = the node's migration image ID).
* **PRF-4.** Migration receipts are composed: each MIG-2 check inside the
  guest is `env::verify(migrate_image_id, journal)`, so a real block
  receipt is only producible when every migration receipt is available
  and valid. The block receipt therefore covers the migrations.
* **PRF-5.** If `require_real_proofs = false`, a *fake* receipt
  (RISC Zero dev mode) is accepted provided its claim is
  `ReceiptClaim::ok(image_id, journal)` for the expected journal. Such a
  chain has no proof-based security and exists for development only.
* **PRF-6.** Receipts are serialized with `bincode` (serde) of
  `risc0_zkvm::Receipt`; real receipts MUST be succinct (STARK) receipts.

---

## 15. Legacy coins and migration

> **日本語要約**: 認識する旧スクリプトは P2PKH / P2WPKH / P2SH-P2WPKH / P2PK /
> P2TR キーパス / P2SH・P2WSH のベアマルチシグ。署名対象は Bitcoin の sighash では
> なく 32 バイトの `msg_i`。migration guest は「スクリプトに対し署名が正しい」こと
> だけを証明し、秘密鍵・署名・(ハッシュ型なら)公開鍵は journal に出ない。

* **LEG-1.** Recognised templates (byte patterns of `script_pubkey`):

| Kind | Pattern |
|------|---------|
| P2PKH | `76 a9 14 <20> 88 ac` |
| P2WPKH | `00 14 <20>` |
| P2SH | `a9 14 <20> 87` |
| P2WSH | `00 20 <32>` |
| P2TR | `51 20 <32>` |
| P2PK | `21 <33> ac` or `41 <65> ac` |

* **LEG-2.** A bare multisig script is `OP_k <pk>… OP_n OP_CHECKMULTISIG`
  with `0x51 ≤ OP_k ≤ OP_n ≤ 0x60`, each push 33 or 65 bytes, `n ≤ 16`.
* **LEG-3.** Multisig authorization: `k` 64-byte ECDSA signatures that
  match public keys in script order, each key used at most once
  (CHECKMULTISIG semantics without Script).
* **MIG-4.** `MigrationJournal = msg:32 ‖ script_hash:32`,
  `script_hash = H_0x0D(script_pubkey)`.
* **MIG-5.** Authorization data (`MigrationAuth`, private input):
  `0x00 KeyHash{pubkey:bytes, sig:64}` (P2PKH, P2WPKH, P2SH-P2WPKH with
  `redeem = 00 14 HASH160(pubkey)`), `0x01 PubKey{sig:64}` (P2PK),
  `0x02 Taproot{sig:64}` (P2TR key path, BIP340 over the output key),
  `0x03 Multisig{script:bytes, vec<sig:64>}` (P2SH: `HASH160(script)`;
  P2WSH: `SHA256(script)`).
* **MIG-6.** The migration guest (`guest/src/bin/migrate.rs`) takes
  `enc(MigrationInput) = msg ‖ script_pubkey:bytes ‖ auth`, aborts unless
  the authorization verifies for `msg` (ECDSA: 64-byte `r‖s`, verified
  over the 32-byte `msg` as a pre-hashed message; Schnorr: BIP340 over
  `msg`), and commits `enc(MigrationJournal)`.
* **MIG-7.** `HASH160(x) = RIPEMD160(SHA256(x))`; `SHA256` here is untagged
  (Bitcoin compatibility).

---

## 16. Cryptography

> **日本語要約**: SLH-DSA-SHA2-128s、FIPS 205 の pure モード、コンテキスト空、
> 決定論的署名(署名者側)。検証側はランダム化の有無を区別しない。

* **CRYPTO-1.** The only signature scheme for SLH conditions is
  SLH-DSA-SHA2-128s (FIPS 205): public key 32 bytes, signature 7 856 bytes.
* **CRYPTO-2.** Signatures are produced with the *pure* interface
  (`slh_sign`) and an empty context string; the message is the 32-byte
  `sighash_i`. Signers SHOULD use the deterministic variant.
* **CRYPTO-3.** Verification is `slh_verify(M = sighash_i, SIG, ctx = "")`.
  Any signature of the wrong length is invalid.
* **CRYPTO-4.** Legacy verification uses secp256k1 ECDSA (compact 64-byte
  signatures, high-S permitted) and BIP340 Schnorr.

---

## 17. Addresses, network, RPC (non-consensus)

> **日本語要約**: アドレスは bech32m(HRP = params.name, enc(OutputKind))。P2P は
> 長さ接頭辞フレームの単純ゴシップ。RPC は JSON-RPC 2.0。いずれもコンセンサス外。

* **ADDR-1.** `address = bech32m(hrp = params.name, enc(OutputKind))` for
  `P2pkSlh`, `MultisigSlh`, `Timelock` only.
* **NET-1.** Frames are `len:u32 LE ‖ payload`, `payload = tag:u8 ‖ body`:
  `0 Hello{network:bytes, genesis_hash, height:u32, tip}`, `1 Block`,
  `2 Tx`, `3 GetBlocks{from_height:u32, count:u32}`, `4 vec<Block>`.
* **NET-2.** Peers whose `Hello` names a different network or genesis are
  disconnected.
* **NET-3.** Blocks and transactions accepted by a node are relayed to all
  other peers; a block with unknown parent triggers `GetBlocks`.
* **NET-4.** Chain selection: the valid chain with the greatest height
  wins (constant difficulty makes height equivalent to work); ties keep the
  current chain.
* **RPC-1.** JSON-RPC 2.0 at `POST /`. Methods: `getblockchaininfo`,
  `getblockcount`, `getbestblockhash`, `getblockhash`, `getblock`,
  `getrawblock`, `getrawtransaction`, `decoderawtransaction`,
  `sendrawtransaction`, `getrawmempool`, `listunspent`, `listlegacy`,
  `getcoin`, `getbalance`, `generate`, `getpeerinfo`, `getparams`.

---

## Appendix A — Rule index

| Area | IDs |
|------|-----|
| Hashing | HASH-1, HASH-2 |
| Encoding | ENC-1 … ENC-8 |
| Outputs / coins | OUT-1 … OUT-6, AMT-1, COIN-1 |
| Transactions | TX-1 … TX-10 |
| Blocks | BLK-1 … BLK-11 |
| Parameters | PAR-1 … PAR-3 |
| SMT | SMT-1 … SMT-8 |
| Header / PoW | HDR-1 … HDR-7, POW-1, POW-2 |
| Inputs / signatures | IN-1 … IN-3, SIG-1 … SIG-3, AMT-2 |
| Coinbase | CB-1 … CB-5 |
| State | STATE-1 … STATE-5 |
| Genesis | GEN-1 … GEN-5 |
| Proofs | PRF-1 … PRF-6 |
| Legacy / migration | LEG-1 … LEG-3, MIG-1 … MIG-7 |
| Cryptography | CRYPTO-1 … CRYPTO-4 |
| Non-consensus | ADDR-1, NET-1 … NET-4, RPC-1 |

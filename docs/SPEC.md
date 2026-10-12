# BHSS Consensus Specification

**BHSS** = *bitcoin-hardfork-stark-slhdsa*. Specification version 1.

> **日本語要約**: 本書は BHSS(Bitcoin の UTXO スナップショットをジェネシス状態と
> する regtest 用チェーン)のコンセンサスルールの正本である。各ルールには ID
> (例 `TX-3`)が付き、Rust 実装(`crates/bhss-consensus` ほか)とテストはその ID を
> 参照する。要点:
> (1) コンセンサスのハッシュはすべてタグ付き単一 SHA-256、(2) 新規コインの署名は
> SLH-DSA-SHA2-128s のみ、(3) Bitcoin Script は無く、固定の出力タイプのみ、
> (4) UTXO 集合は深さ 256 の SHA-256 スパース Merkle ツリー(SMT)でコミットし、
> すべての状態操作に SMT 証明を要求、(5) 各ブロックは RISC Zero の succinct STARK
> レシートで自身の有効性を証明し、ノードはそれに加えてネイティブでも全ルールを
> 再検証する(二重検証。例外は旧コインの secp256k1 署名のみ)、(6) スナップショット
> 由来の旧 UTXO(secp256k1)は、入力ごとの STARK(マイグレーション証明)でのみ
> 消費できる。STARK 内部のハッシュは SHA-256 ではなく Poseidon2 であり(PRF-8)、
> 証明系の健全性に依存するのは未移行の旧コインだけである。

This document is normative. Where the implementation and this document
disagree, the document wins and the implementation is a bug. "MUST",
"MUST NOT" and "SHOULD" have their RFC 2119 meaning. All integers are
unsigned. `H(x)` is SHA-256 of `x`, `‖` is byte-string concatenation, `0³²`
is 32 zero bytes, and a field written `name:32` is exactly 32 bytes.

Sections 2 to 16 are consensus. Section 17 (addresses, network, RPC)
describes the reference node and is not consensus. Design decisions and
their rationale are in [`DECISIONS.md`](DECISIONS.md).

Terminology: a *competing branch* (or *side branch*) is a sequence of valid
blocks of this same chain that is not part of a node's best chain. This
document never uses "side chain" for it, because that term usually means a
separate chain.

---

## 1. Overview

> **日本語要約**: ノードが受理するブロックの条件と、証明(STARK)が何を担保するかの
> 全体像。証明系が破られても危険にさらされるのは未移行の旧コインだけである。
> `require_real_proofs = false` のチェーンでは偽レシートが通るため、旧コインは
> 鍵を持たない者でも移行できる(開発専用)。

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
theft of **un-migrated legacy coins**; the rules for coins locked by SLH-DSA
conditions are checked natively by every node and do not depend on the
proof system. On a chain whose parameters set `require_real_proofs = false`
(PRF-5) receipts can be fabricated without any proving, so on such a chain
anyone can spend any legacy coin; such chains are for development only.

All conforming validators agree on whether a block is valid. When a block
violates several rules at once, which rule ID an implementation reports is
not part of consensus.

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
| 0x09 | MigrationJournal | reserved (unused; journals are committed raw) |
| 0x0A | Params | chain parameter hash (PAR-2) |
| 0x0B | MerkleNode | Merkle inner node (BLK-3) |
| 0x0C | GenesisState | reserved (unused; the genesis state is committed by its SMT root) |
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
* **ENC-3.** Counts and lengths use Bitcoin CompactSize: a value below
  `0xfd` is one byte; otherwise `0xfd` followed by a u16, `0xfe` followed
  by a u32, or `0xff` followed by a u64 (ENC-1 byte order).
* **ENC-4.** `bytes` = CompactSize length followed by the bytes.
  `vec<T>` = CompactSize count followed by the encoded elements.
* **ENC-5.** A CompactSize MUST use the shortest form that can hold its
  value (for example `0xfd 0x05 0x00` is invalid).
* **ENC-6.** Decoding a top-level object MUST consume the whole input;
  trailing bytes are invalid.
* **ENC-7.** No `vec` or `bytes` may declare a count or length greater
  than 2²⁴, nor greater than the number of input bytes that remain after
  the CompactSize.
* **ENC-8.** `enc(x)` denotes the canonical encoding of `x`. Encodings of
  each type are given with the type below.

---

## 4. Outputs and coins

> **日本語要約**: 出力は「値 + 種別」。種別は P2PK-SLH、k-of-n マルチシグ、
> タイムロック包装、データ、レガシー(スナップショット由来のみ)の 5 つ。
> Data は値 0 で SMT に入らない。Legacy はトランザクションでは作れない。
> 金額とその合計はすべて MAX_MONEY 以下(AMT-1)。

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
* **OUT-2.** `MultisigSlh`: `1 ≤ k ≤ n = len(pkhs) ≤ 16`, and the `pkhs`
  are pairwise distinct (a repeated key would turn k-of-n into fewer-of-n).
* **OUT-3.** `Timelock`: at least one of `abs_height`, `rel_blocks` is
  non-zero; `inner` MUST be `P2pkSlh` or `MultisigSlh`. Nesting is
  impossible at the encoding level: inside a `Timelock` only tags `0x00`
  and `0x01` are valid, and any other tag is a decoding error (decoders
  MUST NOT recurse).
* **OUT-4.** `Data.data` is at most 1 024 bytes.
* **OUT-5.** A `Data` output MUST have `value = 0`. Data outputs are never
  inserted into the UTXO set.
* **OUT-6.** A transaction MUST NOT create a `Legacy` output. Legacy
  outputs exist only in the genesis state (§13). Their script is 1 to
  10 000 bytes (both bounds inclusive).
* **AMT-1.** Every output value and every sum of values a rule computes
  (the output sum and the input sum of a transaction, the sum of the fees
  of a block, `subsidy + fees`) MUST be `≤ MAX_MONEY = 21 000 000 × 10⁸`;
  arithmetic that would overflow `u64` is invalid. (A coinbase that merely
  pays more than `subsidy + fees` is a CB-3 failure.)
* **COIN-1.** A coin records the output, the height of the block that
  created it and whether that transaction was the coinbase.

---

## 5. Transactions

> **日本語要約**: トランザクションは version、入力列(prevout + witness)、出力列、
> locktime、proofs から成る。txid は witness と proofs を除いた「コア」のハッシュ。
> witness は別途 `witness_hash` としてブロックにコミットされる。proofs
> (マイグレーションレシート)はどのハッシュにもコミットされず、内容で検証される。

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
  `proofs[j]` belongs to input `j` (by MIG-1 every input of such a
  transaction is a legacy input). Each proof is at most `MAX_RECEIPT_LEN`
  bytes (PRF-7).
* **TX-10.** The *committed size* of a transaction is
  `len(version ‖ vec<Input> ‖ vec<Output> ‖ locktime)`, i.e. its encoding
  without the `proofs` field.

---

## 6. Blocks

> **日本語要約**: ブロックはヘッダ、トランザクション列、ブロック witness(消費
> コインと SMT 証明)、レシートから成る。Merkle root は tx_commit に対して計算し、
> 奇数要素は複製せずそのまま持ち上げる。witness・レシート・proofs はヘッダに
> コミットされないので、block_hash が同じでも有効性が異なるコピーがありうる
> (ノードは検証済みのコピーしか保存しない)。コミットされるトランザクション列は
> 既定で 128 KiB 以下(BLK-7)、ブロック全体は 32 MiB 以下(BLK-12)。

```
Header       = version:u32 ‖ prev_hash:32 ‖ merkle_root:32 ‖ state_root:32 ‖ time:u32 ‖ bits:u32 ‖ nonce:u32
Block        = header:Header ‖ vec<Transaction> ‖ witness:BlockWitness ‖ receipt:bytes
BlockWitness = vec<Coin> ‖ vec<SmtProof>
SmtProof     = bitmap:32 ‖ vec<sibling:32>
```

* **BLK-1.** Block encoding as above. `receipt` is the serialized RISC
  Zero receipt (§14); `witness`, `receipt` and `Transaction::proofs` are
  not committed by the header — they are validated by content. Hence
  `block_hash` identifies the *committed* part only: two byte strings with
  the same hash can differ in validity. A node MUST NOT treat a block hash
  as permanently invalid because one copy failed a check on uncommitted
  data, and MUST NOT keep a copy it has not validated (see NET-5).
* **BLK-2.** `witness.coins` lists, in block order, the coin spent by each
  input of every non-coinbase transaction. `witness.proofs` lists one SMT
  proof per state operation in the order of STATE-1.
* **BLK-3.** `header.merkle_root` MUST equal the root computed over
  `[tx_commit₀, tx_commit₁, …]`: while more than one element remains,
  replace each adjacent pair `(l, r)` by `H_0x0B(l ‖ r)`; an unpaired last
  element is carried up unchanged. The root of a single element is that
  element.
* **BLK-4.** At least one transaction.
* **BLK-5.** Transaction 0 is the coinbase (§11); no other transaction may
  be or contain a `Coinbase` witness.
* **BLK-6.** No two transactions in a block share a txid.
* **BLK-7.** `CompactSize(len(txs)) + Σ committed_size(tx)` MUST be
  `≤ max_block_tx_bytes` (default 131 072).
* **BLK-8.** The total number of SLH-DSA signers in the block (the sum of
  `len(signers)` over every `Slh` witness of every non-coinbase
  transaction) MUST be `≤ max_sig_checks` (default 16).
* **BLK-9.** The number of legacy inputs in the block (inputs whose
  witness coin is `Legacy`) MUST be `≤ max_migrations` (default 16).
* **BLK-10.** `len(witness.coins)` MUST equal the number of non-coinbase
  inputs.
* **BLK-11.** `len(witness.proofs)` MUST equal the number of state
  operations (non-coinbase inputs + non-`Data` outputs of all transactions,
  STATE-1). Validators check the count before any state or signature
  work; every proof is then consumed in order, none is left over.
* **BLK-12.** `len(enc(Block))` (header, transactions *including* proofs,
  witness and receipt) MUST be `≤ MAX_BLOCK_LEN = 2²⁵` bytes (32 MiB). The
  guest input contains neither the block receipt nor, in general, the
  bytes of `Transaction::proofs` (PRF-1), so like PRF-3 this rule is
  checked by nodes only.

---

## 7. Chain parameters

> **日本語要約**: ネットワーク固有の定数。`params_hash` が各ブロックの journal に
> 入るため、パラメータが違えば証明も互換しない。guest の image ID も params に
> 含まれ(PAR-5)、ノードは起動時にパラメータの妥当性(PAR-4)と、自身に埋め込まれた
> guest との一致を検査する。

```
ChainParams = name:bytes ‖ max_block_tx_bytes:u32 ‖ max_sig_checks:u32 ‖ max_migrations:u32
            ‖ coinbase_maturity:u32 ‖ subsidy_halving_interval:u32 ‖ initial_subsidy:u64
            ‖ pow_bits:u32 ‖ genesis_time:u32 ‖ genesis_state_root:32 ‖ require_real_proofs:bool
            ‖ block_image_id:32 ‖ migrate_image_id:32
```

* **PAR-1.** Default values (network `bhrt`):

| Field | Default |
|-------|---------|
| `name` | `bhrt` |
| `max_block_tx_bytes` | 131 072 (128 KiB) |
| `max_sig_checks` | 16 |
| `max_migrations` | 16 |
| `coinbase_maturity` | 100 |
| `subsidy_halving_interval` | 150 |
| `initial_subsidy` | 5 000 000 000 |
| `pow_bits` | `0x207fffff` |
| `genesis_time` | 1 760 000 000 |
| `genesis_state_root` | computed from the genesis state (GEN-2) |
| `require_real_proofs` | `false` |
| `block_image_id`, `migrate_image_id` | the image IDs of the guests the network is created with (PAR-5) |

  `name` is encoded as `bytes` and MUST be valid UTF-8.
* **PAR-2.** `params_hash = H_0x0A(enc(ChainParams))`.
* **PAR-3.** `name` is also the bech32m human-readable part (ADDR-1).
* **PAR-4.** A parameter set is usable only if `name` is 1–83 characters
  of `[a-z0-9]`, `subsidy_halving_interval > 0`, `max_block_tx_bytes > 0`,
  `max_sig_checks > 0`, `initial_subsidy ≤ MAX_MONEY`, and
  `target(pow_bits)` is non-zero and fits 256 bits (exponent `≤ 32`).
  Nodes refuse to start otherwise.
* **PAR-5.** `block_image_id` / `migrate_image_id` are the RISC Zero image
  IDs (32 bytes, little-endian words) of the two guest programs (PRF-1,
  MIG-2). They are part of `params_hash`, so a chain is bound to exact
  guest binaries; a node whose embedded guests differ (or that carries no
  guests, i.e. zero IDs) MUST refuse to start. `bhss-snapshot` writes the
  IDs of the guests it was built with into `params.json`; the file must be
  regenerated whenever the guest code or its toolchain changes.
  (`params.json` is the JSON object with exactly the field names above;
  the three 32-byte fields are lowercase hex strings. A file with an
  unknown or a missing field is rejected.)

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
* **SMT-7.** `root(key, leaf, proof)`: `h ← leaf`; `j ← len(siblings)`;
  for `i` from 255 down to 0: if bitmap bit `i` is set, `j ← j − 1` and
  `s ← siblings[j]`, otherwise `s ← E[i+1]`; then `h ← node(h, s)` if key
  bit `i` = 0, else `h ← node(s, h)`. (Siblings are stored from depth 0
  downward and therefore consumed from the last to the first.) The result
  is the root implied by the proof. `proof` proves inclusion of
  `(key, leaf)` under `R` iff `root(key, leaf, proof) = R`; it proves
  non-inclusion of `key` iff `root(key, 0³², proof) = R`. A proof that
  violates SMT-5 or SMT-6 has no root and proves nothing.
* **SMT-8.** The same siblings give the post-update root:
  deleting = `root(key, 0³², proof)`, inserting = `root(key, leaf, proof)`.

The in-memory tree in `crates/bhss-smt` is an implementation detail; only
SMT-1…SMT-8 are consensus.

---

## 9. Header rules

> **日本語要約**: version 1、prev_hash が親に一致、bits は固定、time は親以上
> (単調非減少)、block_hash がターゲット以下、merkle_root と state_root(適用後
> root)が一致。難易度調整は無い。

* **HDR-1.** The header is encoded as in §6 (112 bytes).
* **HDR-2.** `block_hash = H_0x03(enc(Header))`.
* **HDR-3.** `state_root` MUST equal the SMT root *after* applying the
  block (§12).
* **HDR-4.** `version = 1`.
* **HDR-5.** `prev_hash` MUST equal the hash of the parent block; the
  block's height is the parent's height + 1.
* **HDR-6.** `bits` MUST equal `params.pow_bits` (constant difficulty).
* **HDR-7.** `time` MUST be `≥` the parent's `time`. Consensus sets no
  upper bound on `time`; the reference node applies one as local policy
  (NET-5).
* **POW-1.** `block_hash`, read as a 256-bit big-endian integer, MUST be
  `≤ target(bits)`.
* **POW-2.** `target(bits)`: exponent `e = bits >> 24`, mantissa
  `m = bits & 0x007fffff`. For `e ≥ 3` the target is `m × 256^(e−3)`; for
  `e < 3` it is `⌊m / 256^(3−e)⌋`. (This is Bitcoin's compact encoding
  with the sign bit `0x00800000` ignored.) PAR-4 restricts `e` to at most
  32, so the target fits 256 bits.

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
  `h ≥ c.height + rel`. In IN-2 and IN-3 a sum that exceeds `2³² − 1` is
  replaced by `2³² − 1` (saturating addition).
* **SIG-1.** `sighash_i = H_0x07(genesis_hash ‖ txid ‖ i:u32 ‖ leaf(c))`.
  (`txid` already commits every prevout, output and locktime; `leaf(c)`
  (SMT-3) commits the value, the condition, the creation height and the
  coinbase flag of the coin being spent; `genesis_hash` (GEN-5) binds the
  network. There are no sighash flags.)
* **SIG-2.** `P2pkSlh{pkh}`: exactly one signer (any other count is a
  SIG-2 failure) with `index = 0`,
  `H_0x10(pubkey) = pkh`, and `SLH-DSA.Verify(pubkey, sighash_i, signature)`
  (CRYPTO-3) succeeds.
* **SIG-3.** `MultisigSlh{k, pkhs}`: exactly `k` signers with strictly
  increasing `index < len(pkhs)`; for each, `H_0x10(pubkey) = pkhs[index]`
  and the signature verifies over `sighash_i`. (Every failure of a
  multisig spend, including a bad signature of one signer, is a SIG-3
  failure; SIG-2 is reserved for `P2pkSlh`.)
* **MIG-1.** If any input spends a `Legacy` coin then *all* inputs MUST
  spend `Legacy` coins, and every output kind MUST be `P2pkSlh`,
  `MultisigSlh` or `Timelock` (a *migration transaction*).
* **MIG-2.** For each legacy input `i`, there MUST be a valid receipt
  (PRF-5, PRF-6) for the migration guest image (§15) whose journal is
  exactly `enc(MigrationJournal{msg_i, script_hash})` with `msg_i` per
  MIG-3 and `script_hash = H_0x0D(script_pubkey)`. Natively the receipt is
  `tx.proofs[i]`; inside the block guest it is an assumption (PRF-4).
* **MIG-3.** `msg_i = H_0x08(genesis_hash ‖ txid ‖ i:u32 ‖ leaf(c))`.
* **AMT-2.** `Σ input values ≥ Σ output values`; the difference is the fee.
* **STATE-3.** Spending an outpoint that is not in the set, or whose
  committed coin differs from the witness coin, is invalid. The set is the
  one produced by all earlier operations of STATE-1, so a transaction MAY
  spend an output created by an earlier transaction of the same block.
* **STATE-4.** Creating an outpoint that already exists is invalid.

---

## 11. Coinbase rules

> **日本語要約**: 入力は 1 つ(prevout = (0³², height)、witness は Coinbase)、
> 出力合計 ≤ 補助金 + 手数料。既定値では補助金は 150 ブロックごとに半減し、
> coinbase 由来のコインは 100 ブロック後に使える。

* **CB-1.** Exactly one input, with a `Coinbase` witness.
* **CB-2.** That input's prevout is `(0³², height)`.
* **CB-3.** `Σ outputs ≤ subsidy(height) + Σ fees of the block`, where
  `subsidy(h) = initial_subsidy >> ⌊h / subsidy_halving_interval⌋` and 0
  once the shift reaches 64. Paying less is valid; the difference is
  destroyed.
* **CB-4.** Coins created by the coinbase have `coinbase = true` and are
  subject to IN-2.
* **CB-5.** The coinbase obeys TX-1 and its outputs obey TX-7; `proofs` is
  empty; `locktime = 0`.

---

## 12. State transition

> **日本語要約**: 操作順序は固定である。トランザクション順に、入力を削除して
> から出力を挿入する。ただし coinbase の出力は最後(手数料確定後)に挿入する。
> 各操作に SMT 証明が 1 つ対応する。UTXO 集合を持たない検証者(guest、および
> 競合ブランチのブロックを検証するノード)は、witness の証明だけで同じ判定に至る。

* **STATE-1.** Operations are applied in this order: for each non-coinbase
  transaction in block order — delete each input's key (input order), then
  insert each non-Data output `(txid, vout)` with
  `Coin{output, height, coinbase=false}` (vout order) — and finally insert
  the coinbase outputs with `coinbase = true`.
* **STATE-2.** A stateless verifier consumes `witness.proofs` in that
  order: a deletion requires `root(key, leaf(c), p) = current_root` and sets
  `current_root ← root(key, 0³², p)`; an insertion requires
  `root(key, 0³², p) = current_root` and sets `current_root ← root(key, leaf, p)`.
  A failed proof check is a STATE-2 failure. A stateful verifier first
  checks every operation against its own UTXO set (STATE-3, STATE-4) and
  MUST reach the same root. Both kinds of verifier therefore always agree
  on whether a block is valid, but they may name different rules for the
  same invalid block: a stateless verifier (the guest, or a node judging
  a block on a competing branch) cannot tell "the coin is not in the set"
  from "the proof is wrong" and reports STATE-2 for both.
* **STATE-5.** The root before the block is the parent's `state_root`; the
  root after must equal `header.state_root` (HDR-3).

---

## 13. Genesis

> **日本語要約**: ジェネシスはパラメータから決定論的に生成。スナップショット由来の
> コインは height 0・coinbase false の Legacy として SMT に入り、その root が
> `genesis_state_root`。outpoint は重複せず、合計額は MAX_MONEY 以下(GEN-2)。

* **GEN-1.** The genesis block has `prev_hash = 0³²`, one coinbase with
  prevout `(0³², 0)` and a single `Data{"BHSS genesis"}` output of value 0,
  `state_root = genesis_state_root`, `time = genesis_time`,
  `bits = pow_bits`, and the smallest `nonce` satisfying POW-1. It carries
  no receipt and is never validated by §9–§12.
* **GEN-2.** The genesis state is a set of `(OutPoint, Coin)` with
  pairwise distinct outpoints, every coin a well-formed `Legacy` coin
  (OUT-6) with `height = 0`, `coinbase = false`, and a total value
  `≤ MAX_MONEY`. Its root is the SMT root after inserting every entry.
  Because SMT roots are order-independent, anyone can recompute it from
  the set.
* **GEN-3.** When importing a Bitcoin Core `dumptxoutset` file, each coin
  becomes `Coin{Output{value, Legacy{script_pubkey}}, height = 0, coinbase = false}`
  under its original outpoint. `txid` is the 32 bytes as serialized in the
  file (Bitcoin's internal byte order, the reverse of the hex string
  Bitcoin RPCs display). The coin's original height and coinbase flag are
  discarded. The importer reads the format with the `utxo\xff` magic and
  version 2, and the older format without magic; it does not check the
  network magic or the base block hash of the file, and nothing in the
  chain parameters records them.
* **GEN-4.** Unspendable scripts (empty, or starting with `OP_RETURN`) are
  not imported. A snapshot containing a script longer than 10 000 bytes
  (which Bitcoin Core never writes) is rejected as corrupt, as is one with
  non-canonical lengths, an amount that overflows, or trailing bytes.
* **GEN-5.** `genesis_hash` (used by SIG-1, MIG-3, the block journal
  (PRF-2) and the network handshake) is the hash of the genesis header.

---

## 14. Block proofs

> **日本語要約**: ブロックの guest(RISC Zero)は本仕様 §9–§12 をステートレスに
> 実行し、journal に (params_hash, genesis_hash, height, block_hash, prev_time,
> root_prev, root_next, migrate_image_id) を出力する。guest への入力のうち
> block_hash から導けないものはすべて journal に含まれるので、証明者が別の値を
> 与えて「正しい証明」を作ることはできない。ノードはレシートを image ID と
> journal の完全一致で検証する。`require_real_proofs = false` のチェーンは
> dev-mode の偽レシートも受理し、証明による安全性を持たない。レシートは 1 MiB
> 以下。証明系はハッシュベースの FRI STARK(succinct レシート)のみで、Groth16
> などの SNARK は生成も受理もしない(PRF-6, PRF-8)。ただし STARK 内部のハッシュは
> SHA-256 ではなく Poseidon2 であり、安全性は推測ベースで 97 ビットである。

* **PRF-1.** The block guest is the RISC Zero program in
  `crates/bhss-methods/guest/src/bin/block.rs`; its image ID is consensus
  (`params.block_image_id`, PAR-5). It reads five private inputs, each as
  one frame `len:u32 ‖ payload` (ENC-1), in this order:
  `enc(ChainParams)`; `genesis_hash` (32 bytes); `enc(PrevState)` with
  `PrevState = height:u32 ‖ hash:32 ‖ state_root:32 ‖ time:u32` of the
  parent; `enc(Block)` with an empty `receipt` (the guest aborts
  otherwise); the migration image ID (32 bytes). A prover SHOULD also
  replace every element of every `Transaction::proofs` in that input by
  the empty byte string, keeping the number of elements: the guest uses
  only the count (TX-9), and the bytes are committed by no hash.
* **PRF-2.** The guest runs §9–§12 with a proof-backed state (STATE-2),
  requires BLK-11, and commits the journal
  `enc(BlockJournal) = params_hash ‖ genesis_hash ‖ height:u32 ‖ block_hash ‖ prev_time:u32 ‖ root_prev ‖ root_next ‖ migrate_image_id`
  (200 bytes). Every private input that is not fixed by `block_hash` (the
  parameters, the genesis hash used in SIG-1/MIG-3, the parent's height,
  time and state root, and the migration image ID) therefore appears in
  the journal; a prover cannot substitute any of them. The parent's hash
  is fixed by `block_hash` through `prev_hash` (HDR-5).
* **PRF-3.** A node accepts `block.receipt` iff it deserializes to a RISC
  Zero receipt (PRF-6) that verifies for the block image ID and whose
  journal bytes equal `enc(BlockJournal)` built from the node's own view:
  its `params_hash` and `genesis_hash`, `height` = the parent's height
  + 1, `block_hash` = the hash of the block's header, the parent's `time`
  and `state_root` as `prev_time` and `root_prev`, `root_next` = the
  header's `state_root`, and `migrate_image_id` = the node's migration
  image ID.
* **PRF-4.** Migration receipts are composed: each MIG-2 check inside the
  guest is `env::verify(migrate_image_id, journal)`, which adds an
  assumption that the prover must discharge with the matching migration
  receipt. A real block receipt can therefore be produced only when every
  migration receipt is available and valid, and it covers the migrations.
* **PRF-5.** If `require_real_proofs = false`, a *fake* receipt
  (RISC Zero dev mode) is accepted provided its claim is
  `ReceiptClaim::ok(image_id, journal)` for the expected image ID and
  journal. A fake receipt contains no proof. Such a chain has no
  proof-based security (in particular, MIG-2 can be satisfied without any
  legacy key) and exists for development only. If
  `require_real_proofs = true`, fake receipts are invalid.
* **PRF-6.** A receipt is the `bincode` 1.x serialization (fixed-width
  little-endian integers) of `risc0_zkvm::Receipt`; bytes after the end of
  the serialized value are ignored. Real receipts MUST be succinct (STARK)
  receipts. Composite receipts (which may carry fake assumption receipts)
  and Groth16 receipts (pairing-based, trusted setup) are rejected, as is
  anything that does not deserialize. Verification never consults the
  `RISC0_DEV_MODE` environment variable: whether fake receipts pass is
  decided by `require_real_proofs` alone (PRF-5).
* **PRF-7.** A serialized receipt (the block receipt, and each element of
  `Transaction::proofs`) MUST be `≤ MAX_RECEIPT_LEN = 2²⁰` bytes (1 MiB).
  Nodes check both. The guest applies the same check to the `proofs`
  elements of its input (it is part of TX-9's context), which is vacuous
  when the prover has emptied them (PRF-1); it never sees the block
  receipt.
* **PRF-8.** The proof system is hash-based: a succinct receipt is a
  FRI-based STARK over the BabyBear field, with no elliptic-curve or
  pairing assumption and no trusted setup. Groth16 receipts are neither
  produced nor accepted (PRF-6). The hash used for the STARK's Merkle
  commitments and Fiat–Shamir transcript is **Poseidon2**, not SHA-256
  (in RISC Zero 3.0.x segment proofs accept no other hash, so a pure
  SHA-256 configuration does not exist in this version). Soundness
  therefore rests on Poseidon2, on the *conjectured* soundness of FRI at
  the RISC Zero parameters (stated by RISC Zero as 97 bits of conjectured
  security), and on the correctness of the RISC Zero circuits, recursion
  programs, verifier and of the two guest programs. This specification
  makes no claim about the security of the proof system against quantum
  attackers. As everywhere else in this specification (§1), the proof
  system only protects un-migrated legacy coins.

---

## 15. Legacy coins and migration

> **日本語要約**: 認識する旧スクリプトは P2PKH / P2WPKH / P2SH-P2WPKH / P2PK /
> P2TR キーパス / P2SH・P2WSH で包んだベアマルチシグ。それ以外のスクリプトの
> コインはジェネシス状態には入るが、消費できない。署名対象は Bitcoin の sighash
> ではなく 32 バイトの `msg_i`。migration guest は「スクリプトに対し署名が正しい」
> ことだけを証明し、署名と(ハッシュ型なら)公開鍵は journal にもチェーン上の
> データにも現れない。

* **LEG-1.** Recognised templates (byte patterns of `script_pubkey`):

| Kind | Pattern |
|------|---------|
| P2PKH | `76 a9 14 <20> 88 ac` |
| P2WPKH | `00 14 <20>` |
| P2SH | `a9 14 <20> 87` |
| P2WSH | `00 20 <32>` |
| P2TR | `51 20 <32>` |
| P2PK | `21 <33> ac` or `41 <65> ac` |

  A P2SH or P2WSH coin is migratable only as described in MIG-5 (P2SH
  wrapping P2WPKH; P2SH or P2WSH wrapping a bare multisig script). A
  legacy coin whose script matches no template, or matches one only in a
  form MIG-5 does not cover (for example a bare multisig `script_pubkey`,
  a P2TR script-path spend, P2SH-P2WSH, or any other script), is part of
  the genesis state but can never be spent.

* **LEG-2.** A bare multisig script is `OP_k <pk>… OP_n OP_CHECKMULTISIG`
  with `0x51 ≤ OP_k ≤ OP_n ≤ 0x60`, each push 33 or 65 bytes, `n ≤ 16`.
* **LEG-3.** Multisig authorization: exactly `k` 64-byte ECDSA signatures.
  The public keys are scanned once in script order; the next unmatched
  signature is checked against each key, and when it verifies the scan
  moves to the next signature. The authorization holds iff all `k`
  signatures are matched (CHECKMULTISIG semantics without Script:
  signatures in key order, each key used at most once).
* **MIG-4.** `MigrationJournal = msg:32 ‖ script_hash:32`,
  `script_hash = H_0x0D(script_pubkey)`.
* **MIG-5.** Authorization data (`MigrationAuth`, private input):
  `0x00 KeyHash{pubkey:bytes, sig:64}` (P2PKH; P2WPKH and P2SH-P2WPKH
  with `redeem = 00 14 HASH160(pubkey)`, for both of which the pubkey
  MUST be the 33-byte compressed form), `0x01 PubKey{sig:64}` (P2PK),
  `0x02 Taproot{sig:64}` (P2TR key path, BIP340 over the output key),
  `0x03 Multisig{script:bytes, vec<sig:64>}` (P2SH: `HASH160(script)`;
  P2WSH: `SHA256(script)`).
* **MIG-6.** The migration guest
  (`crates/bhss-methods/guest/src/bin/migrate.rs`) takes
  `enc(MigrationInput) = msg ‖ script_pubkey:bytes ‖ auth` as one frame
  (PRF-1), aborts unless
  the authorization verifies for `msg` (ECDSA: 64-byte `r‖s`, verified
  over the 32-byte `msg` as a pre-hashed message; Schnorr: BIP340 over
  `msg`), and commits `enc(MigrationJournal)`.
* **MIG-7.** `HASH160(x) = RIPEMD160(SHA256(x))`; `SHA256` here is untagged
  (Bitcoin compatibility).

---

## 16. Cryptography

> **日本語要約**: SLH-DSA-SHA2-128s、FIPS 205 の pure モード、コンテキスト空、
> 決定論的署名(署名者側)。検証側はランダム化の有無を区別しない。旧コインの検証は
> secp256k1 ECDSA(high-S は正規化して受理)と BIP340 Schnorr。hybrid 公開鍵
> (0x06/0x07)は非対応。

* **CRYPTO-1.** The only signature scheme for SLH conditions is
  SLH-DSA-SHA2-128s (FIPS 205): public key 32 bytes, signature 7 856 bytes.
* **CRYPTO-2.** Signatures are produced with the *pure* interface
  (`slh_sign`) and an empty context string; the message is the 32-byte
  `sighash_i`. Signers SHOULD use the deterministic variant.
* **CRYPTO-3.** Verification is `slh_verify(M = sighash_i, SIG, ctx = "")`.
  A signature whose length is not exactly 7 856 bytes is invalid.
* **CRYPTO-4.** Legacy verification uses secp256k1 ECDSA (compact 64-byte
  signatures; high-S permitted — verifiers normalize `s` before checking)
  and BIP340 Schnorr. ECDSA public keys are SEC1 compressed (33 bytes,
  first byte `0x02`/`0x03`) or uncompressed (65 bytes, first byte `0x04`);
  any other encoding (hybrid `0x06`/`0x07`, compact `0x05`) never verifies.

---

## 17. Addresses, network, RPC (non-consensus)

> **日本語要約**: アドレスは bech32m(HRP = params.name、データ = enc(OutputKind))。
> P2P は長さ接頭辞フレームの単純なゴシップで、認証も暗号化も無い。最初のフレームは
> Hello でなければならない(NET-7)。競合ブランチ(同じチェーンの、ベストチェーンに
> 入らなかった枝。フォークとも呼ぶ)のブロックも、保存前に親の state root に対して
> ステートレスに完全検証し、メモリ上に 64 MiB まで保持する(NET-5)。チェーン選択は
> 高さが最大の有効なチェーン(NET-4)。mempool は 1 000 件 / 16 MiB で、最低手数料は
> 無い(NET-6)。RPC は JSON-RPC 2.0 形式で認証が無い(RPC-1)。本章はいずれも
> コンセンサス外で、参照ノード `bhssd` の動作を記述する。

This section describes the reference node (`bhssd`). Nothing in it affects
block validity. The peer-to-peer protocol has no authentication and no
encryption, and peers are neither scored nor banned.

* **ADDR-1.** `address = bech32m(hrp = params.name, data = enc(OutputKind))`
  for well-formed `P2pkSlh`, `MultisigSlh` and `Timelock` kinds only. The
  data part is the encoding regrouped into 5-bit symbols as in BIP 173;
  there is no witness-version symbol. A `P2pkSlh` address has 53 data
  symbols; addresses of the other kinds can be longer than the 90
  characters to which BIP 173 limits an address.
  Encoders MUST produce the bech32m checksum. The reference decoder also
  accepts the original bech32 checksum over the same data (a deviation
  from this rule; an address is not consensus data, so this affects only
  the error-detection strength of a typed address).
* **NET-1.** Frames are `len:u32 ‖ payload` with `len ≤ 48 MiB`
  (50 331 648 bytes); `payload = tag:u8 ‖ body`, decoded under §3:

| Tag | Message | Body |
|----:|---------|------|
| 0 | `Hello` | `network:bytes ‖ genesis_hash:32 ‖ params_hash:32 ‖ height:u32 ‖ tip:32` |
| 1 | `Block` | `Block` |
| 2 | `Tx` | `Transaction` |
| 3 | `GetBlocks` | `from_height:u32 ‖ count:u32` |
| 4 | `Blocks` | `vec<Block>` |
| 5 | `Ping` | empty |

  `network` is `params.name`; `height` and `tip` describe the sender's
  best chain (`tip` is informational). A frame that is too long or does
  not decode ends the connection. The reply to `GetBlocks` is one `Blocks`
  message holding best-chain blocks from `from_height` upward: at most
  `min(count, 32)` blocks, and no further block once the encoded blocks
  would exceed 8 MiB, except that the first block is always included. A
  request for heights the node does not have is answered with an empty
  list. Each side sends `Ping` every 60 s; a peer from which no frame
  arrives for 300 s (30 s before its `Hello`) is dropped. A node serves at
  most 64 inbound peers and re-dials each configured outbound peer 2 s
  after a failed attempt or a closed connection.
* **NET-2.** Peers whose `Hello` names a different network, genesis or
  `params_hash` are disconnected.
* **NET-3.** A transaction the node admits to its mempool is relayed to
  all other peers. A block is relayed to all other peers when its arrival
  extends the node's best chain or makes the node switch to another
  branch; the earlier blocks of an adopted branch are not relayed again
  (peers obtain them through (b) below), and blocks stored on a competing
  branch are not relayed. Relay is best effort. Block download keeps at
  most one `GetBlocks` outstanding per peer, always with `count = 32`:
  (a) a peer whose `Hello` announces a greater height is asked for the
  blocks above the node's tip;
  (b) a block with an unknown parent (the peer is on another branch)
  triggers a request for the 32 heights ending at the node's tip, and
  each reply that again contains a block with an unknown parent moves
  that window down by 32, until a window starting at height 1 has been
  tried;
  (c) a reply whose blocks were all already known or were stored on a
  competing branch is followed by a request for the next heights, so that
  after the fork point is found the node walks forward until a block
  connects or the node reorganizes;
  (d) a reply that extends the best chain continues from the new tip, as
  long as the peer announced a greater height or relayed a block with an
  unknown parent while the request was outstanding (it has mined past the
  height in its `Hello`); an empty reply, or a reply containing an invalid
  block and no block that extended the best chain, ends the exchange.
  A node answers every `GetBlocks`, with an empty `Blocks` if it has
  nothing, holds at most one `Blocks` reply per peer in memory, and drops
  a peer that does not take a frame within 300 s. An invalid block or
  transaction is discarded without disconnecting its sender.
* **NET-4.** Chain selection: the valid chain with the greatest height
  wins (constant difficulty makes height equivalent to work); between
  chains of equal height the node keeps the one it already follows.
* **NET-5.** A node stores only blocks it has fully validated, and
  validates only blocks whose parent it has stored; a block whose parent
  (or an ancestor on its branch) is not stored is treated as having an
  unknown parent and is not kept. Validation proceeds in this order:
  1. the cheap checks: HDR-4, HDR-6, HDR-7, POW-1, the policy
     `time ≤ now + 7 200 s` (node clock), PRF-7 for the block receipt,
     BLK-12 and BLK-7;
  2. the receipt (PRF-3);
  3. §9–§12 in full. A block that extends the best chain is checked
     against the node's UTXO set and, in addition, against the block
     witness (STATE-2). A block on any other branch is checked
     statelessly, against the witness and the parent's `state_root` alone
     (STATE-2); the node does not hold the UTXO set of that branch.

  Because every stored block is valid, a second copy of a stored hash is
  ignored even if its uncommitted bytes differ (BLK-1), and a rejected
  copy leaves no trace, so it cannot shadow a valid one. A block rejected
  only by the time policy can be accepted when it is received again later.

  Blocks on competing branches are kept in memory only, up to 64 MiB of
  encoded size in total. When a new block takes the store over that
  budget, the oldest stored competing-branch blocks that are not ancestors
  of the new block are evicted until the budget is met; if only the new
  block's own branch is left and the store is still over the budget, the
  new block is dropped instead, so stored branches stay connected. A
  competing branch that needs more than 64 MiB of this storage therefore
  cannot be adopted (see DECISIONS, limitations).

  A block on another branch whose height exceeds the best chain's height
  triggers a reorganization: the node rebuilds the UTXO set from the
  genesis state by applying the stored blocks of the new best chain
  without re-verifying signatures or receipts, and requires every
  resulting root to equal the block's `state_root`. The blocks of the
  abandoned branch become competing-branch blocks. Best-chain blocks are
  written to the data directory; at start the node replays them with full
  validation (steps 1 to 3).
* **NET-6.** The mempool holds at most 1 000 transactions and at most
  16 MiB of encoded transactions (proofs included). There is no minimum
  fee and no eviction by fee. A transaction is admitted only if it is not
  a coinbase, is not already in the best chain, could fit a block on its
  own (BLK-8, BLK-9, and BLK-7 with 640 bytes reserved for the coinbase
  and the transaction count, the same reserve block templates use), and
  is fully valid at the next height against the UTXO set as modified by
  every transaction already in the mempool (so mempool double spends are
  rejected). After every new tip an entry stays iff each of its inputs
  still resolves to exactly the coin it was validated against and IN-2,
  IN-3 and TX-8 hold at the next height; no signature or receipt is
  verified again, because SIG-1 and MIG-3 bind them to that coin.
  (Consequence: a transaction spending an *unconfirmed* output is only
  minable in the same block as its parent at the height it was signed
  for, since the leaf it signed includes the parent's confirmation
  height.) Transactions of blocks disconnected by a reorganization are
  re-validated in full and return ahead of the waiting entries; coinbases
  never return. A node started with `--prove-mode real` does not admit
  transactions carrying fake migration receipts, even on a chain whose
  consensus accepts them. A block template takes mempool transactions in
  arrival order, skipping any that would exceed BLK-7, BLK-8 or BLK-9 and
  any whose mempool parent was skipped; its `time` is the node clock, or
  the parent's `time` if that is greater.
* **NET-7.** The first frame a peer sends MUST be `Hello`; anything else
  disconnects the peer.
* **RPC-1.** JSON-RPC 2.0 request objects at `POST /` (one request per
  HTTP request, positional parameters, no batches; every error has code
  `-1`). Methods: `getblockchaininfo`, `getblockcount`,
  `getbestblockhash`, `getblockhash`, `getblock`, `getrawblock`,
  `getrawtransaction`, `decoderawtransaction`, `sendrawtransaction`,
  `getrawmempool`, `listunspent`, `listlegacy`, `getcoin`, `getbalance`,
  `generate` (at most 1 000 blocks per call), `getpeerinfo`, `getparams`.
  `getblockchaininfo` reports, among others, `params_hash`,
  `block_image_id`, `migrate_image_id`, `require_real_proofs` and the
  node's `prove_mode`. `listunspent` and `getbalance` include immature
  coinbase coins and timelocked coins. There is no authentication, and
  any caller can mine blocks with `generate`: bind the RPC to a trusted
  interface only (the default is `127.0.0.1:18443`).

---

## Appendix A — Rule index

| Area | IDs |
|------|-----|
| Hashing | HASH-1, HASH-2 |
| Encoding | ENC-1 … ENC-8 |
| Outputs / coins | OUT-1 … OUT-6, AMT-1, COIN-1 |
| Transactions | TX-1 … TX-10 |
| Blocks | BLK-1 … BLK-12 |
| Parameters | PAR-1 … PAR-5 |
| SMT | SMT-1 … SMT-8 |
| Header / PoW | HDR-1 … HDR-7, POW-1, POW-2 |
| Inputs / signatures | IN-1 … IN-3, SIG-1 … SIG-3, AMT-2 |
| Coinbase | CB-1 … CB-5 |
| State | STATE-1 … STATE-5 |
| Genesis | GEN-1 … GEN-5 |
| Proofs | PRF-1 … PRF-8 |
| Legacy / migration | LEG-1 … LEG-3, MIG-1 … MIG-7 |
| Cryptography | CRYPTO-1 … CRYPTO-4 |
| Non-consensus | ADDR-1, NET-1 … NET-7, RPC-1 |

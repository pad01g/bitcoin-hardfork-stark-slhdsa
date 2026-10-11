# BHSS — Design Decisions (2026-10-10)

> 日本語要約: Bitcoin signet/regtest 向けハードフォーク "BHSS" (bitcoin-hardfork-stark-slhdsa) の設計決定記録。
> 署名は SLH-DSA-SHA2-128s のみ、各ブロックは RISC Zero STARK で自身の有効性を証明し、
> ノードはネイティブ検証も併せて行う(二重検証)。UTXO 集合は SHA-256 スパース Merkle ツリーで
> コミットし、全入力に包含証明を要求する。旧 UTXO(secp256k1)は支出者が作る tx 単位の
> マイグレーション STARK でのみ消費できる。開発は Docker 経由のみ。

Project name: **BHSS** (bitcoin-hardfork-stark-slhdsa). Crate prefix `bhss-`, node binary `bhssd`, CLI `bhss-cli`,
bech32m HRP `bhrt` (regtest) / `bhsn` (signet-snapshot net). Rename is a global search-and-replace.

## 1. Proof role

| ID | Decision |
|----|----------|
| D1 | Every block carries a RISC Zero STARK receipt proving **full block validity** (Hazync-style): header rules, tx structure, amounts, SLH-DSA signatures, SMT state transition `root_prev → root_next`, and composition of migration proofs. |
| D2 | Proof is **synchronous**: the block itself contains its own receipt. No delayed commit. |
| D3 | Nodes perform **double verification**: the receipt must verify, *and* the node re-validates everything natively (SLH-DSA, amounts, SMT updates) against its own full UTXO set. A block is valid only if both pass. The one exception is legacy (secp256k1) signatures inside migration proofs, which are verified only inside the STARK. STARK soundness failure therefore only endangers un-migrated legacy coins, never SLH-DSA-locked coins. |
| D4 | Proof system: **RISC Zero zkVM**, Rust guest, SHA-256 accelerator. The consensus crate exposes a `ProofVerifier` trait so SP1 could be swapped later, but v1 implements only RISC0. |
| D5 | Dev loop uses `RISC0_DEV_MODE=1` (fake receipts). Real proving is explicit via `make prove`. The chain parameter `require_real_proofs` controls whether fake receipts are accepted (PRF-5); it is `false` for `bhrt` and should be `true` for `bhsn`. |

## 2. Cryptography

| ID | Decision |
|----|----------|
| C1 | Only signature scheme for new outputs: **SLH-DSA-SHA2-128s** (FIPS 205). Pubkey 32 B, signature 7 856 B. No parameter-set agility in v1. |
| C2 | All hashing in consensus is SHA-256 with domain-separation tags (first byte). No SHA256d, no RIPEMD-160 for new output types. |
| C3 | Legacy (migration) verification supports: P2PKH, P2WPKH, P2SH-P2WPKH, P2PK (ECDSA); P2TR key-path (BIP340 Schnorr); P2WSH / P2SH standard `OP_CHECKMULTISIG` (ECDSA). Verified inside the migration guest only. |

## 3. Transaction and script model

| ID | Decision |
|----|----------|
| T1 | Bitcoin Script is **removed**. Outputs are typed: `P2PK_SLH(pubkey_hash)`, `MULTISIG_SLH(k, [pubkey_hash])`, optional absolute/relative timelock wrapper, `DATA(bytes)` (unspendable, OP_RETURN equivalent), and `LEGACY(bitcoin_script_pubkey)` (snapshot-only, never creatable by a new tx). |
| T2 | Legacy outputs are spendable **only by a migration transaction**: all inputs are `LEGACY`, all outputs are new-type, and the witness carries one RISC0 receipt per input (or one per tx) proving `SMT inclusion ∧ legacy signature valid` for a sighash over the migration tx. The legacy signature and (for hashed-pubkey types) the pubkey are private witness, never on chain. |
| T3 | The block guest composes migration receipts via `env::verify` (receipt assumption), so the block proof covers them. |
| T4 | Every input (legacy or new) carries an SMT inclusion proof in its witness. |

## 4. State commitment

| ID | Decision |
|----|----------|
| S1 | UTXO set commitment: **SHA-256 sparse Merkle tree**, depth 256. Key = `SHA256(0x02 ‖ txid ‖ vout_le32)`, leaf = `SHA256(0x00 ‖ txout_bytes ‖ height_le32 ‖ coinbase_flag)`, node = `SHA256(0x01 ‖ l ‖ r)`, empty subtree hashes precomputed. Roots are order-independent, so a `dumptxoutset` snapshot deterministically yields the genesis root. |
| S2 | Wire format of inclusion proofs omits empty-subtree siblings via a 256-bit bitmap. |
| S3 | Non-membership proofs are used to forbid creating an outpoint that already exists. |
| S4 | Nodes are stateful (full UTXO set in a KV store) but the guest is stateless: public inputs are `(root_prev, root_next, block_hash, chain_params_hash)`. |

## 5. Network and blocks

| ID | Decision |
|----|----------|
| N1 | Block production: **regtest-style only**. SHA256d-free header; PoW is a minimal SHA-256 target check so anyone can `generate`. No signet block-signing challenge in v1. |
| N2 | Two chainparams: `bhrt` (regtest, empty or synthetic snapshot) and `bhsn` (same rules, genesis root taken from a signet `dumptxoutset`). A tool `bhss-snapshot` parses Core's `dumptxoutset` format and builds the genesis SMT. |
| N3 | Default limits: block ≤ **128 KiB** serialized (excluding the receipt), ≤ **16 signature verifications** per block, ≤ 64 inputs. Values are chainparams. |
| N4 | Subsidy/halving/maturity copy Bitcoin regtest (50 coins, halving every 150 blocks, 100-block maturity). |
| N5 | v1 software: `bhss-consensus` (no_std, shared with guest), `bhss-smt`, `bhss-slhdsa` (wrapper over RustCrypto `slh-dsa`), `bhss-guest-block`, `bhss-guest-migrate`, `bhss-prover`, `bhssd` (minimal gossip P2P + JSON-RPC), `bhss-cli` (keys, sign, build migration proof). No Bitcoin P2P wire compatibility. |

## 6. Process

| ID | Decision |
|----|----------|
| P1 | Spec: `docs/SPEC.md`, English body with a Japanese summary at the top of each chapter. Every rule has an ID (`HDR-n`, `TX-n`, `BLK-n`, `SMT-n`, `MIG-n`, `PRF-n`) referenced from code and tests. |
| P2 | All tooling runs in Docker (linux/arm64 image with Rust + `rzup`). `Makefile` wraps `docker run`; `docker compose` runs multi-node regtest. Nothing is installed on the host. |
| P3 | Real proving locally is CPU-only inside Docker (8 CPU / 8 GB); expect minutes per small block. |

## Implementation notes (2026-10-11)

- `slh-dsa` 0.1.0 is vendored under `vendor/` with its `signature` dependency
  pinned to the stable 2.2 line; the crates.io release requires a `2.3.0-pre`
  that cannot coexist with `k256` 0.13.
- The dev image is `linux/amd64` (Rosetta on Apple Silicon): RISC Zero
  publishes Linux toolchains for x86_64 only. `rust:1.98.1` because risc0 3.0.6
  dependencies need rustc ≥ 1.90.
- RISC Zero's generated C++ prover kernels are compiled with `-O1`
  (`RISC0_CXXFLAGS`) and `JOBS=2`; at `-O3` a single compiler process exceeds
  the memory of a shared 8 GB Docker VM.
- The guest reads inputs as length-prefixed frames implemented locally because
  `env::read_frame` is behind risc0's `unstable` feature.
- Migration receipts are composed into the block receipt via `env::verify`; the
  block journal carries the migration image ID so nodes can pin both images.

## Open items (not yet decided)

- Exact sighash definition for SLH-DSA (proposal: BIP341-style "sign all" over a tagged SHA-256 of the tx, with the SMT root of the spent coin included).
- Fee rules: minimum relay fee vs consensus; proposal: consensus only requires `sum(in) ≥ sum(out)`.
- Receipt format: RISC0 `succinct` receipt (~200 KB) vs Groth16 wrap (~few KB). Proposal: succinct in v1.

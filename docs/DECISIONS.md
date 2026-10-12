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
| D4 | Proof system: **RISC Zero zkVM**, Rust guest, SHA-256 accelerator. The consensus crate is proof-system-agnostic (it only sees a `MigrationChecker`); receipt handling lives in `bhss-prover`, which is the single place to change for another zkVM. |
| D5 | Dev loop uses fake receipts (`--prove-mode dev`, `ProveMode::Dev`). Real proving is explicit via `make prove` / `--prove-mode real`. The chain parameter `require_real_proofs` alone controls whether fake receipts are accepted (PRF-5); it is `false` for `bhrt` and should be `true` for `bhsn`. The `RISC0_DEV_MODE` environment variable is never consulted by verification and is refused by real proving. |

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
| T2 | Legacy outputs are spendable **only by a migration transaction**: all inputs are `LEGACY`, all outputs are new-type, and `tx.proofs` carries one RISC0 receipt per input proving that the legacy script's owner signed the migration message (MIG-3). SMT inclusion of the spent coin is proved by the *block* witness like for every other input. The legacy signature and (for hashed-pubkey types) the pubkey are private witness, never on chain. |
| T3 | The block guest composes migration receipts via `env::verify` (receipt assumption), so the block proof covers them. |
| T4 | Every input (legacy or new) is backed by an SMT inclusion proof in the block witness (`BlockWitness.proofs`), consumed in STATE-1 order. |

## 4. State commitment

| ID | Decision |
|----|----------|
| S1 | UTXO set commitment: **SHA-256 sparse Merkle tree**, depth 256. Key = `SHA256(0x02 ‖ txid ‖ vout_le32)`, leaf = `SHA256(0x00 ‖ txout_bytes ‖ height_le32 ‖ coinbase_flag)`, node = `SHA256(0x01 ‖ l ‖ r)`, empty subtree hashes precomputed. Roots are order-independent, so a `dumptxoutset` snapshot deterministically yields the genesis root. |
| S2 | Wire format of inclusion proofs omits empty-subtree siblings via a 256-bit bitmap. |
| S3 | Non-membership proofs are used to forbid creating an outpoint that already exists. |
| S4 | Nodes are stateful (full UTXO set in memory, rebuilt from the stored blocks at start) but the guest is stateless: its journal is `(params_hash, genesis_hash, height, block_hash, prev_time, root_prev, root_next, migrate_image_id)` (PRF-2). The same statelessness lets a node fully validate a block on a side branch from the block's own witness. |

## 5. Network and blocks

| ID | Decision |
|----|----------|
| N1 | Block production: **regtest-style only**. SHA256d-free header; PoW is a minimal SHA-256 target check so anyone can `generate`. No signet block-signing challenge in v1. |
| N2 | Two chainparams: `bhrt` (regtest, empty or synthetic snapshot) and `bhsn` (same rules, genesis root taken from a signet `dumptxoutset`). A tool `bhss-snapshot` parses Core's `dumptxoutset` format and builds the genesis SMT. |
| N3 | Default limits: committed transaction bytes ≤ **128 KiB** per block, ≤ **16 signature verifications** and ≤ 16 migrations per block (chainparams); whole block ≤ 32 MiB and each receipt ≤ 1 MiB (constants, BLK-12/PRF-7). |
| N4 | Subsidy/halving/maturity copy Bitcoin regtest (50 coins, halving every 150 blocks, 100-block maturity). |
| N5 | v1 software: `bhss-primitives`, `bhss-smt`, `bhss-slhdsa` (wrapper over RustCrypto `slh-dsa`), `bhss-legacy`, `bhss-consensus` (all no_std, shared with the guest), `bhss-methods` (embeds the guest package `bhss-guest` with its two programs `block` and `migrate`), `bhss-prover`, `bhss-snapshot`, `bhssd` (minimal gossip P2P + JSON-RPC), `bhss-cli` (keys, sign, build migration proof). No Bitcoin P2P wire compatibility. |

## 6. Process

| ID | Decision |
|----|----------|
| P1 | Spec: `docs/SPEC.md`, English body with a Japanese summary at the top of each chapter. Every rule has an ID (`HDR-n`, `TX-n`, `BLK-n`, `SMT-n`, `MIG-n`, `PRF-n`, …; the full list is SPEC Appendix A) referenced from code and tests. |
| P2 | All tooling runs in Docker (linux/amd64 image with Rust + `rzup`, under Rosetta on Apple Silicon). `Makefile` wraps `docker run`; `docker compose` runs multi-node regtest. Nothing is installed on the host. |
| P3 | Real proving locally is CPU-only inside Docker (8 CPU / 8 GB); expect tens of minutes for a coinbase-only block and hours for a block with SLH-DSA spends (measurements in the README). |

## Implementation notes (2026-10-11)

- `slh-dsa` 0.1.0 is vendored under `vendor/` with its `signature` dependency
  pinned to the stable 2.2 line; the crates.io release requires a `2.3.0-pre`
  that cannot coexist with `k256` 0.13.
- The dev image is `linux/amd64` (Rosetta on Apple Silicon): RISC Zero
  publishes Linux toolchains for x86_64 only. `rust:1.98.1` because risc0 3.0.6
  dependencies need rustc ≥ 1.90.
- RISC Zero's generated C++ prover kernels are compiled with `-O1`
  (`RISC0_CXXFLAGS`) and `JOBS=1`; at `-O3` a single compiler process exceeds
  the memory of a shared 8 GB Docker VM.
- The guest reads inputs as length-prefixed frames implemented locally because
  `env::read_frame` is behind risc0's `unstable` feature.
- Migration receipts are composed into the block receipt via `env::verify`; the
  block journal carries the migration image ID so nodes can pin both images.

## Adversarial self-review (2026-10-11)

The whole system was reviewed twice: first adversarially (four independent
passes: consensus core, proofs and cryptography, node/P2P/RPC/CLI, and
snapshot/build/tests), then, after fixing what that found, a second general
pass (regressions in the fixes, spec-versus-code consistency, engineering
quality). What was found and changed:

### Round 1 — adversarial

- **Journal did not bind every guest input.** `genesis_hash` (used in every
  sighash) and the parent's `time` (HDR-7) were private inputs absent from
  the journal, so a prover could have produced a valid receipt for a block
  whose signatures were made for another network. Nodes would still have
  rejected it natively (D3), but the proof alone was not sound. Both are now
  in `BlockJournal` (PRF-2) and compared by nodes (PRF-3).
- **Decoder recursion.** `Timelock.inner` was decoded recursively, so a
  ~100 KB transaction could overflow the stack of any node or prover that
  decoded it (process abort, not a panic). `inner` is now decoded without
  recursion and only tags 0x00/0x01 are valid there (OUT-3).
- **Guest image IDs were not pinned**: nodes built with a different guest
  compiler would silently fork. `ChainParams` now carries both image IDs
  (PAR-5, inside `params_hash`), the node refuses to start if its embedded
  guests differ, the dev image pins the RISC Zero Rust toolchain and its
  base image digest, and `Hello` carries `params_hash` (NET-2).
- **Receipt verification** accepted composite and Groth16 receipts and
  built its verifier context from the environment. It now requires succinct
  receipts (PRF-6), ignores `RISC0_DEV_MODE`, and runs *before* native
  validation so a block with a bad proof costs one STARK verification.
- **Unbounded receipt and block sizes.** `Transaction::proofs` and
  `Block::receipt` were not covered by BLK-7, and bincode would allocate
  whatever a crafted receipt claimed. Added PRF-7 (receipt ≤ 1 MiB, checked
  in guest and node) and BLK-12 (whole block ≤ 32 MiB, node only).
- **Block validity depends on uncommitted bytes** (witness, receipt,
  proofs), and side-chain blocks were stored without any check, so a
  relayer could plant a corrupted copy of an honest block and block the
  honest copy by hash. See round 2 for the final design.
- **Mempool** was unbounded, re-verified every signature and receipt of
  the whole pool for each new transaction (O(n²) under the chain lock),
  and admitted transactions that could never fit a block.
- **Sync** answered every orphan with a new `GetBlocks` (request storms)
  and never converged on forks deeper than 32 blocks; a `GetBlocks` reply
  could exceed the frame limit; the listener died on an `accept` error;
  a peer could skip `Hello`.
- Consensus details: `MultisigSlh` keys must be distinct (OUT-2); BLK-11 is
  checked up front in `connect_block`; AMT-1 is enforced on input sums,
  fees and `subsidy + fees`; BLK-8/BLK-9 and the amount rules are decided
  before any signature is verified; parameters are validated (PAR-4);
  `overflow-checks` are on for all `bhss-*` crates in release builds, in
  the guest too; high-S ECDSA signatures are normalized (CRYPTO-4).
- Tooling: the snapshot importer rejects duplicate outpoints, non-Legacy
  coins, oversized scripts, totals above `MAX_MONEY`, non-canonical
  lengths, overflowing varints and trailing bytes; the CLI uses checked
  arithmetic and creates key files mode 0600; `main.txt` is written
  atomically and disk writes precede in-memory commits; the miner no longer
  selects a child of a skipped mempool parent; the P2P frame reader no
  longer pre-allocates the claimed length; compose publishes the RPC on
  loopback only.

### Round 2 — review of the fixes and of the whole

- **The round-1 sync fix stalled on any chain longer than 32 blocks** (the
  e2e chain is 15 blocks, so the test did not see it): after walking back
  to the fork point the node never walked forward again. Block download is
  now a small explicit state machine (`SyncState` in `p2p.rs`, NET-3) with
  unit tests for shallow forks on long chains, deep forks and dead ends.
- **Side-chain blocks are now fully validated before they are stored.**
  The block witness exists precisely so that a block can be checked
  against its parent's state root alone; the node uses that for every
  block that does not extend its tip (NET-5). This removes the poisoning
  problem at the root (nothing unvalidated is stored, so a hash can be
  treated as known), removes the round-1 "replace a differing copy" rule
  (which let anyone swap a good copy for a bad one), and makes a
  reorganization a pure replay of already-validated blocks: no signature
  or receipt is verified again.
- **Mempool revalidation still re-verified everything after each block.**
  The crypto-free part of transaction validation is now a separate
  consensus function (`check_tx_context`); after a new tip an entry stays
  iff its inputs still resolve to the coins it was validated against and
  the height-dependent rules hold (NET-6). Transactions returned by a
  reorganization are re-added *before* the waiting ones.
- The coinbase size reserve used at admission (640 bytes) is now the same
  one block templates use, and covers the largest possible coinbase, so an
  admitted transaction always fits a block.
- `make e2e-real` could not have passed: the script expected a receipt
  kind string the node never emits. Receipt kinds are an enum now.
- Idle peers were dropped every 10 minutes (no keep-alive): added `Ping`.
- Block assembly existed three times (miner, two test suites); it is one
  function in `bhss-consensus` (`assemble_block`), as is applying a
  validated block to the UTXO set (`apply_block_unchecked`).
- A stateless verifier reports a wrong witness proof as STATE-2; only a
  verifier with the full set can say STATE-3/STATE-4 (spec clarified).
  Every failure of a multisig spend is SIG-3.
- Spec corrections: TX-10 (committed size excludes the `proofs` field,
  it does not encode an empty one), NET-3/NET-5/NET-6 rewritten to match
  the node, PAR-4 (name charset, target range), PAR-5 ordering and index,
  GEN-2/GEN-4, MIG-5 (compressed keys for P2WPKH), Japanese summaries.
- Tests added: node unit tests (side-chain validation and eviction,
  reorganization bookkeeping, mempool policy), sync state machine,
  known-answer vectors for hashes and compact targets, negative tests for
  some twenty rule IDs that had none, receipt rejection paths without real
  proofs, high-S / hybrid-key vectors, dumptxoutset v1 and malformed
  input, genesis preconditions, addresses. RPC integer parameters are
  range-checked; `clippy -D warnings` is clean.

### Round 3 — final read of the round-2 changes

One more independent read of the round-2 diff. Nothing made a node accept
an invalid block; no panic or deadlock was reachable from a peer. Host-only
fixes (guest code, and so the image IDs, are unchanged):

- **Side-store eviction could cut the branch being downloaded.** Oldest-
  first eviction removed the earliest blocks of a long competing branch
  while its later blocks arrived, and re-fetching them evicted the next
  ones: the reorganization never happened. Eviction now spares the
  ancestors of the block being stored and, if that branch alone is over
  the budget, drops the new block instead (NET-5).
- **A peer that stopped reading pinned memory.** Writes had no timeout and
  up to 64 `Blocks` replies could queue per peer. Writes now time out
  after 300 s, the session ends with its writer, and at most one `Blocks`
  reply per peer is held (NET-3).
- **Catch-up stopped at the height announced in `Hello`** when the peer
  mined further blocks during the download; they arrived as orphans while
  a request was outstanding and were dropped. The sync state now remembers
  that and asks once more (NET-3 (d), unit test).
- With fake receipts, BLK-6's quadratic duplicate scan ran before BLK-7
  on a block of millions of tiny transactions. The node now checks BLK-7
  with the other cheap checks. (Inside `connect_block` the order is kept:
  changing it would change the guest.)
- A comment on `apply_block_unchecked` claimed STATE-1 order; corrected.
- **The block guest was fed the migration receipts.** Found while the
  real-proof run was slow: a block with 7 migrations executed 13.2 M
  cycles, about 1.6 M per migration just to decode ≈223 KB of receipt
  bytes the guest never uses. `prove_block` now empties
  `Transaction::proofs` in the guest input (same count, so TX-9 holds;
  the bytes are in no hash). Host-only (PRF-1).

Left as is: read-only RPC handlers and the P2P handshake take the chain
mutex on async worker threads and so wait behind a block validation.

## Proof system: what "STARK only" means here (checked against risc0-zkvm 3.0.6)

- RISC Zero has three real receipt kinds. *Composite* (one STARK per
  segment) and *succinct* (one recursion STARK) are FRI-based and
  hash-based; *Groth16* is a pairing-based SNARK with a trusted setup. A
  naive `default_prover().prove()` yields a composite receipt; Groth16 only
  appears when explicitly requested. BHSS requests succinct receipts
  (`ProverOpts::succinct()`) and its verifier rejects every other kind
  before any verification code runs (PRF-6, PRF-8). No SNARK is on any
  path.
- The hash is **Poseidon2 over BabyBear**, not SHA-256. In 3.0.x the
  segment verifier refuses any other hash (`SegmentReceipt` checks
  `hashfn == "poseidon2"`), and the recursion programs only take Poseidon2
  inputs, so a pure SHA-256 STARK cannot be configured. (The final
  recursion step can re-commit with SHA-256, but the inner proofs it
  attests to are still Poseidon2.) Poseidon2 is an algebraic hash with a
  much shorter analysis history than SHA-256.
- Parameters: 50 FRI queries, rate 1/4, "97 bits (conjectured security)"
  per the risc0-zkp source.
- The Groth16 *verifier* crate (`risc0-groth16`, arkworks/BN254) is still
  linked into the binaries as a dependency of `risc0-zkvm`; BHSS never
  calls it.
- Consequence for the threat model (D3): none of this affects coins locked
  by SLH-DSA, which are always verified natively. A break of Poseidon2 or
  of the 97-bit conjecture would let someone forge migration receipts,
  i.e. steal *un-migrated legacy coins* — the risk the user accepted for
  migrations. If SHA-256-only proofs are required, the options are another
  zkVM/prover whose STARK uses SHA-256 or Blake3 (larger proofs, no
  succinct recursion in most cases), or dropping the migration STARK in
  favour of revealing the legacy signature on chain.

## Resolved in SPEC v1

- Sighash: SIG-1 (`H(0x07 ‖ genesis_hash ‖ txid ‖ index ‖ leaf(coin))`).
- Fees: consensus only requires `Σin ≥ Σout` (AMT-2); no minimum relay fee.
- Receipt format: succinct STARK receipts only (PRF-6).

## Known limitations / residual risk (not fixed on purpose)

- A reorganization rebuilds the UTXO set from genesis (SMT operations
  only, no signature or receipt verification) under the chain lock. Fine
  for regtest; a long chain needs undo data or periodic state snapshots.
  Likewise a restart re-validates the whole chain from disk.
- Regtest PoW is free, so anyone can make a node validate and store
  side-chain blocks. They must be fully valid (on a dev-mode chain that
  includes a fake receipt, which costs nothing), and storage is bounded by
  the 64 MiB side-chain budget; the work is bounded per block, not
  prevented.
- No minimum fee and no mempool eviction by fee: a flood of valid zero-fee
  transactions fills the 1 000-entry mempool until blocks drain it.
- A transaction that spends an *unconfirmed* output signs the parent's
  expected confirmation height (SIG-1 covers the coin's leaf), so it is
  only valid in the same block as its parent at that height; otherwise it
  drops out of the mempool and must be re-signed.
- The RPC has no authentication; `docker-compose.yml` publishes it on
  loopback only.
- Peers are not scored or banned; an invalid block ends the current
  download exchange with that peer but not the connection.
- A competing branch whose blocks below the node's tip exceed the 64 MiB
  side store cannot be adopted by that node (about 250 real-proof blocks,
  fewer if they carry many migration receipts). Regtest-scale bound.
- Hybrid secp256k1 public keys (`0x06`/`0x07`) are not migratable.
- `make e2e` (dev mode) exercises the migration *logic* with fake receipts;
  only `make prove` / `make e2e-real` exercise real STARK soundness. Both
  passed after the review (2026-10-11/12, numbers in the README). `make
  e2e-real` ran with the guests of this tree but with node binaries built
  before the round-3 host changes; those changes are covered by the unit
  tests, the dev-mode e2e and (for the prover input) `make prove`.
- SLH-DSA has no FIPS 205 known-answer test here; the vendored crate is
  byte-identical to crates.io `slh-dsa` 0.1.0 (only its `signature`
  dependency pin differs).
- The guest ELFs are not built reproducibly (no `use_docker`): two builds
  agree only if they use the same pinned dev image. PAR-5 turns a mismatch
  into a startup error instead of a silent fork.

# BHSS — Design Rationale

> **日本語要約**: BHSS (bitcoin-hardfork-stark-slhdsa) の設計判断とその理由、帰結を
> まとめた文書である。新規コインの署名は SLH-DSA-SHA2-128s のみ。各ブロックは
> RISC Zero の succinct STARK で自身の有効性を証明し、ノードはそれに加えて全ルールを
> ネイティブでも検証する(二重検証)。UTXO 集合は SHA-256 スパース Merkle ツリーで
> コミットし、すべての状態操作に SMT 証明を付ける。旧 UTXO(secp256k1)は、入力ごとの
> マイグレーション STARK でのみ消費できる。証明系はハッシュベース(FRI STARK、
> Groth16 不使用)だが、内部ハッシュは SHA-256 ではなく Poseidon2 で、安全性は
> 推測ベースの 97 ビットである。証明系の健全性に依存するのは未移行の旧コインだけで、
> SLH-DSA でロックされたコインは依存しない。競合ブランチ(フォーク)のブロックは、
> 保存前に親の state root に対してステートレスに完全検証する。対象は regtest のみで、
> 既知の制限は末尾にまとめる。開発ツールはすべて Docker 経由で動かす。

This document records what was decided, why, and what follows from it. The
rules themselves are in [`SPEC.md`](SPEC.md); rule IDs such as `PRF-6` refer
to it. Decision IDs (`D3`, `S1`, …) are cited from the code and the
specification and are stable.

Names: the project is **BHSS** (bitcoin-hardfork-stark-slhdsa). Crates are
prefixed `bhss-`; the node binary is `bhssd`, the wallet and RPC client is
`bhss-cli`, and the network-definition tool is `bhss-snapshot`. The network
name is also the bech32m human-readable part of addresses: `bhrt` is the
default, and `bhss-snapshot from-dump` defaults to `bhsn`.

"Hard fork" here means that the genesis state of a BHSS chain is a Bitcoin
UTXO snapshot and that the rules for spending it differ from Bitcoin's.
BHSS is a separate implementation: it shares no code, block format or
network protocol with Bitcoin Core, and it does not validate Bitcoin's
block history.

## 1. Proof role

### D1. Every block proves its own full validity

**Decision.** Every block after genesis carries a RISC Zero receipt proving
that the block satisfies all consensus rules: header rules, transaction
structure, amounts, SLH-DSA signatures, the state transition from the
parent's state root to the block's state root, and the validity of every
migration receipt (T3).

**Rationale.** A proof of full validity, as opposed to a proof of selected
properties, lets a verifier that holds only the parent's state root check a
block. The same guest program is the executable definition of the rules.

**Consequence.** The guest runs the same `bhss-consensus` code as the node.
Proving cost bounds the block limits (N3).

### D2. The proof is synchronous

**Decision.** The block itself contains its receipt. There is no delayed or
separately published proof.

**Rationale.** A block without a receipt would have to be accepted
provisionally, which adds a second notion of validity.

**Consequence.** A block cannot be published before its proof exists. Block
production time is at least the proving time (see the README for measured
costs).

### D3. Double verification

**Decision.** A node accepts a block only if the receipt verifies *and* the
node's own native validation of every rule succeeds. The one exception is
the secp256k1 authorization of a legacy coin, which is checked only inside
the migration guest; the node verifies that guest's receipt instead.

**Rationale.** The proof system is the newest and least analysed component
(D6). With native re-validation, a soundness failure of the proof system,
or a bug in the prover or verifier, cannot make a node accept an invalid
SLH-DSA spend, an invalid amount or an invalid state transition.

**Consequence.** Coins locked by SLH-DSA conditions do not depend on the
proof system. Un-migrated legacy coins do: forging a migration receipt
spends a legacy coin without its key. Nodes pay the full cost of native
validation; the receipt does not make validation cheaper for them.

"Native validation" has two forms (N6). A block that extends the node's
best chain is checked against the node's own UTXO set and against the block
witness. A block on a competing branch is checked against the block witness
and the parent's state root alone. In both forms every SLH-DSA signature
and every amount rule is checked natively; the second form relies on the
binding property of the SHA-256 sparse Merkle tree, not on the proof
system.

### D4. RISC Zero zkVM, isolated behind one crate

**Decision.** The proof system is the RISC Zero zkVM with a Rust guest and
its SHA-256 accelerator. `bhss-consensus` does not depend on it: it sees
migration proofs only through the `MigrationChecker` trait. All receipt
handling is in `bhss-prover`.

**Rationale.** A general-purpose zkVM lets the guest reuse the node's
consensus code unchanged. The accelerator matters because every consensus
hash and SLH-DSA-SHA2 are SHA-256.

**Consequence.** Replacing the proof system changes `bhss-prover`, the
guest wrappers and the image IDs, not the rules.

### D5. Development receipts are a chain parameter, not an environment setting

**Decision.** `--prove-mode dev` produces RISC Zero *fake* receipts: the
guest is executed, no proof is made. `--prove-mode real` produces succinct
STARK receipts. Whether a chain accepts fake receipts is decided only by
the chain parameter `require_real_proofs` (PRF-5). Verification never
reads the `RISC0_DEV_MODE` environment variable, and real proving refuses
to run when it is set.

**Rationale.** Real proofs take minutes to hours on a CPU, which is too
slow for a development loop. An environment variable that silently turns
verification off is a hazard, so the switch is part of `params_hash`.

**Consequence.** `require_real_proofs` is `false` in every network that
`bhss-snapshot` creates, except with `from-dump --require-real-proofs`. On
such a chain a receipt proves nothing: anyone can spend any legacy coin,
and the block receipt adds no assurance. A chain meant to protect legacy
coins must set `require_real_proofs = true`.

### D6. Succinct STARK receipts only

**Decision.** BHSS produces succinct receipts (`ProverOpts::succinct()`)
and its verifier rejects every other real receipt kind before running any
verification code for it (PRF-6, PRF-8).

**Rationale.** RISC Zero has three real receipt kinds. A *composite*
receipt is one STARK per execution segment and may carry unresolved or fake
assumption receipts. A *succinct* receipt is a single recursion STARK of
constant size. A *Groth16* receipt is a pairing-based SNARK with a trusted
setup. The requirement is a proof system with no elliptic-curve or pairing
assumption and no trusted setup, which excludes Groth16; composite receipts
are excluded because their size grows with the execution and because of the
assumption receipts they can carry.

**Consequence.** Receipts are about 224 KB regardless of block content.
Proving includes the recursion steps, which dominate the cost (see
[`HASH_FUNCTION_TRADEOFF.md`](HASH_FUNCTION_TRADEOFF.md)). The properties
and limits of this proof system are stated in §7 below.

### D7. The journal binds every guest input

**Decision.** The block journal is `(params_hash, genesis_hash, height,
block_hash, prev_time, root_prev, root_next, migrate_image_id)` (PRF-2).
Every private input of the guest that is not already fixed by `block_hash`
appears in it, and a node compares the journal byte for byte with the one
it computes from its own view (PRF-3).

**Rationale.** A private input that is absent from the journal can be
chosen by the prover. For example, without `genesis_hash` in the journal a
valid receipt could be produced for a block whose signatures were made for
another network.

**Consequence.** A receipt is specific to one network, one parent and one
block. The receipt itself can be checked before native validation, because
the expected journal needs only the parent and the header.

### D8. Guest image IDs are chain parameters

**Decision.** The image IDs of the block guest and the migration guest are
fields of `ChainParams` and therefore part of `params_hash` (PAR-5). A node
refuses to start if the guests embedded in its binary differ from the
parameters, and peers with a different `params_hash` are disconnected
(NET-2).

**Rationale.** The image ID is the identity of the rule set that receipts
attest to. Nodes built with a different guest compiler would otherwise
accept different receipts and diverge without notice.

**Consequence.** Any change to the guest code, its dependencies or the
RISC Zero toolchain changes the IDs and requires a new `params.json`. The
guest build is not reproducible across environments (see limitations), so
the pinned development image is part of what defines a network.

### D9. Uncommitted data is bounded and validated before storage

**Decision.** The block witness, the block receipt and the migration
receipts in `Transaction::proofs` are not committed by the block hash
(BLK-1). A serialized receipt is at most 1 MiB (PRF-7) and an encoded block
at most 32 MiB (BLK-12). A node verifies the receipt before native
validation and never stores a copy of a block it has not fully validated
(NET-5).

**Rationale.** Committing a receipt in the header it proves is circular,
and the witness and migration receipts are derivable or replaceable data.
Because they are uncommitted, two byte strings with the same block hash can
differ in validity, so a block hash can be neither blacklisted nor trusted
on sight. The size limits bound what a deserializer can be made to
allocate. Checking the receipt first means a block with a bad proof costs
one STARK verification and no signature checks.

**Consequence.** A stored hash always refers to a valid copy, so a second
copy is ignored, and a rejected copy leaves no trace.

## 2. Cryptography

### C1. SLH-DSA-SHA2-128s is the only signature scheme for new coins

**Decision.** New outputs can be locked only by SLH-DSA-SHA2-128s keys
(FIPS 205): 32-byte public keys, 7 856-byte signatures, pure mode, empty
context string. Version 1 has no parameter-set or algorithm agility.

**Rationale.** SLH-DSA is a standardized stateless hash-based scheme. Its
security rests on the hash function alone, and the SHA2 parameter set uses
SHA-256, the same assumption as every other consensus hash in BHSS and the
function the zkVM accelerates. The "s" (small) variant is chosen because
signature size, not signing time, is what a block limit pays for. A single
scheme keeps the rules and the guest small.

**Consequence.** Coins created under BHSS rules are protected by a
post-quantum signature scheme at NIST security category 1. Signatures
dominate transaction size, and one SLH-DSA spend costs about 7 million
guest cycles (README), which is what limits the number of signature checks
per block (N3). The implementation is the RustCrypto `slh-dsa` crate, which
has not been independently audited (see limitations).

### C2. One hash function with domain separation

**Decision.** Every consensus hash is a single SHA-256 whose first input
byte is a domain tag (HASH-1, HASH-2). New structures use neither double
SHA-256 nor RIPEMD-160.

**Rationale.** Tags prevent a hash computed for one purpose from being
valid for another. A single invocation is cheaper in the guest than a
double one, and nothing in BHSS needs the length-extension protection that
double hashing gives Bitcoin.

**Consequence.** `HASH160` and untagged SHA-256 appear only where a legacy
Bitcoin script is recognised (MIG-7).

### C3. Legacy templates are recognised structurally

**Decision.** Migration supports P2PKH, P2WPKH, P2SH-P2WPKH and P2PK
(ECDSA), P2TR key path (BIP 340 Schnorr), and P2SH or P2WSH wrapping a bare
`OP_CHECKMULTISIG` script (ECDSA). The legacy key signs a 32-byte BHSS
message (MIG-3), not a Bitcoin sighash. Verification runs only inside the
migration guest.

**Rationale.** These templates cover the common single-key and multisig
outputs without implementing Bitcoin Script. Signing a BHSS message binds
the authorization to one BHSS transaction, input and network.

**Consequence.** A legacy coin with any other script (for example a bare
multisig output, a P2TR script path, P2SH-P2WSH or an arbitrary script) is
imported into the genesis state but can never be spent. High-S ECDSA
signatures are accepted, because the journal binds the message and not the
signature, so malleability has no effect. Only compressed and uncompressed
SEC1 public keys are accepted; hybrid keys are not (CRYPTO-4).

## 3. Transaction and output model

### T1. Typed outputs instead of Script

**Decision.** There is no script language. An output is one of `P2pkSlh`
(hash of one key), `MultisigSlh` (k of up to 16 key hashes), `Timelock`
(an absolute height and a relative block count around one of the former
two), `Data` (unspendable, at most 1 024 bytes, value 0) and `Legacy`
(a Bitcoin `script_pubkey`, present only in the genesis state).

**Rationale.** A fixed set of conditions has a fixed, small verification
cost inside the guest and no interpreter to specify or prove.

**Consequence.** Conditions outside this set cannot be expressed. Adding
one is a consensus change and a new guest image.

### T2. Legacy coins move only through migration transactions

**Decision.** A transaction that spends a legacy coin must spend only
legacy coins and create only SLH-DSA-locked outputs (MIG-1). Its `proofs`
field carries one RISC Zero receipt per input, proving that the owner of
the legacy script authorized the migration message of that input (MIG-2,
MIG-3). The legacy signature, and for hashed-key templates the public key,
are private inputs of the migration guest.

**Rationale.** Legacy coins are the only coins that depend on secp256k1.
Restricting them to a one-way move into SLH-DSA outputs keeps secp256k1
verification out of native consensus. Keeping the signature and public key
out of the journal means a migration does not publish a secp256k1 public
key that was previously known only as a hash.

**Consequence.** A legacy coin is exactly as secure as its secp256k1 key
and the proof system until it is migrated. That nothing about the private
inputs can be learned from a receipt relies on the zero-knowledge property
of RISC Zero receipts, which BHSS does not evaluate. Each migration costs
its sender one zkVM proof.

### T3. The block proof composes the migration proofs

**Decision.** Inside the block guest each migration check is
`env::verify(migrate_image_id, journal)`. The prover resolves these
assumptions with the migration receipts when it builds the block receipt
(PRF-4).

**Rationale.** A block receipt that did not cover the migrations would not
prove full validity (D1).

**Consequence.** A real block receipt exists only if every migration
receipt in the block is real and valid. A miner that produces real proofs
therefore cannot include a transaction carrying a fake migration receipt,
and such a node keeps those transactions out of its mempool (NET-6).

### T4. Every state operation is backed by an SMT proof

**Decision.** The block witness lists the coin spent by every non-coinbase
input and one sparse-Merkle-tree proof per state operation, in the fixed
order of STATE-1 (BLK-2, BLK-11).

**Rationale.** This is what lets a verifier without the UTXO set, the
guest or a node looking at a competing branch, check a block.

**Consequence.** Blocks are larger than their transactions. The witness is
not committed by the header (D9).

### T5. Signatures commit to the spent coin's leaf and to the network

**Decision.** The message signed for input `i` is
`H(tag ‖ genesis_hash ‖ txid ‖ i ‖ leaf(coin))` for both SLH-DSA spends
(SIG-1) and migrations (MIG-3). There are no sighash flags.

**Rationale.** `txid` commits all prevouts, outputs and the locktime; the
leaf commits the value, condition, creation height and coinbase flag of the
coin; the genesis hash binds the network.

**Consequence.** A mempool entry stays valid exactly as long as each input
still resolves to the same coin, so re-validation after a new block needs
no cryptography (N7). A transaction that spends an unconfirmed output signs
the height at which its parent is expected to confirm; it is valid only in
the same block as its parent at that height.

## 4. State commitment

### S1. SHA-256 sparse Merkle tree, not Utreexo

**Decision.** The UTXO set is committed by a sparse Merkle tree of depth
256 over SHA-256. The key of a coin is `H(0x02 ‖ txid ‖ vout)`, its leaf is
`H(0x00 ‖ enc(Coin))`, an inner node is `H(0x01 ‖ left ‖ right)`, and empty
subtrees have fixed hashes (SMT-1 to SMT-4).

**Rationale.** The root of a sparse Merkle tree is a function of the set
alone. Anyone can therefore recompute the genesis state root from a Bitcoin
Core `dumptxoutset` snapshot, in any insertion order. The root of a Utreexo
accumulator depends on the history of insertions and deletions, so it
cannot be checked against a snapshot of the set. A sparse Merkle tree also
gives non-membership proofs (S3).

**Consequence.** Every state operation is a path of 256 hashes in the
guest. Proofs are compressed (S2).

### S2. Proofs omit empty siblings

**Decision.** A proof is a 256-bit bitmap plus the non-empty sibling
hashes. A proof that lists an empty-subtree hash explicitly is invalid
(SMT-5, SMT-6).

**Rationale.** In a tree with far fewer than 2²⁵⁶ leaves almost all
siblings are empty. Requiring the canonical form leaves one valid encoding
per proof.

**Consequence.** A proof is a 32-byte bitmap, a count and 32 bytes per
non-empty sibling.

### S3. Non-membership proofs guard output creation

**Decision.** Inserting an output requires a proof that its key is absent
(STATE-2, STATE-4).

**Rationale.** A stateless verifier cannot otherwise know that an insertion
does not overwrite an existing coin.

**Consequence.** Outputs cost one SMT proof each, like inputs.

### S4. Stateful nodes, stateless guest

**Decision.** A node keeps the full UTXO set in memory and rebuilds it from
its stored blocks at start. The guest holds no state: it starts from the
parent's state root in its input and consumes the witness proofs.

**Rationale.** The guest cannot hold the set. Nodes hold it so that they
can build witnesses, serve wallets and validate natively (D3).

**Consequence.** The same stateless procedure lets a node fully validate a
block on a competing branch from the block's own witness (N6).

## 5. Network and blocks

### N1. Regtest-style block production only

**Decision.** The header has a compact target and a nonce; the default
target is satisfied by about half of all hashes, and difficulty never
adjusts (HDR-6). There is no signet block-signing challenge.

**Rationale.** The purpose is to exercise the rules, proofs and migration,
not to secure a public network.

**Consequence.** Anyone who can reach a node can extend or fork the chain
at no cost. Chain selection is by height (NET-4). BHSS provides no
resistance to chain rewriting.

### N2. A network is a parameter file plus a genesis state

**Decision.** `bhss-snapshot` writes `params.json` and `genesis_state.bin`.
Its subcommands build an empty state (`empty`), a state from explicit
legacy coins (`synthetic`) or a state from a Bitcoin Core `dumptxoutset`
file (`from-dump`). All use the same default rules; only the name, the
genesis state root, `require_real_proofs` and the image IDs differ. The
genesis block is a deterministic function of the parameters (GEN-1).

**Rationale.** One rule set avoids rules that are tested on one network and
used on another.

**Consequence.** `from-dump` does not check which Bitcoin network a
snapshot comes from. Unspendable scripts are not imported (GEN-4). Imported
coins lose their original height and coinbase flag (GEN-3).

### N3. Block limits follow proving cost

**Decision.** Defaults: at most 128 KiB of committed transaction bytes, 16
SLH-DSA signature checks and 16 legacy inputs per block (chain parameters,
BLK-7 to BLK-9); at most 32 MiB per encoded block and 1 MiB per receipt
(constants, BLK-12 and PRF-7).

**Rationale.** One SLH-DSA spend costs about 7 million guest cycles. The
limits keep the proof of a full block within what a CPU prover can produce
in hours rather than days. 16 signatures of 7 856 bytes fit in 128 KiB.

**Consequence.** Throughput is a few transactions per block.

### N4. Monetary parameters copy Bitcoin regtest

**Decision.** The initial subsidy is 50 coins of 10⁸ units, halving every
150 blocks; coinbase outputs mature after 100 blocks; no value or sum may
exceed 21 000 000 × 10⁸ units (AMT-1).

**Rationale.** Familiar values; nothing in the experiment depends on them.

**Consequence.** The subsidy is created in addition to the imported
snapshot value. The supply cap of Bitcoin is not enforced as a total; the
bound applies to each value and each sum the rules compute.

### N5. Crate layout

**Decision.** `bhss-primitives`, `bhss-smt`, `bhss-slhdsa`, `bhss-legacy`
and `bhss-consensus` are compiled both into the node and into the guest.
`bhss-methods` embeds the guest package `bhss-guest` with its two programs,
`block` and `migrate`. `bhss-prover`, `bhss-snapshot`, `bhss-node`
(`bhssd`) and `bhss-cli` are host-only. The peer-to-peer protocol is BHSS's
own; it is not compatible with Bitcoin's.

**Rationale.** Sharing the consensus code between node and guest removes a
second implementation of the rules.

**Consequence.** A change to any shared crate changes the guest image IDs
(D8).

### N6. Competing-branch blocks are validated statelessly before storage

**Decision.** A node validates every block before storing it, including
blocks that do not extend its best chain. For those it runs the full rules
against the block witness and the parent's state root, without a UTXO set
for that branch (NET-5). Blocks on competing branches are kept in memory up
to 64 MiB; eviction is oldest first and spares the ancestors of the block
being stored.

**Rationale.** Because validity depends on uncommitted bytes (D9), storing
an unvalidated block would let a relayer plant an invalid copy of an honest
block under the honest block's hash. Validating first removes that problem
at its root. The witness exists precisely so that a block can be checked
against its parent's state root alone (T4), so no additional data is
needed. Sparing the ancestors of the arriving block keeps a long branch
from being evicted piece by piece while it is being downloaded.

**Consequence.** A reorganization applies only blocks that are already
validated: it rebuilds the UTXO set by applying their state operations,
verifies no signature or receipt again, and checks every resulting root
against the block's header. Since proof of work is free (N1), anyone can
make a node validate and store competing-branch blocks; the cost is bounded
per block and the storage by the 64 MiB budget, but the work is not
prevented.

### N7. Mempool re-validation uses no cryptography

**Decision.** The part of transaction validation that needs no signature
or receipt check is a separate consensus function (`check_tx_context`).
After a new tip, a mempool entry stays if and only if each input still
resolves to the coin it was validated against and the height-dependent
rules hold at the next height (NET-6). The mempool is bounded to 1 000
transactions and 16 MiB, and admits only transactions that could fit a
block on their own.

**Rationale.** Signatures and receipts are bound to the spent coin (T5), so
they remain valid while the coin is unchanged. Re-verifying 7 856-byte
SLH-DSA signatures and STARK receipts for the whole pool after every block
would be the dominant cost of the node.

**Consequence.** There is no minimum fee and no eviction by fee; a full
mempool refuses new transactions until blocks drain it.

### N8. Block download is an explicit per-peer state machine

**Decision.** For each peer a node keeps at most one block request
outstanding and follows the four cases of NET-3: catch up, search backwards
for the fork point in windows of 32 heights, walk forward from it, and
continue while the peer keeps growing. A node answers every request, holds
at most one reply per peer and drops a peer that does not read for 300 s.

**Rationale.** One outstanding request per peer bounds both the traffic a
block with an unknown parent can trigger and the memory a peer that stops
reading can pin.

**Consequence.** A fork deeper than 32 blocks is found in several round
trips. There is no header-first synchronization.

## 6. Process

### P1. Specification with rule IDs

**Decision.** `docs/SPEC.md` is the normative text, in English with a
Japanese summary per chapter. Every rule has an ID (listed in its
Appendix A) that the code and tests cite.

**Rationale.** A rule ID in an error message or a test name ties behaviour
to one sentence of the specification.

**Consequence.** Rule IDs are never renumbered or reused.

### P2. All tooling runs in Docker

**Decision.** Builds, tests and proving run in a `linux/amd64` development
image that contains Rust and the RISC Zero toolchain. `Makefile` wraps
`docker run`; `docker compose` runs the three-node test network.

**Rationale.** RISC Zero publishes Linux toolchains for x86_64 only, and
the guest image IDs depend on the exact toolchain (D8). The image pins its
base image by digest and the RISC Zero components by version.

**Consequence.** No Rust or RISC Zero toolchain is needed on the host. The
host needs Docker with Compose, `make`, and for the end-to-end test `bash`,
`curl` and `jq`. On Apple Silicon the image runs under Rosetta. Real
proving in the container is CPU-only.

### P3. Build defaults fit an 8 GB Docker VM

**Decision.** The defaults are one cargo job, RISC Zero's C++ prover
kernels compiled at `-O1`, and zkVM segments of 2¹⁷ cycles through `make`
and Compose.

**Rationale.** At `-O3` a single compiler process for the generated kernels
needs more than 4 GB, and segments of 2¹⁹ cycles make the prover exceed the
memory of an 8 GB VM that other containers share.

**Consequence.** Proving is slower than on a machine with more memory,
where `RISC0_CXXFLAGS=-O3`, a higher `JOBS` and a larger `SEGMENT_PO2` are
appropriate. Run directly, `bhssd` and `bhss-cli` default to
`--segment-po2 20`.

### P4. Dependency pins

**Decision.** `slh-dsa` 0.1.0 is vendored under `vendor/` with its
`signature` dependency set to the stable 2.2 line. The guest reads its
inputs as length-prefixed frames implemented in the guest itself.

**Rationale.** The crates.io release of `slh-dsa` 0.1.0 requires a
`signature` pre-release that cannot coexist with `k256` 0.13, which the
legacy verification uses. RISC Zero's own `env::read_frame` is behind its
`unstable` feature.

**Consequence.** The vendored crate must be updated by hand. The frame
format is part of the guest program and therefore of the image ID.

## 7. Proof system: what "hash-based" means here

Checked against risc0-zkvm 3.0.6 and risc0-zkp 3.0.5, the versions the
workspace resolves to.

- **No SNARK on any path.** BHSS requests succinct receipts and accepts no
  other real kind (D6). The Groth16 *verifier* crate (`risc0-groth16`) is
  linked into the binaries as a dependency of `risc0-zkvm`; BHSS never
  calls it.
- **The hash is Poseidon2 over the BabyBear field, not SHA-256.** In
  risc0-zkvm 3.0.x the segment verifier refuses any other hash
  (`SegmentReceipt` requires `hashfn == "poseidon2"`) and the recursion
  programs take only Poseidon2 inputs, so a STARK that uses SHA-256
  throughout cannot be configured. (The final recursion step can re-commit
  with SHA-256, but the proofs it attests to still use Poseidon2.)
  Poseidon2 is an algebraic hash with a much shorter history of analysis
  than SHA-256.
- **The security level is conjectured.** The parameters are 50 FRI queries
  at rate 1/4, which the risc0-zkp source describes as "97 bits
  (conjectured security)". This is not a proven bound.
- **Quantum attackers.** The proof system uses no elliptic-curve or pairing
  assumption. BHSS makes no quantitative claim about its security against
  quantum attackers.
- **What depends on it.** Nothing about coins locked by SLH-DSA (D3). A
  break of Poseidon2, of the FRI conjecture, or a soundness bug in the
  RISC Zero circuits, the recursion programs, the verifier or the guests
  would let an attacker forge migration receipts and take un-migrated
  legacy coins on a chain with `require_real_proofs = true`.
- **Alternatives.** A proof whose only hash is SHA-256 needs either
  another prover or giving up the migration proof in favour of revealing
  the legacy signature on chain. The cost of the first option is estimated
  in [`HASH_FUNCTION_TRADEOFF.md`](HASH_FUNCTION_TRADEOFF.md).

## 8. Security properties and what each depends on

| Property | Depends on | Does not depend on |
|----------|------------|--------------------|
| An SLH-DSA-locked coin is spent only with its keys | SLH-DSA-SHA2-128s; SHA-256 (key hash, signing message, txid, SMT); the node's native validation code and the unaudited `slh-dsa` crate | the proof system; secp256k1 |
| Amounts, subsidy and the state transition are valid | SHA-256; the node's native validation code | the proof system |
| A block on a competing branch is validated without that branch's UTXO set | SHA-256 (binding of the sparse Merkle tree); validity of the stored parent | the proof system |
| A legacy coin is spent only by the holder of its secp256k1 key | secp256k1 ECDSA or Schnorr (not post-quantum); the proof system (§7); `require_real_proofs = true`; the pinned image IDs | SLH-DSA |
| A migration does not reveal the legacy signature or a hashed public key | the zero-knowledge property of RISC Zero receipts (not evaluated by BHSS) | — |
| The chain cannot be rewritten | nothing: proof of work is trivial by design (N1) | — |

"Post-quantum" in BHSS documents therefore means: coins created under BHSS
rules are locked by a post-quantum signature scheme and committed with
SHA-256. It does not apply to un-migrated legacy coins, which remain
secp256k1 coins, and it is not a claim about the proof system or about the
chain as a whole.

## 9. Limitations and non-goals

BHSS is a regtest experiment. The following are properties of the current
design and implementation, not open tasks.

**Scope**

- Regtest only: constant trivial difficulty, no difficulty adjustment, no
  block-signing challenge, chain selection by height (N1).
- The RPC has no authentication, and any RPC caller can mine blocks.
  `bhssd` binds it to `127.0.0.1` by default and `docker-compose.yml`
  publishes it on loopback only. The peer-to-peer protocol has no
  authentication or encryption; peers are not scored or banned, and an
  invalid block ends the current download exchange with a peer but not the
  connection.
- Address decoding accepts a bech32 checksum as well as the bech32m
  checksum that ADDR-1 specifies; encoding always uses bech32m.
- `bhss-cli` stores SLH-DSA secret keys unencrypted (file mode 0600) and
  takes legacy secp256k1 secrets as command-line arguments. It builds
  single-key `P2pkSlh` spends and single-input migrations only; multisig
  and timelock conditions are consensus features without wallet support.

**Proofs**

- On a chain with `require_real_proofs = false`, receipts prove nothing
  and any legacy coin can be taken by anyone (D5).
- `make e2e` uses fake receipts and so exercises the migration logic, not
  STARK soundness. `make e2e-real` proves every block and migration for
  real, but its network still has `require_real_proofs = false`, so it does
  not show that consensus rejects fake receipts. `make prove` does: it
  verifies its chain with fake receipts disallowed.
- The guest programs are not built reproducibly (RISC Zero's Docker-based
  guest build is not used). Two builds produce the same image IDs only if
  they use the same pinned development image. PAR-5 turns a mismatch into a
  startup error instead of a silent fork.
- SLH-DSA is not tested against the FIPS 205 known-answer vectors in this
  repository, and the `slh-dsa` crate states that it has never been
  independently audited.

**Legacy coins**

- Only the templates of C3 are migratable. Coins with other scripts, and
  coins whose keys are hybrid secp256k1 public keys (`0x06`/`0x07`), are
  permanently unspendable.
- Imported coins lose their original height and coinbase flag, so an
  immature Bitcoin coinbase output is immediately spendable.

**Node**

- A reorganization rebuilds the UTXO set from the genesis state under the
  chain lock (state operations only, no signature or receipt
  verification), and a restart re-validates the whole stored chain in
  full. Both are linear in the chain length; a long chain would need undo
  data or state snapshots.
- A competing branch whose blocks below the node's tip exceed the 64 MiB
  store cannot be adopted by that node. With receipts of about 224 KB that
  is fewer than 300 blocks, and fewer still when blocks carry migration
  receipts. Competing-branch blocks are not written to disk.
- Since proof of work is free, anyone can make a node validate and store
  competing-branch blocks. They must be fully valid, which on a chain that
  accepts fake receipts costs nothing.
- There is no minimum fee and no mempool eviction by fee: valid zero-fee
  transactions can fill the 1 000-entry mempool until blocks drain it.
- A transaction that spends an unconfirmed output is valid only in the same
  block as its parent at the height it was signed for (T5); otherwise it
  leaves the mempool and must be signed again.
- Read-only RPC handlers and the peer handshake take the chain lock and so
  wait while a block is being validated.

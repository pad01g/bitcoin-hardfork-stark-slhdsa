# Poseidon2 → SHA-256: what would change

Status: **analysis only, nothing here is implemented.** Written 2026-10-11
against risc0-zkvm 3.0.6 / risc0-zkp 3.0.5, the versions BHSS pins.

> **日本語要約**: BHSS のブロック証明・移行証明は RISC Zero の succinct STARK で、
> SNARK(Groth16)は使っていないが、STARK 内部のハッシュは SHA-256 ではなく
> Poseidon2 である。これを SHA-256 に変えた場合の影響を見積もった(実装はしていない)。
> 結論: (1) 証明を 1 個に畳む構成のまま SHA-256 にすると、再帰回路の中で SHA-256 を
> 計算することになり、証明時間は 50〜200 倍(coinbase のみのブロックで 15〜60 時間)と
> なり実用にならない。(2) 畳むのをやめて「セグメントごとの STARK を並べる」構成に
> すれば、証明はむしろ今より速くなる(0.3〜0.6 倍)が、レシートが 250 KB から
> 数 MB〜数十 MB に増える。(3) ただし RISC Zero 3.0.6 はセグメント証明が Poseidon2
> 固定なので、どちらもこの版のままでは実現できない。数値は実測ではなく、既存の
> 実測値と証明系の構造からの推定である。

## 1. Where things stand

* BHSS produces and accepts only **succinct** receipts (SPEC PRF-6, PRF-8):
  one FRI-based STARK over the BabyBear field. No Groth16, no pairing, no
  trusted setup.
* "Hash-based" is true, but the hash is **Poseidon2**, an algebraic hash
  designed to be cheap inside arithmetic circuits. It is used for the Merkle
  commitments and the Fiat–Shamir transcript of every STARK involved.
* The parameters (50 FRI queries, rate 1/4) target "97 bits (conjectured
  security)" (`risc0-zkp/src/lib.rs`).
* What this protects: only un-migrated legacy coins (DECISIONS D3). Coins
  locked by SLH-DSA are verified natively and never depend on the proof.

Why one might want SHA-256 instead: its security has two more decades of
analysis than Poseidon2, and the rest of BHSS (hashes, SMT, SLH-DSA-SHA2)
already rests on it, so the proof system would add no new hash assumption.

## 2. Why the answer depends on recursion

A receipt for a long execution is built in two stages, and the hash
function matters in opposite ways in each.

**Stage 1 — segment proofs.** The execution is cut into segments (2^17
cycles each in the default BHSS setup) and each segment gets its own STARK.
Here the *prover* just computes hashes natively to build Merkle trees.
Native SHA-256 is at least as fast as native Poseidon2 on a CPU, so this
stage would get no slower, probably somewhat faster. Hashing is a minority
of segment proving time anyway (the rest is witness generation, NTTs and
polynomial evaluation).

**Stage 2 — recursion.** To get a single constant-size receipt, each
segment proof is verified *inside another circuit* (`lift`), pairs of those
are merged (`join`), and migration receipts are attached (`resolve`). The
circuit therefore has to *compute* every hash a STARK verifier computes:
Merkle paths for 50 queries across several trees plus the FRI layers, and
the hashing of the opened rows — tens of thousands of hash invocations per
verified proof. A Poseidon2 permutation costs a handful of circuit rows. A
SHA-256 compression is 32-bit boolean logic and costs on the order of a
hundred times more rows over a small prime field. The recursion circuit
that fits in 2^18 rows today would need roughly 2^24–2^25.

So: with SHA-256, stage 1 is fine and stage 2 becomes the whole cost.

## 3. What was measured (Poseidon2, today)

`make prove`, M1 Pro, amd64 image under Rosetta, 8 threads, `-O1` prover
kernels, segments of 2^17 cycles (README "Proving cost"):

| Proof | Cycles | Segments | Wall time | Receipt |
|-------|-------:|---------:|----------:|--------:|
| block, coinbase only | 1.74 M | 14 | ≈27 min | ≈250 KB |
| migration (ECDSA in guest) | 0.52 M | 4 | ≈7 min | ≈250 KB |
| block, one SLH-DSA spend + one migration | 12.3 M | 94 | ≈2.8 h | ≈250 KB |

For the coinbase-only block that is 14 segment proofs plus 14 `lift` and 13
`join` proofs: 41 STARKs in 27 minutes, about 40 s each, of which 27 (about
two thirds of the time) are recursion.

## 4. Estimates

These are derived from the table above and the reasoning in §2. **None of
them was measured**; the recursion multiplier in particular is an
order-of-magnitude figure.

| Configuration | Coinbase-only block | Block with one SLH-DSA spend | Receipt size | Removes the Poseidon2 assumption? |
|---|---|---|---|---|
| A. Today: Poseidon2, succinct | ≈27 min | ≈2.8 h | ≈250 KB | — |
| B. SHA-256, succinct (recursion in SHA-256) | ≈15–60 h | ≈100–350 h | ≈250 KB | yes |
| C. SHA-256, composite (no recursion) | ≈8–15 min | ≈1–1.7 h | ≈3–4 MB / ≈20–25 MB | yes |
| D. Poseidon2 inside, final wrap in SHA-256 | ≈28 min | ≈2.8 h | ≈250 KB | **no** |

How the numbers were obtained:

* **B.** Two thirds of today's time is recursion; multiply that part by
  50–200 and leave the rest unchanged. 27 min × ⅔ × (50…200) ≈ 15–60 h.
* **C.** Keep only stage 1 (one third of today's time) and allow ±30 % for
  the different native hash: 27 min × ⅓ × (0.9…1.6) ≈ 8–15 min. Receipt
  size assumes about 250 KB per segment proof; with 2^20-cycle segments on
  a machine with more memory the 12.3 M-cycle block needs 12 segments
  (≈3 MB) instead of 94.
* **D.** One extra recursion step (`identity` with the SHA-256 suite, which
  3.0.6 supports) at about 40 s. The outer proof is SHA-256 but it only
  attests that Poseidon2-based proofs verified, so soundness still rests on
  Poseidon2. Listed only to rule it out.

Verification cost: A, B and D verify one STARK (milliseconds natively). C
verifies one STARK per segment, i.e. time and block size grow linearly with
the cycles in the block; at regtest scale that is tens of milliseconds to a
few seconds.

## 5. What option C would require (not done)

Option C is the only one that both removes the Poseidon2 assumption and is
practical. It is a consensus change and a dependency change:

1. **A prover that makes SHA-256 segment proofs.** risc0-zkvm 3.0.6 cannot:
   `SegmentReceipt::verify_integrity_with_context` rejects any receipt
   whose `hashfn` is not `"poseidon2"`, and `ProverOpts` offers no other
   suite for the rv32im circuit even though `risc0-zkp` still ships a
   SHA-256 hash suite. Earlier RISC Zero lines had SHA-256 segment proving;
   whether a version exists that has both that and everything else BHSS
   uses (the SHA-256 and secp256k1 precompiles, `env::verify` composition)
   was **not checked**. The alternative is a different zkVM.
2. **PRF-6 inverted.** Accept composite receipts and reject succinct ones;
   pin the hash suite to SHA-256 in the verifier.
3. **Composition without recursion.** A composite block receipt would carry
   the migration receipts as attached assumption receipts instead of
   resolving them in-circuit. They are already in `Transaction::proofs`, so
   the data is there, but the block receipt would be conditional on them
   and nodes would have to check that linkage explicitly.
4. **Size limits.** PRF-7 (receipt ≤ 1 MiB) and BLK-12 (block ≤ 32 MiB)
   would have to grow by one to two orders of magnitude, or the per-block
   cycle budget (BLK-8: at most 16 SLH-DSA verifications, about 10 M cycles
   each) would have to shrink to keep receipts small.
5. **New image IDs** and a new network definition (PAR-5), as for any guest
   or prover change.

## 6. Caveats

* The recursion multiplier (50–200×) is the weakest number here. It comes
  from the relative circuit cost of SHA-256 versus Poseidon2 per hash, not
  from a SHA-256 recursion circuit that exists and could be timed.
* All timings are for a CPU prover under emulation with `-O1` kernels. A
  GPU or a native x86_64 host shifts every row by a similar factor; the
  ratios between configurations should hold, the absolute times will not.
* Segment proof size (≈250 KB) is assumed, not measured: BHSS has only ever
  produced succinct receipts.
* SHA-256 would not change the "97 bits, conjectured" security level; that
  comes from the FRI parameters, not from the hash.

## 7. Sources

* risc0-zkvm 3.0.6: `src/host/client/prove/opts.rs` (`ProverOpts`: every
  constructor sets `hashfn: "poseidon2"`; receipt kinds),
  `src/receipt/segment.rs` (`hashfn != "poseidon2"` → `InvalidHashSuite`),
  `src/receipt/succinct.rs` (`SuccinctReceipt`, control roots,
  `inner_control_root` for switching hash functions),
  `src/host/recursion/prove/mod.rs` (`ensure_poseidon2!`, `lift`, `join`,
  `resolve`, `identity`), `src/host/recursion/tests.rs`
  (`test_recursion_identity_sha256`).
* risc0-zkp 3.0.5: `src/lib.rs` (`QUERIES = 50`, `INV_RATE = 4`, the
  97-bit comment), `src/core/hash/mod.rs` (`hash_suite_from_name`).
* BHSS: `README.md` (measured proving cost), `docs/SPEC.md` PRF-6/PRF-8,
  `docs/DECISIONS.md` ("Proof system: what STARK only means here").

# Replacing Poseidon2 with SHA-256 in the STARK: estimated cost

**This is an analysis. Nothing in it is implemented, and every figure in §4
is an estimate, not a measurement.** It was checked against risc0-zkvm 3.0.6
and risc0-zkp 3.0.5, the versions the BHSS workspace resolves to.

> **日本語要約**: BHSS のブロック証明と移行証明は RISC Zero の succinct STARK で、
> SNARK(Groth16)は使わないが、STARK 内部のハッシュは SHA-256 ではなく Poseidon2
> である。本書は、これを SHA-256 に変えた場合の影響の見積もりであり、実装は
> していない。結論: (1) 証明を 1 個に畳む構成のまま SHA-256 にすると、再帰回路の中で
> SHA-256 を計算することになり、再帰部分の証明時間が 50〜200 倍になる(coinbase
> のみのブロックで 10〜40 時間)ため実用にならない。(2) 畳むのをやめて
> セグメントごとの STARK を並べる構成にすれば、証明時間は現在の 0.3〜0.5 倍に
> 短くなるが、レシートは約 224 KB から数 MB〜20 MB 程度に増える。(3) RISC Zero
> 3.0.6 はセグメント証明のハッシュが Poseidon2 に固定されているので、どちらも
> この版のままでは実現できない。§4 の数値は実測ではなく、§3 の実測値と証明系の
> 構造から導いた推定である。

## 1. Background

* BHSS produces and accepts only **succinct** receipts (SPEC PRF-6, PRF-8):
  one FRI-based STARK over the BabyBear field. There is no Groth16 proof,
  no pairing and no trusted setup.
* The proof system is hash-based, but the hash is **Poseidon2**, an
  algebraic hash designed to be cheap inside arithmetic circuits. It is
  used for the Merkle commitments and the Fiat–Shamir transcript of every
  STARK involved.
* The parameters (50 FRI queries, rate 1/4) are described in
  `risc0-zkp/src/lib.rs` as "97 bits (conjectured security)".
* The proof system protects only un-migrated legacy coins (DECISIONS D3).
  Coins locked by SLH-DSA are verified natively and do not depend on it.

The reason to consider SHA-256 is that it has about two more decades of
cryptanalysis than Poseidon2, and that the rest of BHSS (consensus hashes,
the sparse Merkle tree, SLH-DSA-SHA2) already rests on it, so the proof
system would add no further hash assumption.

## 2. Why the answer depends on recursion

A receipt for a long execution is built in two stages, and the hash
function matters in opposite ways in each.

**Stage 1: segment proofs.** The execution is cut into segments (2¹⁷ cycles
each with the BHSS `make` defaults) and each segment gets its own STARK.
Here the prover computes hashes natively to build Merkle trees. Native
SHA-256 is at least as fast as native Poseidon2 on a CPU, so this stage
would not get slower. Hashing is a minority of segment proving time; the
rest is witness generation, number-theoretic transforms and polynomial
evaluation.

**Stage 2: recursion.** To obtain a single receipt of constant size, each
segment proof is verified inside another circuit (`lift`), pairs of the
results are merged (`join`), and migration receipts are attached
(`resolve`). That circuit has to compute every hash a STARK verifier
computes: the Merkle paths for 50 queries across several trees, the FRI
layers and the hashing of the opened rows, which is tens of thousands of
hash invocations per verified proof. A Poseidon2 permutation costs a few
circuit rows. A SHA-256 compression consists of 32-bit boolean operations
and costs on the order of a hundred times more rows over a small prime
field. The recursion circuit that fits in 2¹⁸ rows with Poseidon2 would
need roughly 2²⁴ to 2²⁵ rows.

With SHA-256, stage 1 is unaffected and stage 2 becomes almost the entire
cost.

## 3. Measured baseline (Poseidon2)

`make prove` on an Apple M1 Pro, `linux/amd64` image under Rosetta, 8
threads, prover kernels compiled at `-O1`, segments of 2¹⁷ cycles, no other
load in the 8 GB Docker VM. These are the figures of the README section
"Proving cost"; the segment counts are the cycle counts divided by 2¹⁷,
rounded up.

| Proof | Cycles | Segments | Wall time | Receipt |
|-------|-------:|---------:|----------:|--------:|
| block, coinbase only | 1.74 M | 14 | ≈18 min | ≈224 KB |
| migration (ECDSA in the guest) | 0.52 M | 4 | ≈5 min | ≈224 KB |
| block, one SLH-DSA spend and one migration | 11.4 M | 87 | ≈2.0 h | ≈224 KB |

The coinbase-only block needs 14 segment proofs, 14 `lift` proofs and 13
`join` proofs: 41 STARKs in 18 minutes, about 26 s each. 27 of the 41 are
recursion. The estimates below assume that all 41 take about the same
time, so that recursion is about two thirds of the total; this split was
not measured.

## 4. Estimates

These figures are derived from §3 and the reasoning of §2. **None of them
was measured.** The recursion multiplier in particular is an
order-of-magnitude figure.

| Configuration | Coinbase-only block | Block with one SLH-DSA spend and one migration | Receipt size | Removes the Poseidon2 assumption |
|---|---|---|---|---|
| A. Poseidon2, succinct (what BHSS does; measured) | ≈18 min | ≈2.0 h | ≈224 KB | — |
| B. SHA-256, succinct (recursion in SHA-256) | ≈10–40 h | ≈70–270 h | ≈224 KB | yes |
| C. SHA-256, composite (no recursion) | ≈5–10 min | ≈0.6–1.1 h | ≈3.5 MB and ≈22 MB | yes |
| D. Poseidon2 inside, final step re-committed with SHA-256 | ≈19 min | ≈2.0 h | ≈224 KB | **no** |

How the figures are obtained:

* **B.** Multiply the recursion part (two thirds of the measured time) by
  50 to 200 and leave the rest unchanged: 18 min × ⅔ × 50 to 200 is about
  10 to 40 hours.
* **C.** Keep only stage 1 (one third of the measured time) and allow a
  factor of 0.9 to 1.6 for the different native hash: 18 min × ⅓ × 0.9 to
  1.6 is about 5 to 10 minutes. The receipt size assumes about 250 KB per
  segment proof, which gives about 3.5 MB for 14 segments and about 22 MB
  for 87. With segments of 2²⁰ cycles, on a machine with more memory, the
  11.4 M-cycle block needs 11 segments (about 3 MB).
* **D.** One additional recursion step (`identity` with the SHA-256 suite,
  which risc0-zkvm 3.0.6 supports) at about 26 s. The outer proof uses
  SHA-256, but it only attests that Poseidon2-based proofs verified, so
  soundness still rests on Poseidon2. It is listed only to rule it out.

Verification cost: A, B and D verify one STARK, which takes milliseconds
natively. C verifies one STARK per segment, so verification time and block
size grow linearly with the number of cycles in the block; at regtest scale
that is tens of milliseconds to a few seconds.

## 5. What configuration C would require

Configuration C is the only one that both removes the Poseidon2 assumption
and is practical. It is a consensus change and a dependency change:

1. **A prover that makes SHA-256 segment proofs.** risc0-zkvm 3.0.6 cannot:
   `SegmentReceipt::verify_integrity_with_context` rejects any receipt
   whose `hashfn` is not `"poseidon2"`, and `ProverOpts` offers no other
   suite for the rv32im circuit, although `risc0-zkp` still ships a SHA-256
   hash suite. Whether some RISC Zero version provides SHA-256 segment
   proving together with everything else BHSS uses (the SHA-256 and
   secp256k1 accelerators and `env::verify` composition) has **not been
   checked**. The alternative is a different zkVM.
2. **PRF-6 inverted.** Nodes would accept composite receipts and reject
   succinct ones, and the verifier would pin the hash suite to SHA-256.
3. **Composition without recursion.** A composite block receipt would
   carry the migration receipts as attached assumption receipts instead of
   resolving them in a circuit. They are already present in
   `Transaction::proofs`, but the block receipt would be conditional on
   them and nodes would have to check that linkage explicitly.
4. **Size limits.** PRF-7 (receipt at most 1 MiB) would have to grow by
   one to two orders of magnitude and BLK-12 (block at most 32 MiB) would
   have to be reconsidered, or the per-block cycle budget (BLK-8: at most
   16 SLH-DSA signature checks, about 7 M cycles for each spend) would have
   to shrink to keep receipts small.
5. **New image IDs** and a new network definition (PAR-5), as for any
   change to the guests or the prover.

## 6. Caveats

* The recursion multiplier (50 to 200) is the weakest figure. It comes from
  the relative circuit cost of SHA-256 and Poseidon2 per hash, not from a
  SHA-256 recursion circuit that exists and could be timed.
* The assumption that recursion is two thirds of the proving time comes
  from counting proofs, not from timing the stages separately.
* All timings are for a CPU prover under emulation with `-O1` kernels. A
  GPU or a native x86_64 host changes every row; the ratios between
  configurations are expected to hold, the absolute times are not.
* The size of a segment proof (about 250 KB) is assumed, not measured: BHSS
  produces only succinct receipts.
* SHA-256 would not change the "97 bits, conjectured" security level,
  which comes from the FRI parameters and not from the hash.

## 7. Sources

* risc0-zkvm 3.0.6: `src/host/client/prove/opts.rs` (`ProverOpts`: every
  constructor sets `hashfn: "poseidon2"`; receipt kinds),
  `src/receipt/segment.rs` (a `hashfn` other than `"poseidon2"` is an
  `InvalidHashSuite` error), `src/receipt/succinct.rs` (`SuccinctReceipt`,
  control roots, `inner_control_root` for switching hash functions),
  `src/host/recursion/prove/mod.rs` (`ensure_poseidon2!`, `lift`, `join`,
  `resolve`, `identity`), `src/host/recursion/tests.rs`
  (`test_recursion_identity_sha256`).
* risc0-zkp 3.0.5: `src/lib.rs` (`QUERIES = 50`, `INV_RATE = 4`, the
  97-bit comment), `src/core/hash/mod.rs` (`hash_suite_from_name`).
* BHSS: `README.md` (measured proving cost), `docs/SPEC.md` PRF-6 and
  PRF-8, `docs/DECISIONS.md` §7.

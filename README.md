# BHSS — bitcoin-hardfork-stark-slhdsa

A Bitcoin regtest/signet-style hard fork, written from scratch in Rust, where

* every block carries a **RISC Zero STARK** proving its own validity and nodes
  *also* re-validate everything natively (double verification),
* the only signature scheme for new coins is **SLH-DSA-SHA2-128s** (FIPS 205),
* the UTXO set is committed in a **SHA-256 sparse Merkle tree** and every input
  carries an inclusion proof,
* legacy (secp256k1) coins from a Bitcoin Core `dumptxoutset` snapshot can be
  spent only through a **migration proof** (a per-transaction STARK of the
  legacy authorization) into SLH-DSA outputs.

The consensus rules are specified in [`docs/SPEC.md`](docs/SPEC.md) (English,
Japanese summaries per chapter); design choices are recorded in
[`docs/DECISIONS.md`](docs/DECISIONS.md).

## Layout

| Crate | Role |
|-------|------|
| `bhss-primitives` | types, canonical encoding, tagged hashing, chain params, addresses (`no_std`) |
| `bhss-smt` | sparse Merkle tree and proof verification (`no_std`) |
| `bhss-slhdsa` | SLH-DSA-SHA2-128s wrapper (vendored `slh-dsa` 0.1.0) |
| `bhss-legacy` | legacy script templates + secp256k1 verification for migrations |
| `bhss-consensus` | the executable form of `SPEC.md`, shared by node and zkVM guest |
| `bhss-methods` | RISC Zero guests: `block` (full block validity) and `migrate` |
| `bhss-prover` | host-side proving (dev / real), receipt verification |
| `bhss-node` (`bhssd`) | chain state, mempool, miner+prover, gossip P2P, JSON-RPC |
| `bhss-cli` | keys, addresses, spending, migration proofs |
| `bhss-snapshot` | `dumptxoutset` parser and genesis state builder |

## Running (everything through Docker)

```sh
make image      # build the dev image (Rust + RISC Zero toolchain, linux/amd64)
make test       # unit + integration tests, dev-mode proofs (seconds)
make bins       # release binaries into ./bin
make e2e        # 3-node regtest end-to-end test, dev-mode proofs
make prove      # real STARK for a 3-block chain incl. a migration (CPU, slow)
make e2e-real   # end-to-end with a real STARK per block (very slow on CPU)
make clippy     # lints, warnings are errors
```

The dev image is `linux/amd64` because RISC Zero ships Linux toolchains for
x86_64 only; on Apple Silicon it runs under Rosetta. Real proving inside that
container is CPU-only. Base images are digest-pinned and the RISC Zero
toolchain (cargo-risczero, r0vm, guest Rust) is version-pinned because the
guest image IDs are part of the chain parameters: `bhss-snapshot` writes the
IDs of the guests it was built with into `params.json`, and a node refuses a
network whose IDs differ from its own binaries. So after any change to the
guest code or the toolchain, regenerate the network with `bhss-snapshot`
(`params.json` files from before the image IDs were added are rejected:
unknown or missing fields are errors).

Build knobs (all optional, see `Makefile`): `JOBS` (cargo parallelism, default
1 because linking the two ~170 MB binaries in parallel exhausts a shared 8 GB
VM; raise it on a bigger machine), `RISC0_CXXFLAGS` (optimization level of RISC Zero's generated C++ prover
kernels, default `-O1` so they compile inside an 8 GB Docker VM; use `-O3` on a
larger machine for faster proving), `SEGMENT_PO2` (zkVM segment size, default
17 through `make` and compose; 19 was OOM-killed in a shared 8 GB VM. The
binaries themselves default to `--segment-po2 20` when run directly).

## Proving cost (measured)

Measured on an M1 Pro running the amd64 image under Rosetta, 8 threads,
`-O1` kernels, segment 2^17 (`cycles` as reported by the prover). `make
prove`, 2026-10-12, with nothing else running in the 8 GB Docker VM:

| Proof | Guest cycles | Wall time | RAM |
|-------|-------------:|----------:|----:|
| block, coinbase only | 1.74 M | ≈18 min | ≈1.5 GB |
| migration receipt (P2WPKH, ECDSA inside the guest) | 0.52 M | ≈5 min | <1 GB |
| block with one SLH-DSA spend + one composed migration | 11.4 M | ≈2.0 h | ≈1.7 GB |

With other containers competing for the VM the same proofs took 25–28 min,
≈7 min and ≈2.8 h. Receipts are 223–224 KB each (succinct).

`make e2e-real`, 2026-10-11/12 (6 real block proofs and 7 real migration
proofs, every check of the scenario passed):

| Proof | Guest cycles | Wall time |
|-------|-------------:|----------:|
| block, coinbase only | 1.74 M | 23–26 min |
| block with one SLH-DSA spend | 8.9 M | 1.85 h |
| migration receipts, one per template | 0.46–1.46 M | 6–17 min |
| block with 7 migrations | 13.2 M | ≈11 h (segment 2^16) |

The last row is not what the code does any more. That run still fed the
migration receipts themselves (≈223 KB each) to the block guest, which
costs about 1.6 M cycles of input decoding per migration; the prover now
empties them (the guest needs only their number), without changing the
guest. It was also proven with segment 2^16 after an out-of-memory kill,
which doubles the number of recursion proofs. The run was interrupted
twice (the OOM kill and a killed driver shell) and resumed from the nodes'
disks; blocks 1–3 and the migration receipts were not redone.

One SLH-DSA-SHA2-128s verification therefore costs roughly 10 M cycles in the
guest even with the SHA-256 accelerator, which is why the default block limit
is 16 signature checks.

Dev-mode execution of the same block takes ≈50 ms, which is what `make e2e`
uses. **Dev mode proves nothing**: the receipts are RISC Zero fake receipts,
so `make e2e` exercises the migration *logic* (wrong keys fail in the
executor, forged receipts for the wrong image are rejected by nodes) but not
the soundness of the STARK. A chain with `require_real_proofs = true` rejects
fake receipts regardless of any environment variable. Real proving is a `make prove` / `make e2e-real` affair: `make prove`
proves three blocks plus a composed migration receipt (hours on this setup);
`make e2e-real` runs the same end-to-end scenario with a real STARK for every
block and every migration; it shortens the coinbase maturity to 1
(`E2E_MATURITY`) so that the chain is 7 blocks instead of 15, and still takes
many hours on this setup; do not build or test in the same Docker VM while it
runs, the prover gets OOM-killed (a GPU or a native x86_64 host with
`RISC0_CXXFLAGS=-O3` is the practical way to run it).

## What the e2e test covers

`tests/e2e.sh` starts three nodes in a line (node1 – node2 – node3), builds a
synthetic snapshot with seven legacy coins (P2WPKH, uncompressed P2PKH, P2TR,
P2SH-P2WPKH, P2PK, 2-of-3 P2WSH multisig, 1-of-2 P2SH multisig) and checks:

* blocks mined on node1 (each carrying a block receipt) sync to node3 with
  identical state roots;
* an SLH-DSA spend relayed through the network and confirmed;
* a corrupted SLH-DSA signature is rejected with `SIG-2` (hidden CLI test
  hook `send --corrupt-signature`);
* every legacy template is migrated with a zkVM migration proof (fake in dev
  mode, see above) submitted via node2 and mined by node1; a wrong key is
  rejected by the executor and a forged receipt for the wrong image is
  rejected by the node with `MIG-2` (hidden CLI test hook
  `migrate --forge-receipt`);
* all nodes report the same guest image IDs, which are pinned in
  `params.json`;
* a network partition where node3 mines the longer chain and node1 reorganizes;
* node restart with full re-validation from disk.

The e2e chain is short (15 blocks). The behaviours it cannot reach — forks
on chains longer than one download window, side-chain storage and eviction,
mempool policy across reorganizations — are covered by unit tests in
`crates/bhss-node` (`chain.rs`, `p2p.rs`), which build blocks in memory with
forged dev-mode receipts.

## Review status

`docs/DECISIONS.md` has the log of the adversarial self-review (what was
found, what was changed) and the list of known limitations that were left
as they are on purpose.

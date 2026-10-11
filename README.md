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
```

The dev image is `linux/amd64` because RISC Zero ships Linux toolchains for
x86_64 only; on Apple Silicon it runs under Rosetta. Real proving inside that
container is CPU-only.

Build knobs (all optional, see `Makefile`): `JOBS` (cargo parallelism, default
1 because linking the two ~170 MB binaries in parallel exhausts a shared 8 GB
VM; raise it on a bigger machine), `RISC0_CXXFLAGS` (optimization level of RISC Zero's generated C++ prover
kernels, default `-O1` so they compile inside an 8 GB Docker VM; use `-O3` on a
larger machine for faster proving), `SEGMENT_PO2` (zkVM segment size, default
17; 19 was OOM-killed in a shared 8 GB VM).

## Proving cost (measured)

Measured by `make prove` on an M1 Pro running the amd64 image under Rosetta,
8 threads, `-O1` kernels, segment 2^17 (`cycles` as reported by the prover):

| Proof | Guest cycles | Wall time | RAM |
|-------|-------------:|----------:|----:|
| block, coinbase only | 1.74 M | 25–28 min | ≈1.5 GB |
| migration receipt (P2WPKH, ECDSA inside the guest) | 0.52 M | ≈7 min | <1 GB |
| block with one SLH-DSA spend + one composed migration | 12.3 M | ≈2.8 h | ≈1.6 GB |

One SLH-DSA-SHA2-128s verification therefore costs roughly 10 M cycles in the
guest even with the SHA-256 accelerator, which is why the default block limit
is 16 signature checks.

Dev-mode execution of the same block takes ≈50 ms, which is what `make e2e`
uses. Real proving is a `make prove` / `make e2e-real` affair: `make prove`
proves three blocks plus a composed migration receipt (hours on this setup);
`make e2e-real` proves every block of the 15-block e2e chain and is only
practical on a GPU or a native x86_64 host with `RISC0_CXXFLAGS=-O3`.

## What the e2e test covers

`tests/e2e.sh` starts three nodes in a line (node1 – node2 – node3), builds a
synthetic snapshot with seven legacy coins (P2WPKH, uncompressed P2PKH, P2TR,
P2SH-P2WPKH, P2PK, 2-of-3 P2WSH multisig, 1-of-2 P2SH multisig) and checks:

* blocks mined on node1 (each carrying a block receipt) sync to node3 with
  identical state roots;
* an SLH-DSA spend relayed through the network and confirmed;
* a corrupted SLH-DSA signature is rejected with `SIG-2`;
* every legacy template is migrated with a zkVM migration proof submitted via
  node2 and mined by node1; a wrong key is rejected;
* a network partition where node3 mines the longer chain and node1 reorganizes;
* node restart with full re-validation from disk.

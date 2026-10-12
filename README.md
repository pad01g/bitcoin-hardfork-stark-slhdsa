# BHSS — bitcoin-hardfork-stark-slhdsa

BHSS is an experimental regtest chain, written from scratch in Rust, whose
genesis state is a Bitcoin UTXO snapshot. Its rules differ from Bitcoin's in
four ways:

* Every block carries a **RISC Zero succinct STARK receipt** proving that the
  block is valid, and every node also validates the block natively (double
  verification).
* New coins can be locked only by **SLH-DSA-SHA2-128s** keys (FIPS 205).
  There is no script language.
* The UTXO set is committed by a **SHA-256 sparse Merkle tree**, and every
  block carries a Merkle proof for each coin it spends or creates.
* Legacy (secp256k1) coins from a Bitcoin Core `dumptxoutset` snapshot can
  only be moved into SLH-DSA outputs, by a transaction that carries one
  **migration proof** per input: a STARK showing that the owner of the
  legacy script authorized the move.

BHSS shares no code, block format or network protocol with Bitcoin Core and
does not validate Bitcoin's block history.

The consensus rules are specified in [`docs/SPEC.md`](docs/SPEC.md) (English,
with a Japanese summary per chapter). The reasons for the design are in
[`docs/DECISIONS.md`](docs/DECISIONS.md).
[`docs/HASH_FUNCTION_TRADEOFF.md`](docs/HASH_FUNCTION_TRADEOFF.md) estimates
what replacing the STARK's internal hash with SHA-256 would cost.

## Read this first

* **Regtest only.** Proof of work is trivial and difficulty never adjusts.
  Anyone who can reach a node can extend or rewrite the chain. BHSS is not
  suitable for holding value.
* **What the proof system protects.** Nodes check every rule natively
  except the secp256k1 authorization of legacy coins, which is checked only
  inside the migration proof. A failure of the proof system can therefore
  affect un-migrated legacy coins, and nothing else.
* **What "hash-based" and "post-quantum" mean here.** The proof system is a
  FRI-based STARK: no Groth16, no pairing, no trusted setup. Its internal
  hash is **Poseidon2 over the BabyBear field, not SHA-256**, and its
  security level is RISC Zero's *conjectured* 97 bits. Coins created under
  BHSS rules are locked by a post-quantum signature scheme. Un-migrated
  legacy coins are still secp256k1 coins. No claim is made about the proof
  system's security against quantum attackers.
* **Dev-mode receipts prove nothing.** `--prove-mode dev`, the default,
  produces RISC Zero fake receipts. A chain accepts them when its parameter
  `require_real_proofs` is `false`, which is the case for every network the
  tools create unless `bhss-snapshot from-dump --require-real-proofs` is
  used. On such a chain anyone can spend any legacy coin without its key.
* **No RPC authentication.** Any caller of the JSON-RPC interface can mine
  blocks and submit transactions. `bhssd` binds it to `127.0.0.1` by
  default; do not expose it. The peer-to-peer protocol is unauthenticated
  and unencrypted.
* **Guest image IDs are part of the network definition.** `bhss-snapshot`
  writes the image IDs of the guest programs it was built with into
  `params.json`, and a node refuses a network whose IDs differ from the
  guests in its own binary. After any change to the guest code, to a crate
  the guest uses, or to the RISC Zero toolchain, regenerate the network
  with `bhss-snapshot`. A `params.json` with an unknown or missing field is
  rejected.
* **The guest build is not reproducible.** Two builds produce the same
  image IDs only if they use the same development image
  (`docker/Dockerfile`, which pins its base image by digest and the RISC
  Zero components by version).
* **Unaudited cryptography.** Nothing here has been audited. The vendored
  `slh-dsa` crate states that it has never been independently audited.
* **Wallet keys.** `bhss-cli` stores SLH-DSA secret keys unencrypted and
  takes legacy secp256k1 secrets on the command line.
* **Licence.** The Cargo manifests declare `MIT OR Apache-2.0`. The
  repository contains no licence file of its own; `vendor/slh-dsa` carries
  the licence files of that crate.

## Layout

| Crate | Role |
|-------|------|
| `bhss-primitives` | types, canonical encoding, tagged hashing, chain parameters, addresses |
| `bhss-smt` | sparse Merkle tree and proof verification |
| `bhss-slhdsa` | SLH-DSA-SHA2-128s wrapper around the vendored `slh-dsa` 0.1.0 |
| `bhss-legacy` | legacy script templates and secp256k1 verification for migrations |
| `bhss-consensus` | the executable form of `docs/SPEC.md`, shared by the node and the zkVM guest |
| `bhss-methods` | the RISC Zero guest programs `block` (full block validity) and `migrate` |
| `bhss-prover` | host-side proving (dev or real) and receipt verification |
| `bhss-node` (`bhssd`) | chain state, mempool, miner and prover, gossip P2P, JSON-RPC |
| `bhss-cli` | keys, addresses, spending, migration proofs, raw RPC calls |
| `bhss-snapshot` | `dumptxoutset` parser and network definition (`params.json`, `genesis_state.bin`) |

## Building and testing

All builds, tests and proving run in Docker. The host needs Docker with
Compose and `make`; the end-to-end tests also need `bash`, `curl` and `jq`.
No Rust or RISC Zero toolchain is needed on the host.

```sh
make image      # build the development image (Rust and the RISC Zero toolchain, linux/amd64)
make test       # unit and integration tests with dev-mode receipts
make clippy     # lints; warnings are errors
make bins       # release binaries (linux/amd64) into ./bin
make e2e        # three-node end-to-end test with dev-mode receipts
make prove      # real STARKs for a three-block chain including a migration (CPU, hours)
make e2e-real   # the end-to-end test with a real STARK for every block and migration (CPU, many hours)
```

The development image is `linux/amd64` because RISC Zero publishes Linux
toolchains for x86_64 only. On Apple Silicon it runs under Rosetta. Proving
in the container uses the CPU only.

Optional build settings (see `Makefile`):

| Variable | Default | Meaning |
|----------|---------|---------|
| `JOBS` | 1 | cargo parallelism. Compiling the prover kernels or linking the large binaries in parallel exceeds the memory of an 8 GB Docker VM. |
| `RISC0_CXXFLAGS` | `-O1` | optimization level of RISC Zero's generated C++ prover kernels. `-O3` proves faster but needs more than 4 GB per compiler process. |
| `SEGMENT_PO2` | 17 | zkVM segment size as a power of two, used by `make prove`, `make e2e` and `make e2e-real`. Larger segments need more prover memory. |

Run directly, `bhssd` and `bhss-cli migrate` default to `--segment-po2 20`
and `--prove-mode dev`.

## Running a network

A network is defined by two files that `bhss-snapshot` writes into a
directory: `params.json` and `genesis_state.bin`.

| Command | Result |
|---------|--------|
| `bhss-snapshot empty --out-dir DIR` | a network named `bhrt` with an empty genesis state |
| `bhss-snapshot synthetic --out-dir DIR --coin TXID:VOUT:VALUE:SCRIPT_HEX …` | a network with the given legacy coins |
| `bhss-snapshot from-dump --dump FILE --out-dir DIR [--require-real-proofs]` | a network named `bhsn` whose genesis state is a Bitcoin Core `dumptxoutset` file |

`bhssd --params DIR/params.json --genesis-state DIR/genesis_state.bin`
starts a node. Its other options are `--datadir` (default `data`),
`--p2p-bind` (default `127.0.0.1:18555`), `--rpc-bind` (default
`127.0.0.1:18443`), `--connect HOST:PORT` (repeatable), `--prove-mode`
(`dev` or `real`) and `--segment-po2`. Blocks are produced only on request,
through the `generate` RPC method.

`bhss-cli --rpc URL` provides `keygen`, `address`, `balance`, `send`,
`legacy-script`, `migrate` and `rpc`. `docker-compose.yml` and
`tests/e2e.sh` show a complete three-node setup that runs these binaries in
containers.

## Proving cost

All figures were measured on an Apple M1 Pro running the `linux/amd64`
image under Rosetta with 8 threads, `-O1` prover kernels and an 8 GB Docker
VM. Cycle counts are those reported by the prover. Succinct receipts were
223 to 224 KB each.

`make prove`, segments of 2¹⁷ cycles, no other load in the VM:

| Proof | Guest cycles | Wall time | Memory |
|-------|-------------:|----------:|-------:|
| block, coinbase only | 1.74 M | ≈18 min | ≈1.5 GB |
| migration receipt (P2WPKH, ECDSA inside the guest) | 0.52 M | ≈5 min | <1 GB |
| block with one SLH-DSA spend and one composed migration | 11.4 M | ≈2.0 h | ≈1.7 GB |

With other containers competing for the same VM, the same three proofs took
25 to 28 minutes, about 7 minutes and about 2.8 hours.

`make e2e-real`, segments of 2¹⁷ cycles, three node containers in the VM:

| Proof | Guest cycles | Wall time |
|-------|-------------:|----------:|
| block, coinbase only | 1.74 M | 23–26 min |
| block with one SLH-DSA spend | 8.9 M | 1.85 h |
| migration receipts, one per legacy template | 0.46–1.46 M | 6–17 min |

One measurement does not correspond to the current prover: a block with
seven migrations took 13.2 M cycles and about 11 hours, with segments of
2¹⁶ cycles and with a prover that passed the bytes of the seven migration
receipts (about 223 KB each) into the block guest. The current prover
passes only the number of receipts, which avoids decoding them in the
guest (estimated at 1.6 M cycles per receipt). A block with seven
migrations has not been measured in that configuration.

From the tables, one SLH-DSA spend adds about 7 M cycles to a block
(8.9 M against 1.74 M), even with the zkVM's SHA-256 accelerator. This is
why the default limit is 16 signature checks per block; a block that uses
the whole limit is on the order of 10⁸ cycles, which is an extrapolation
and was not measured.

Dev mode executes the guest without proving it, which was measured at about
50 ms for a block.

`make e2e-real` shortens the coinbase maturity to 1 (`E2E_MATURITY`), so
that the scenario needs 7 blocks instead of 16. Do not build or run tests
in the same Docker VM while a real proof is running: the prover is killed
when the VM runs out of memory. A GPU prover or a native x86_64 host with
`RISC0_CXXFLAGS=-O3` is the practical way to run real proofs.

## What the tests cover

`tests/e2e.sh` starts three nodes connected in a line (node1, node2,
node3), builds a synthetic genesis state with seven legacy coins (P2WPKH,
uncompressed P2PKH, P2TR, P2SH-P2WPKH, P2PK, 2-of-3 P2WSH multisig and
1-of-2 P2SH multisig) and checks that:

* the nodes agree on the genesis hash and the parameter hash, and each
  reports the guest image IDs pinned in `params.json`;
* blocks mined on node1, each with a block receipt, reach node3, and the
  nodes agree on the state root;
* an SLH-DSA spend submitted to node1 is mined and visible on node3;
* a transaction with a corrupted SLH-DSA signature is rejected with
  `SIG-2` (hidden test option `send --corrupt-signature`);
* a migration with the right journal but a receipt for the wrong image is
  rejected (hidden test option `migrate --forge-receipt`): with `MIG-2` in
  dev mode, and by the mempool policy against fake receipts when the nodes
  prove for real;
* every legacy template is migrated with a zkVM migration receipt,
  submitted through node2 and mined by node1, and a migration attempted
  with the wrong key fails in the guest before any receipt exists;
* after a partition in which node3 mines the longer branch, node1
  reorganizes to it;
* a restarted node re-validates its stored chain and reaches the same tip.

In dev mode the receipts are fake, so `make e2e` exercises the migration
logic but not the soundness of the STARK. `make e2e-real` proves every
block and migration for real; its network still has
`require_real_proofs = false`, so it does not test that consensus rejects
fake receipts. `make prove` proves three blocks and a composed migration
receipt and verifies them with fake receipts disallowed.

The end-to-end chain is short (height 15 in dev mode). Behaviour it cannot
reach, such as forks on chains longer than one download window of 32
blocks, storage and eviction of competing-branch blocks, and mempool policy
across reorganizations, is covered by unit tests in `crates/bhss-node`
(`chain.rs`, `p2p.rs`), which build blocks in memory with dev-mode
receipts. The consensus rules are tested rule by rule in
`crates/bhss-consensus/tests/rules.rs`.

Known limitations are listed in
[`docs/DECISIONS.md`](docs/DECISIONS.md#9-limitations-and-non-goals).

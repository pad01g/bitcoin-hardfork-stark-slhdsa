//! Rule-level tests for docs/SPEC.md. Each test names the rule it exercises.

use bhss_consensus::genesis::{genesis_prev_state, genesis_state_root};
use bhss_consensus::*;
use bhss_primitives::params::hash_meets_target;
use bhss_primitives::types::*;
use bhss_primitives::{ChainParams, Hash32};
use bhss_slhdsa::SecretKey;

struct AcceptAll;
impl MigrationChecker for AcceptAll {
    fn check(&mut self, _: usize, _: usize, _: &MigrationJournal) -> bool {
        true
    }
}

struct Net {
    params: ChainParams,
    genesis_hash: Hash32,
    state: FullState,
    prev: PrevState,
    blocks: Vec<Block>,
}

fn key(i: u8) -> SecretKey {
    SecretKey::from_seeds(&[i; 16], &[i + 1; 16], &[i + 2; 16])
}
fn p2pk(sk: &SecretKey) -> OutputKind {
    OutputKind::P2pkSlh { pkh: sk.public_key().hash() }
}

fn net(legacy: Vec<(OutPoint, Coin)>) -> Net {
    let root = genesis_state_root(&legacy);
    let mut params = ChainParams::regtest(root);
    params.coinbase_maturity = 2;
    let (genesis_hash, prev) = genesis_prev_state(&params);
    Net { params, genesis_hash, state: FullState::from_coins(legacy), prev, blocks: vec![] }
}

fn coinbase(height: u32, payout: OutputKind) -> Transaction {
    Transaction { version: 1, inputs: vec![Input { prevout: OutPoint::coinbase(height), witness: Witness::Coinbase }], outputs: vec![Output { value: 0, kind: payout }], locktime: 0, proofs: vec![] }
}

/// Build a valid block on `n` (coinbase value = subsidy + fees) with the
/// witness filled in. `n` itself is not advanced.
fn build(n: &mut Net, txs: Vec<Transaction>, coins: Vec<Coin>) -> Block {
    let mut state = n.state.clone();
    assemble_block(&n.params, &n.genesis_hash, &n.prev, &mut state, txs, coins, n.prev.time, &mut AcceptAll).expect("valid template")
}

/// Re-seal a deliberately broken block: fix the Merkle root and nonce and pad
/// the proof list to the BLK-11 count so the intended rule is what fires.
fn reseal(n: &Net, mut b: Block) -> Block {
    b.witness.proofs.resize(expected_state_ops(&b.txs), SmtProof::default());
    b.header.merkle_root = body_merkle_root(&b.txs);
    b.header.nonce = 0;
    while !hash_meets_target(&b.header.hash(), &n.params.target()) {
        b.header.nonce += 1;
    }
    b
}

/// Validate both statelessly (proof-backed) and against the full set.
fn try_connect(n: &mut Net, b: &Block) -> Result<BlockSummary> {
    let mut pb = ProofBackedState::new(n.prev.state_root, &b.witness.proofs);
    let stateless = connect_block(&n.params, &n.genesis_hash, &n.prev, b, &mut pb, &mut AcceptAll);
    let mut full = n.state.clone();
    let mut dual = DualState { full: &mut full, proofs: ProofBackedState::new(n.prev.state_root, &b.witness.proofs) };
    let stateful = connect_block(&n.params, &n.genesis_hash, &n.prev, b, &mut dual, &mut AcceptAll);
    // Both verifiers must agree on the verdict and the resulting root. The
    // rule ID may differ in one case only: a stateless verifier cannot tell
    // "coin not in the set" (STATE-3/STATE-4) from "bad proof" (STATE-2).
    assert_eq!(stateless.as_ref().ok().map(|s| s.root_next), stateful.as_ref().ok().map(|s| s.root_next));
    if let (Err(a), Err(b)) = (&stateless, &stateful) {
        assert!(a.rule == b.rule || (a.rule == "STATE-2" && b.rule.starts_with("STATE-")), "stateless {a} vs stateful {b}");
    }
    if stateful.is_ok() && !pb.all_proofs_consumed() {
        return Err(ConsensusError { rule: "BLK-11", detail: "unused SMT proofs".into() });
    }
    if let Ok(s) = &stateful {
        n.state = full;
        n.prev = PrevState { height: s.height, hash: s.block_hash, state_root: s.root_next, time: b.header.time };
        n.blocks.push(b.clone());
    }
    stateful
}

/// Re-seal (merkle root + nonce) then try to connect.
fn try_resealed(n: &mut Net, b: Block) -> Result<BlockSummary> {
    let b = reseal(n, b);
    try_connect(n, &b)
}

fn connect(n: &mut Net, b: Block) -> BlockSummary {
    try_connect(n, &b).expect("valid block")
}

fn rule(r: Result<BlockSummary>) -> &'static str {
    r.err().map(|e| e.rule).unwrap_or("OK")
}

fn mine_to(n: &mut Net, sk: &SecretKey, count: u32) {
    for _ in 0..count {
        let h = n.prev.height + 1;
        let b = build(n, vec![coinbase(h, p2pk(sk))], vec![]);
        connect(n, b);
    }
}

fn first_coin(n: &Net, kind: &OutputKind) -> (OutPoint, Coin) {
    n.state.coins.iter().find(|(_, c)| &c.output.kind == kind).map(|(o, c)| (*o, c.clone())).unwrap()
}

fn sign_slh(n: &Net, tx: &mut Transaction, index: usize, coin: &Coin, sk: &SecretKey) {
    let msg = slh_sighash(&n.genesis_hash, &tx.txid(), index as u32, &coin.leaf_hash());
    tx.inputs[index].witness = Witness::Slh { signers: vec![SlhSigner { index: 0, pubkey: sk.public_key().0, signature: sk.sign(&msg) }] };
}

#[test]
fn genesis_is_deterministic_and_empty_root_matches_smt() {
    let n = net(vec![]);
    assert_eq!(n.params.genesis_state_root, bhss_smt::Smt::new().root());
    let (g2, _) = genesis_prev_state(&n.params);
    assert_eq!(n.genesis_hash, g2);
    let g = bhss_consensus::genesis::genesis_block(&n.params);
    assert!(hash_meets_target(&g.hash(), &n.params.target()));
}

#[test]
fn coinbase_only_chain_and_header_rules() {
    let alice = key(1);
    let mut n = net(vec![]);
    mine_to(&mut n, &alice, 3);
    assert_eq!(n.prev.height, 3);
    assert_eq!(n.state.coins.len(), 3);
    let b = build(&mut n, vec![coinbase(4, p2pk(&alice))], vec![]);

    let mut x = b.clone();
    x.header.state_root[0] ^= 1;
    assert_eq!(rule(try_resealed(&mut n, x)), "HDR-3");
    let mut x = b.clone();
    x.header.prev_hash[0] ^= 1;
    assert_eq!(rule(try_resealed(&mut n, x)), "HDR-5");
    let mut x = b.clone();
    x.header.bits = 0x1d00ffff;
    assert_eq!(rule(try_resealed(&mut n, x)), "HDR-6");
    let mut x = b.clone();
    x.header.time = n.prev.time - 1;
    assert_eq!(rule(try_resealed(&mut n, x)), "HDR-7");
    let mut x = b.clone();
    x.header.merkle_root[0] ^= 1;
    assert_eq!(rule(try_connect(&mut n, &x)), "BLK-3");
    let mut x = b.clone();
    x.txs[0].outputs[0].value += 1; // more than subsidy
    assert_eq!(rule(try_resealed(&mut n, x)), "CB-3");
    let mut x = b.clone();
    x.txs[0].inputs[0].prevout.vout = 99;
    assert_eq!(rule(try_resealed(&mut n, x)), "CB-2");
    let mut x = b.clone();
    x.txs.push(x.txs[0].clone());
    assert_eq!(rule(try_resealed(&mut n, x)), "BLK-5");
    let mut x = b.clone();
    x.witness.proofs.push(SmtProof::default());
    assert_eq!(rule(try_connect(&mut n, &x)), "BLK-11");
    connect(&mut n, b);
    assert_eq!(n.prev.height, 4);
}

#[test]
fn slh_spend_signature_and_amount_rules() {
    let alice = key(1);
    let bob = key(9);
    let mut n = net(vec![]);
    mine_to(&mut n, &alice, 3); // coinbase 1 matures at height 3
    let (op, coin) = first_coin(&n, &p2pk(&alice));
    assert_eq!(coin.height, 1);
    let mut tx = Transaction {
        version: 1,
        inputs: vec![Input { prevout: op, witness: Witness::Slh { signers: vec![] } }],
        outputs: vec![Output { value: 10_000, kind: p2pk(&bob) }, Output { value: coin.output.value - 10_000 - 100, kind: p2pk(&alice) }],
        locktime: 0,
        proofs: vec![],
    };
    sign_slh(&n, &mut tx, 0, &coin, &alice);
    let good = build(&mut n, vec![coinbase(4, p2pk(&alice)), tx.clone()], vec![coin.clone()]);

    // SIG-2: wrong key
    let mut bad = tx.clone();
    sign_slh(&n, &mut bad, 0, &coin, &bob);
    let b = Block { txs: vec![good.txs[0].clone(), bad], ..good.clone() };
    assert_eq!(rule(try_resealed(&mut n, b)), "SIG-2");
    // SIG-2: corrupted signature
    let mut bad = tx.clone();
    if let Witness::Slh { signers } = &mut bad.inputs[0].witness {
        signers[0].signature[100] ^= 1;
    }
    let b = Block { txs: vec![good.txs[0].clone(), bad], ..good.clone() };
    assert_eq!(rule(try_resealed(&mut n, b)), "SIG-2");
    // AMT-2: outputs exceed inputs
    let mut bad = tx.clone();
    bad.outputs[0].value = coin.output.value;
    sign_slh(&n, &mut bad, 0, &coin, &alice);
    let b = Block { txs: vec![good.txs[0].clone(), bad], ..good.clone() };
    assert_eq!(rule(try_resealed(&mut n, b)), "AMT-2");
    // A witness coin that differs from the set (here: its value)
    let mut w = good.witness.clone();
    w.coins[0].output.value += 1;
    let b = Block { witness: w, ..good.clone() };
    assert_eq!(rule(try_connect(&mut n, &b)), "SIG-2"); // the sighash binds the leaf, so the signature fails before STATE-3 is reached
    // TX-6: duplicate prevout
    let mut bad = tx.clone();
    bad.inputs.push(bad.inputs[0].clone());
    let proofs = vec![SmtProof::default(); expected_state_ops(&[good.txs[0].clone(), bad.clone()])];
    let b = Block { txs: vec![good.txs[0].clone(), bad], witness: BlockWitness { coins: vec![coin.clone(), coin.clone()], proofs }, ..good.clone() };
    assert_eq!(rule(try_resealed(&mut n, b)), "TX-6");
    // BLK-10: witness coin count
    let b = Block { witness: BlockWitness { coins: vec![], proofs: good.witness.proofs.clone() }, ..good.clone() };
    assert_eq!(rule(try_connect(&mut n, &b)), "BLK-10");
    // OUT-5: Data output with value
    let mut bad = tx.clone();
    bad.outputs[0] = Output { value: 10_000, kind: OutputKind::Data { data: b"x".to_vec() } };
    sign_slh(&n, &mut bad, 0, &coin, &alice);
    let b = Block { txs: vec![good.txs[0].clone(), bad], ..good.clone() };
    assert_eq!(rule(try_resealed(&mut n, b)), "OUT-5");
    // OUT-6: creating a Legacy output
    let mut bad = tx.clone();
    bad.outputs[0] = Output { value: 10_000, kind: OutputKind::Legacy { script_pubkey: vec![0x00, 0x14] } };
    sign_slh(&n, &mut bad, 0, &coin, &alice);
    let b = Block { txs: vec![good.txs[0].clone(), bad], ..good.clone() };
    assert_eq!(rule(try_resealed(&mut n, b)), "OUT-6");

    let s = connect(&mut n, good);
    assert_eq!(s.fees, 100);
    assert_eq!(s.sig_checks, 1);
    // Coinbase of block 4 got subsidy + fee.
    let cb = n.blocks.last().unwrap().txs[0].outputs[0].value;
    assert_eq!(cb, n.params.subsidy(4) + 100);
    // STATE-3: spending the same coin again
    let b = build_unchecked(&mut n, vec![coinbase(5, p2pk(&alice)), tx.clone()], vec![coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "STATE-3");
}

/// Build without validating (for blocks that are expected to fail). SMT
/// proofs are generated leniently in STATE-1 order so that the failure
/// surfaces at the intended rule rather than as a missing proof.
fn build_unchecked(n: &mut Net, mut txs: Vec<Transaction>, coins: Vec<Coin>) -> Block {
    let height = n.prev.height + 1;
    txs[0].outputs[0].value = n.params.subsidy(height);
    let mut smt = n.state.smt.clone();
    let mut proofs = Vec::new();
    for (i, tx) in txs.iter().enumerate().skip(1) {
        for input in &tx.inputs {
            let key = input.prevout.smt_key();
            proofs.push(smt.prove(&key));
            smt.remove(&key);
        }
        for (vout, o) in tx.outputs.iter().enumerate() {
            if o.kind.is_data() {
                continue;
            }
            let op = OutPoint::new(tx.txid(), vout as u32);
            proofs.push(smt.prove(&op.smt_key()));
            smt.insert(op.smt_key(), Coin { output: o.clone(), height, coinbase: i == 0 }.leaf_hash());
        }
    }
    for (vout, o) in txs[0].outputs.iter().enumerate() {
        if o.kind.is_data() {
            continue;
        }
        let op = OutPoint::new(txs[0].txid(), vout as u32);
        proofs.push(smt.prove(&op.smt_key()));
        smt.insert(op.smt_key(), Coin { output: o.clone(), height, coinbase: true }.leaf_hash());
    }
    let mut header = Header { version: 1, prev_hash: n.prev.hash, merkle_root: body_merkle_root(&txs), state_root: smt.root(), time: n.prev.time, bits: n.params.pow_bits, nonce: 0 };
    while !hash_meets_target(&header.hash(), &n.params.target()) {
        header.nonce += 1;
    }
    Block { header, txs, witness: BlockWitness { coins, proofs }, receipt: vec![] }
}

#[test]
fn maturity_timelocks_and_multisig() {
    let alice = key(1);
    let k1 = key(11);
    let k2 = key(21);
    let k3 = key(31);
    let mut n = net(vec![]);
    mine_to(&mut n, &alice, 2);
    // IN-2: coinbase 1 is immature at height 3? maturity=2 => spendable at height 3. Try at height 3 with coin from block 2 (immature).
    let coin2 = n.state.coins.iter().find(|(_, c)| c.height == 2).map(|(o, c)| (*o, c.clone())).unwrap();
    let mut tx = Transaction { version: 1, inputs: vec![Input { prevout: coin2.0, witness: Witness::Slh { signers: vec![] } }], outputs: vec![Output { value: 1, kind: p2pk(&alice) }], locktime: 0, proofs: vec![] };
    sign_slh(&n, &mut tx, 0, &coin2.1, &alice);
    let b = build_unchecked(&mut n, vec![coinbase(3, p2pk(&alice)), tx], vec![coin2.1.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "IN-2");

    // Create a 2-of-3 multisig output and a timelocked output from coinbase 1.
    let (op, coin) = n.state.coins.iter().find(|(_, c)| c.height == 1).map(|(o, c)| (*o, c.clone())).unwrap();
    let ms = OutputKind::MultisigSlh { k: 2, pkhs: vec![k1.public_key().hash(), k2.public_key().hash(), k3.public_key().hash()] };
    let tl = OutputKind::Timelock { abs_height: 0, rel_blocks: 3, inner: Box::new(p2pk(&alice)) };
    let mut tx = Transaction {
        version: 1,
        inputs: vec![Input { prevout: op, witness: Witness::Slh { signers: vec![] } }],
        outputs: vec![Output { value: 1_000, kind: ms.clone() }, Output { value: 2_000, kind: tl.clone() }, Output { value: 0, kind: OutputKind::Data { data: b"memo".to_vec() } }],
        locktime: 3,
        proofs: vec![],
    };
    sign_slh(&n, &mut tx, 0, &coin, &alice);
    let b = build(&mut n, vec![coinbase(3, p2pk(&alice)), tx], vec![coin]);
    connect(&mut n, b); // height 3; TX-8 satisfied (locktime 3)
    assert!(n.state.coins.values().all(|c| !c.output.kind.is_data()), "OUT-5: data never enters the set");

    // IN-3: relative timelock 3 blocks from height 3 => spendable at 6.
    let (tl_op, tl_coin) = first_coin(&n, &tl);
    let mut spend_tl = Transaction { version: 1, inputs: vec![Input { prevout: tl_op, witness: Witness::Slh { signers: vec![] } }], outputs: vec![Output { value: 1_500, kind: p2pk(&alice) }], locktime: 0, proofs: vec![] };
    sign_slh(&n, &mut spend_tl, 0, &tl_coin, &alice);
    let b = build_unchecked(&mut n, vec![coinbase(4, p2pk(&alice)), spend_tl.clone()], vec![tl_coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "IN-3");
    mine_to(&mut n, &alice, 2); // heights 4, 5
    let b = build(&mut n, vec![coinbase(6, p2pk(&alice)), spend_tl], vec![tl_coin]);
    connect(&mut n, b);

    // SIG-3: multisig needs 2 signers with increasing indices.
    let (ms_op, ms_coin) = first_coin(&n, &ms);
    let mut spend_ms = Transaction { version: 1, inputs: vec![Input { prevout: ms_op, witness: Witness::Slh { signers: vec![] } }], outputs: vec![Output { value: 900, kind: p2pk(&alice) }], locktime: 0, proofs: vec![] };
    let msg = slh_sighash(&n.genesis_hash, &spend_ms.txid(), 0, &ms_coin.leaf_hash());
    let signer = |i: u8, k: &SecretKey| SlhSigner { index: i, pubkey: k.public_key().0, signature: k.sign(&msg) };
    spend_ms.inputs[0].witness = Witness::Slh { signers: vec![signer(0, &k1)] };
    let b = build_unchecked(&mut n, vec![coinbase(7, p2pk(&alice)), spend_ms.clone()], vec![ms_coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "SIG-3");
    spend_ms.inputs[0].witness = Witness::Slh { signers: vec![signer(2, &k3), signer(0, &k1)] };
    let b = build_unchecked(&mut n, vec![coinbase(7, p2pk(&alice)), spend_ms.clone()], vec![ms_coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "SIG-3");
    spend_ms.inputs[0].witness = Witness::Slh { signers: vec![signer(0, &k1), signer(2, &k2)] }; // wrong key at index 2
    let b = build_unchecked(&mut n, vec![coinbase(7, p2pk(&alice)), spend_ms.clone()], vec![ms_coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "SIG-3");
    spend_ms.inputs[0].witness = Witness::Slh { signers: vec![signer(0, &k1), signer(3, &k3)] }; // index out of range
    let b = build_unchecked(&mut n, vec![coinbase(7, p2pk(&alice)), spend_ms.clone()], vec![ms_coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "SIG-3");
    spend_ms.inputs[0].witness = Witness::Slh { signers: vec![signer(0, &k1), signer(2, &k3)] };
    let b = build(&mut n, vec![coinbase(7, p2pk(&alice)), spend_ms], vec![ms_coin]);
    let s = connect(&mut n, b);
    assert_eq!(s.sig_checks, 2);
}

#[test]
fn migration_rules() {
    let alice = key(1);
    let bob = key(9);
    let legacy = (
        OutPoint::new([5u8; 32], 0),
        Coin { output: Output { value: 50_000, kind: OutputKind::Legacy { script_pubkey: vec![0x00, 0x14, 0xaa] } }, height: 0, coinbase: false },
    );
    let mut n = net(vec![legacy.clone()]);
    mine_to(&mut n, &alice, 3);
    let (op, coin) = first_coin(&n, &p2pk(&alice));
    // MIG-1: mixing a legacy input with an SLH input
    let mut mixed = Transaction {
        version: 1,
        inputs: vec![Input { prevout: legacy.0, witness: Witness::Legacy }, Input { prevout: op, witness: Witness::Slh { signers: vec![] } }],
        outputs: vec![Output { value: 1, kind: p2pk(&bob) }],
        locktime: 0,
        proofs: vec![vec![1]],
    };
    sign_slh(&n, &mut mixed, 1, &coin, &alice);
    let b = build_unchecked(&mut n, vec![coinbase(4, p2pk(&alice)), mixed], vec![legacy.1.clone(), coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "MIG-1");
    // MIG-1: migration into a Data output
    let mig = Transaction { version: 1, inputs: vec![Input { prevout: legacy.0, witness: Witness::Legacy }], outputs: vec![Output { value: 0, kind: OutputKind::Data { data: vec![] } }], locktime: 0, proofs: vec![vec![1]] };
    let b = build_unchecked(&mut n, vec![coinbase(4, p2pk(&alice)), mig], vec![legacy.1.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "MIG-1");
    // TX-9: missing proof
    let mig = Transaction { version: 1, inputs: vec![Input { prevout: legacy.0, witness: Witness::Legacy }], outputs: vec![Output { value: 1, kind: p2pk(&bob) }], locktime: 0, proofs: vec![] };
    let b = build_unchecked(&mut n, vec![coinbase(4, p2pk(&alice)), mig], vec![legacy.1.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "TX-9");
    // PRF-7: oversized migration receipt
    let mig = Transaction { version: 1, inputs: vec![Input { prevout: legacy.0, witness: Witness::Legacy }], outputs: vec![Output { value: 1, kind: p2pk(&bob) }], locktime: 0, proofs: vec![vec![0u8; MAX_RECEIPT_LEN + 1]] };
    let b = build_unchecked(&mut n, vec![coinbase(4, p2pk(&alice)), mig], vec![legacy.1.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "PRF-7");
    // IN-1: SLH witness on a legacy coin
    let mig = Transaction { version: 1, inputs: vec![Input { prevout: legacy.0, witness: Witness::Slh { signers: vec![] } }], outputs: vec![Output { value: 1, kind: p2pk(&bob) }], locktime: 0, proofs: vec![vec![1]] };
    let b = build_unchecked(&mut n, vec![coinbase(4, p2pk(&alice)), mig], vec![legacy.1.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "IN-1");
    // MIG-2: checker rejects
    let mig = Transaction { version: 1, inputs: vec![Input { prevout: legacy.0, witness: Witness::Legacy }], outputs: vec![Output { value: 40_000, kind: p2pk(&bob) }], locktime: 0, proofs: vec![vec![1]] };
    let b = build(&mut n, vec![coinbase(4, p2pk(&alice)), mig], vec![legacy.1.clone()]);
    let mut pb = ProofBackedState::new(n.prev.state_root, &b.witness.proofs);
    let r = connect_block(&n.params, &n.genesis_hash, &n.prev, &b, &mut pb, &mut NoMigrations);
    assert_eq!(rule(r), "MIG-2");
    // With an accepting checker the migration goes through and the fee is collected.
    let s = connect(&mut n, b);
    assert_eq!(s.migrations, 1);
    assert_eq!(s.fees, 10_000);
    assert!(n.state.coins.values().all(|c| !c.output.kind.is_legacy()));
}

#[test]
fn duplicate_multisig_keys_and_proof_count() {
    let alice = key(1);
    let bob = key(9);
    let mut n = net(vec![]);
    mine_to(&mut n, &alice, 3);
    let (op, coin) = first_coin(&n, &p2pk(&alice));
    // OUT-2: repeated pkh in a multisig output is malformed.
    let dup = OutputKind::MultisigSlh { k: 2, pkhs: vec![bob.public_key().hash(), bob.public_key().hash(), alice.public_key().hash()] };
    assert!(!dup.is_well_formed());
    let mut tx = Transaction { version: 1, inputs: vec![Input { prevout: op, witness: Witness::Slh { signers: vec![] } }], outputs: vec![Output { value: 1, kind: dup }], locktime: 0, proofs: vec![] };
    sign_slh(&n, &mut tx, 0, &coin, &alice);
    let b = build_unchecked(&mut n, vec![coinbase(4, p2pk(&alice)), tx.clone()], vec![coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "OUT-2");
    // BLK-11: wrong number of SMT proofs is rejected before anything else.
    tx.outputs[0].kind = p2pk(&bob);
    sign_slh(&n, &mut tx, 0, &coin, &alice);
    let mut b = build(&mut n, vec![coinbase(4, p2pk(&alice)), tx], vec![coin]);
    assert_eq!(b.witness.proofs.len(), expected_state_ops(&b.txs));
    b.witness.proofs.push(SmtProof::default());
    assert_eq!(rule(try_connect(&mut n, &b)), "BLK-11");
    b.witness.proofs.truncate(b.witness.proofs.len() - 2);
    assert_eq!(rule(try_connect(&mut n, &b)), "BLK-11");
}

#[test]
fn block_limits() {
    let alice = key(1);
    let mut n = net(vec![]);
    n.params.max_sig_checks = 1;
    n.params.max_block_tx_bytes = 20_000;
    mine_to(&mut n, &alice, 4);
    let coins: Vec<(OutPoint, Coin)> = n.state.coins.iter().filter(|(_, c)| c.height <= 2).map(|(o, c)| (*o, c.clone())).collect();
    assert_eq!(coins.len(), 2);
    let mut txs = vec![coinbase(5, p2pk(&alice))];
    let mut wcoins = vec![];
    for (op, coin) in &coins {
        let mut tx = Transaction { version: 1, inputs: vec![Input { prevout: *op, witness: Witness::Slh { signers: vec![] } }], outputs: vec![Output { value: 1, kind: p2pk(&alice) }], locktime: 0, proofs: vec![] };
        sign_slh(&n, &mut tx, 0, coin, &alice);
        txs.push(tx);
        wcoins.push(coin.clone());
    }
    let b = build_unchecked(&mut n, txs.clone(), wcoins.clone());
    assert_eq!(rule(try_connect(&mut n, &b)), "BLK-8");
    n.params.max_sig_checks = 16;
    n.params.max_block_tx_bytes = 8_000; // one SLH signature alone is 7 856 bytes
    let b = build_unchecked(&mut n, txs, wcoins);
    assert_eq!(rule(try_connect(&mut n, &b)), "BLK-7");
}

#[test]
fn encoding_roundtrips_and_strictness() {
    use bhss_primitives::{Decode, Encode};
    let alice = key(1);
    let mut n = net(vec![]);
    mine_to(&mut n, &alice, 2);
    let b = n.blocks[1].clone();
    let bytes = b.to_bytes();
    assert_eq!(Block::from_bytes(&bytes).unwrap(), b);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(Block::from_bytes(&trailing).unwrap_err(), bhss_primitives::DecodeError::TrailingBytes);
    // OUT-3 at the encoding level: a Timelock nested in a Timelock is an
    // invalid tag, and arbitrarily deep nesting cannot overflow the stack.
    let mut nested = Vec::new();
    for _ in 0..200_000 {
        nested.extend_from_slice(&[0x02, 1, 0, 0, 0, 0, 0, 0, 0]);
    }
    nested.extend_from_slice(&[0x00]);
    nested.extend_from_slice(&[7u8; 32]);
    assert_eq!(OutputKind::from_bytes(&nested).unwrap_err(), bhss_primitives::DecodeError::InvalidTag(0x02));
    // Non-minimal CompactSize is rejected (ENC-5).
    let mut e = bhss_primitives::Encoder::new();
    e.u8(0xfd).u16(3);
    assert_eq!(bhss_primitives::Decoder::new(e.as_slice()).compact().unwrap_err(), bhss_primitives::DecodeError::NonMinimalCompactSize);
}

#[test]
fn header_structure_and_transaction_negatives() {
    let alice = key(1);
    let bob = key(9);
    let mut n = net(vec![]);
    mine_to(&mut n, &alice, 3);
    let b = build(&mut n, vec![coinbase(4, p2pk(&alice))], vec![]);

    // POW-1: a nonce whose hash is above the target.
    let mut x = b.clone();
    x.header.nonce = 0;
    while hash_meets_target(&x.header.hash(), &n.params.target()) {
        x.header.nonce += 1;
    }
    assert_eq!(rule(try_connect(&mut n, &x)), "POW-1");
    // HDR-4
    let mut x = b.clone();
    x.header.version = 2;
    assert_eq!(rule(try_resealed(&mut n, x)), "HDR-4");
    // BLK-4: no transactions (merkle root of nothing is ZERO_HASH).
    let mut x = b.clone();
    x.txs.clear();
    x.witness.proofs.clear();
    assert_eq!(rule(try_resealed(&mut n, x)), "BLK-4");
    // CB-5: coinbase with proofs / locktime.
    let mut x = b.clone();
    x.txs[0].proofs.push(vec![1]);
    assert_eq!(rule(try_resealed(&mut n, x)), "CB-5");
    let mut x = b.clone();
    x.txs[0].locktime = 1;
    assert_eq!(rule(try_resealed(&mut n, x)), "CB-5");
    // AMT-1 / OUT-4 / OUT-3 on coinbase outputs (TX-7).
    let mut x = b.clone();
    x.txs[0].outputs[0].value = MAX_MONEY + 1;
    assert_eq!(rule(try_resealed(&mut n, x)), "AMT-1");
    let mut x = b.clone();
    x.txs[0].outputs.push(Output { value: 0, kind: OutputKind::Data { data: vec![0; MAX_DATA_LEN + 1] } });
    assert_eq!(rule(try_resealed(&mut n, x)), "OUT-4");
    let mut x = b.clone();
    x.txs[0].outputs[0].kind = OutputKind::Timelock { abs_height: 0, rel_blocks: 0, inner: Box::new(p2pk(&alice)) };
    assert_eq!(rule(try_resealed(&mut n, x)), "OUT-3");
    connect(&mut n, b);

    // Spends of a mature coinbase (maturity is 2 in these tests; next height is 5).
    let (op, coin) = n.state.coins.iter().find(|(_, c)| c.height <= 2).map(|(o, c)| (*o, c.clone())).unwrap();
    let mk = |outputs: Vec<Output>, locktime: u32| Transaction { version: 1, inputs: vec![Input { prevout: op, witness: Witness::Slh { signers: vec![] } }], outputs, locktime, proofs: vec![] };
    // TX-1: wrong version / no outputs.
    let mut tx = mk(vec![Output { value: 1, kind: p2pk(&bob) }], 0);
    tx.version = 2;
    sign_slh(&n, &mut tx, 0, &coin, &alice);
    let x = build_unchecked(&mut n, vec![coinbase(5, p2pk(&alice)), tx], vec![coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &x)), "TX-1");
    let mut tx = mk(vec![], 0);
    sign_slh(&n, &mut tx, 0, &coin, &alice);
    let x = build_unchecked(&mut n, vec![coinbase(5, p2pk(&alice)), tx], vec![coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &x)), "TX-1");
    // TX-8: locktime in the future.
    let mut tx = mk(vec![Output { value: 1, kind: p2pk(&bob) }], 6);
    sign_slh(&n, &mut tx, 0, &coin, &alice);
    let x = build_unchecked(&mut n, vec![coinbase(5, p2pk(&alice)), tx], vec![coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &x)), "TX-8");
    // BLK-6: the same transaction twice.
    let mut tx = mk(vec![Output { value: 1, kind: p2pk(&bob) }], 0);
    sign_slh(&n, &mut tx, 0, &coin, &alice);
    let x = build_unchecked(&mut n, vec![coinbase(5, p2pk(&alice)), tx.clone(), tx.clone()], vec![coin.clone(), coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &x)), "BLK-6");
    // CRYPTO-3 / SIG-2: wrong signature length, and SIG-2 for a P2pkSlh with two signers.
    let mut tx = mk(vec![Output { value: 1, kind: p2pk(&bob) }], 0);
    sign_slh(&n, &mut tx, 0, &coin, &alice);
    if let Witness::Slh { signers } = &mut tx.inputs[0].witness {
        signers[0].signature.pop();
    }
    let x = build_unchecked(&mut n, vec![coinbase(5, p2pk(&alice)), tx], vec![coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &x)), "SIG-2");
    let mut tx = mk(vec![Output { value: 1, kind: p2pk(&bob) }], 0);
    sign_slh(&n, &mut tx, 0, &coin, &alice);
    if let Witness::Slh { signers } = &mut tx.inputs[0].witness {
        signers.push(signers[0].clone());
    }
    let x = build_unchecked(&mut n, vec![coinbase(5, p2pk(&alice)), tx], vec![coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &x)), "SIG-2");
    // A valid spend with the same inputs still connects (the negatives above left no trace).
    let mut tx = mk(vec![Output { value: 1, kind: p2pk(&bob) }], 5);
    sign_slh(&n, &mut tx, 0, &coin, &alice);
    let x = build(&mut n, vec![coinbase(5, p2pk(&alice)), tx], vec![coin]);
    connect(&mut n, x);
}

#[test]
fn migration_limit_blk9() {
    let alice = key(1);
    let bob = key(9);
    let legacy = (
        OutPoint::new([6u8; 32], 0),
        Coin { output: Output { value: 50_000, kind: OutputKind::Legacy { script_pubkey: vec![0x00, 0x14, 0xaa] } }, height: 0, coinbase: false },
    );
    let mut n = net(vec![legacy.clone()]);
    n.params.max_migrations = 0;
    mine_to(&mut n, &alice, 1);
    let mig = Transaction { version: 1, inputs: vec![Input { prevout: legacy.0, witness: Witness::Legacy }], outputs: vec![Output { value: 40_000, kind: p2pk(&bob) }], locktime: 0, proofs: vec![vec![1]] };
    let b = build_unchecked(&mut n, vec![coinbase(2, p2pk(&alice)), mig], vec![legacy.1.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "BLK-9");
}

#[test]
fn encoding_negatives() {
    use bhss_primitives::{Decode, DecodeError, Decoder};
    // ENC-2: bool must be 0 or 1.
    assert_eq!(Decoder::new(&[2]).bool().unwrap_err(), DecodeError::InvalidValue("bool"));
    // ENC-7: a count larger than the remaining bytes is rejected before allocation.
    let mut e = bhss_primitives::Encoder::new();
    e.compact(1 << 20);
    assert_eq!(Vec::<u32>::from_bytes(e.as_slice()).unwrap_err(), DecodeError::TooLarge);
    // SMT-5: sibling count must match the bitmap.
    let mut e = bhss_primitives::Encoder::new();
    e.raw(&[0u8; 32]).compact(1).raw(&[1u8; 32]);
    assert_eq!(SmtProof::from_bytes(e.as_slice()).unwrap_err(), DecodeError::InvalidValue("smt proof sibling count"));
    // Unknown tags.
    assert_eq!(OutputKind::from_bytes(&[0x05]).unwrap_err(), DecodeError::InvalidTag(0x05));
    assert_eq!(Witness::from_bytes(&[0x03]).unwrap_err(), DecodeError::InvalidTag(0x03));
}

/// Known-answer vectors: any change to an encoding or a hash tag changes
/// these and therefore forks the network. Update deliberately.
#[test]
fn golden_vectors() {
    let n = net(vec![]);
    let g = bhss_consensus::genesis::genesis_block(&n.params);
    let v = [
        ("params_hash", bhss_primitives::hash::to_hex(&n.params.hash())),
        ("genesis_hash", bhss_primitives::hash::to_hex(&n.genesis_hash)),
        ("genesis_coinbase_txid", bhss_primitives::hash::to_hex(&g.txs[0].txid())),
        ("empty_smt_root", bhss_primitives::hash::to_hex(&bhss_smt::Smt::new().root())),
        ("smt_key", bhss_primitives::hash::to_hex(&OutPoint::new([1u8; 32], 2).smt_key())),
        ("leaf", bhss_primitives::hash::to_hex(&Coin { output: Output { value: 7, kind: OutputKind::P2pkSlh { pkh: [3u8; 32] } }, height: 9, coinbase: true }.leaf_hash())),
        ("sighash", bhss_primitives::hash::to_hex(&slh_sighash(&[1u8; 32], &[2u8; 32], 3, &[4u8; 32]))),
        ("migration_msg", bhss_primitives::hash::to_hex(&migration_msg(&[1u8; 32], &[2u8; 32], 3, &[4u8; 32]))),
        ("pkh", bhss_primitives::hash::to_hex(&slh_pubkey_hash(&[5u8; 32]))),
    ];
    let expected: &[(&str, &str)] = &GOLDEN;
    let mut bad = Vec::new();
    for (name, got) in &v {
        let want = expected.iter().find(|(k, _)| k == name).map(|(_, v)| *v).unwrap_or("");
        if got != want {
            bad.push(format!("(\"{name}\", \"{got}\"),"));
        }
    }
    assert!(bad.is_empty(), "golden vectors changed:\n{}", bad.join("\n"));
}

const GOLDEN: [(&str, &str); 9] = [
    ("params_hash", "7bdc327e095a74ed313cd867cf7c36a2858990f9ea36d584d643523ab5add149"),
    ("genesis_hash", "67a49e9331c2cc21cda53948427b9acff31a0415ffbf9f3ea772c696853515a1"),
    ("genesis_coinbase_txid", "d2ae8e615e1db13ea5c439c08491f740c3c30554f43ac2554b0290c3f4ff2c1b"),
    ("empty_smt_root", "6155289130893872355eac98042d22aefa2c2e708bea169402760e3b55f9a2dc"),
    ("smt_key", "656d533464f123819041419e9409e0c36a70d5ca4d99c5d1141ce77cd1e0e5ad"),
    ("leaf", "ae6c11cf9b1adc04829a705bc8b7bcfa820774cd9bcc9a3dbf7d4f565b5b048e"),
    ("sighash", "0fe469173377c64230f0dd854f5d7e00c296f0af15157192f025ab93e8c31b56"),
    ("migration_msg", "cd4a3c77b7ab7c1c702bcc6c74196d2637ea805d536c42d2f6bb4b00a30772ae"),
    ("pkh", "8f1aa3c1a9b3df156a6faa1fad2d2edd9eb362159ec3d73cf4091b2b8c36c8e4"),
];

#[test]
fn amount_sums_existing_outpoints_and_absolute_timelocks() {
    let alice = key(1);
    let bob = key(9);
    // AMT-1 on the input sum: two legacy coins that are each within range
    // but not together (a genesis state like this is refused by GEN-2; the
    // rule must hold regardless).
    let big = |i: u8| (OutPoint::new([i; 32], 0), Coin { output: Output { value: MAX_MONEY, kind: OutputKind::Legacy { script_pubkey: vec![0x00, 0x14, i] } }, height: 0, coinbase: false });
    let mut n = net(vec![big(1), big(2)]);
    let mig = Transaction {
        version: 1,
        inputs: vec![Input { prevout: big(1).0, witness: Witness::Legacy }, Input { prevout: big(2).0, witness: Witness::Legacy }],
        outputs: vec![Output { value: 1, kind: p2pk(&bob) }],
        locktime: 0,
        proofs: vec![vec![1], vec![1]],
    };
    let b = build_unchecked(&mut n, vec![coinbase(1, p2pk(&alice)), mig], vec![big(1).1, big(2).1]);
    assert_eq!(rule(try_connect(&mut n, &b)), "AMT-1");
    // AMT-1 on the output sum of one transaction.
    let mig = Transaction {
        version: 1,
        inputs: vec![Input { prevout: big(1).0, witness: Witness::Legacy }],
        outputs: vec![Output { value: MAX_MONEY, kind: p2pk(&bob) }, Output { value: 1, kind: p2pk(&bob) }],
        locktime: 0,
        proofs: vec![vec![1]],
    };
    let b = build_unchecked(&mut n, vec![coinbase(1, p2pk(&alice)), mig], vec![big(1).1]);
    assert_eq!(rule(try_connect(&mut n, &b)), "AMT-1");

    // STATE-4: the genesis state already holds the outpoint the first
    // coinbase is going to create. A stateless verifier sees the same block
    // fail its non-inclusion proof (STATE-2); `try_connect` checks that the
    // two verdicts agree and returns the stateful one.
    let mut cb = coinbase(1, p2pk(&alice));
    cb.outputs[0].value = ChainParams::regtest([0u8; 32]).subsidy(1);
    let squat = (OutPoint::new(cb.txid(), 0), Coin { output: Output { value: 5, kind: OutputKind::Legacy { script_pubkey: vec![0x51] } }, height: 0, coinbase: false });
    let mut n = net(vec![squat]);
    let b = build_unchecked(&mut n, vec![coinbase(1, p2pk(&alice))], vec![]);
    assert_eq!(b.txs[0].txid(), cb.txid());
    assert_eq!(rule(try_connect(&mut n, &b)), "STATE-4");

    // IN-3, absolute height: spendable only from height 6 on.
    let mut n = net(vec![]);
    mine_to(&mut n, &alice, 3);
    let (op, coin) = n.state.coins.iter().find(|(_, c)| c.height == 1).map(|(o, c)| (*o, c.clone())).unwrap();
    let tl = OutputKind::Timelock { abs_height: 6, rel_blocks: 0, inner: Box::new(p2pk(&alice)) };
    let mut lock = Transaction { version: 1, inputs: vec![Input { prevout: op, witness: Witness::Slh { signers: vec![] } }], outputs: vec![Output { value: 1_000, kind: tl.clone() }], locktime: 0, proofs: vec![] };
    sign_slh(&n, &mut lock, 0, &coin, &alice);
    let b = build(&mut n, vec![coinbase(4, p2pk(&alice)), lock], vec![coin]);
    connect(&mut n, b);
    let (tl_op, tl_coin) = first_coin(&n, &tl);
    let mut unlock = Transaction { version: 1, inputs: vec![Input { prevout: tl_op, witness: Witness::Slh { signers: vec![] } }], outputs: vec![Output { value: 900, kind: p2pk(&bob) }], locktime: 0, proofs: vec![] };
    sign_slh(&n, &mut unlock, 0, &tl_coin, &alice);
    let b = build_unchecked(&mut n, vec![coinbase(5, p2pk(&alice)), unlock.clone()], vec![tl_coin.clone()]);
    assert_eq!(rule(try_connect(&mut n, &b)), "IN-3");
    mine_to(&mut n, &alice, 1);
    let b = build(&mut n, vec![coinbase(6, p2pk(&alice)), unlock], vec![tl_coin]);
    connect(&mut n, b);
}

//! Builds a tiny chain in memory and proves blocks with the real guest
//! (dev-mode by default; `--features real-proof-tests` produces a STARK).

use bhss_consensus::{assemble_block, connect_block, FullState, PrevState, ProofBackedState, StateView};
use bhss_legacy::sign as lsign;
use bhss_legacy::MigrationInput;
use bhss_primitives::types::*;
use bhss_primitives::{ChainParams, Decode, Encode, Hash32};
use bhss_prover::*;

fn legacy_key() -> k256::SecretKey {
    lsign::secret_from_bytes(&[7u8; 32]).unwrap()
}

/// Genesis state with one P2WPKH legacy coin.
fn network() -> (ChainParams, Hash32, Vec<(OutPoint, Coin)>) {
    let script = lsign::script_p2wpkh(&lsign::compressed_pubkey(&legacy_key()));
    let coins = vec![(
        OutPoint::new([9u8; 32], 1),
        Coin { output: Output { value: 250_000_000, kind: OutputKind::Legacy { script_pubkey: script } }, height: 0, coinbase: false },
    )];
    let root = bhss_consensus::genesis::genesis_state_root(&coins);
    let mut params = ChainParams::regtest(root);
    params.coinbase_maturity = 2;
    let (genesis_hash, _) = bhss_consensus::genesis::genesis_prev_state(&params);
    (params, genesis_hash, coins)
}

fn seal(params: &ChainParams, genesis_hash: &Hash32, prev: &PrevState, state: &mut FullState, txs: Vec<Transaction>, coins: Vec<Coin>, cfg: &ProverConfig) -> Block {
    let all = txs.clone();
    let mut m = NativeMigrationChecker::new(&all, true);
    let mut block = assemble_block(params, genesis_hash, prev, state, txs, coins, prev.time + 1, &mut m).expect("assemble");
    block.receipt = prove_block(cfg, params, genesis_hash, prev, &block).expect("prove block");
    block
}

fn coinbase(height: u32, payout: OutputKind) -> Transaction {
    Transaction { version: 1, inputs: vec![Input { prevout: OutPoint::coinbase(height), witness: Witness::Coinbase }], outputs: vec![Output { value: 0, kind: payout }], locktime: 0, proofs: vec![] }
}

/// Verify a block exactly as a node would (stateless proof check + receipt).
fn verify_as_node(params: &ChainParams, genesis_hash: &Hash32, prev: &PrevState, block: &Block, allow_fake: bool) -> PrevState {
    let mut st = ProofBackedState::new(prev.state_root, &block.witness.proofs);
    let mut m = NativeMigrationChecker::new(&block.txs, allow_fake);
    let s = connect_block(params, genesis_hash, prev, block, &mut st, &mut m).expect("native validation");
    assert!(st.all_proofs_consumed());
    let journal = expected_block_journal(params, genesis_hash, prev, &block.header);
    assert_eq!((journal.height, journal.root_next), (s.height, s.root_next));
    verify_block_receipt(&block.receipt, &journal, allow_fake).expect("receipt");
    // A tampered journal must not verify.
    let mut bad = journal.clone();
    bad.root_next[0] ^= 1;
    assert!(verify_block_receipt(&block.receipt, &bad, allow_fake).is_err());
    let mut bad = journal.clone();
    bad.genesis_hash[0] ^= 1;
    assert!(verify_block_receipt(&block.receipt, &bad, allow_fake).is_err(), "journal must bind genesis_hash");
    let mut bad = journal.clone();
    bad.prev_time ^= 1;
    assert!(verify_block_receipt(&block.receipt, &bad, allow_fake).is_err(), "journal must bind prev_time");
    PrevState { height: s.height, hash: s.block_hash, state_root: s.root_next, time: block.header.time }
}

fn run_chain(cfg: &ProverConfig, allow_fake: bool) {
    let (params, genesis_hash, coins) = network();
    let mut state = FullState::from_coins(coins.clone());
    let (_, mut prev) = bhss_consensus::genesis::genesis_prev_state(&params);
    let alice = bhss_slhdsa::SecretKey::from_seeds(&[1; 16], &[2; 16], &[3; 16]);
    let bob = bhss_slhdsa::SecretKey::from_seeds(&[4; 16], &[5; 16], &[6; 16]);
    let alice_kind = OutputKind::P2pkSlh { pkh: alice.public_key().hash() };
    let bob_kind = OutputKind::P2pkSlh { pkh: bob.public_key().hash() };

    // Block 1: coinbase only.
    let b1 = seal(&params, &genesis_hash, &prev, &mut state, vec![coinbase(1, alice_kind.clone())], vec![], cfg);
    assert!(!b1.receipt.is_empty());
    prev = verify_as_node(&params, &genesis_hash, &prev, &b1, allow_fake);
    // Block 2: coinbase only (lets block-1 coinbase mature at height 3).
    let b2 = seal(&params, &genesis_hash, &prev, &mut state, vec![coinbase(2, alice_kind.clone())], vec![], cfg);
    prev = verify_as_node(&params, &genesis_hash, &prev, &b2, allow_fake);

    // Block 3: SLH spend alice -> bob, plus a legacy migration.
    let cb1_txid = b1.txs[0].txid();
    let cb1_coin = state.get(&OutPoint::new(cb1_txid, 0)).unwrap().clone();
    let mut spend = Transaction {
        version: 1,
        inputs: vec![Input { prevout: OutPoint::new(cb1_txid, 0), witness: Witness::Slh { signers: vec![] } }],
        outputs: vec![Output { value: 1_000_000, kind: bob_kind.clone() }, Output { value: cb1_coin.output.value - 1_000_000 - 500, kind: alice_kind.clone() }],
        locktime: 0,
        proofs: vec![],
    };
    let msg = slh_sighash(&genesis_hash, &spend.txid(), 0, &cb1_coin.leaf_hash());
    spend.inputs[0].witness = Witness::Slh { signers: vec![SlhSigner { index: 0, pubkey: alice.public_key().0, signature: alice.sign(&msg) }] };

    let (legacy_op, legacy_coin) = coins[0].clone();
    let mut mig = Transaction {
        version: 1,
        inputs: vec![Input { prevout: legacy_op, witness: Witness::Legacy }],
        outputs: vec![Output { value: legacy_coin.output.value - 700, kind: bob_kind.clone() }],
        locktime: 0,
        proofs: vec![],
    };
    let m = migration_msg(&genesis_hash, &mig.txid(), 0, &legacy_coin.leaf_hash());
    let script = match &legacy_coin.output.kind { OutputKind::Legacy { script_pubkey } => script_pubkey.clone(), _ => unreachable!() };
    let input = MigrationInput { msg: m, script_pubkey: script.clone(), auth: lsign::auth_keyhash(&legacy_key(), &m, true) };
    let receipt = prove_migration(cfg, &input).expect("prove migration");
    let journal = MigrationJournal { msg: m, script_hash: MigrationJournal::script_hash_of(&script) };
    verify_migration_receipt(&receipt, &journal, allow_fake).expect("migration receipt");
    mig.proofs = vec![receipt];

    let txs = vec![coinbase(3, alice_kind.clone()), spend, mig];
    let b3 = seal(&params, &genesis_hash, &prev, &mut state, txs, vec![cb1_coin, legacy_coin], cfg);
    let after = verify_as_node(&params, &genesis_hash, &prev, &b3, allow_fake);
    assert_eq!(after.state_root, state.root());
    assert_eq!(state.coins.values().filter(|c| c.output.kind.is_legacy()).count(), 0, "legacy coin migrated");
    assert_eq!(state.coins.values().filter(|c| c.output.kind == bob_kind).map(|c| c.output.value).sum::<u64>(), 1_000_000 + 250_000_000 - 700);

    // Round-trip through the wire encoding.
    let bytes = b3.to_bytes();
    assert_eq!(Block::from_bytes(&bytes).unwrap(), b3);
    let j = block_receipt_journal(&b3.receipt).unwrap();
    assert_eq!(j.height, 3);
    assert_eq!(j.migrate_image_id, migrate_image_id());
}

/// PRF-5 / PRF-6 rejection paths, exercised without any real proof.
#[test]
fn fake_receipt_rejections() {
    use bhss_prover::*;
    let journal = MigrationJournal { msg: [1u8; 32], script_hash: [2u8; 32] }.to_bytes();
    // A fake receipt for the right image: accepted only when allowed.
    let fake = forge_fake_receipt(MIGRATE_ID, &journal).unwrap();
    assert!(verify_receipt(&decode_receipt(&fake).unwrap(), MIGRATE_ID, &journal, true).is_ok());
    let err = verify_receipt(&decode_receipt(&fake).unwrap(), MIGRATE_ID, &journal, false).unwrap_err();
    assert!(err.to_string().contains("PRF-5"), "{err}");
    // Wrong image id with the right journal: rejected even when fakes are allowed.
    let forged = forge_fake_receipt(BLOCK_ID, &journal).unwrap();
    let err = verify_receipt(&decode_receipt(&forged).unwrap(), MIGRATE_ID, &journal, true).unwrap_err();
    assert!(err.to_string().contains("claim mismatch"), "{err}");
    // Journal mismatch.
    let mut other = journal.clone();
    other[0] ^= 1;
    let err = verify_receipt(&decode_receipt(&fake).unwrap(), MIGRATE_ID, &other, true).unwrap_err();
    assert!(err.to_string().contains("journal mismatch"), "{err}");
    assert_eq!(receipt_kind(&fake), ReceiptKind::Fake);
    // PRF-6: a composite receipt is refused by kind, before any of its
    // (here empty) contents are looked at, whether or not fakes are allowed.
    // risc0 does not let other crates construct one, so it is written in its
    // wire form: variant 0, no segments, no assumption receipts, zero
    // verifier parameters, the journal, zero metadata.
    let mut wire = Vec::new();
    wire.extend(0u32.to_le_bytes());
    wire.extend(0u64.to_le_bytes());
    wire.extend(0u64.to_le_bytes());
    wire.extend([0u8; 32]);
    wire.extend((journal.len() as u64).to_le_bytes());
    wire.extend(&journal);
    wire.extend([0u8; 32]);
    let composite = decode_receipt(&wire).expect("composite receipt wire form");
    assert_eq!(receipt_kind(&wire), ReceiptKind::Composite);
    for allow_fake in [true, false] {
        let err = verify_receipt(&composite, MIGRATE_ID, &journal, allow_fake).unwrap_err();
        assert!(err.to_string().contains("PRF-6"), "{err}");
    }
    // Oversized receipts are refused before deserialization (PRF-7).
    assert!(decode_receipt(&vec![0u8; MAX_RECEIPT_LEN + 1]).is_err());
    // Image id byte order agrees with risc0's Digest.
    assert_eq!(block_image_id(), *risc0_zkvm::sha::Digest::from(BLOCK_ID).as_bytes().first_chunk::<32>().unwrap());
    assert_ne!(block_image_id(), [0u8; 32]);
    assert_ne!(migrate_image_id(), block_image_id());
}

#[test]
fn dev_mode_chain() {
    let cfg = ProverConfig { mode: ProveMode::Dev, segment_po2: Some(19) };
    run_chain(&cfg, true);
}

#[test]
fn migration_guest_rejects_wrong_key() {
    let cfg = ProverConfig { mode: ProveMode::Dev, segment_po2: Some(19) };
    let script = lsign::script_p2wpkh(&lsign::compressed_pubkey(&legacy_key()));
    let wrong = lsign::secret_from_bytes(&[8u8; 32]).unwrap();
    let m = [0x42u8; 32];
    let input = MigrationInput { msg: m, script_pubkey: script, auth: lsign::auth_keyhash(&wrong, &m, true) };
    let err = prove_migration(&cfg, &input).unwrap_err();
    assert!(format!("{err:#}").contains("legacy authorization failed"), "{err:#}");
}

/// `make prove`: real STARKs for blocks 1..3 including a composed migration
/// receipt; fake receipts are rejected along the way.
#[cfg(feature = "real-proof-tests")]
#[test]
fn real_block_proof() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let po2 = std::env::var("SEGMENT_PO2").ok().and_then(|v| v.parse().ok()).unwrap_or(19);
    let cfg = ProverConfig { mode: ProveMode::Real, segment_po2: Some(po2) };
    run_chain(&cfg, false);
}

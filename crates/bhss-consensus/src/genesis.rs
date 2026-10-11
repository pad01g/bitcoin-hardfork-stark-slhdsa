//! GEN-1..GEN-4: the genesis block is a pure function of the chain params.

use alloc::vec;
use alloc::vec::Vec;

use bhss_primitives::merkle::merkle_root;
use bhss_primitives::params::hash_meets_target;
use bhss_primitives::types::*;
use bhss_primitives::{ChainParams, Hash32};

use crate::validate::PrevState;

/// GEN-1: coinbase with one zero-value Data output, state root = genesis
/// state root, nonce = the smallest value satisfying POW-1.
pub fn genesis_block(params: &ChainParams) -> Block {
    let coinbase = Transaction {
        version: Transaction::VERSION,
        inputs: vec![Input { prevout: OutPoint::coinbase(0), witness: Witness::Coinbase }],
        outputs: vec![Output { value: 0, kind: OutputKind::Data { data: b"BHSS genesis".to_vec() } }],
        locktime: 0,
        proofs: Vec::new(),
    };
    let mut header = Header {
        version: Header::VERSION,
        prev_hash: [0u8; 32],
        merkle_root: merkle_root(&[coinbase.commitment()]),
        state_root: params.genesis_state_root,
        time: params.genesis_time,
        bits: params.pow_bits,
        nonce: 0,
    };
    let target = params.target();
    while !hash_meets_target(&header.hash(), &target) {
        header.nonce += 1;
    }
    Block { header, txs: vec![coinbase], witness: BlockWitness::default(), receipt: Vec::new() }
}

pub fn genesis_prev_state(params: &ChainParams) -> (Hash32, PrevState) {
    let g = genesis_block(params);
    let hash = g.hash();
    (hash, PrevState { height: 0, hash, state_root: params.genesis_state_root, time: g.header.time })
}

/// GEN-2: `H(0x0C || enc(sorted coins))`, and the SMT root of those coins.
pub fn genesis_state_root(coins: &[(OutPoint, Coin)]) -> Hash32 {
    let mut smt = bhss_smt::Smt::new();
    for (op, coin) in coins {
        smt.insert(op.smt_key(), coin.leaf_hash());
    }
    smt.root()
}

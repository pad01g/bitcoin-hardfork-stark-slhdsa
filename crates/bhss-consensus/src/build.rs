//! Block assembly shared by the miner and the tests: apply the body on a
//! recording [`FullState`], seal the header (BLK-3, HDR-3), search the nonce
//! (POW-1). The receipt (PRF-*) is attached by the caller.

use alloc::vec::Vec;

use bhss_primitives::params::hash_meets_target;
use bhss_primitives::types::*;
use bhss_primitives::{ChainParams, Hash32};

use crate::state::FullState;
use crate::validate::{apply_block_body, body_merkle_root, fail, ConsensusError, MigrationChecker, PrevState, Result};

/// Build the block at `prev.height + 1` from a coinbase template (`txs[0]`,
/// whose first output receives subsidy + fees) and the mempool selection
/// `txs[1..]` spending `coins`. `state` is advanced to the post-block state
/// (and left unspecified if assembly fails; pass a clone to keep the
/// original).
#[allow(clippy::too_many_arguments)]
pub fn assemble_block<M: MigrationChecker>(
    params: &ChainParams,
    genesis_hash: &Hash32,
    prev: &PrevState,
    state: &mut FullState,
    mut txs: Vec<Transaction>,
    coins: Vec<Coin>,
    time: u32,
    migrations: &mut M,
) -> Result<Block> {
    let height = prev.height.checked_add(1).ok_or_else(|| ConsensusError { rule: "HDR-5", detail: "height overflow".into() })?;
    if txs.is_empty() || txs[0].outputs.is_empty() {
        return fail("CB-1", "template needs a coinbase with an output");
    }
    // Fees follow from the selection arithmetically; the body pass below
    // enforces CB-3 so a wrong value can only fail, never mint.
    let in_sum: u64 = coins.iter().map(|c| c.output.value).try_fold(0u64, |a, v| a.checked_add(v)).ok_or_else(|| ConsensusError { rule: "AMT-1", detail: "input sum".into() })?;
    let out_sum: u64 = txs.iter().skip(1).flat_map(|t| t.outputs.iter().map(|o| o.value)).try_fold(0u64, |a, v| a.checked_add(v)).ok_or_else(|| ConsensusError { rule: "AMT-1", detail: "output sum".into() })?;
    let fees = in_sum.checked_sub(out_sum).ok_or_else(|| ConsensusError { rule: "AMT-2", detail: "selection outputs exceed inputs".into() })?;
    txs[0].outputs[0].value = params.subsidy(height).checked_add(fees).ok_or_else(|| ConsensusError { rule: "AMT-1", detail: "subsidy + fees".into() })?;

    let witness_coins = BlockWitness { coins: coins.clone(), proofs: Vec::new() };
    state.start_recording();
    let body = match apply_block_body(params, genesis_hash, height, &txs, &witness_coins, state, migrations) {
        Ok(b) => b,
        Err(e) => {
            state.take_recording();
            return Err(e);
        }
    };
    let proofs = state.take_recording();
    let mut header = Header {
        version: Header::VERSION,
        prev_hash: prev.hash,
        merkle_root: body_merkle_root(&txs),
        state_root: body.root_next,
        time: time.max(prev.time),
        bits: params.pow_bits,
        nonce: 0,
    };
    let target = params.target();
    while !hash_meets_target(&header.hash(), &target) {
        header.nonce = header.nonce.checked_add(1).ok_or_else(|| ConsensusError { rule: "POW-1", detail: "nonce space exhausted".into() })?;
    }
    Ok(Block { header, txs, witness: BlockWitness { coins, proofs }, receipt: Vec::new() })
}

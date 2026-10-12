//! Block assembly, PoW search and proof generation (the block producer role).

use anyhow::{anyhow, Result};
use bhss_consensus::{assemble_block, FullState, PrevState};
use bhss_primitives::types::*;
use bhss_primitives::{ChainParams, Hash32};
use bhss_prover::{NativeMigrationChecker, ProverConfig};

use crate::chain::{MempoolEntry, COINBASE_RESERVE_BYTES};

/// Everything needed to seal a block, captured under the chain lock.
pub struct Template {
    pub params: ChainParams,
    pub genesis_hash: Hash32,
    pub prev: PrevState,
    pub txs: Vec<Transaction>,
    pub coins: Vec<Coin>,
    /// Clone of the UTXO set at `prev` (records proofs while applying).
    pub state: FullState,
    pub time: u32,
}

/// Choose mempool transactions that fit the block limits (BLK-7..BLK-9), in
/// mempool order. The coinbase gets the same fixed reserve the mempool uses
/// at admission, so a transaction that was admitted always fits an empty
/// block.
pub fn select_txs(params: &ChainParams, mempool: &[MempoolEntry]) -> (Vec<Transaction>, Vec<Coin>) {
    let mut txs = Vec::new();
    let mut coins = Vec::new();
    let mut size = COINBASE_RESERVE_BYTES;
    let mut sigs = 0u32;
    let mut migs = 0u32;
    let in_mempool: std::collections::HashSet<Hash32> = mempool.iter().map(|e| e.txid).collect();
    let mut included: std::collections::HashSet<Hash32> = std::collections::HashSet::new();
    for e in mempool {
        let s = e.tx.committed_size();
        let tx_sigs: u32 = e.tx.inputs.iter().map(|i| match &i.witness { Witness::Slh { signers } => signers.len() as u32, _ => 0 }).sum();
        let tx_migs = e.tx.proofs.len() as u32;
        if size + s > params.max_block_tx_bytes as usize || sigs + tx_sigs > params.max_sig_checks || migs + tx_migs > params.max_migrations {
            continue;
        }
        // A child of a mempool transaction that was skipped cannot go in.
        if e.tx.inputs.iter().any(|i| in_mempool.contains(&i.prevout.txid) && !included.contains(&i.prevout.txid)) {
            continue;
        }
        included.insert(e.txid);
        size += s;
        sigs += tx_sigs;
        migs += tx_migs;
        txs.push(e.tx.clone());
        coins.extend(e.coins.iter().cloned());
    }
    (txs, coins)
}

pub fn coinbase_tx(height: u32, value: u64, payout: OutputKind) -> Transaction {
    Transaction {
        version: Transaction::VERSION,
        inputs: vec![Input { prevout: OutPoint::coinbase(height), witness: Witness::Coinbase }],
        outputs: vec![Output { value, kind: payout }],
        locktime: 0,
        proofs: Vec::new(),
    }
}

/// Assemble the block (body, header, nonce) and prove it. `payout` receives
/// subsidy + fees.
pub fn seal_and_prove(mut t: Template, payout: OutputKind, prover: &ProverConfig) -> Result<Block> {
    let height = t.prev.height + 1;
    let mut txs = vec![coinbase_tx(height, 0, payout)];
    txs.append(&mut t.txs);
    // Receipts are looked up by transaction index, so the checker sees the
    // same list the block will carry.
    let for_receipts = txs.clone();
    let mut migrations = NativeMigrationChecker::new(&for_receipts, !t.params.require_real_proofs);
    let mut block = assemble_block(&t.params, &t.genesis_hash, &t.prev, &mut t.state, txs, t.coins, t.time, &mut migrations)
        .map_err(|e| anyhow!("template invalid: {e}"))?;
    let started = std::time::Instant::now();
    block.receipt = bhss_prover::prove_block(prover, &t.params, &t.genesis_hash, &t.prev, &block)?;
    tracing::info!(height, secs = started.elapsed().as_secs_f64(), receipt_bytes = block.receipt.len(), mode = ?prover.mode, "block proof ready");
    Ok(block)
}

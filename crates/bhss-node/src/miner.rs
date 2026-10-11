//! Block assembly, PoW search and proof generation (the block producer role).

use anyhow::{anyhow, Result};
use bhss_consensus::{apply_block_body, FullState, PrevState};
use bhss_primitives::params::hash_meets_target;
use bhss_primitives::types::*;
use bhss_primitives::{ChainParams, Hash32};
use bhss_prover::{NativeMigrationChecker, ProverConfig};

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

/// Choose mempool transactions that fit the block limits (BLK-7..BLK-9).
pub fn select_txs(params: &ChainParams, coinbase_size: usize, mempool: &[(Transaction, Vec<Coin>)]) -> (Vec<Transaction>, Vec<Coin>) {
    let mut txs = Vec::new();
    let mut coins = Vec::new();
    let mut size = coinbase_size + 9;
    let mut sigs = 0u32;
    let mut migs = 0u32;
    for (tx, tx_coins) in mempool {
        let s = tx.committed_size();
        let tx_sigs: u32 = tx.inputs.iter().map(|i| match &i.witness { Witness::Slh { signers } => signers.len() as u32, _ => 0 }).sum();
        let tx_migs = tx.proofs.len() as u32;
        if size + s > params.max_block_tx_bytes as usize || sigs + tx_sigs > params.max_sig_checks || migs + tx_migs > params.max_migrations {
            continue;
        }
        size += s;
        sigs += tx_sigs;
        migs += tx_migs;
        txs.push(tx.clone());
        coins.extend(tx_coins.iter().cloned());
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

/// Apply the body on the recording state, seal the header, search the nonce,
/// then prove. `payout` receives subsidy + fees.
pub fn seal_and_prove(mut t: Template, payout: OutputKind, prover: &ProverConfig) -> Result<Block> {
    let height = t.prev.height + 1;
    // First pass with a placeholder coinbase value to learn the fees.
    let mut txs = vec![coinbase_tx(height, 0, payout.clone())];
    txs.extend(t.txs.iter().cloned());
    let witness_coins = BlockWitness { coins: t.coins.clone(), proofs: Vec::new() };
    let allow_fake = !t.params.require_real_proofs;
    let fees = {
        let mut probe = t.state.clone();
        let mut m = NativeMigrationChecker::new(&txs, allow_fake);
        apply_block_body(&t.params, &t.genesis_hash, height, &txs, &witness_coins, &mut probe, &mut m)
            .map_err(|e| anyhow!("template invalid: {e}"))?
            .fees
    };
    txs[0].outputs[0].value = t.params.subsidy(height) + fees;

    t.state.start_recording();
    let mut m = NativeMigrationChecker::new(&txs, allow_fake);
    let body = apply_block_body(&t.params, &t.genesis_hash, height, &txs, &witness_coins, &mut t.state, &mut m)
        .map_err(|e| anyhow!("template invalid: {e}"))?;
    let proofs = t.state.take_recording();

    let mut header = Header {
        version: Header::VERSION,
        prev_hash: t.prev.hash,
        merkle_root: bhss_consensus::body_merkle_root(&txs),
        state_root: body.root_next,
        time: t.time.max(t.prev.time),
        bits: t.params.pow_bits,
        nonce: 0,
    };
    let target = t.params.target();
    while !hash_meets_target(&header.hash(), &target) {
        header.nonce = header.nonce.checked_add(1).ok_or_else(|| anyhow!("nonce space exhausted"))?;
    }
    let mut block = Block { header, txs, witness: BlockWitness { coins: t.coins, proofs }, receipt: Vec::new() };
    let started = std::time::Instant::now();
    block.receipt = bhss_prover::prove_block(prover, &t.params, &t.genesis_hash, &t.prev, &block)?;
    tracing::info!(height, secs = started.elapsed().as_secs_f64(), receipt_bytes = block.receipt.len(), mode = ?prover.mode, "block proof ready");
    Ok(block)
}

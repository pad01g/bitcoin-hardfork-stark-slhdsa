//! Block and transaction validation (SPEC §9, §10, §12).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use bhss_primitives::merkle::merkle_root;
use bhss_primitives::params::hash_meets_target;
use bhss_primitives::types::*;
use bhss_primitives::{ChainParams, Hash32};

use crate::state::{StateError, StateView};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusError {
    /// Rule ID from docs/SPEC.md, e.g. "TX-3".
    pub rule: &'static str,
    pub detail: String,
}

impl core::fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.rule, self.detail)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConsensusError {}

pub type Result<T> = core::result::Result<T, ConsensusError>;

fn fail<T>(rule: &'static str, detail: impl Into<String>) -> Result<T> {
    Err(ConsensusError { rule, detail: detail.into() })
}

/// What the validator must know about the previous block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrevState {
    pub height: u32,
    pub hash: Hash32,
    pub state_root: Hash32,
    pub time: u32,
}

impl bhss_primitives::Encode for PrevState {
    fn encode(&self, e: &mut bhss_primitives::Encoder) {
        e.u32(self.height).raw(&self.hash).raw(&self.state_root).u32(self.time);
    }
}
impl bhss_primitives::Decode for PrevState {
    fn decode(d: &mut bhss_primitives::Decoder<'_>) -> core::result::Result<Self, bhss_primitives::DecodeError> {
        Ok(Self { height: d.u32()?, hash: d.array()?, state_root: d.array()?, time: d.u32()? })
    }
}

/// Verifier of migration receipts (MIG-2). In the guest this is
/// `env::verify`; natively it is a RISC Zero receipt verification.
pub trait MigrationChecker {
    fn check(&mut self, tx_index: usize, input_index: usize, journal: &MigrationJournal) -> bool;
}

/// Rejects every migration; useful where legacy coins cannot occur.
pub struct NoMigrations;
impl MigrationChecker for NoMigrations {
    fn check(&mut self, _: usize, _: usize, _: &MigrationJournal) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockSummary {
    pub height: u32,
    pub block_hash: Hash32,
    pub root_prev: Hash32,
    pub root_next: Hash32,
    pub fees: u64,
    pub sig_checks: u32,
    pub migrations: u32,
}

/// Per-block context shared by all transaction checks.
pub struct TxContext<'a> {
    pub params: &'a ChainParams,
    pub genesis_hash: &'a Hash32,
    pub height: u32,
}

/// Validate `block` on top of `prev` and apply it to `state`.
///
/// `block.receipt` is ignored here: the STARK itself is checked by the caller
/// (PRF-3) and never by the guest.
pub fn connect_block<S: StateView, M: MigrationChecker>(
    params: &ChainParams,
    genesis_hash: &Hash32,
    prev: &PrevState,
    block: &Block,
    state: &mut S,
    migrations: &mut M,
) -> Result<BlockSummary> {
    let height = prev.height.checked_add(1).ok_or_else(|| ConsensusError { rule: "HDR-5", detail: "height overflow".into() })?;
    let h = &block.header;

    // ---- header (HDR-*, POW-*) ----
    if h.version != Header::VERSION {
        return fail("HDR-4", format!("version {}", h.version));
    }
    if h.prev_hash != prev.hash {
        return fail("HDR-5", "prev_hash does not match parent");
    }
    if h.bits != params.pow_bits {
        return fail("HDR-6", format!("bits {:#x}", h.bits));
    }
    if h.time < prev.time {
        return fail("HDR-7", "time decreases");
    }
    let block_hash = h.hash();
    if !hash_meets_target(&block_hash, &params.target()) {
        return fail("POW-1", "hash above target");
    }
    if h.merkle_root != body_merkle_root(&block.txs) {
        return fail("BLK-3", "merkle root mismatch");
    }

    let body = apply_block_body(params, genesis_hash, height, &block.txs, &block.witness, state, migrations)?;

    // ---- header state root (HDR-3) ----
    if body.root_next != h.state_root {
        return fail("HDR-3", "state_root does not match post-state");
    }

    Ok(BlockSummary {
        height,
        block_hash,
        root_prev: body.root_prev,
        root_next: body.root_next,
        fees: body.fees,
        sig_checks: body.sig_checks,
        migrations: body.migrations,
    })
}

/// BLK-3: Merkle root over `tx_commit` of every transaction.
pub fn body_merkle_root(txs: &[Transaction]) -> Hash32 {
    let commitments: Vec<Hash32> = txs.iter().map(|t| t.commitment()).collect();
    merkle_root(&commitments)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyResult {
    pub root_prev: Hash32,
    pub root_next: Hash32,
    pub fees: u64,
    pub sig_checks: u32,
    pub migrations: u32,
}

/// Everything in a block below the header: structure (BLK-*), every
/// transaction (TX-*, IN-*, SIG-*, MIG-*, AMT-*), the coinbase (CB-*) and the
/// state transition (STATE-*). Block builders call this on a recording state
/// to learn `root_next` and the witness proofs before sealing the header.
pub fn apply_block_body<S: StateView, M: MigrationChecker>(
    params: &ChainParams,
    genesis_hash: &Hash32,
    height: u32,
    txs: &[Transaction],
    witness: &BlockWitness,
    state: &mut S,
    migrations: &mut M,
) -> Result<BodyResult> {
    // ---- block structure (BLK-*) ----
    if txs.is_empty() {
        return fail("BLK-4", "no transactions");
    }
    if !txs[0].is_coinbase() {
        return fail("BLK-5", "first tx is not coinbase");
    }
    for (i, tx) in txs.iter().enumerate().skip(1) {
        if tx.is_coinbase() || tx.inputs.iter().any(|i| matches!(i.witness, Witness::Coinbase)) {
            return fail("BLK-5", format!("tx {i} has a coinbase input"));
        }
    }
    let txids: Vec<Hash32> = txs.iter().map(|t| t.txid()).collect();
    for i in 0..txids.len() {
        for j in 0..i {
            if txids[i] == txids[j] {
                return fail("BLK-6", format!("duplicate txid at {j} and {i}"));
            }
        }
    }
    let size = txs.iter().map(|t| t.committed_size()).sum::<usize>() + compact_len(txs.len());
    if size > params.max_block_tx_bytes as usize {
        return fail("BLK-7", format!("{size} bytes > max {}", params.max_block_tx_bytes));
    }
    let n_inputs: usize = txs.iter().skip(1).map(|t| t.inputs.len()).sum();
    if witness.coins.len() != n_inputs {
        return fail("BLK-10", format!("witness has {} coins for {n_inputs} inputs", witness.coins.len()));
    }

    // ---- transactions ----
    let root_prev = state.root();
    let ctx = TxContext { params, genesis_hash, height };
    let mut fees: u64 = 0;
    let mut sig_checks: u32 = 0;
    let mut n_migrations: u32 = 0;
    let mut coin_cursor = 0usize;

    for (tx_index, tx) in txs.iter().enumerate() {
        let txid = txids[tx_index];
        if tx_index == 0 {
            check_coinbase_structure(tx, height)?;
            // Outputs are created after fees are known; validated below.
            continue;
        }
        let coins = &witness.coins[coin_cursor..coin_cursor + tx.inputs.len()];
        coin_cursor += tx.inputs.len();
        let r = apply_tx(&ctx, tx, &txid, tx_index, coins, state, migrations)?;
        fees = fees.checked_add(r.fee).ok_or_else(|| ConsensusError { rule: "AMT-1", detail: "fee overflow".into() })?;
        sig_checks += r.sig_checks;
        n_migrations += r.migrations;
        if sig_checks > params.max_sig_checks {
            return fail("BLK-8", format!("{sig_checks} signature checks > {}", params.max_sig_checks));
        }
        if n_migrations > params.max_migrations {
            return fail("BLK-9", format!("{n_migrations} migrations > {}", params.max_migrations));
        }
    }

    // ---- coinbase outputs (CB-*) ----
    let cb = &txs[0];
    let out_sum = output_sum(cb, "CB-3")?;
    let allowed = params
        .subsidy(height)
        .checked_add(fees)
        .ok_or_else(|| ConsensusError { rule: "CB-3", detail: "subsidy overflow".into() })?;
    if out_sum > allowed {
        return fail("CB-3", format!("coinbase pays {out_sum} > {allowed}"));
    }
    create_outputs(cb, &txids[0], height, true, state)?;

    Ok(BodyResult { root_prev, root_next: state.root(), fees, sig_checks, migrations: n_migrations })
}

fn check_coinbase_structure(tx: &Transaction, height: u32) -> Result<()> {
    if tx.version != Transaction::VERSION {
        return fail("TX-1", "coinbase version");
    }
    if tx.inputs.len() != 1 || !matches!(tx.inputs[0].witness, Witness::Coinbase) {
        return fail("CB-1", "coinbase must have exactly one Coinbase input");
    }
    if tx.inputs[0].prevout != OutPoint::coinbase(height) {
        return fail("CB-2", "coinbase prevout must be (0, height)");
    }
    if tx.outputs.is_empty() {
        return fail("TX-1", "coinbase without outputs");
    }
    if !tx.proofs.is_empty() {
        return fail("TX-9", "coinbase carries proofs");
    }
    if tx.locktime != 0 {
        return fail("TX-8", "coinbase locktime");
    }
    check_outputs_well_formed(tx)?;
    Ok(())
}

fn check_outputs_well_formed(tx: &Transaction) -> Result<()> {
    for (i, o) in tx.outputs.iter().enumerate() {
        if !o.kind.is_well_formed() {
            return fail("OUT-2", format!("output {i} malformed"));
        }
        if o.kind.is_legacy() {
            return fail("OUT-6", format!("output {i} creates a Legacy output"));
        }
        if o.kind.is_data() && o.value != 0 {
            return fail("OUT-5", format!("output {i} Data with value"));
        }
        if o.value > MAX_MONEY {
            return fail("AMT-1", format!("output {i} value"));
        }
    }
    Ok(())
}

fn output_sum(tx: &Transaction, rule: &'static str) -> Result<u64> {
    let mut sum: u64 = 0;
    for o in &tx.outputs {
        sum = sum.checked_add(o.value).ok_or_else(|| ConsensusError { rule, detail: "output sum overflow".into() })?;
    }
    if sum > MAX_MONEY {
        return fail(rule, "output sum > MAX_MONEY");
    }
    Ok(sum)
}

fn create_outputs<S: StateView>(tx: &Transaction, txid: &Hash32, height: u32, coinbase: bool, state: &mut S) -> Result<()> {
    for (vout, o) in tx.outputs.iter().enumerate() {
        if o.kind.is_data() {
            continue; // OUT-5: never enters the state
        }
        let op = OutPoint::new(*txid, vout as u32);
        let coin = Coin { output: o.clone(), height, coinbase };
        match state.create(&op, &coin) {
            Ok(()) => {}
            Err(StateError::AlreadyExists) => return fail("STATE-4", format!("outpoint {vout} already exists")),
            Err(e) => return fail("STATE-2", format!("{e:?}")),
        }
    }
    Ok(())
}

pub struct TxResult {
    pub fee: u64,
    pub sig_checks: u32,
    pub migrations: u32,
}

/// Validate a non-coinbase transaction against `coins` (one per input) and
/// apply it to `state` (TX-*, IN-*, SIG-*, MIG-*, AMT-1, STATE-1).
pub fn apply_tx<S: StateView, M: MigrationChecker>(
    ctx: &TxContext<'_>,
    tx: &Transaction,
    txid: &Hash32,
    tx_index: usize,
    coins: &[Coin],
    state: &mut S,
    migrations: &mut M,
) -> Result<TxResult> {
    if tx.version != Transaction::VERSION {
        return fail("TX-1", format!("version {}", tx.version));
    }
    if tx.inputs.is_empty() || tx.outputs.is_empty() {
        return fail("TX-1", "empty inputs or outputs");
    }
    if coins.len() != tx.inputs.len() {
        return fail("BLK-10", "coin count");
    }
    for i in 0..tx.inputs.len() {
        for j in 0..i {
            if tx.inputs[i].prevout == tx.inputs[j].prevout {
                return fail("TX-6", format!("duplicate prevout at inputs {j} and {i}"));
            }
        }
    }
    check_outputs_well_formed(tx)?;
    if tx.locktime != 0 && ctx.height < tx.locktime {
        return fail("TX-8", format!("locktime {} > height {}", tx.locktime, ctx.height));
    }
    let n_legacy = coins.iter().filter(|c| c.output.kind.is_legacy()).count();
    if n_legacy > 0 {
        // MIG-1: a migration spends only Legacy coins and creates only SLH outputs.
        if n_legacy != coins.len() {
            return fail("MIG-1", "mixes Legacy and SLH inputs");
        }
        if tx.outputs.iter().any(|o| o.kind.slh_condition().is_none()) {
            return fail("MIG-1", "migration output must be an SLH condition");
        }
    }
    if tx.proofs.len() != n_legacy {
        return fail("TX-9", format!("{} proofs for {n_legacy} legacy inputs", tx.proofs.len()));
    }

    let mut in_sum: u64 = 0;
    let mut sig_checks: u32 = 0;
    for (index, (input, coin)) in tx.inputs.iter().zip(coins).enumerate() {
        // IN-2 maturity
        if coin.coinbase && ctx.height < coin.height.saturating_add(ctx.params.coinbase_maturity) {
            return fail("IN-2", format!("input {index} spends immature coinbase"));
        }
        // IN-3 timelocks
        if let OutputKind::Timelock { abs_height, rel_blocks, .. } = &coin.output.kind {
            if ctx.height < *abs_height {
                return fail("IN-3", format!("input {index} absolute timelock"));
            }
            if ctx.height < coin.height.saturating_add(*rel_blocks) {
                return fail("IN-3", format!("input {index} relative timelock"));
            }
        }
        let leaf = coin.leaf_hash();
        match (&input.witness, &coin.output.kind) {
            (Witness::Slh { signers }, kind) if kind.slh_condition().is_some() => {
                let cond = kind.slh_condition().unwrap();
                let msg = slh_sighash(ctx.genesis_hash, txid, index as u32, &leaf);
                sig_checks += check_slh_signers(cond, signers, &msg, index)?;
            }
            (Witness::Legacy, OutputKind::Legacy { script_pubkey }) => {
                let msg = migration_msg(ctx.genesis_hash, txid, index as u32, &leaf);
                let journal = MigrationJournal { msg, script_hash: MigrationJournal::script_hash_of(script_pubkey) };
                if !migrations.check(tx_index, index, &journal) {
                    return fail("MIG-2", format!("input {index} migration proof rejected"));
                }
            }
            (Witness::Coinbase, _) => return fail("IN-1", format!("input {index} coinbase witness")),
            _ => return fail("IN-1", format!("input {index} witness does not match coin")),
        }
        in_sum = in_sum.checked_add(coin.output.value).ok_or_else(|| ConsensusError { rule: "AMT-1", detail: "input overflow".into() })?;
        match state.spend(&input.prevout, coin) {
            Ok(()) => {}
            Err(StateError::MissingOrMismatch) => return fail("STATE-3", format!("input {index} not in UTXO set")),
            Err(e) => return fail("STATE-2", format!("{e:?}")),
        }
    }
    let out_sum = output_sum(tx, "AMT-1")?;
    if in_sum < out_sum {
        return fail("AMT-2", format!("inputs {in_sum} < outputs {out_sum}"));
    }
    create_outputs(tx, txid, ctx.height, false, state)?;
    Ok(TxResult { fee: in_sum - out_sum, sig_checks, migrations: n_legacy as u32 })
}

/// SIG-2 / SIG-3. Returns the number of signatures verified.
fn check_slh_signers(cond: &OutputKind, signers: &[SlhSigner], msg: &Hash32, index: usize) -> Result<u32> {
    let (k, pkhs): (usize, &[Hash32]) = match cond {
        OutputKind::P2pkSlh { pkh } => (1, core::slice::from_ref(pkh)),
        OutputKind::MultisigSlh { k, pkhs } => (*k as usize, pkhs.as_slice()),
        _ => return fail("IN-1", "not an SLH condition"),
    };
    if signers.len() != k {
        return fail("SIG-3", format!("input {index}: {} signers, need {k}", signers.len()));
    }
    let mut last: Option<u8> = None;
    for s in signers {
        if let Some(l) = last {
            if s.index <= l {
                return fail("SIG-3", format!("input {index}: signer indices not strictly increasing"));
            }
        }
        last = Some(s.index);
        let pkh = pkhs.get(s.index as usize).ok_or_else(|| ConsensusError { rule: "SIG-3", detail: format!("input {index}: signer index out of range") })?;
        if slh_pubkey_hash(&s.pubkey) != *pkh {
            return fail("SIG-2", format!("input {index}: pubkey hash mismatch"));
        }
        if !bhss_slhdsa::verify(&s.pubkey, msg, &s.signature) {
            return fail("SIG-2", format!("input {index}: invalid SLH-DSA signature"));
        }
    }
    Ok(signers.len() as u32)
}

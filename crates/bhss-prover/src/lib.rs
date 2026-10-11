//! PRF-1..PRF-5: producing and checking the STARK receipts that BHSS
//! consensus requires.
//!
//! Two proving modes exist:
//! * `Real` — `default_prover()` with succinct receipts (STARK, ~200 KB).
//! * `Dev`  — execute the guest only and wrap the journal in a RISC Zero
//!   *fake* receipt. Chains with `require_real_proofs = false` accept these
//!   (PRF-5); they prove nothing and exist for fast regtest iteration.

use anyhow::{anyhow, bail, Context, Result};
use bhss_consensus::{MigrationChecker, PrevState};
use bhss_legacy::MigrationInput;
use bhss_primitives::types::{Block, BlockJournal, MigrationJournal, Transaction};
use bhss_primitives::{ChainParams, Decode, Encode, Hash32};
use risc0_zkvm::sha::{Digest, Digestible};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ExecutorEnvBuilder, InnerReceipt, ProverOpts, Receipt, ReceiptClaim, FakeReceipt};

pub use bhss_methods::{BLOCK_ELF, BLOCK_ID, MIGRATE_ELF, MIGRATE_ID};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProveMode {
    Dev,
    Real,
}

impl std::str::FromStr for ProveMode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "dev" => Ok(ProveMode::Dev),
            "real" => Ok(ProveMode::Real),
            _ => bail!("prove mode must be 'dev' or 'real'"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProverConfig {
    pub mode: ProveMode,
    /// Segment size as a power of two (smaller = less RAM, more segments).
    pub segment_po2: Option<u32>,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self { mode: ProveMode::Dev, segment_po2: Some(20) }
    }
}

pub fn block_image_id() -> Hash32 {
    *Digest::from(BLOCK_ID).as_bytes().first_chunk::<32>().unwrap()
}

pub fn migrate_image_id() -> Hash32 {
    *Digest::from(MIGRATE_ID).as_bytes().first_chunk::<32>().unwrap()
}

pub fn encode_receipt(r: &Receipt) -> Result<Vec<u8>> {
    Ok(bincode::serialize(r)?)
}

pub fn decode_receipt(bytes: &[u8]) -> Result<Receipt> {
    Ok(bincode::deserialize(bytes)?)
}

pub fn is_fake(r: &Receipt) -> bool {
    matches!(r.inner, InnerReceipt::Fake(_))
}

/// PRF-3 / MIG-2: check a receipt against an image id and the exact journal
/// bytes the verifier expects. Fake receipts pass only if `allow_fake`.
pub fn verify_receipt(r: &Receipt, image_id: [u32; 8], expected_journal: &[u8], allow_fake: bool) -> Result<()> {
    if r.journal.bytes != expected_journal {
        bail!("journal mismatch");
    }
    if is_fake(r) {
        if !allow_fake {
            bail!("fake (dev-mode) receipt rejected: chain requires real proofs");
        }
        let claim = r.claim().context("fake receipt claim")?;
        let expected = ReceiptClaim::ok(image_id, expected_journal.to_vec());
        if claim.digest() != expected.digest() {
            bail!("fake receipt claim mismatch");
        }
        return Ok(());
    }
    r.verify(image_id).map_err(|e| anyhow!("receipt verification failed: {e}"))
}

fn prove(cfg: &ProverConfig, mut env: ExecutorEnvBuilder<'_>, elf: &[u8], image_id: [u32; 8]) -> Result<Receipt> {
    if let Some(po2) = cfg.segment_po2 {
        env.segment_limit_po2(po2);
    }
    let env: ExecutorEnv<'_> = env.build()?;
    match cfg.mode {
        ProveMode::Dev => {
            let info = default_executor().execute(env, elf).map_err(|e| anyhow!("guest execution failed: {e:#}"))?;
            let journal = info.journal.bytes.clone();
            let claim = ReceiptClaim::ok(image_id, journal.clone());
            let cycles: u64 = info.segments.iter().map(|s| s.cycles as u64).sum();
            tracing::info!(cycles, "dev-mode execution complete");
            Ok(Receipt::new(InnerReceipt::Fake(FakeReceipt::new(claim)), journal))
        }
        ProveMode::Real => {
            if std::env::var("RISC0_DEV_MODE").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false) {
                bail!("RISC0_DEV_MODE is set; refusing to produce a 'real' proof");
            }
            let started = std::time::Instant::now();
            let info = default_prover()
                .prove_with_opts(env, elf, &ProverOpts::succinct())
                .map_err(|e| anyhow!("proving failed: {e:#}"))?;
            tracing::info!(cycles = info.stats.total_cycles, secs = started.elapsed().as_secs_f64(), "real proof complete");
            info.receipt.verify(image_id)?;
            Ok(info.receipt)
        }
    }
}

// ----------------------------------------------------------------------------
// Migration proofs
// ----------------------------------------------------------------------------

pub fn prove_migration(cfg: &ProverConfig, input: &MigrationInput) -> Result<Vec<u8>> {
    let mut env = ExecutorEnv::builder();
    env.write_frame(&input.to_bytes());
    let receipt = prove(cfg, env, MIGRATE_ELF, MIGRATE_ID)?;
    encode_receipt(&receipt)
}

pub fn verify_migration_receipt(bytes: &[u8], journal: &MigrationJournal, allow_fake: bool) -> Result<Receipt> {
    let r = decode_receipt(bytes)?;
    verify_receipt(&r, MIGRATE_ID, &journal.to_bytes(), allow_fake)?;
    Ok(r)
}

/// Native implementation of [`MigrationChecker`]: looks up the receipt in
/// `Transaction::proofs` and verifies it (D3: nodes verify migration receipts
/// themselves, independently of the block receipt).
pub struct NativeMigrationChecker<'a> {
    pub txs: &'a [Transaction],
    pub allow_fake: bool,
    pub verified: Vec<Receipt>,
}

impl<'a> NativeMigrationChecker<'a> {
    pub fn new(txs: &'a [Transaction], allow_fake: bool) -> Self {
        Self { txs, allow_fake, verified: Vec::new() }
    }
}

impl MigrationChecker for NativeMigrationChecker<'_> {
    fn check(&mut self, tx_index: usize, input_index: usize, journal: &MigrationJournal) -> bool {
        let Some(tx) = self.txs.get(tx_index) else { return false };
        let Some(bytes) = tx.proofs.get(input_index) else { return false };
        match verify_migration_receipt(bytes, journal, self.allow_fake) {
            Ok(r) => {
                self.verified.push(r);
                true
            }
            Err(e) => {
                tracing::warn!(tx_index, input_index, "migration receipt rejected: {e:#}");
                false
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Block proofs
// ----------------------------------------------------------------------------

/// Expected journal for `block` (PRF-2); the caller supplies the roots it
/// computed natively.
pub fn expected_block_journal(params: &ChainParams, height: u32, block_hash: Hash32, root_prev: Hash32, root_next: Hash32) -> BlockJournal {
    BlockJournal { params_hash: params.hash(), height, block_hash, root_prev, root_next, migrate_image_id: migrate_image_id() }
}

/// Produce the receipt for `block` (whose `receipt` field is ignored). The
/// migration receipts inside `block.txs[*].proofs` become assumptions.
pub fn prove_block(cfg: &ProverConfig, params: &ChainParams, genesis_hash: &Hash32, prev: &PrevState, block: &Block) -> Result<Vec<u8>> {
    let mut stripped = block.clone();
    stripped.receipt.clear();
    let mut env = ExecutorEnv::builder();
    for tx in &block.txs {
        for p in &tx.proofs {
            let r = decode_receipt(p).context("migration receipt in tx.proofs")?;
            env.add_assumption(r);
        }
    }
    env.write_frame(&params.to_bytes());
    env.write_frame(genesis_hash);
    env.write_frame(&prev.to_bytes());
    env.write_frame(&stripped.to_bytes());
    env.write_frame(&migrate_image_id());
    let receipt = prove(cfg, env, BLOCK_ELF, BLOCK_ID)?;
    encode_receipt(&receipt)
}

pub fn verify_block_receipt(bytes: &[u8], journal: &BlockJournal, allow_fake: bool) -> Result<()> {
    let r = decode_receipt(bytes).context("block receipt")?;
    verify_receipt(&r, BLOCK_ID, &journal.to_bytes(), allow_fake)
}

/// Decode the journal a block receipt commits to (for diagnostics).
pub fn block_receipt_journal(bytes: &[u8]) -> Result<BlockJournal> {
    let r = decode_receipt(bytes)?;
    BlockJournal::from_bytes(&r.journal.bytes).map_err(|e| anyhow!("journal decode: {e}"))
}

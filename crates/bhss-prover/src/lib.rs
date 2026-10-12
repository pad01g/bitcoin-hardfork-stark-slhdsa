//! PRF-1..PRF-7: producing and checking the STARK receipts that BHSS
//! consensus requires.
//!
//! Two proving modes exist:
//! * `Real` — `default_prover()` with succinct receipts (STARK, ~250 KB).
//! * `Dev`  — execute the guest only and wrap the journal in a RISC Zero
//!   *fake* receipt. Chains with `require_real_proofs = false` accept these
//!   (PRF-5); they prove nothing and exist for fast regtest iteration.

use anyhow::{anyhow, bail, Context, Result};
use bhss_consensus::{MigrationChecker, PrevState};
use bhss_legacy::MigrationInput;
use bhss_primitives::types::{Block, BlockJournal, MigrationJournal, Transaction};
use bhss_primitives::{ChainParams, Decode, Encode, Hash32};
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ExecutorEnvBuilder, FakeReceipt, InnerReceipt, ProverOpts, Receipt, ReceiptClaim, VerifierContext};

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
    bhss_methods::block_image_id()
}

pub fn migrate_image_id() -> Hash32 {
    bhss_methods::migrate_image_id()
}

/// Verifier context that never honours `RISC0_DEV_MODE` (PRF-5: fake
/// receipts are accepted only through `allow_fake`, which comes from the
/// chain parameters, never from the environment).
fn strict_context() -> VerifierContext {
    VerifierContext::default().with_dev_mode(false)
}

pub fn encode_receipt(r: &Receipt) -> Result<Vec<u8>> {
    Ok(bincode::serialize(r)?)
}

/// PRF-7: receipts larger than `MAX_RECEIPT_LEN` are rejected before
/// deserialization (bincode would otherwise allocate whatever the length
/// prefixes claim).
pub fn decode_receipt(bytes: &[u8]) -> Result<Receipt> {
    if bytes.len() > bhss_primitives::types::MAX_RECEIPT_LEN {
        bail!("PRF-7: receipt of {} bytes exceeds MAX_RECEIPT_LEN", bytes.len());
    }
    let opts = bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes().with_limit(bhss_primitives::types::MAX_RECEIPT_LEN as u64 * 4);
    use bincode::Options;
    Ok(opts.deserialize(bytes)?)
}

pub fn is_fake(r: &Receipt) -> bool {
    matches!(r.inner, InnerReceipt::Fake(_))
}

/// PRF-3 / MIG-2 / PRF-6: check a receipt against an image id and the exact
/// journal bytes the verifier expects. Fake receipts pass only if
/// `allow_fake`; anything else must be a succinct (STARK) receipt — composite
/// receipts could carry fake assumptions and Groth16 adds a trusted setup.
pub fn verify_receipt(r: &Receipt, image_id: [u32; 8], expected_journal: &[u8], allow_fake: bool) -> Result<()> {
    if r.journal.bytes != expected_journal {
        bail!("journal mismatch");
    }
    match &r.inner {
        InnerReceipt::Fake(_) => {
            if !allow_fake {
                bail!("fake (dev-mode) receipt rejected: chain requires real proofs (PRF-5)");
            }
            let claim = r.claim().context("fake receipt claim")?;
            let expected = ReceiptClaim::ok(image_id, expected_journal.to_vec());
            if claim.digest() != expected.digest() {
                bail!("fake receipt claim mismatch");
            }
            Ok(())
        }
        InnerReceipt::Succinct(_) => r.verify_with_context(&strict_context(), image_id).map_err(|e| anyhow!("receipt verification failed: {e}")),
        other => bail!("PRF-6: receipt kind {} is not accepted (succinct required)", ReceiptKind::of(other)),
    }
}

/// What a serialized receipt is (PRF-5, PRF-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptKind {
    /// RISC Zero dev-mode receipt: proves nothing.
    Fake,
    /// The only real kind consensus accepts.
    Succinct,
    Composite,
    Groth16,
    /// Does not deserialize, or an unknown variant.
    Invalid,
}

impl ReceiptKind {
    fn of(inner: &InnerReceipt) -> Self {
        match inner {
            InnerReceipt::Fake(_) => ReceiptKind::Fake,
            InnerReceipt::Succinct(_) => ReceiptKind::Succinct,
            InnerReceipt::Composite(_) => ReceiptKind::Composite,
            InnerReceipt::Groth16(_) => ReceiptKind::Groth16,
            _ => ReceiptKind::Invalid,
        }
    }
}

impl std::fmt::Display for ReceiptKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ReceiptKind::Fake => "fake",
            ReceiptKind::Succinct => "succinct",
            ReceiptKind::Composite => "composite",
            ReceiptKind::Groth16 => "groth16",
            ReceiptKind::Invalid => "invalid",
        })
    }
}

/// Classify a serialized receipt (diagnostics and mempool policy).
pub fn receipt_kind(bytes: &[u8]) -> ReceiptKind {
    match decode_receipt(bytes) {
        Ok(r) => ReceiptKind::of(&r.inner),
        Err(_) => ReceiptKind::Invalid,
    }
}

/// Whether `RISC0_DEV_MODE` is set the way risc0 itself parses it. BHSS
/// never lets it decide anything: verification ignores it (PRF-5) and real
/// proving refuses to run under it.
pub fn dev_mode_env() -> bool {
    std::env::var("RISC0_DEV_MODE").map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes")).unwrap_or(false)
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
            // The receipt-kind check below also catches dev mode enabled
            // some other way.
            if dev_mode_env() {
                bail!("RISC0_DEV_MODE is set; refusing to produce a 'real' proof");
            }
            let started = std::time::Instant::now();
            let info = default_prover()
                .prove_with_opts(env, elf, &ProverOpts::succinct())
                .map_err(|e| anyhow!("proving failed: {e:#}"))?;
            tracing::info!(cycles = info.stats.total_cycles, secs = started.elapsed().as_secs_f64(), "real proof complete");
            if !matches!(info.receipt.inner, InnerReceipt::Succinct(_)) {
                bail!("prover returned a {} receipt, expected succinct (PRF-6)", ReceiptKind::of(&info.receipt.inner));
            }
            info.receipt.verify_with_context(&strict_context(), image_id)?;
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

/// A fake receipt for an arbitrary image id / journal. Only for tests of the
/// *rejection* paths (PRF-5): it is exactly what an attacker on a dev chain
/// could produce without running any guest.
pub fn forge_fake_receipt(image_id: [u32; 8], journal: &[u8]) -> Result<Vec<u8>> {
    let claim = ReceiptClaim::ok(image_id, journal.to_vec());
    encode_receipt(&Receipt::new(InnerReceipt::Fake(FakeReceipt::new(claim)), journal.to_vec()))
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

/// Expected journal for a block (PRF-2/PRF-3), built from the verifier's
/// own view: its parameters and genesis, the parent (`height`, `time`,
/// `state_root`) and the block's header (`block_hash`, `state_root`). It
/// needs no validation result, so the receipt can be checked first; HDR-3
/// then guarantees that native validation reaches the same `root_next`.
pub fn expected_block_journal(params: &ChainParams, genesis_hash: &Hash32, prev: &PrevState, header: &bhss_primitives::types::Header) -> BlockJournal {
    BlockJournal {
        params_hash: params.hash(),
        genesis_hash: *genesis_hash,
        height: prev.height.wrapping_add(1),
        block_hash: header.hash(),
        prev_time: prev.time,
        root_prev: prev.state_root,
        root_next: header.state_root,
        migrate_image_id: migrate_image_id(),
    }
}

/// Produce the receipt for `block` (whose `receipt` field is ignored). The
/// migration receipts inside `block.txs[*].proofs` become assumptions.
pub fn prove_block(cfg: &ProverConfig, params: &ChainParams, genesis_hash: &Hash32, prev: &PrevState, block: &Block) -> Result<Vec<u8>> {
    let mut stripped = block.clone();
    stripped.receipt.clear();
    // The guest checks migrations through `env::verify` on their journals
    // and needs only the number of proofs per transaction (TX-9), not their
    // bytes, which no hash commits to. Emptying them keeps ~250 KB per
    // migration (about 1.6 M cycles of input decoding each) out of the guest.
    for p in stripped.txs.iter_mut().flat_map(|tx| tx.proofs.iter_mut()) {
        p.clear();
    }
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

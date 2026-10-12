//! Chain state: block store, main chain selection, UTXO set, mempool.
//!
//! Validation is D3 "double verification": the block receipt is verified
//! (PRF-3) and every rule is re-run natively. A block that extends the tip is
//! checked against the full UTXO set *and* its own witness; a block on a side
//! branch is checked statelessly against its parent's state root (which is
//! exactly what the witness is for), so nothing unvalidated is ever stored.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{anyhow, bail, Context, Result};
use bhss_consensus::state::StateError;
use bhss_consensus::{apply_block_unchecked, apply_tx, check_tx_context, coin_for, connect_block, FullState, PrevState, ProofBackedState, StateView, TxContext};
use bhss_primitives::types::*;
use bhss_primitives::{ChainParams, Decode, Encode, Hash32};
use bhss_prover::{NativeMigrationChecker, ReceiptKind};
use bhss_snapshot::GenesisCoins;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accept {
    AlreadyKnown,
    Connected,
    Reorganized,
    SideChain,
    /// Parent (or an ancestor on its branch) is not stored.
    Orphan,
    /// Invalid; only produced by callers that map an error to an outcome.
    Rejected,
}

/// Node policy (NET-5): a header `time` more than this far ahead of the
/// node's clock is not accepted (yet).
pub const MAX_FUTURE_TIME_SECS: u64 = 2 * 60 * 60;
/// Bytes of a block reserved for the coinbase and the transaction count
/// (NET-6). The largest coinbase a miner can build pays to a timelocked
/// 16-key multisig (579 bytes; see `tests::coinbase_reserve_covers_largest_coinbase`).
/// Mempool admission and block templates use the same value, so every
/// admitted transaction fits a block.
pub const COINBASE_RESERVE_BYTES: usize = 640;

/// Resource bounds of one node (NET-5, NET-6). Not consensus.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Encoded bytes of blocks kept outside the main chain; beyond it the
    /// oldest are evicted.
    pub side_bytes: usize,
    pub mempool_txs: usize,
    pub mempool_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self { side_bytes: 64 << 20, mempool_txs: 1000, mempool_bytes: 16 << 20 }
    }
}

/// Lock the chain, recovering from a poisoned mutex (a panic in another task
/// must not take the whole node down with it).
pub fn lock(m: &Mutex<ChainState>) -> MutexGuard<'_, ChainState> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct ChainState {
    pub params: ChainParams,
    pub params_hash: Hash32,
    pub genesis_hash: Hash32,
    pub genesis_coins: GenesisCoins,
    /// Every stored block: the main chain plus validated side-chain blocks.
    /// `heights` always has exactly the same keys.
    pub blocks: HashMap<Hash32, Arc<Block>>,
    /// Height of every stored block (genesis = 0), main chain or not.
    pub heights: HashMap<Hash32, u32>,
    /// Main chain by height.
    pub main: Vec<Hash32>,
    pub tx_index: HashMap<Hash32, Hash32>,
    pub state: FullState,
    pub tip: PrevState,
    pub mempool: Mempool,
    pub datadir: PathBuf,
    pub limits: Limits,
    /// When this node mines real proofs, migration transactions carrying
    /// fake receipts are useless to it (they cannot be composed into a real
    /// block receipt) and are kept out of its mempool.
    pub real_miner: bool,
    /// Side-chain blocks (`blocks` minus `main`) in insertion order, with
    /// their encoded size.
    side: Vec<(Hash32, usize)>,
    side_bytes: usize,
}

/// An in-memory overlay over the full UTXO set. With `proofs`, every
/// operation is additionally checked against the SMT proofs of a block
/// witness (STATE-2); the node's own set is consulted first, so a wrong
/// spend is reported as STATE-3/STATE-4 and a wrong witness as STATE-2.
pub struct Overlay<'a> {
    base: &'a FullState,
    proofs: Option<ProofBackedState<'a>>,
    spent: BTreeSet<OutPoint>,
    created: BTreeMap<OutPoint, Coin>,
}

impl<'a> Overlay<'a> {
    pub fn new(base: &'a FullState) -> Self {
        Self { base, proofs: None, spent: BTreeSet::new(), created: BTreeMap::new() }
    }
    fn with_proofs(base: &'a FullState, proofs: ProofBackedState<'a>) -> Self {
        Self { base, proofs: Some(proofs), spent: BTreeSet::new(), created: BTreeMap::new() }
    }
    pub fn lookup(&self, op: &OutPoint) -> Option<&Coin> {
        if self.spent.contains(op) {
            return None;
        }
        self.created.get(op).or_else(|| self.base.get(op))
    }
}

impl StateView for Overlay<'_> {
    fn root(&self) -> Hash32 {
        match &self.proofs {
            Some(p) => p.root(),
            None => self.base.root(),
        }
    }
    fn spend(&mut self, outpoint: &OutPoint, coin: &Coin) -> std::result::Result<(), StateError> {
        match self.lookup(outpoint) {
            Some(c) if c == coin => {}
            _ => return Err(StateError::MissingOrMismatch),
        }
        if let Some(p) = &mut self.proofs {
            p.spend(outpoint, coin)?;
        }
        self.created.remove(outpoint);
        self.spent.insert(*outpoint);
        Ok(())
    }
    fn create(&mut self, outpoint: &OutPoint, coin: &Coin) -> std::result::Result<(), StateError> {
        if self.lookup(outpoint).is_some() {
            return Err(StateError::AlreadyExists);
        }
        if let Some(p) = &mut self.proofs {
            p.create(outpoint, coin)?;
        }
        self.spent.remove(outpoint);
        self.created.insert(*outpoint, coin.clone());
        Ok(())
    }
}

/// A transaction waiting for a block, with the coins its inputs spend as
/// they were when it was fully validated (NET-6).
#[derive(Clone)]
pub struct MempoolEntry {
    pub txid: Hash32,
    pub tx: Transaction,
    pub coins: Vec<Coin>,
    pub size: usize,
}

#[derive(Default)]
pub struct Mempool {
    /// Insertion-ordered (parents before children).
    pub entries: Vec<MempoolEntry>,
    pub bytes: usize,
}

impl Mempool {
    pub fn contains(&self, txid: &Hash32) -> bool {
        self.entries.iter().any(|e| e.txid == *txid)
    }
    pub fn get(&self, txid: &Hash32) -> Option<&MempoolEntry> {
        self.entries.iter().find(|e| e.txid == *txid)
    }
    fn push(&mut self, e: MempoolEntry) {
        self.bytes += e.size;
        self.entries.push(e);
    }
    fn clear(&mut self) -> Vec<MempoolEntry> {
        self.bytes = 0;
        std::mem::take(&mut self.entries)
    }
}

impl ChainState {
    pub fn new(params: ChainParams, genesis_coins: GenesisCoins, datadir: PathBuf) -> Result<Self> {
        params.validate().map_err(|e| anyhow!("{e}"))?;
        bhss_snapshot::check_genesis_coins(&genesis_coins)?;
        let root = bhss_snapshot::genesis_state_root(&genesis_coins);
        if root != params.genesis_state_root {
            bail!("genesis state root {} does not match params {}", hex::encode(root), hex::encode(params.genesis_state_root));
        }
        // PAR-5: the guest images this binary carries must be the ones the
        // network was defined with.
        if bhss_prover::block_image_id() == [0u8; 32] || bhss_prover::migrate_image_id() == [0u8; 32] {
            bail!("PAR-5: this binary carries no guest programs (built with RISC0_SKIP_BUILD?)");
        }
        if params.block_image_id != bhss_prover::block_image_id() {
            bail!("PAR-5: params.block_image_id {} != this binary's block guest {}", hex::encode(params.block_image_id), hex::encode(bhss_prover::block_image_id()));
        }
        if params.migrate_image_id != bhss_prover::migrate_image_id() {
            bail!("PAR-5: params.migrate_image_id {} != this binary's migration guest {}", hex::encode(params.migrate_image_id), hex::encode(bhss_prover::migrate_image_id()));
        }
        let genesis = Arc::new(bhss_consensus::genesis::genesis_block(&params));
        let genesis_hash = genesis.hash();
        let state = FullState::from_coins(genesis_coins.iter().cloned());
        let tip = PrevState { height: 0, hash: genesis_hash, state_root: root, time: genesis.header.time };
        let mut cs = Self {
            params_hash: params.hash(),
            params,
            genesis_hash,
            genesis_coins,
            blocks: HashMap::new(),
            heights: HashMap::new(),
            main: vec![genesis_hash],
            tx_index: HashMap::new(),
            state,
            tip,
            mempool: Mempool::default(),
            datadir,
            limits: Limits::default(),
            real_miner: false,
            side: Vec::new(),
            side_bytes: 0,
        };
        cs.tx_index.insert(genesis.txs[0].txid(), genesis_hash);
        cs.heights.insert(genesis_hash, 0);
        cs.blocks.insert(genesis_hash, genesis);
        Ok(cs)
    }

    pub fn allow_fake(&self) -> bool {
        !self.params.require_real_proofs
    }

    pub fn height(&self) -> u32 {
        self.tip.height
    }

    pub fn block_at(&self, height: u32) -> Option<&Arc<Block>> {
        self.main.get(height as usize).and_then(|h| self.blocks.get(h))
    }

    pub fn on_main(&self, hash: &Hash32) -> bool {
        self.heights.get(hash).and_then(|h| self.main.get(*h as usize)) == Some(hash)
    }

    /// Load `main.txt` + `blocks/*.bin` from the data dir and replay them
    /// with full validation.
    pub fn load_from_disk(&mut self) -> Result<usize> {
        let main_file = self.datadir.join("main.txt");
        if !main_file.exists() {
            return Ok(0);
        }
        let list = std::fs::read_to_string(&main_file)?;
        let mut lines = list.lines();
        let first = lines.next().unwrap_or("").trim();
        if first != hex::encode(self.genesis_hash) {
            bail!("data dir {} belongs to another network: its genesis is {first}, ours is {}", self.datadir.display(), hex::encode(self.genesis_hash));
        }
        let mut n = 0;
        for line in lines {
            let hash: Hash32 = hex::decode(line.trim())?.try_into().map_err(|_| anyhow!("bad hash in main.txt"))?;
            let bytes = std::fs::read(self.datadir.join("blocks").join(format!("{}.bin", hex::encode(hash))))?;
            let block = Block::from_bytes(&bytes).map_err(|e| anyhow!("block decode: {e}"))?;
            match self.accept_block(block, false)? {
                Accept::Connected => n += 1,
                other => bail!("replaying block {} from disk: {other:?}", hex::encode(hash)),
            }
        }
        Ok(n)
    }

    fn persist_block(&self, block: &Block) -> Result<()> {
        let dir = self.datadir.join("blocks");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.bin", hex::encode(block.hash())));
        let tmp = dir.join(format!("{}.tmp", hex::encode(block.hash())));
        std::fs::write(&tmp, block.to_bytes())?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Written atomically (temp file + rename) so a crash mid-write cannot
    /// leave a truncated chain index behind. Runs after the in-memory
    /// commit; a failure is logged, not returned, because the block *is*
    /// the tip by then (the index is rewritten in full by the next block).
    fn persist_main(&self) {
        let write = || -> Result<()> {
            std::fs::create_dir_all(&self.datadir)?;
            let s: Vec<String> = self.main.iter().map(hex::encode).collect();
            let tmp = self.datadir.join("main.txt.tmp");
            std::fs::write(&tmp, s.join("\n"))?;
            std::fs::rename(&tmp, self.datadir.join("main.txt"))?;
            Ok(())
        };
        if let Err(e) = write() {
            tracing::error!("could not write main.txt: {e:#}");
        }
    }

    /// Header-only checks (HDR-4, HDR-6, HDR-7, POW-1) plus the future-time
    /// policy (NET-5). Cheap; run before anything else.
    fn check_header(&self, block: &Block, parent: &Block) -> Result<()> {
        let h = &block.header;
        if h.version != Header::VERSION {
            bail!("HDR-4: version {}", h.version);
        }
        if h.bits != self.params.pow_bits {
            bail!("HDR-6: bits {:#x}", h.bits);
        }
        if h.time < parent.header.time {
            bail!("HDR-7: time decreases");
        }
        if !bhss_primitives::params::hash_meets_target(&block.hash(), &self.params.target()) {
            bail!("POW-1: hash above target");
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        if h.time as u64 > now.saturating_add(MAX_FUTURE_TIME_SECS) {
            bail!("NET-5: header time {} is too far in the future", h.time);
        }
        Ok(())
    }

    /// BLK-12 / PRF-7: size bounds that only a node (not the guest, which
    /// never sees receipts) can check. Returns the encoded size.
    fn check_size(&self, block: &Block) -> Result<usize> {
        if block.receipt.len() > MAX_RECEIPT_LEN {
            bail!("PRF-7: block receipt of {} bytes > {MAX_RECEIPT_LEN}", block.receipt.len());
        }
        let n = block.to_bytes().len();
        if n > MAX_BLOCK_LEN {
            bail!("BLK-12: block of {n} bytes > {MAX_BLOCK_LEN}");
        }
        // BLK-7 is a consensus rule and is checked again in `connect_block`;
        // checking it here keeps an oversized transaction list away from the
        // receipt check and the per-transaction work that precedes it there.
        let committed = block.committed_tx_bytes();
        if committed > self.params.max_block_tx_bytes as usize {
            bail!("BLK-7: {committed} bytes > max {}", self.params.max_block_tx_bytes);
        }
        Ok(n)
    }

    /// Validate `block` on top of `prev` without mutating anything.
    ///
    /// The receipt is checked first (one STARK verification) so that a block
    /// with a bad proof never reaches the native signature checks. Native
    /// validation then runs against `state` plus the witness when the block
    /// extends that state, or against the witness alone (`state = None`)
    /// for a block on a side branch, whose pre-state this node does not hold
    /// but whose parent's `state_root` it has already validated.
    fn validate_block(&self, block: &Block, prev: &PrevState, state: Option<&FullState>) -> Result<bhss_consensus::BlockSummary> {
        let journal = bhss_prover::expected_block_journal(&self.params, &self.genesis_hash, prev, &block.header);
        bhss_prover::verify_block_receipt(&block.receipt, &journal, self.allow_fake()).context("PRF-3")?;

        let mut migrations = NativeMigrationChecker::new(&block.txs, self.allow_fake());
        let proofs = ProofBackedState::new(prev.state_root, &block.witness.proofs);
        let result = match state {
            Some(base) => connect_block(&self.params, &self.genesis_hash, prev, block, &mut Overlay::with_proofs(base, proofs), &mut migrations),
            None => {
                let mut proofs = proofs;
                connect_block(&self.params, &self.genesis_hash, prev, block, &mut proofs, &mut migrations)
            }
        };
        result.map_err(|e| anyhow!("consensus: {e}"))
    }

    /// Bring the side store back under its byte budget (NET-5), oldest
    /// block first. Blocks that `keep` builds on are spared, so a flood of
    /// other side blocks cannot cut the branch that is currently arriving.
    /// Returns false if `keep` itself had to go: its own branch alone is
    /// over the budget, and dropping the new block (rather than one of its
    /// ancestors) leaves what is stored connected.
    fn evict_side(&mut self, keep: Option<Hash32>) -> bool {
        if self.side_bytes <= self.limits.side_bytes {
            return true;
        }
        let stored: HashSet<Hash32> = self.side.iter().map(|(h, _)| *h).collect();
        let mut spared = HashSet::new();
        let mut cur = keep;
        while let Some(h) = cur.filter(|h| stored.contains(h)) {
            spared.insert(h);
            cur = self.blocks.get(&h).map(|b| b.header.prev_hash);
        }
        let mut i = 0;
        while self.side_bytes > self.limits.side_bytes && i < self.side.len() {
            if spared.contains(&self.side[i].0) {
                i += 1;
                continue;
            }
            let (old, n) = self.side.remove(i);
            self.side_bytes -= n;
            self.blocks.remove(&old);
            self.heights.remove(&old);
        }
        match keep {
            // A single block is always kept, whatever its size.
            Some(h) if self.side_bytes > self.limits.side_bytes && self.side.len() > 1 => {
                self.forget_side(&h);
                false
            }
            _ => true,
        }
    }

    /// Returns false if the block could not be kept (see `evict_side`).
    fn store_side(&mut self, hash: Hash32, height: u32, block: Arc<Block>, size: usize) -> bool {
        self.side.push((hash, size));
        self.side_bytes += size;
        self.heights.insert(hash, height);
        self.blocks.insert(hash, block);
        self.evict_side(Some(hash))
    }

    fn forget_side(&mut self, hash: &Hash32) {
        if let Some(pos) = self.side.iter().position(|(h, _)| h == hash) {
            let (_, n) = self.side.remove(pos);
            self.side_bytes -= n;
            self.blocks.remove(hash);
            self.heights.remove(hash);
        }
    }

    /// Accept a block from any source. `persist` writes it to disk.
    pub fn accept_block(&mut self, block: Block, persist: bool) -> Result<Accept> {
        let hash = block.hash();
        // Every stored block was validated, so a second copy adds nothing
        // even if its uncommitted parts (witness, receipt, proofs) differ.
        if self.blocks.contains_key(&hash) {
            return Ok(Accept::AlreadyKnown);
        }
        let prev_hash = block.header.prev_hash;
        let (Some(parent), Some(&prev_height)) = (self.blocks.get(&prev_hash).cloned(), self.heights.get(&prev_hash)) else {
            return Ok(Accept::Orphan);
        };
        let height = prev_height.checked_add(1).ok_or_else(|| anyhow!("height overflow"))?;
        self.check_header(&block, &parent)?;
        let size = self.check_size(&block)?;

        if prev_hash == self.tip.hash {
            let prev = self.tip.clone();
            let summary = self.validate_block(&block, &prev, Some(&self.state))?;
            // Disk first, memory second: a failed write leaves the in-memory
            // chain untouched instead of half-advanced.
            let block = Arc::new(block);
            if persist {
                self.persist_block(&block)?;
            }
            apply_block_unchecked(&block.txs, &block.witness.coins, height, &mut self.state).expect("block was validated against this state");
            debug_assert_eq!(self.state.root(), summary.root_next);
            self.tip = PrevState { height, hash, state_root: summary.root_next, time: block.header.time };
            for tx in &block.txs {
                self.tx_index.insert(tx.txid(), hash);
            }
            self.heights.insert(hash, height);
            self.main.push(hash);
            self.blocks.insert(hash, block);
            if persist {
                self.persist_main();
            }
            self.rebuild_mempool(Vec::new());
            return Ok(Accept::Connected);
        }

        // A block on another branch: validated statelessly against its
        // parent's (already validated) state root.
        let prev = PrevState { height: prev_height, hash: prev_hash, state_root: parent.header.state_root, time: parent.header.time };
        self.validate_block(&block, &prev, None)?;
        let block = Arc::new(block);
        // Longer chain wins (constant difficulty => height == work); ties
        // keep the current chain (NET-4).
        if height <= self.tip.height {
            if !self.store_side(hash, height, block, size) {
                tracing::warn!(hash = hex::encode(hash), height, "side branch exceeds the side-store budget; block dropped");
            }
            return Ok(Accept::SideChain);
        }
        self.reorganize(block, height, persist)
    }

    /// Switch the main chain to the branch ending in `block` (already
    /// validated, height above the tip).
    fn reorganize(&mut self, block: Arc<Block>, height: u32, persist: bool) -> Result<Accept> {
        // Collect the new branch from `block` back to the main chain.
        let mut branch: Vec<Arc<Block>> = vec![block];
        let mut cur = branch[0].header.prev_hash;
        let mut cur_height = height - 1;
        while self.main.get(cur_height as usize) != Some(&cur) {
            // An ancestor was evicted: ask for the branch again.
            let Some(b) = self.blocks.get(&cur).cloned() else { return Ok(Accept::Orphan) };
            cur = b.header.prev_hash;
            cur_height = cur_height.checked_sub(1).ok_or_else(|| anyhow!("branch does not reach genesis"))?;
            branch.push(b);
        }
        branch.reverse();
        let fork_height = cur_height;

        // Rebuild the UTXO set: genesis, the shared prefix, then the branch.
        // Every block involved is already validated, so this only moves
        // coins (no signature or receipt is checked again); the full set
        // still refuses any spend it does not agree with, and the resulting
        // root must match each header.
        let mut state = FullState::from_coins(self.genesis_coins.iter().cloned());
        let shared: Vec<Arc<Block>> = self.main[1..=fork_height as usize].iter().map(|h| self.blocks[h].clone()).collect();
        let disconnected: Vec<Arc<Block>> = self.main[fork_height as usize + 1..].iter().map(|h| self.blocks[h].clone()).collect();
        let mut new_main = vec![self.genesis_hash];
        for (i, b) in shared.iter().chain(branch.iter()).enumerate() {
            let h = i as u32 + 1;
            let applied = apply_block_unchecked(&b.txs, &b.witness.coins, h, &mut state);
            if applied.is_err() || state.root() != b.header.state_root {
                let bad = b.hash();
                self.forget_side(&bad);
                bail!("block {} at height {h} does not apply to this node's UTXO set ({applied:?})", hex::encode(bad));
            }
            new_main.push(b.hash());
        }
        let new_tip = branch.last().expect("branch is never empty").clone();

        // Commit: disk first, then memory.
        if persist {
            for b in &branch {
                self.persist_block(b)?;
            }
        }
        for (i, b) in branch.iter().enumerate() {
            let h = b.hash();
            self.forget_side(&h);
            self.heights.insert(h, fork_height + 1 + i as u32);
            self.blocks.insert(h, b.clone());
        }
        for b in &disconnected {
            let size = b.to_bytes().len();
            self.side.push((b.hash(), size));
            self.side_bytes += size;
        }
        self.state = state;
        self.tip = PrevState { height, hash: new_tip.hash(), state_root: new_tip.header.state_root, time: new_tip.header.time };
        self.main = new_main;
        self.tx_index.clear();
        for h in &self.main {
            for tx in &self.blocks[h].txs {
                self.tx_index.insert(tx.txid(), *h);
            }
        }
        self.evict_side(None);
        if persist {
            self.persist_main();
        }
        // Transactions of the disconnected blocks go back to the mempool,
        // ahead of what was already waiting (coinbases never do).
        let returned: Vec<Transaction> = disconnected.iter().flat_map(|b| b.txs.iter().skip(1).cloned()).collect();
        self.rebuild_mempool(returned);
        Ok(Accept::Reorganized)
    }

    /// Apply a mempool entry to `overlay` from its cached coins.
    fn apply_entry(overlay: &mut Overlay<'_>, e: &MempoolEntry, height: u32) -> std::result::Result<(), StateError> {
        for (input, coin) in e.tx.inputs.iter().zip(&e.coins) {
            overlay.spend(&input.prevout, coin)?;
        }
        for (vout, o) in e.tx.outputs.iter().enumerate() {
            if !o.kind.is_data() {
                overlay.create(&OutPoint::new(e.txid, vout as u32), &coin_for(o, height, false))?;
            }
        }
        Ok(())
    }

    /// The UTXO set as it would be after every mempool transaction, built
    /// from the coins cached at admission (no signature or receipt is
    /// verified here, NET-6).
    fn mempool_overlay(&self) -> Result<Overlay<'_>> {
        let mut overlay = Overlay::new(&self.state);
        for e in &self.mempool.entries {
            Self::apply_entry(&mut overlay, e, self.tip.height + 1).map_err(|err| anyhow!("mempool entry {} is inconsistent: {err:?}", hex::encode(e.txid)))?;
        }
        Ok(overlay)
    }

    /// Fully validate a transaction against the current state + mempool. On
    /// success returns the coins its inputs spend.
    pub fn check_mempool_tx(&self, tx: &Transaction) -> Result<Vec<Coin>> {
        if tx.is_coinbase() {
            bail!("coinbase transactions cannot be relayed");
        }
        // NET-6: a transaction that can never fit a block is not admitted,
        // otherwise it would occupy the pool forever.
        let p = &self.params;
        let sigs: usize = tx.inputs.iter().map(|i| match &i.witness { Witness::Slh { signers } => signers.len(), _ => 0 }).sum();
        if sigs > p.max_sig_checks as usize {
            bail!("{sigs} signature checks can never fit a block (BLK-8)");
        }
        if tx.proofs.len() > p.max_migrations as usize {
            bail!("{} migrations can never fit a block (BLK-9)", tx.proofs.len());
        }
        if tx.committed_size() + COINBASE_RESERVE_BYTES > p.max_block_tx_bytes as usize {
            bail!("transaction of {} committed bytes can never fit a block (BLK-7)", tx.committed_size());
        }
        if self.real_miner && tx.proofs.iter().any(|r| bhss_prover::receipt_kind(r) == ReceiptKind::Fake) {
            bail!("this node mines real proofs and does not take transactions with dev-mode (fake) migration receipts");
        }
        let mut overlay = self.mempool_overlay()?;
        let ctx = TxContext { params: &self.params, genesis_hash: &self.genesis_hash, height: self.tip.height + 1 };
        let mut coins = Vec::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            coins.push(overlay.lookup(&input.prevout).cloned().ok_or_else(|| anyhow!("input {}:{} not found or already spent", hex::encode(input.prevout.txid), input.prevout.vout))?);
        }
        let mut migrations = NativeMigrationChecker::new(std::slice::from_ref(tx), self.allow_fake());
        apply_tx(&ctx, tx, &tx.txid(), 0, &coins, &mut overlay, &mut migrations).map_err(|e| anyhow!("consensus: {e}"))?;
        Ok(coins)
    }

    /// Returns the txid and whether the transaction is new to this node.
    pub fn add_to_mempool(&mut self, tx: Transaction) -> Result<(Hash32, bool)> {
        let txid = tx.txid();
        if self.mempool.contains(&txid) {
            return Ok((txid, false));
        }
        if self.tx_index.contains_key(&txid) {
            bail!("transaction already in chain");
        }
        let size = tx.to_bytes().len();
        if self.mempool.entries.len() >= self.limits.mempool_txs || self.mempool.bytes + size > self.limits.mempool_bytes {
            bail!("mempool full (NET-6)");
        }
        let coins = self.check_mempool_tx(&tx)?;
        self.mempool.push(MempoolEntry { txid, tx, coins, size });
        Ok((txid, true))
    }

    /// Bring the mempool in line with a new tip (NET-6).
    ///
    /// `returned` (transactions of disconnected blocks) are fully validated
    /// and go first. The previous entries are then re-checked without any
    /// cryptography: an entry stays iff every input still resolves to
    /// exactly the coin it was validated against (the signatures commit to
    /// that coin's leaf, SIG-1) and the height-dependent rules (IN-2, IN-3,
    /// TX-8) hold at the next height.
    fn rebuild_mempool(&mut self, returned: Vec<Transaction>) {
        let old = self.mempool.clear();
        for tx in returned {
            let _ = self.add_to_mempool(tx);
        }
        let kept: Vec<MempoolEntry> = {
            let Ok(mut overlay) = self.mempool_overlay() else { return };
            let height = self.tip.height + 1;
            let ctx = TxContext { params: &self.params, genesis_hash: &self.genesis_hash, height };
            let mut n = self.mempool.entries.len();
            let mut bytes = self.mempool.bytes;
            let mut kept = Vec::new();
            for e in old {
                if self.tx_index.contains_key(&e.txid) || self.mempool.contains(&e.txid) {
                    continue;
                }
                if n >= self.limits.mempool_txs || bytes + e.size > self.limits.mempool_bytes {
                    continue;
                }
                let unchanged = e.tx.inputs.iter().zip(&e.coins).all(|(i, c)| overlay.lookup(&i.prevout) == Some(c));
                if !unchanged || check_tx_context(&ctx, &e.tx, &e.coins).is_err() {
                    continue;
                }
                if Self::apply_entry(&mut overlay, &e, height).is_err() {
                    // Cannot happen after the checks above; stop rather
                    // than continue on a half-applied overlay.
                    break;
                }
                n += 1;
                bytes += e.size;
                kept.push(e);
            }
            kept
        };
        for e in kept {
            self.mempool.push(e);
        }
    }

    pub fn find_coins(&self, kind: Option<&OutputKind>) -> Vec<(OutPoint, Coin)> {
        self.state
            .coins
            .iter()
            .filter(|(_, c)| kind.map(|k| &c.output.kind == k).unwrap_or(true))
            .map(|(op, c)| (*op, c.clone()))
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::miner::coinbase_tx;
    use bhss_consensus::{assemble_block, NoMigrations};
    use bhss_slhdsa::SecretKey;

    fn key(i: u8) -> SecretKey {
        SecretKey::from_seeds(&[i; 16], &[i + 1; 16], &[i + 2; 16])
    }
    fn p2pk(sk: &SecretKey) -> OutputKind {
        OutputKind::P2pkSlh { pkh: sk.public_key().hash() }
    }

    /// An empty-genesis chain with dev-mode proofs and 2-block maturity.
    pub(crate) fn chain() -> ChainState {
        let coins = GenesisCoins::new();
        let mut params = ChainParams::regtest(bhss_snapshot::genesis_state_root(&coins)).with_images(bhss_prover::block_image_id(), bhss_prover::migrate_image_id());
        params.coinbase_maturity = 2;
        ChainState::new(params, coins, PathBuf::from("/nonexistent")).unwrap()
    }

    /// A branch a test extends by hand: its tip and the UTXO set there.
    #[derive(Clone)]
    struct Branch {
        prev: PrevState,
        state: FullState,
    }

    fn genesis_branch(cs: &ChainState) -> Branch {
        Branch { prev: cs.tip.clone(), state: cs.state.clone() }
    }

    /// Build a valid block on `b` paying `payout`, with a forged (dev-mode)
    /// receipt for exactly the journal a node expects, and advance `b`.
    fn forge(cs: &ChainState, b: &mut Branch, payout: &SecretKey, txs: Vec<Transaction>, coins: Vec<Coin>) -> Block {
        let height = b.prev.height + 1;
        let mut all = vec![coinbase_tx(height, 0, p2pk(payout))];
        all.extend(txs);
        let mut block = assemble_block(&cs.params, &cs.genesis_hash, &b.prev, &mut b.state, all, coins, b.prev.time, &mut NoMigrations).unwrap();
        let journal = bhss_prover::expected_block_journal(&cs.params, &cs.genesis_hash, &b.prev, &block.header);
        block.receipt = bhss_prover::forge_fake_receipt(bhss_prover::BLOCK_ID, &journal.to_bytes()).unwrap();
        b.prev = PrevState { height, hash: block.hash(), state_root: block.header.state_root, time: block.header.time };
        block
    }

    /// `from` pays `value` of the coinbase of `block` to `to`.
    fn spend(cs: &ChainState, block: &Block, height: u32, from: &SecretKey, to: &SecretKey, value: u64) -> (Transaction, Coin) {
        let op = OutPoint::new(block.txs[0].txid(), 0);
        let coin = coin_for(&block.txs[0].outputs[0], height, true);
        let mut tx = Transaction {
            version: 1,
            inputs: vec![Input { prevout: op, witness: Witness::Slh { signers: vec![] } }],
            outputs: vec![Output { value, kind: p2pk(to) }, Output { value: coin.output.value - value - 100, kind: p2pk(from) }],
            locktime: 0,
            proofs: vec![],
        };
        let msg = slh_sighash(&cs.genesis_hash, &tx.txid(), 0, &coin.leaf_hash());
        tx.inputs[0].witness = Witness::Slh { signers: vec![SlhSigner { index: 0, pubkey: from.public_key().0, signature: from.sign(&msg) }] };
        (tx, coin)
    }

    fn assert_consistent(cs: &ChainState) {
        assert_eq!(cs.blocks.len(), cs.heights.len());
        assert!(cs.blocks.keys().all(|h| cs.heights.contains_key(h)));
        assert_eq!(cs.blocks.len(), cs.main.len() + cs.side.len());
        assert!(cs.side.iter().all(|(h, _)| cs.blocks.contains_key(h) && !cs.on_main(h)));
        assert_eq!(cs.side_bytes, cs.side.iter().map(|(_, n)| n).sum::<usize>());
        assert_eq!(cs.tip.hash, *cs.main.last().unwrap());
        assert_eq!(cs.tip.state_root, cs.state.root());
        assert_eq!(cs.mempool.bytes, cs.mempool.entries.iter().map(|e| e.size).sum::<usize>());
    }

    #[test]
    fn startup_checks() {
        let coins = GenesisCoins::new();
        let root = bhss_snapshot::genesis_state_root(&coins);
        let new = |p: ChainParams| ChainState::new(p, GenesisCoins::new(), PathBuf::from("/nonexistent")).map(|_| ()).map_err(|e| format!("{e:#}"));
        let good = ChainParams::regtest(root).with_images(bhss_prover::block_image_id(), bhss_prover::migrate_image_id());
        assert!(new(good.clone()).is_ok());
        // PAR-5: the image IDs must be the ones this binary embeds.
        assert!(new(ChainParams::regtest(root)).unwrap_err().contains("PAR-5"));
        assert!(new(good.clone().with_images(bhss_prover::migrate_image_id(), bhss_prover::block_image_id())).unwrap_err().contains("PAR-5"));
        // PAR-4.
        let mut bad = good.clone();
        bad.subsidy_halving_interval = 0;
        assert!(new(bad).unwrap_err().contains("PAR-4"));
        // The genesis coins must be the ones the parameters commit to.
        let mut bad = good.clone();
        bad.genesis_state_root[0] ^= 1;
        assert!(new(bad).unwrap_err().contains("genesis state root"));
    }

    #[test]
    fn coinbase_reserve_covers_largest_coinbase() {
        let largest = OutputKind::Timelock { abs_height: u32::MAX, rel_blocks: u32::MAX, inner: Box::new(OutputKind::MultisigSlh { k: 16, pkhs: (0..16u8).map(|i| [i; 32]).collect() }) };
        assert!(largest.is_well_formed());
        let size = coinbase_tx(u32::MAX, u64::MAX, largest).committed_size();
        assert_eq!(size, 579);
        assert!(size + 9 <= COINBASE_RESERVE_BYTES);
    }

    #[test]
    fn side_chain_blocks_are_validated_stored_and_evicted() {
        let (alice, bob, carol) = (key(1), key(9), key(17));
        let mut cs = chain();
        let g = genesis_branch(&cs);
        let mut a = g.clone();
        for _ in 0..2 {
            let blk = forge(&cs, &mut a, &alice, vec![], vec![]);
            assert_eq!(cs.accept_block(blk, false).unwrap(), Accept::Connected);
        }
        // A competing block at height 1 is validated statelessly and kept.
        let mut b = g.clone();
        let b1 = forge(&cs, &mut b, &bob, vec![], vec![]);
        assert_eq!(cs.accept_block(b1.clone(), false).unwrap(), Accept::SideChain);
        assert_eq!(cs.accept_block(b1.clone(), false).unwrap(), Accept::AlreadyKnown);
        // A copy with different uncommitted bytes does not displace it.
        let mut junk = b1.clone();
        junk.receipt = bhss_prover::forge_fake_receipt(bhss_prover::BLOCK_ID, b"junk").unwrap();
        assert_eq!(junk.hash(), b1.hash());
        assert_eq!(cs.accept_block(junk, false).unwrap(), Accept::AlreadyKnown);
        assert_eq!(cs.blocks[&b1.hash()].receipt, b1.receipt);
        assert_consistent(&cs);

        // Side-chain blocks with a bad receipt or a bad witness are refused
        // outright: nothing unvalidated is stored (NET-5).
        let mut c = g.clone();
        let c1 = forge(&cs, &mut c, &carol, vec![], vec![]);
        let mut bad = c1.clone();
        bad.receipt = bhss_prover::forge_fake_receipt(bhss_prover::BLOCK_ID, b"junk").unwrap();
        let err = cs.accept_block(bad, false).unwrap_err();
        assert!(format!("{err:#}").contains("PRF-3"), "{err:#}");
        let mut bad = c1.clone();
        bad.witness.proofs[0].bitmap[0] ^= 0x80;
        bad.witness.proofs[0].siblings.push([7u8; 32]);
        let err = cs.accept_block(bad, false).unwrap_err();
        assert!(format!("{err:#}").contains("STATE-2"), "{err:#}");
        let mut bad = c1.clone();
        bad.witness.proofs.clear();
        let err = cs.accept_block(bad, false).unwrap_err();
        assert!(format!("{err:#}").contains("BLK-11"), "{err:#}");
        assert!(!cs.blocks.contains_key(&c1.hash()));
        // An oversized receipt is refused before it is even decoded (PRF-7).
        let mut bad = c1.clone();
        bad.receipt = vec![0u8; MAX_RECEIPT_LEN + 1];
        let err = cs.accept_block(bad, false).unwrap_err();
        assert!(format!("{err:#}").contains("PRF-7"), "{err:#}");
        // So is a block above the total size limit (BLK-12): 33 proofs of
        // 1 MiB each on the coinbase.
        let mut bad = c1.clone();
        bad.txs[0].proofs = vec![vec![0u8; MAX_RECEIPT_LEN]; 33];
        assert_eq!(bad.hash(), c1.hash());
        let err = cs.accept_block(bad, false).unwrap_err();
        assert!(format!("{err:#}").contains("BLK-12"), "{err:#}");
        // A header that fails POW-1 never gets that far.
        let mut bad = c1.clone();
        while bhss_primitives::params::hash_meets_target(&bad.hash(), &cs.params.target()) {
            bad.header.nonce += 1;
        }
        let err = cs.accept_block(bad, false).unwrap_err();
        assert!(format!("{err:#}").contains("POW-1"), "{err:#}");

        // The byte budget evicts the oldest side block.
        cs.limits.side_bytes = b1.to_bytes().len();
        assert_eq!(cs.accept_block(c1.clone(), false).unwrap(), Accept::SideChain);
        assert!(!cs.blocks.contains_key(&b1.hash()) && !cs.heights.contains_key(&b1.hash()));
        assert!(cs.blocks.contains_key(&c1.hash()));
        assert_consistent(&cs);
        // A block whose parent was evicted is an orphan again.
        let b2 = forge(&cs, &mut b, &bob, vec![], vec![]);
        assert_eq!(cs.accept_block(b2, false).unwrap(), Accept::Orphan);
        assert_eq!(cs.height(), 2);

        // Eviction spares the ancestors of the block being stored: with room
        // for two blocks, c2 pushes out the unrelated d1, not its parent c1.
        let mut d = g.clone();
        let d1 = forge(&cs, &mut d, &bob, vec![], vec![]);
        let c2 = forge(&cs, &mut c, &carol, vec![], vec![]);
        cs.limits.side_bytes = c1.to_bytes().len() + c2.to_bytes().len().max(d1.to_bytes().len());
        assert_eq!(cs.accept_block(d1.clone(), false).unwrap(), Accept::SideChain);
        assert_eq!(cs.accept_block(c2.clone(), false).unwrap(), Accept::SideChain);
        assert!(cs.blocks.contains_key(&c1.hash()) && cs.blocks.contains_key(&c2.hash()));
        assert!(!cs.blocks.contains_key(&d1.hash()));
        assert_consistent(&cs);
        // A branch that is over the budget on its own loses the new block,
        // never an ancestor, so what is stored stays connected.
        cs.limits.side_bytes = c1.to_bytes().len();
        let mut e = g.clone();
        let e1 = forge(&cs, &mut e, &bob, vec![], vec![]);
        let e2 = forge(&cs, &mut e, &bob, vec![], vec![]);
        assert_eq!(cs.accept_block(e1.clone(), false).unwrap(), Accept::SideChain);
        assert!(cs.blocks.contains_key(&e1.hash()) && !cs.blocks.contains_key(&c2.hash()));
        assert_eq!(cs.accept_block(e2.clone(), false).unwrap(), Accept::SideChain);
        assert!(cs.blocks.contains_key(&e1.hash()) && !cs.blocks.contains_key(&e2.hash()));
        assert_consistent(&cs);
    }

    #[test]
    fn reorganization_and_mempool() {
        let (alice, bob, carol) = (key(1), key(9), key(17));
        let mut cs = chain();
        let mut a = genesis_branch(&cs);
        let a1 = forge(&cs, &mut a, &alice, vec![], vec![]);
        let a2 = forge(&cs, &mut a, &alice, vec![], vec![]);
        for blk in [&a1, &a2] {
            assert_eq!(cs.accept_block(blk.clone(), false).unwrap(), Accept::Connected);
        }
        let fork = a.clone();

        // S spends the (mature) coinbase of a1 and is mined in a3.
        let (s, s_coin) = spend(&cs, &a1, 1, &alice, &bob, 1_000);
        assert!(cs.add_to_mempool(s.clone()).unwrap().1);
        assert!(!cs.add_to_mempool(s.clone()).unwrap().1, "second submission is not new");
        let a3 = forge(&cs, &mut a, &alice, vec![s.clone()], vec![s_coin.clone()]);
        assert_eq!(cs.accept_block(a3.clone(), false).unwrap(), Accept::Connected);
        assert!(cs.mempool.entries.is_empty(), "mined transaction left the mempool");
        assert_eq!(cs.tx_index[&s.txid()], a3.hash());
        assert!(format!("{:#}", cs.add_to_mempool(s.clone()).unwrap_err()).contains("already in chain"));

        // M spends the coinbase of a2 (mature at height 4) and waits.
        let (m, _) = spend(&cs, &a2, 2, &alice, &carol, 2_000);
        assert!(cs.add_to_mempool(m.clone()).unwrap().1);
        // A conflicting spend of the same coin is refused.
        let (m2, _) = spend(&cs, &a2, 2, &alice, &bob, 3_000);
        assert!(format!("{:#}", cs.add_to_mempool(m2).unwrap_err()).contains("not found or already spent"));

        // A competing branch from a2: the first block ties and is only
        // stored, the second one wins.
        let mut b = fork;
        let b3 = forge(&cs, &mut b, &bob, vec![], vec![]);
        assert_eq!(cs.accept_block(b3.clone(), false).unwrap(), Accept::SideChain);
        assert_eq!(cs.tip.hash, a3.hash());
        let b4 = forge(&cs, &mut b, &bob, vec![], vec![]);
        assert_eq!(cs.accept_block(b4.clone(), false).unwrap(), Accept::Reorganized);

        assert_eq!(cs.main, vec![cs.genesis_hash, a1.hash(), a2.hash(), b3.hash(), b4.hash()]);
        assert_eq!(cs.tip.state_root, b4.header.state_root);
        assert_eq!(cs.state.root(), b.state.root());
        assert_eq!(cs.heights[&b4.hash()], 4);
        assert!(!cs.on_main(&a3.hash()) && cs.blocks.contains_key(&a3.hash()), "disconnected block is kept as a side block");
        assert!(!cs.tx_index.contains_key(&a3.txs[0].txid()));
        assert_eq!(cs.tx_index[&b4.txs[0].txid()], b4.hash());
        // S came back from the disconnected block, ahead of M which was
        // already waiting; the disconnected coinbase did not.
        let pool: Vec<Hash32> = cs.mempool.entries.iter().map(|e| e.txid).collect();
        assert_eq!(pool, vec![s.txid(), m.txid()]);
        assert_consistent(&cs);

        // Both are minable on the new chain.
        let (s_coin2, m_coin2) = (cs.mempool.entries[0].coins[0].clone(), cs.mempool.entries[1].coins[0].clone());
        let b5 = forge(&cs, &mut b, &bob, vec![s, m], vec![s_coin2, m_coin2]);
        assert_eq!(cs.accept_block(b5, false).unwrap(), Accept::Connected);
        assert!(cs.mempool.entries.is_empty());
        assert_consistent(&cs);
    }

    #[test]
    fn mempool_admission_policy() {
        let (alice, bob) = (key(1), key(9));
        let mut cs = chain();
        let mut a = genesis_branch(&cs);
        let a1 = forge(&cs, &mut a, &alice, vec![], vec![]);
        let a2 = forge(&cs, &mut a, &alice, vec![], vec![]);
        let a3 = forge(&cs, &mut a, &alice, vec![], vec![]);
        for blk in [&a1, &a2, &a3] {
            assert_eq!(cs.accept_block(blk.clone(), false).unwrap(), Accept::Connected);
        }
        let reject = |cs: &mut ChainState, tx: Transaction| format!("{:#}", cs.add_to_mempool(tx).unwrap_err());

        assert!(reject(&mut cs, coinbase_tx(4, 0, p2pk(&alice))).contains("cannot be relayed"));
        let (good, _) = spend(&cs, &a1, 1, &alice, &bob, 1_000);
        // More signers than a block may verify.
        let mut tx = good.clone();
        if let Witness::Slh { signers } = &mut tx.inputs[0].witness {
            *signers = vec![signers[0].clone(); cs.params.max_sig_checks as usize + 1];
        }
        assert!(reject(&mut cs, tx).contains("BLK-8"));
        // Larger than a block can hold next to its coinbase.
        let mut tx = good.clone();
        tx.outputs.extend((0..130).map(|_| Output { value: 0, kind: OutputKind::Data { data: vec![0; MAX_DATA_LEN] } }));
        assert!(reject(&mut cs, tx).contains("BLK-7"));
        // Proofs on a transaction with no legacy input.
        let mut tx = good.clone();
        tx.proofs = vec![vec![1]; cs.params.max_migrations as usize + 1];
        assert!(reject(&mut cs, tx).contains("BLK-9"));
        // An immature coinbase (a3 matures at height 5; next block is 4).
        let (early, _) = spend(&cs, &a3, 3, &alice, &bob, 1_000);
        assert!(reject(&mut cs, early.clone()).contains("IN-2"));
        // A broken signature.
        let mut tx = good.clone();
        if let Witness::Slh { signers } = &mut tx.inputs[0].witness {
            signers[0].signature[100] ^= 1;
        }
        assert!(reject(&mut cs, tx).contains("SIG-2"));

        // The pool is bounded.
        cs.limits.mempool_txs = 1;
        assert!(cs.add_to_mempool(good.clone()).unwrap().1);
        let (second, second_coin) = spend(&cs, &a2, 2, &alice, &bob, 1_000);
        assert!(reject(&mut cs, second.clone()).contains("mempool full"));
        cs.limits.mempool_txs = 10;
        assert!(cs.add_to_mempool(second.clone()).unwrap().1);

        // A block that mines one of them leaves the other in place, and the
        // re-check does not need (or redo) any signature: break the cached
        // signature and see it survive.
        if let Witness::Slh { signers } = &mut cs.mempool.entries[0].tx.inputs[0].witness {
            signers[0].signature[100] ^= 1;
        }
        let a4 = forge(&cs, &mut a, &alice, vec![second], vec![second_coin]);
        assert_eq!(cs.accept_block(a4, false).unwrap(), Accept::Connected);
        assert_eq!(cs.mempool.entries.len(), 1);
        assert_eq!(cs.mempool.entries[0].txid, good.txid());
        // The coinbase of a3 is mature now.
        cs.mempool.clear();
        assert!(cs.add_to_mempool(early).unwrap().1);
        assert_consistent(&cs);
    }
}

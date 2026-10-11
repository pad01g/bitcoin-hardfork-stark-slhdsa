//! Chain state: block store, main chain selection, UTXO set, mempool.
//! Validation is D3 "double verification": the block receipt is verified
//! (PRF-3), then every rule is re-run natively with the block witness checked
//! against the full UTXO set.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use bhss_consensus::state::StateError;
use bhss_consensus::{apply_tx, connect_block, FullState, PrevState, ProofBackedState, StateView, TxContext};
use bhss_primitives::types::*;
use bhss_primitives::{ChainParams, Decode, Encode, Hash32};
use bhss_prover::NativeMigrationChecker;
use bhss_snapshot::GenesisCoins;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accept {
    AlreadyKnown,
    Connected,
    Reorganized,
    SideChain,
    Orphan,
}

pub struct ChainState {
    pub params: ChainParams,
    pub params_hash: Hash32,
    pub genesis_hash: Hash32,
    pub genesis_coins: GenesisCoins,
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
}

/// A view used to validate a block statelessly against the full set: coins
/// are looked up in `base` (with an in-block overlay) and every operation is
/// also checked against the SMT proofs in the block witness (STATE-2).
struct CheckingState<'a> {
    base: &'a FullState,
    proofs: ProofBackedState<'a>,
    spent: BTreeSet<OutPoint>,
    created: BTreeMap<OutPoint, Coin>,
}

impl<'a> CheckingState<'a> {
    fn lookup(&self, op: &OutPoint) -> Option<&Coin> {
        if self.spent.contains(op) {
            return None;
        }
        self.created.get(op).or_else(|| self.base.get(op))
    }
}

impl StateView for CheckingState<'_> {
    fn root(&self) -> Hash32 {
        self.proofs.root()
    }
    fn spend(&mut self, outpoint: &OutPoint, coin: &Coin) -> std::result::Result<(), StateError> {
        match self.lookup(outpoint) {
            Some(c) if c == coin => {}
            _ => return Err(StateError::MissingOrMismatch),
        }
        self.proofs.spend(outpoint, coin)?;
        self.created.remove(outpoint);
        self.spent.insert(*outpoint);
        Ok(())
    }
    fn create(&mut self, outpoint: &OutPoint, coin: &Coin) -> std::result::Result<(), StateError> {
        if self.lookup(outpoint).is_some() {
            return Err(StateError::AlreadyExists);
        }
        self.proofs.create(outpoint, coin)?;
        self.spent.remove(outpoint);
        self.created.insert(*outpoint, coin.clone());
        Ok(())
    }
}

/// Overlay over the full state for mempool / template validation.
pub struct Overlay<'a> {
    base: &'a FullState,
    pub spent: BTreeSet<OutPoint>,
    pub created: BTreeMap<OutPoint, Coin>,
}

impl<'a> Overlay<'a> {
    pub fn new(base: &'a FullState) -> Self {
        Self { base, spent: BTreeSet::new(), created: BTreeMap::new() }
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
        self.base.root()
    }
    fn spend(&mut self, outpoint: &OutPoint, coin: &Coin) -> std::result::Result<(), StateError> {
        match self.lookup(outpoint) {
            Some(c) if c == coin => {}
            _ => return Err(StateError::MissingOrMismatch),
        }
        self.created.remove(outpoint);
        self.spent.insert(*outpoint);
        Ok(())
    }
    fn create(&mut self, outpoint: &OutPoint, coin: &Coin) -> std::result::Result<(), StateError> {
        if self.lookup(outpoint).is_some() {
            return Err(StateError::AlreadyExists);
        }
        self.spent.remove(outpoint);
        self.created.insert(*outpoint, coin.clone());
        Ok(())
    }
}

#[derive(Default)]
pub struct Mempool {
    /// Insertion-ordered; each entry carries the coins its inputs spend.
    pub txs: Vec<(Transaction, Vec<Coin>)>,
}

impl Mempool {
    pub fn contains(&self, txid: &Hash32) -> bool {
        self.txs.iter().any(|(t, _)| t.txid() == *txid)
    }
}

impl ChainState {
    pub fn new(params: ChainParams, genesis_coins: GenesisCoins, datadir: PathBuf) -> Result<Self> {
        let root = bhss_snapshot::genesis_state_root(&genesis_coins);
        if root != params.genesis_state_root {
            bail!("genesis state root {} does not match params {}", hex::encode(root), hex::encode(params.genesis_state_root));
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

    /// Load `main.txt` + `blocks/*.bin` from the data dir and replay them
    /// with full validation.
    pub fn load_from_disk(&mut self) -> Result<usize> {
        let main_file = self.datadir.join("main.txt");
        if !main_file.exists() {
            return Ok(0);
        }
        let list = std::fs::read_to_string(&main_file)?;
        let mut n = 0;
        for line in list.lines().skip(1) {
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
        std::fs::write(dir.join(format!("{}.bin", hex::encode(block.hash()))), block.to_bytes())?;
        Ok(())
    }

    fn persist_main(&self) -> Result<()> {
        std::fs::create_dir_all(&self.datadir)?;
        let s: Vec<String> = self.main.iter().map(hex::encode).collect();
        std::fs::write(self.datadir.join("main.txt"), s.join("\n"))?;
        Ok(())
    }

    /// Validate `block` on top of `prev` against `state` without mutating it.
    /// Returns the summary (whose roots the receipt journal must match).
    fn validate_block(&self, block: &Block, prev: &PrevState, state: &FullState) -> Result<bhss_consensus::BlockSummary> {
        let mut checking = CheckingState {
            base: state,
            proofs: ProofBackedState::new(prev.state_root, &block.witness.proofs),
            spent: BTreeSet::new(),
            created: BTreeMap::new(),
        };
        let mut migrations = NativeMigrationChecker::new(&block.txs, self.allow_fake());
        let summary = connect_block(&self.params, &self.genesis_hash, prev, block, &mut checking, &mut migrations)
            .map_err(|e| anyhow!("consensus: {e}"))?;
        if !checking.proofs.all_proofs_consumed() {
            bail!("consensus: BLK-11: unused SMT proofs in witness");
        }
        // PRF-3: the block's STARK must attest exactly this transition.
        let journal = bhss_prover::expected_block_journal(&self.params, summary.height, summary.block_hash, summary.root_prev, summary.root_next);
        bhss_prover::verify_block_receipt(&block.receipt, &journal, self.allow_fake()).context("PRF-3")?;
        Ok(summary)
    }

    /// Apply an already-validated block to the full state.
    fn apply_to_state(state: &mut FullState, block: &Block, height: u32) {
        let mut cursor = 0;
        for (i, tx) in block.txs.iter().enumerate() {
            let txid = tx.txid();
            if i > 0 {
                for input in &tx.inputs {
                    let coin = &block.witness.coins[cursor];
                    cursor += 1;
                    state.spend(&input.prevout, coin).expect("validated");
                }
            }
            for (vout, o) in tx.outputs.iter().enumerate() {
                if o.kind.is_data() {
                    continue;
                }
                let coin = Coin { output: o.clone(), height, coinbase: i == 0 };
                state.create(&OutPoint::new(txid, vout as u32), &coin).expect("validated");
            }
        }
    }

    /// Accept a block from any source. `persist` writes it to disk.
    pub fn accept_block(&mut self, block: Block, persist: bool) -> Result<Accept> {
        let hash = block.hash();
        if self.blocks.contains_key(&hash) {
            return Ok(Accept::AlreadyKnown);
        }
        let Some(&prev_height) = self.heights.get(&block.header.prev_hash) else {
            return Ok(Accept::Orphan);
        };
        let height = prev_height + 1;

        if block.header.prev_hash == self.tip.hash {
            let prev = self.tip.clone();
            let summary = self.validate_block(&block, &prev, &self.state)?;
            Self::apply_to_state(&mut self.state, &block, height);
            debug_assert_eq!(self.state.root(), summary.root_next);
            self.tip = PrevState { height, hash, state_root: summary.root_next, time: block.header.time };
            let block = Arc::new(block);
            if persist {
                self.persist_block(&block)?;
            }
            for tx in &block.txs {
                self.tx_index.insert(tx.txid(), hash);
            }
            self.heights.insert(hash, height);
            self.main.push(hash);
            self.blocks.insert(hash, block);
            if persist {
                self.persist_main()?;
            }
            self.revalidate_mempool();
            return Ok(Accept::Connected);
        }

        // Fork. Longer chain wins (constant difficulty => height == work).
        if height <= self.tip.height {
            self.heights.insert(hash, height);
            if persist {
                self.persist_block(&block)?;
            }
            self.blocks.insert(hash, Arc::new(block));
            return Ok(Accept::SideChain);
        }
        self.reorganize(block, height, persist)
    }

    fn reorganize(&mut self, block: Block, height: u32, persist: bool) -> Result<Accept> {
        // Collect the new branch from `block` back to the main chain.
        let mut branch: Vec<Arc<Block>> = vec![Arc::new(block)];
        let mut cur = branch[0].header.prev_hash;
        let mut cur_height = height - 1;
        while self.main.get(cur_height as usize) != Some(&cur) {
            let b = self.blocks.get(&cur).ok_or_else(|| anyhow!("fork ancestor missing"))?.clone();
            cur = b.header.prev_hash;
            cur_height -= 1;
            branch.push(b);
        }
        branch.reverse();
        let fork_height = cur_height;
        // Replay from genesis: simple and always correct at regtest scale.
        let mut state = FullState::from_coins(self.genesis_coins.iter().cloned());
        let genesis = self.blocks[&self.genesis_hash].clone();
        let mut prev = PrevState { height: 0, hash: self.genesis_hash, state_root: self.params.genesis_state_root, time: genesis.header.time };
        let mut new_main = vec![self.genesis_hash];
        let old_main: Vec<Arc<Block>> = self.main[1..=fork_height as usize].iter().map(|h| self.blocks[h].clone()).collect();
        for b in old_main.iter().chain(branch.iter()) {
            let summary = self.validate_block(b, &prev, &state)?;
            Self::apply_to_state(&mut state, b, summary.height);
            prev = PrevState { height: summary.height, hash: summary.block_hash, state_root: summary.root_next, time: b.header.time };
            new_main.push(summary.block_hash);
        }
        // Commit.
        let new_block = branch.last().unwrap().clone();
        let new_hash = new_block.hash();
        if persist {
            self.persist_block(&new_block)?;
        }
        self.heights.insert(new_hash, height);
        self.blocks.insert(new_hash, new_block);
        self.state = state;
        self.tip = prev;
        self.main = new_main;
        self.tx_index.clear();
        for h in &self.main {
            for tx in &self.blocks[h].txs {
                self.tx_index.insert(tx.txid(), *h);
            }
        }
        if persist {
            self.persist_main()?;
        }
        self.revalidate_mempool();
        Ok(Accept::Reorganized)
    }

    /// Validate a transaction against the current state + mempool. On success
    /// returns the coins its inputs spend.
    pub fn check_mempool_tx(&self, tx: &Transaction) -> Result<Vec<Coin>> {
        let mut overlay = Overlay::new(&self.state);
        let ctx = TxContext { params: &self.params, genesis_hash: &self.genesis_hash, height: self.tip.height + 1 };
        let mut migrations = NativeMigrationChecker::new(std::slice::from_ref(tx), self.allow_fake());
        // Replay the mempool so double spends against it are caught.
        for (i, (mtx, mcoins)) in self.mempool.txs.iter().enumerate() {
            let mut m = bhss_prover::NativeMigrationChecker::new(std::slice::from_ref(mtx), self.allow_fake());
            apply_tx(&ctx, mtx, &mtx.txid(), 0, mcoins, &mut overlay, &mut m).map_err(|e| anyhow!("mempool entry {i} invalid: {e}"))?;
        }
        if tx.is_coinbase() {
            bail!("coinbase transactions cannot be relayed");
        }
        let mut coins = Vec::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            coins.push(overlay.lookup(&input.prevout).cloned().ok_or_else(|| anyhow!("input {} not found", hex::encode(input.prevout.txid)))?);
        }
        apply_tx(&ctx, tx, &tx.txid(), 0, &coins, &mut overlay, &mut migrations).map_err(|e| anyhow!("consensus: {e}"))?;
        Ok(coins)
    }

    pub fn add_to_mempool(&mut self, tx: Transaction) -> Result<Hash32> {
        let txid = tx.txid();
        if self.mempool.contains(&txid) {
            return Ok(txid);
        }
        if self.tx_index.contains_key(&txid) {
            bail!("transaction already in chain");
        }
        let coins = self.check_mempool_tx(&tx)?;
        self.mempool.txs.push((tx, coins));
        Ok(txid)
    }

    fn revalidate_mempool(&mut self) {
        let old = std::mem::take(&mut self.mempool.txs);
        for (tx, _) in old {
            if self.tx_index.contains_key(&tx.txid()) {
                continue;
            }
            if let Ok(coins) = self.check_mempool_tx(&tx) {
                self.mempool.txs.push((tx, coins));
            }
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

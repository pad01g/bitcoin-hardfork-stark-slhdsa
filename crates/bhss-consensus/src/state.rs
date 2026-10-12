//! STATE-1..STATE-4: how a block transforms the UTXO commitment.

use alloc::vec::Vec;

use bhss_primitives::types::{Coin, OutPoint, SmtProof};
use bhss_primitives::Hash32;
use bhss_smt::{compute_root, EmptyHashes, EMPTY_LEAF};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// STATE-3: spending an outpoint that is not in the set, or whose committed
    /// coin differs from the one claimed.
    MissingOrMismatch,
    /// STATE-4: creating an outpoint that already exists.
    AlreadyExists,
    /// STATE-2: witness ran out of proofs / proof malformed.
    BadProof,
    /// STATE-2: the proof does not reproduce the current root for the
    /// claimed leaf. For a stateless verifier this is indistinguishable from
    /// STATE-3/STATE-4; a stateful verifier checks its own set first and
    /// therefore knows the witness itself is wrong.
    ProofMismatch,
}

/// A mutable view of the UTXO commitment.
pub trait StateView {
    fn root(&self) -> Hash32;
    /// Remove `outpoint`, which must currently commit to exactly `coin`.
    fn spend(&mut self, outpoint: &OutPoint, coin: &Coin) -> Result<(), StateError>;
    /// Insert `outpoint -> coin`, which must currently be absent.
    fn create(&mut self, outpoint: &OutPoint, coin: &Coin) -> Result<(), StateError>;
}

/// Stateless view: a root plus a stream of SMT proofs consumed in operation
/// order (STATE-2). Used by the zkVM guest and, natively, to check that the
/// block witness is what a stateless verifier needs.
pub struct ProofBackedState<'a> {
    root: Hash32,
    proofs: &'a [SmtProof],
    next: usize,
    empty: EmptyHashes,
}

impl<'a> ProofBackedState<'a> {
    pub fn new(root: Hash32, proofs: &'a [SmtProof]) -> Self {
        Self { root, proofs, next: 0, empty: EmptyHashes::new() }
    }
    pub fn proofs_consumed(&self) -> usize {
        self.next
    }
    pub fn all_proofs_consumed(&self) -> bool {
        self.next == self.proofs.len()
    }
    fn take(&mut self) -> Result<&'a SmtProof, StateError> {
        let p = self.proofs.get(self.next).ok_or(StateError::BadProof)?;
        self.next += 1;
        Ok(p)
    }
    fn transition(&mut self, key: &Hash32, from: &Hash32, to: &Hash32) -> Result<(), StateError> {
        let proof = self.take()?;
        let cur = compute_root(&self.empty, key, from, proof).map_err(|_| StateError::BadProof)?;
        if cur != self.root {
            return Err(StateError::ProofMismatch);
        }
        self.root = compute_root(&self.empty, key, to, proof).map_err(|_| StateError::BadProof)?;
        Ok(())
    }
}

impl StateView for ProofBackedState<'_> {
    fn root(&self) -> Hash32 {
        self.root
    }
    fn spend(&mut self, outpoint: &OutPoint, coin: &Coin) -> Result<(), StateError> {
        let key = outpoint.smt_key();
        let leaf = coin.leaf_hash();
        self.transition(&key, &leaf, &EMPTY_LEAF)
    }
    fn create(&mut self, outpoint: &OutPoint, coin: &Coin) -> Result<(), StateError> {
        let key = outpoint.smt_key();
        let leaf = coin.leaf_hash();
        self.transition(&key, &EMPTY_LEAF, &leaf)
    }
}

/// Full in-memory state: the SMT plus the coins themselves. Also records
/// proofs for every operation so a block builder can assemble the witness.
#[derive(Clone)]
pub struct FullState {
    pub smt: bhss_smt::Smt,
    pub coins: alloc::collections::BTreeMap<OutPoint, Coin>,
    pub record: Option<Vec<SmtProof>>,
}

impl Default for FullState {
    fn default() -> Self {
        Self::new()
    }
}

impl FullState {
    pub fn new() -> Self {
        Self { smt: bhss_smt::Smt::new(), coins: alloc::collections::BTreeMap::new(), record: None }
    }
    pub fn from_coins<I: IntoIterator<Item = (OutPoint, Coin)>>(iter: I) -> Self {
        let mut s = Self::new();
        for (op, coin) in iter {
            s.insert_unchecked(op, coin);
        }
        s
    }
    pub fn insert_unchecked(&mut self, op: OutPoint, coin: Coin) {
        self.smt.insert(op.smt_key(), coin.leaf_hash());
        self.coins.insert(op, coin);
    }
    pub fn get(&self, op: &OutPoint) -> Option<&Coin> {
        self.coins.get(op)
    }
    /// Start recording proofs (one per operation) for witness construction.
    pub fn start_recording(&mut self) {
        self.record = Some(Vec::new());
    }
    pub fn take_recording(&mut self) -> Vec<SmtProof> {
        self.record.take().unwrap_or_default()
    }
    fn record_proof(&mut self, key: &Hash32) {
        if self.record.is_none() {
            return;
        }
        let p = self.smt.prove(key);
        if let Some(r) = self.record.as_mut() {
            r.push(p);
        }
    }
}

impl StateView for FullState {
    fn root(&self) -> Hash32 {
        self.smt.root()
    }
    fn spend(&mut self, outpoint: &OutPoint, coin: &Coin) -> Result<(), StateError> {
        match self.coins.get(outpoint) {
            Some(c) if c == coin => {}
            _ => return Err(StateError::MissingOrMismatch),
        }
        let key = outpoint.smt_key();
        self.record_proof(&key);
        self.smt.remove(&key);
        self.coins.remove(outpoint);
        Ok(())
    }
    fn create(&mut self, outpoint: &OutPoint, coin: &Coin) -> Result<(), StateError> {
        if self.coins.contains_key(outpoint) {
            return Err(StateError::AlreadyExists);
        }
        let key = outpoint.smt_key();
        self.record_proof(&key);
        self.smt.insert(key, coin.leaf_hash());
        self.coins.insert(*outpoint, coin.clone());
        Ok(())
    }
}

/// Runs a full state and a proof-backed state side by side so that a native
/// node also checks the block witness (D3 double verification, STATE-2).
pub struct DualState<'a> {
    pub full: &'a mut FullState,
    pub proofs: ProofBackedState<'a>,
}

impl StateView for DualState<'_> {
    fn root(&self) -> Hash32 {
        self.full.root()
    }
    fn spend(&mut self, outpoint: &OutPoint, coin: &Coin) -> Result<(), StateError> {
        // The full set decides STATE-3; only then is the witness proof judged.
        if self.full.get(outpoint) != Some(coin) {
            return Err(StateError::MissingOrMismatch);
        }
        self.proofs.spend(outpoint, coin)?;
        self.full.spend(outpoint, coin)?;
        debug_assert_eq!(self.proofs.root(), self.full.root());
        Ok(())
    }
    fn create(&mut self, outpoint: &OutPoint, coin: &Coin) -> Result<(), StateError> {
        if self.full.get(outpoint).is_some() {
            return Err(StateError::AlreadyExists);
        }
        self.proofs.create(outpoint, coin)?;
        self.full.create(outpoint, coin)?;
        debug_assert_eq!(self.proofs.root(), self.full.root());
        Ok(())
    }
}

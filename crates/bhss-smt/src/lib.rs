//! SPEC §8 — the UTXO set commitment.
//!
//! * Binary tree of depth 256; the path of a key is its bits MSB-first (bit 0
//!   = left) (SMT-1).
//! * Empty leaf = 32 zero bytes; empty subtree hashes `E[d]` are derived
//!   upward: `E[256] = 0^32`, `E[d] = H(0x01 || E[d+1] || E[d+1])` (SMT-4).
//! * Inner node = `H(0x01 || left || right)` (SMT-4).
//! * Proofs carry only non-empty siblings plus a bitmap (SMT-5) and must be
//!   canonical: a sibling flagged non-empty must differ from `E[d+1]` (SMT-6).
//!
//! The tree itself (`Smt`) is a host-side structure; verifiers only need
//! [`compute_root`] and [`EmptyHashes`].
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bhss_primitives::hash::{tagged_hash, Hash32, Tag};
pub use bhss_primitives::types::SmtProof;

pub const DEPTH: usize = 256;
pub const EMPTY_LEAF: Hash32 = [0u8; 32];

#[inline]
pub fn node_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    tagged_hash(Tag::SmtNode, &[left, right])
}

/// Direction at `depth` for `key` (SMT-1): 0 = left, 1 = right.
#[inline]
pub fn key_bit(key: &Hash32, depth: usize) -> u8 {
    (key[depth / 8] >> (7 - (depth % 8))) & 1
}

/// `E[0..=256]`.
#[derive(Clone)]
pub struct EmptyHashes {
    table: Vec<Hash32>,
}

impl EmptyHashes {
    pub fn new() -> Self {
        let mut table = alloc::vec![EMPTY_LEAF; DEPTH + 1];
        for d in (0..DEPTH).rev() {
            let child = table[d + 1];
            table[d] = node_hash(&child, &child);
        }
        Self { table }
    }
    #[inline]
    pub fn at(&self, depth: usize) -> &Hash32 {
        &self.table[depth]
    }
    pub fn empty_root(&self) -> Hash32 {
        self.table[0]
    }
}

impl Default for EmptyHashes {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// Sibling count does not match bitmap.
    Malformed,
    /// A sibling flagged non-empty equals the empty hash (SMT-6).
    NonCanonical,
}

/// Root implied by `(key, leaf, proof)` (SMT-7). Verification of inclusion of
/// `leaf` under `root` is `compute_root(...) == root`; with `leaf = EMPTY_LEAF`
/// it is a non-inclusion proof; applying the same siblings to a new leaf gives
/// the root after an update (SMT-8).
pub fn compute_root(empty: &EmptyHashes, key: &Hash32, leaf: &Hash32, proof: &SmtProof) -> Result<Hash32, ProofError> {
    let expected: usize = proof.bitmap.iter().map(|b| b.count_ones() as usize).sum();
    if proof.siblings.len() != expected {
        return Err(ProofError::Malformed);
    }
    let mut h = *leaf;
    let mut idx = proof.siblings.len();
    for depth in (0..DEPTH).rev() {
        let sib: &Hash32 = if proof.has_sibling(depth) {
            idx -= 1;
            let s = &proof.siblings[idx];
            if s == empty.at(depth + 1) {
                return Err(ProofError::NonCanonical);
            }
            s
        } else {
            empty.at(depth + 1)
        };
        h = if key_bit(key, depth) == 0 { node_hash(&h, sib) } else { node_hash(sib, &h) };
    }
    Ok(h)
}

#[derive(Clone)]
enum Node {
    Empty,
    /// A subtree containing exactly one leaf. `hash` is the subtree hash at the
    /// depth where this node sits.
    Stub { key: Hash32, leaf: Hash32, hash: Hash32 },
    Branch { left: Box<Node>, right: Box<Node>, hash: Hash32 },
}

impl Node {
    fn hash<'a>(&'a self, empty: &'a EmptyHashes, depth: usize) -> &'a Hash32 {
        match self {
            Node::Empty => empty.at(depth),
            Node::Stub { hash, .. } => hash,
            Node::Branch { hash, .. } => hash,
        }
    }
    fn is_empty(&self) -> bool {
        matches!(self, Node::Empty)
    }
}

/// Hash of a single-leaf subtree rooted at `depth`.
fn stub_hash(empty: &EmptyHashes, key: &Hash32, leaf: &Hash32, depth: usize) -> Hash32 {
    let mut h = *leaf;
    for d in (depth..DEPTH).rev() {
        let sib = empty.at(d + 1);
        h = if key_bit(key, d) == 0 { node_hash(&h, sib) } else { node_hash(sib, &h) };
    }
    h
}

/// In-memory sparse Merkle tree with compact single-leaf subtrees.
#[derive(Clone)]
pub struct Smt {
    root: Node,
    empty: EmptyHashes,
    leaves: BTreeMap<Hash32, Hash32>,
}

impl Default for Smt {
    fn default() -> Self {
        Self::new()
    }
}

impl Smt {
    pub fn new() -> Self {
        Self { root: Node::Empty, empty: EmptyHashes::new(), leaves: BTreeMap::new() }
    }

    pub fn from_leaves<I: IntoIterator<Item = (Hash32, Hash32)>>(iter: I) -> Self {
        let mut t = Self::new();
        for (k, l) in iter {
            t.insert(k, l);
        }
        t
    }

    pub fn empty_hashes(&self) -> &EmptyHashes {
        &self.empty
    }

    pub fn root(&self) -> Hash32 {
        *self.root.hash(&self.empty, 0)
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn get(&self, key: &Hash32) -> Option<&Hash32> {
        self.leaves.get(key)
    }

    pub fn contains(&self, key: &Hash32) -> bool {
        self.leaves.contains_key(key)
    }

    pub fn leaves(&self) -> impl Iterator<Item = (&Hash32, &Hash32)> {
        self.leaves.iter()
    }

    /// Insert or replace. `leaf` must not be `EMPTY_LEAF` (use `remove`).
    pub fn insert(&mut self, key: Hash32, leaf: Hash32) {
        assert_ne!(leaf, EMPTY_LEAF, "insert of empty leaf");
        let root = core::mem::replace(&mut self.root, Node::Empty);
        self.root = Self::insert_at(&self.empty, root, 0, &key, &leaf);
        self.leaves.insert(key, leaf);
    }

    /// Remove; returns the previous leaf if present.
    pub fn remove(&mut self, key: &Hash32) -> Option<Hash32> {
        let prev = self.leaves.remove(key)?;
        let root = core::mem::replace(&mut self.root, Node::Empty);
        self.root = Self::remove_at(&self.empty, root, 0, key);
        Some(prev)
    }

    fn insert_at(empty: &EmptyHashes, node: Node, depth: usize, key: &Hash32, leaf: &Hash32) -> Node {
        match node {
            Node::Empty => Node::Stub { key: *key, leaf: *leaf, hash: stub_hash(empty, key, leaf, depth) },
            Node::Stub { key: k2, leaf: l2, .. } => {
                if k2 == *key {
                    return Node::Stub { key: *key, leaf: *leaf, hash: stub_hash(empty, key, leaf, depth) };
                }
                // Find first depth at which the keys diverge.
                let mut d = depth;
                while key_bit(key, d) == key_bit(&k2, d) {
                    d += 1;
                }
                let new_stub = Node::Stub { key: *key, leaf: *leaf, hash: stub_hash(empty, key, leaf, d + 1) };
                let old_stub = Node::Stub { key: k2, leaf: l2, hash: stub_hash(empty, &k2, &l2, d + 1) };
                let (left, right) = if key_bit(key, d) == 0 { (new_stub, old_stub) } else { (old_stub, new_stub) };
                let mut cur = Self::branch(empty, left, right, d);
                // Wrap upward with empty siblings until we reach `depth`.
                while d > depth {
                    d -= 1;
                    cur = if key_bit(key, d) == 0 {
                        Self::branch(empty, cur, Node::Empty, d)
                    } else {
                        Self::branch(empty, Node::Empty, cur, d)
                    };
                }
                cur
            }
            Node::Branch { left, right, .. } => {
                if key_bit(key, depth) == 0 {
                    let l = Self::insert_at(empty, *left, depth + 1, key, leaf);
                    Self::branch(empty, l, *right, depth)
                } else {
                    let r = Self::insert_at(empty, *right, depth + 1, key, leaf);
                    Self::branch(empty, *left, r, depth)
                }
            }
        }
    }

    fn branch(empty: &EmptyHashes, left: Node, right: Node, depth: usize) -> Node {
        let hash = node_hash(left.hash(empty, depth + 1), right.hash(empty, depth + 1));
        Node::Branch { left: Box::new(left), right: Box::new(right), hash }
    }

    fn remove_at(empty: &EmptyHashes, node: Node, depth: usize, key: &Hash32) -> Node {
        match node {
            Node::Empty => Node::Empty,
            Node::Stub { key: k2, leaf, hash } => {
                if k2 == *key {
                    Node::Empty
                } else {
                    Node::Stub { key: k2, leaf, hash }
                }
            }
            Node::Branch { left, right, .. } => {
                let (left, right) = if key_bit(key, depth) == 0 {
                    (Self::remove_at(empty, *left, depth + 1, key), *right)
                } else {
                    (*left, Self::remove_at(empty, *right, depth + 1, key))
                };
                match (left, right) {
                    (Node::Empty, Node::Empty) => Node::Empty,
                    (Node::Empty, Node::Stub { key, leaf, .. }) | (Node::Stub { key, leaf, .. }, Node::Empty) => {
                        Node::Stub { key, leaf, hash: stub_hash(empty, &key, &leaf, depth) }
                    }
                    (l, r) => Self::branch(empty, l, r, depth),
                }
            }
        }
    }

    /// Proof for `key` against the current root (inclusion if present,
    /// non-inclusion otherwise).
    pub fn prove(&self, key: &Hash32) -> SmtProof {
        let mut proof = SmtProof::default();
        let mut node = &self.root;
        let mut depth = 0usize;
        loop {
            match node {
                Node::Empty => break,
                Node::Stub { key: k2, leaf, .. } => {
                    if k2 == key {
                        break;
                    }
                    let mut d = depth;
                    while d < DEPTH && key_bit(key, d) == key_bit(k2, d) {
                        d += 1;
                    }
                    // At depth d the sibling is the other key's subtree at d+1.
                    if d < DEPTH {
                        proof.set_sibling(d);
                        proof.siblings.push(stub_hash(&self.empty, k2, leaf, d + 1));
                    }
                    break;
                }
                Node::Branch { left, right, .. } => {
                    let (next, sib) = if key_bit(key, depth) == 0 { (left, right) } else { (right, left) };
                    if !sib.is_empty() {
                        proof.set_sibling(depth);
                        proof.siblings.push(*sib.hash(&self.empty, depth + 1));
                    }
                    node = next;
                    depth += 1;
                }
            }
        }
        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bhss_primitives::hash::sha256;

    fn k(i: u32) -> Hash32 {
        sha256(&i.to_le_bytes())
    }
    fn l(i: u32) -> Hash32 {
        sha256(&[b"leaf", &i.to_le_bytes()[..]].concat())
    }

    #[test]
    fn empty_root_is_e0() {
        let t = Smt::new();
        assert_eq!(t.root(), t.empty_hashes().empty_root());
    }

    #[test]
    fn insert_remove_roundtrip_and_proofs() {
        let mut t = Smt::new();
        let e0 = t.root();
        for i in 0..200 {
            t.insert(k(i), l(i));
        }
        let root = t.root();
        for i in 0..200 {
            let p = t.prove(&k(i));
            assert_eq!(compute_root(t.empty_hashes(), &k(i), &l(i), &p).unwrap(), root);
            // wrong leaf fails
            assert_ne!(compute_root(t.empty_hashes(), &k(i), &l(i + 1), &p).unwrap(), root);
        }
        // non-inclusion for absent keys
        for i in 200..260 {
            let p = t.prove(&k(i));
            assert_eq!(compute_root(t.empty_hashes(), &k(i), &EMPTY_LEAF, &p).unwrap(), root);
        }
        // order independence
        let mut t2 = Smt::new();
        for i in (0..200).rev() {
            t2.insert(k(i), l(i));
        }
        assert_eq!(t2.root(), root);
        // update via proof matches tree
        let p = t.prove(&k(300));
        let predicted = compute_root(t.empty_hashes(), &k(300), &l(300), &p).unwrap();
        t.insert(k(300), l(300));
        assert_eq!(t.root(), predicted);
        // delete via proof
        let p = t.prove(&k(5));
        let predicted = compute_root(t.empty_hashes(), &k(5), &EMPTY_LEAF, &p).unwrap();
        assert_eq!(t.remove(&k(5)), Some(l(5)));
        assert_eq!(t.root(), predicted);
        for i in 0..200 {
            t.remove(&k(i));
        }
        t.remove(&k(300));
        assert_eq!(t.root(), e0);
        assert!(t.is_empty());
    }

    #[test]
    fn non_canonical_sibling_rejected() {
        // SMT-6: a proof that lists the empty hash as a non-empty sibling.
        let t = Smt::from_leaves([(k(1), l(1))]);
        let mut p = t.prove(&k(2));
        assert!(!p.has_sibling(255));
        p.set_sibling(255);
        p.siblings.push(*t.empty_hashes().at(256));
        assert_eq!(compute_root(t.empty_hashes(), &k(2), &EMPTY_LEAF, &p), Err(ProofError::NonCanonical));
        // A sibling count that disagrees with the bitmap is malformed.
        let mut p = t.prove(&k(2));
        p.siblings.push([9u8; 32]);
        assert_eq!(compute_root(t.empty_hashes(), &k(2), &EMPTY_LEAF, &p), Err(ProofError::Malformed));
    }

    #[test]
    fn proof_encoding_roundtrip() {
        use bhss_primitives::{Decode, Encode};
        let mut t = Smt::new();
        for i in 0..50 {
            t.insert(k(i), l(i));
        }
        let p = t.prove(&k(7));
        let bytes = p.to_bytes();
        let p2 = SmtProof::from_bytes(&bytes).unwrap();
        assert_eq!(p, p2);
    }
}

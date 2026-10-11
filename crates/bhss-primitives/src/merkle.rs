//! BLK-3: Merkle root over transaction commitments. Inner nodes are tagged
//! (0x0B); an odd trailing element is carried up unchanged (no duplication).

use alloc::vec::Vec;

use crate::hash::{tagged_hash, Hash32, Tag, ZERO_HASH};

pub fn merkle_root(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return ZERO_HASH;
    }
    let mut level: Vec<Hash32> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2 + 1);
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                next.push(tagged_hash(Tag::MerkleNode, &[&pair[0], &pair[1]]));
            } else {
                next.push(pair[0]);
            }
        }
        level = next;
    }
    level[0]
}

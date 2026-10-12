//! SPEC §2 — all consensus hashing is single SHA-256 with a one-byte domain tag
//! as the *first* byte hashed (HASH-1). No SHA256d anywhere.

use sha2::{Digest, Sha256};

pub type Hash32 = [u8; 32];

pub const ZERO_HASH: Hash32 = [0u8; 32];

/// Domain-separation tags (HASH-2). Adding a tag is a consensus change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    /// SMT leaf: `H(0x00 || enc(Coin))`
    SmtLeaf = 0x00,
    /// SMT inner node: `H(0x01 || left || right)`
    SmtNode = 0x01,
    /// SMT key: `H(0x02 || txid || vout_le32)`
    SmtKey = 0x02,
    /// Block hash: `H(0x03 || enc(Header))`
    BlockHeader = 0x03,
    /// Txid: `H(0x04 || enc_core(Transaction))`
    TxId = 0x04,
    /// Merkle leaf (tx commitment): `H(0x05 || txid || witness_hash)`
    TxCommit = 0x05,
    /// Witness hash: `H(0x06 || enc(witnesses))`
    Witness = 0x06,
    /// SLH-DSA sighash: `H(0x07 || genesis_hash || txid || index_le32 || leaf_hash)`
    SigHash = 0x07,
    /// Migration message: `H(0x08 || genesis_hash || txid || index_le32 || leaf_hash)`
    MigrationMsg = 0x08,
    /// Reserved (unused): migration journals are committed raw (MIG-4).
    MigrationJournal = 0x09,
    /// Chain params hash: `H(0x0A || enc(ChainParams))`
    Params = 0x0A,
    /// Merkle inner node: `H(0x0B || left || right)`
    MerkleNode = 0x0B,
    /// Reserved (unused): the genesis state is committed by its SMT root (GEN-2).
    GenesisState = 0x0C,
    /// Legacy script hash in migration journal: `H(0x0D || script_pubkey)`
    LegacyScript = 0x0D,
    /// SLH public key hash: `H(0x10 || pubkey32)`
    SlhPubKey = 0x10,
}

/// `H(tag || parts[0] || parts[1] || ...)`.
pub fn tagged_hash(tag: Tag, parts: &[&[u8]]) -> Hash32 {
    let mut h = Sha256::new();
    h.update([tag as u8]);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Plain SHA-256 (used only where an external format demands it, e.g. legacy
/// Bitcoin scripts, never for new BHSS structures).
pub fn sha256(data: &[u8]) -> Hash32 {
    Sha256::digest(data).into()
}

pub fn to_hex(h: &[u8]) -> alloc::string::String {
    hex::encode(h)
}

#[cfg(feature = "serde")]
pub mod serde_hex32 {
    use super::Hash32;
    pub fn serialize<S: serde::Serializer>(v: &Hash32, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Hash32, D::Error> {
        let s: alloc::string::String = serde::Deserialize::deserialize(d)?;
        let v = hex::decode(s).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

//! SPEC §4 (outputs & coins), §5 (transactions), §6 (blocks).

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::encoding::{Decode, DecodeError, Decoder, Encode, Encoder};
use crate::hash::{tagged_hash, Hash32, Tag, ZERO_HASH};

/// Satoshi-denominated amount (AMT-1): 0 <= v <= MAX_MONEY.
pub type Amount = u64;
pub const MAX_MONEY: Amount = 21_000_000 * 100_000_000;

/// SLH-DSA-SHA2-128s sizes (CRYPTO-1).
pub const SLH_PUBKEY_LEN: usize = 32;
pub const SLH_SIG_LEN: usize = 7856;
pub const MAX_MULTISIG_KEYS: usize = 16;
pub const MAX_DATA_LEN: usize = 1024;
pub const MAX_LEGACY_SCRIPT_LEN: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OutPoint {
    pub txid: Hash32,
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: Hash32, vout: u32) -> Self {
        Self { txid, vout }
    }
    /// SMT key (SMT-2): `H(0x02 || txid || vout_le32)`.
    pub fn smt_key(&self) -> Hash32 {
        tagged_hash(Tag::SmtKey, &[&self.txid, &self.vout.to_le_bytes()])
    }
    /// Coinbase inputs reference `(ZERO_HASH, height)` (CB-2).
    pub fn coinbase(height: u32) -> Self {
        Self { txid: ZERO_HASH, vout: height }
    }
}

impl Encode for OutPoint {
    fn encode(&self, e: &mut Encoder) {
        e.raw(&self.txid).u32(self.vout);
    }
}
impl Decode for OutPoint {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self { txid: d.array()?, vout: d.u32()? })
    }
}

/// OUT-1..OUT-6. The only spending conditions that exist.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OutputKind {
    /// 0x00 — pay to hash of one SLH-DSA public key.
    P2pkSlh { pkh: Hash32 },
    /// 0x01 — k-of-n over SLH-DSA public key hashes, 1 <= k <= n <= 16.
    MultisigSlh { k: u8, pkhs: Vec<Hash32> },
    /// 0x02 — timelock wrapper around P2pkSlh / MultisigSlh.
    /// `abs_height`: spendable only at block height >= abs_height (0 = none).
    /// `rel_blocks`: spendable only at height >= coin.height + rel_blocks (0 = none).
    Timelock { abs_height: u32, rel_blocks: u32, inner: Box<OutputKind> },
    /// 0x03 — unspendable data carrier, value MUST be 0, never enters the SMT.
    Data { data: Vec<u8> },
    /// 0x04 — Bitcoin scriptPubKey from the imported snapshot. Only the genesis
    /// state may contain these; a transaction MUST NOT create one (OUT-6).
    Legacy { script_pubkey: Vec<u8> },
}

impl OutputKind {
    pub fn tag(&self) -> u8 {
        match self {
            OutputKind::P2pkSlh { .. } => 0x00,
            OutputKind::MultisigSlh { .. } => 0x01,
            OutputKind::Timelock { .. } => 0x02,
            OutputKind::Data { .. } => 0x03,
            OutputKind::Legacy { .. } => 0x04,
        }
    }
    pub fn is_data(&self) -> bool {
        matches!(self, OutputKind::Data { .. })
    }
    pub fn is_legacy(&self) -> bool {
        matches!(self, OutputKind::Legacy { .. })
    }
    /// The SLH spending condition after unwrapping a timelock, if any.
    pub fn slh_condition(&self) -> Option<&OutputKind> {
        match self {
            OutputKind::P2pkSlh { .. } | OutputKind::MultisigSlh { .. } => Some(self),
            OutputKind::Timelock { inner, .. } => inner.slh_condition(),
            _ => None,
        }
    }
    /// Structural validity (OUT-2..OUT-5) independent of context.
    pub fn is_well_formed(&self) -> bool {
        match self {
            OutputKind::P2pkSlh { .. } => true,
            OutputKind::MultisigSlh { k, pkhs } => {
                *k >= 1 && (*k as usize) <= pkhs.len() && pkhs.len() <= MAX_MULTISIG_KEYS
            }
            OutputKind::Timelock { abs_height, rel_blocks, inner } => {
                (*abs_height > 0 || *rel_blocks > 0)
                    && matches!(**inner, OutputKind::P2pkSlh { .. } | OutputKind::MultisigSlh { .. })
                    && inner.is_well_formed()
            }
            OutputKind::Data { data } => data.len() <= MAX_DATA_LEN,
            OutputKind::Legacy { script_pubkey } => {
                !script_pubkey.is_empty() && script_pubkey.len() <= MAX_LEGACY_SCRIPT_LEN
            }
        }
    }
}

impl Encode for OutputKind {
    fn encode(&self, e: &mut Encoder) {
        e.u8(self.tag());
        match self {
            OutputKind::P2pkSlh { pkh } => {
                e.raw(pkh);
            }
            OutputKind::MultisigSlh { k, pkhs } => {
                e.u8(*k).vec(pkhs);
            }
            OutputKind::Timelock { abs_height, rel_blocks, inner } => {
                e.u32(*abs_height).u32(*rel_blocks).item(inner.as_ref());
            }
            OutputKind::Data { data } => {
                e.bytes(data);
            }
            OutputKind::Legacy { script_pubkey } => {
                e.bytes(script_pubkey);
            }
        }
    }
}
impl Decode for OutputKind {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(match d.u8()? {
            0x00 => OutputKind::P2pkSlh { pkh: d.array()? },
            0x01 => OutputKind::MultisigSlh { k: d.u8()?, pkhs: d.vec()? },
            0x02 => OutputKind::Timelock {
                abs_height: d.u32()?,
                rel_blocks: d.u32()?,
                inner: Box::new(OutputKind::decode(d)?),
            },
            0x03 => OutputKind::Data { data: d.bytes()? },
            0x04 => OutputKind::Legacy { script_pubkey: d.bytes()? },
            t => return Err(DecodeError::InvalidTag(t)),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Output {
    pub value: Amount,
    pub kind: OutputKind,
}

impl Encode for Output {
    fn encode(&self, e: &mut Encoder) {
        e.u64(self.value).item(&self.kind);
    }
}
impl Decode for Output {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self { value: d.u64()?, kind: OutputKind::decode(d)? })
    }
}

/// A UTXO as committed in the SMT (COIN-1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Coin {
    pub output: Output,
    /// Height of the block that created it (0 for imported snapshot coins, GEN-3).
    pub height: u32,
    pub coinbase: bool,
}

impl Coin {
    /// SMT leaf hash (SMT-3): `H(0x00 || enc(Coin))`.
    pub fn leaf_hash(&self) -> Hash32 {
        tagged_hash(Tag::SmtLeaf, &[&self.to_bytes()])
    }
}

impl Encode for Coin {
    fn encode(&self, e: &mut Encoder) {
        e.item(&self.output).u32(self.height).bool(self.coinbase);
    }
}
impl Decode for Coin {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self { output: Output::decode(d)?, height: d.u32()?, coinbase: d.bool()? })
    }
}

/// One SLH-DSA signer in a witness (WIT-2).
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SlhSigner {
    /// Index into `MultisigSlh.pkhs` (must be 0 for P2pkSlh).
    pub index: u8,
    pub pubkey: [u8; SLH_PUBKEY_LEN],
    #[cfg_attr(feature = "serde", serde(with = "serde_sig"))]
    pub signature: Vec<u8>,
}

impl core::fmt::Debug for SlhSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlhSigner")
            .field("index", &self.index)
            .field("pubkey", &crate::hash::to_hex(&self.pubkey))
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

#[cfg(feature = "serde")]
mod serde_sig {
    use alloc::vec::Vec;
    pub fn serialize<S: serde::Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: alloc::string::String = serde::Deserialize::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

/// WIT-1. Witness data is committed through `witness_hash` (TX-4) but is not
/// part of the txid.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Witness {
    /// 0x00 — spend of an SLH condition.
    Slh { signers: Vec<SlhSigner> },
    /// 0x01 — spend of a Legacy coin; authorization lives in the migration
    /// receipt carried in `Transaction::proofs` (MIG-*).
    Legacy,
    /// 0x02 — the coinbase input.
    Coinbase,
}

impl Encode for Witness {
    fn encode(&self, e: &mut Encoder) {
        match self {
            Witness::Slh { signers } => {
                e.u8(0x00).compact(signers.len() as u64);
                for s in signers {
                    e.u8(s.index).raw(&s.pubkey).bytes(&s.signature);
                }
            }
            Witness::Legacy => {
                e.u8(0x01);
            }
            Witness::Coinbase => {
                e.u8(0x02);
            }
        }
    }
}
impl Decode for Witness {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(match d.u8()? {
            0x00 => {
                let n = d.len()?;
                let mut signers = Vec::with_capacity(n.min(MAX_MULTISIG_KEYS));
                for _ in 0..n {
                    signers.push(SlhSigner { index: d.u8()?, pubkey: d.array()?, signature: d.bytes()? });
                }
                Witness::Slh { signers }
            }
            0x01 => Witness::Legacy,
            0x02 => Witness::Coinbase,
            t => return Err(DecodeError::InvalidTag(t)),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Input {
    pub prevout: OutPoint,
    pub witness: Witness,
}

/// TX-1. `proofs` carries one serialized migration receipt per Legacy input,
/// in input order; it is neither part of the txid nor of the witness hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub locktime: u32,
    pub proofs: Vec<Vec<u8>>,
}

impl Transaction {
    pub const VERSION: u32 = 1;

    /// Core encoding (TX-2): everything except witnesses and proofs.
    pub fn encode_core(&self, e: &mut Encoder) {
        e.u32(self.version).compact(self.inputs.len() as u64);
        for i in &self.inputs {
            e.item(&i.prevout);
        }
        e.vec(&self.outputs).u32(self.locktime);
    }
    pub fn core_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_core(&mut e);
        e.finish()
    }
    /// TX-3: `txid = H(0x04 || enc_core)`.
    pub fn txid(&self) -> Hash32 {
        tagged_hash(Tag::TxId, &[&self.core_bytes()])
    }
    /// TX-4: `witness_hash = H(0x06 || enc(witnesses))`.
    pub fn witness_hash(&self) -> Hash32 {
        let mut e = Encoder::new();
        e.compact(self.inputs.len() as u64);
        for i in &self.inputs {
            e.item(&i.witness);
        }
        tagged_hash(Tag::Witness, &[e.as_slice()])
    }
    /// TX-5: `tx_commit = H(0x05 || txid || witness_hash)`.
    pub fn commitment(&self) -> Hash32 {
        tagged_hash(Tag::TxCommit, &[&self.txid(), &self.witness_hash()])
    }
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && matches!(self.inputs[0].witness, Witness::Coinbase)
    }
    /// Encoding without `proofs` (used for block size accounting, BLK-7).
    pub fn committed_size(&self) -> usize {
        let mut e = Encoder::new();
        self.encode_committed(&mut e);
        e.as_slice().len()
    }
    fn encode_committed(&self, e: &mut Encoder) {
        e.u32(self.version).vec(&self.inputs).vec(&self.outputs).u32(self.locktime);
    }
}

impl Encode for Input {
    fn encode(&self, e: &mut Encoder) {
        e.item(&self.prevout).item(&self.witness);
    }
}
impl Decode for Input {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self { prevout: OutPoint::decode(d)?, witness: Witness::decode(d)? })
    }
}
impl Encode for Transaction {
    fn encode(&self, e: &mut Encoder) {
        self.encode_committed(e);
        e.compact(self.proofs.len() as u64);
        for p in &self.proofs {
            e.bytes(p);
        }
    }
}
impl Decode for Transaction {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let version = d.u32()?;
        let inputs = d.vec()?;
        let outputs = d.vec()?;
        let locktime = d.u32()?;
        let n = d.len()?;
        let mut proofs = Vec::with_capacity(n.min(16));
        for _ in 0..n {
            proofs.push(d.bytes()?);
        }
        Ok(Self { version, inputs, outputs, locktime, proofs })
    }
}

/// HDR-1.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Header {
    pub version: u32,
    pub prev_hash: Hash32,
    pub merkle_root: Hash32,
    /// SMT root *after* applying this block (HDR-3).
    pub state_root: Hash32,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl Header {
    pub const VERSION: u32 = 1;
    /// HDR-2: `block_hash = H(0x03 || enc(Header))`.
    pub fn hash(&self) -> Hash32 {
        tagged_hash(Tag::BlockHeader, &[&self.to_bytes()])
    }
}

impl Encode for Header {
    fn encode(&self, e: &mut Encoder) {
        e.u32(self.version)
            .raw(&self.prev_hash)
            .raw(&self.merkle_root)
            .raw(&self.state_root)
            .u32(self.time)
            .u32(self.bits)
            .u32(self.nonce);
    }
}
impl Decode for Header {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            version: d.u32()?,
            prev_hash: d.array()?,
            merkle_root: d.array()?,
            state_root: d.array()?,
            time: d.u32()?,
            bits: d.u32()?,
            nonce: d.u32()?,
        })
    }
}

/// Compact SMT inclusion / non-inclusion proof (SMT-5). `bitmap` bit `i`
/// (bit 7 of byte 0 is depth 0) is set when the sibling at depth `i` is
/// non-empty; `siblings` lists those hashes from depth 0 downward.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SmtProof {
    pub bitmap: [u8; 32],
    pub siblings: Vec<Hash32>,
}

impl SmtProof {
    #[inline]
    pub fn has_sibling(&self, depth: usize) -> bool {
        (self.bitmap[depth / 8] >> (7 - (depth % 8))) & 1 == 1
    }
    #[inline]
    pub fn set_sibling(&mut self, depth: usize) {
        self.bitmap[depth / 8] |= 1 << (7 - (depth % 8));
    }
}

impl Encode for SmtProof {
    fn encode(&self, e: &mut Encoder) {
        e.raw(&self.bitmap).vec(&self.siblings);
    }
}
impl Decode for SmtProof {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let bitmap: [u8; 32] = d.array()?;
        let siblings: Vec<Hash32> = d.vec()?;
        let expected = bitmap.iter().map(|b| b.count_ones() as usize).sum::<usize>();
        if siblings.len() != expected {
            return Err(DecodeError::InvalidValue("smt proof sibling count"));
        }
        Ok(Self { bitmap, siblings })
    }
}

/// BLK-2. Uncommitted data needed by a stateless verifier: the spent coins
/// (one per non-coinbase input, block order) and one SMT proof per state
/// operation in canonical order (STATE-2).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlockWitness {
    pub coins: Vec<Coin>,
    pub proofs: Vec<SmtProof>,
}

impl Encode for BlockWitness {
    fn encode(&self, e: &mut Encoder) {
        e.vec(&self.coins).vec(&self.proofs);
    }
}
impl Decode for BlockWitness {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self { coins: d.vec()?, proofs: d.vec()? })
    }
}

/// BLK-1.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Block {
    pub header: Header,
    pub txs: Vec<Transaction>,
    pub witness: BlockWitness,
    /// Serialized RISC Zero receipt for the block (PRF-*). Empty only for genesis.
    pub receipt: Vec<u8>,
}

impl Block {
    pub fn hash(&self) -> Hash32 {
        self.header.hash()
    }
    /// BLK-7 size accounting: encoded transactions without proofs.
    pub fn committed_tx_bytes(&self) -> usize {
        self.txs.iter().map(|t| t.committed_size()).sum::<usize>() + compact_len(self.txs.len())
    }
}

pub fn compact_len(n: usize) -> usize {
    match n as u64 {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

impl Encode for Block {
    fn encode(&self, e: &mut Encoder) {
        e.item(&self.header).vec(&self.txs).item(&self.witness).bytes(&self.receipt);
    }
}
impl Decode for Block {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self { header: Header::decode(d)?, txs: d.vec()?, witness: BlockWitness::decode(d)?, receipt: d.bytes()? })
    }
}

/// Journal committed by the block guest (PRF-2). Encoded with the canonical codec.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlockJournal {
    pub params_hash: Hash32,
    pub height: u32,
    pub block_hash: Hash32,
    pub root_prev: Hash32,
    pub root_next: Hash32,
    /// Image ID of the migration guest the block guest accepted assumptions from.
    pub migrate_image_id: Hash32,
}

impl Encode for BlockJournal {
    fn encode(&self, e: &mut Encoder) {
        e.raw(&self.params_hash)
            .u32(self.height)
            .raw(&self.block_hash)
            .raw(&self.root_prev)
            .raw(&self.root_next)
            .raw(&self.migrate_image_id);
    }
}
impl Decode for BlockJournal {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            params_hash: d.array()?,
            height: d.u32()?,
            block_hash: d.array()?,
            root_prev: d.array()?,
            root_next: d.array()?,
            migrate_image_id: d.array()?,
        })
    }
}

/// Journal committed by the migration guest (MIG-4): the signed message and
/// the hash of the legacy script that authorized it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationJournal {
    pub msg: Hash32,
    pub script_hash: Hash32,
}

impl MigrationJournal {
    pub fn script_hash_of(script_pubkey: &[u8]) -> Hash32 {
        tagged_hash(Tag::LegacyScript, &[script_pubkey])
    }
}

impl Encode for MigrationJournal {
    fn encode(&self, e: &mut Encoder) {
        e.raw(&self.msg).raw(&self.script_hash);
    }
}
impl Decode for MigrationJournal {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self { msg: d.array()?, script_hash: d.array()? })
    }
}

/// SIG-1: message signed by SLH-DSA for input `index`.
pub fn slh_sighash(genesis_hash: &Hash32, txid: &Hash32, index: u32, leaf_hash: &Hash32) -> Hash32 {
    tagged_hash(Tag::SigHash, &[genesis_hash, txid, &index.to_le_bytes(), leaf_hash])
}

/// MIG-3: message signed by the legacy key for input `index`.
pub fn migration_msg(genesis_hash: &Hash32, txid: &Hash32, index: u32, leaf_hash: &Hash32) -> Hash32 {
    tagged_hash(Tag::MigrationMsg, &[genesis_hash, txid, &index.to_le_bytes(), leaf_hash])
}

/// OUT-1: `pkh = H(0x10 || pubkey)`.
pub fn slh_pubkey_hash(pubkey: &[u8; SLH_PUBKEY_LEN]) -> Hash32 {
    tagged_hash(Tag::SlhPubKey, &[pubkey])
}

//! SPEC §7 — chain parameters. Everything here is consensus; `params_hash`
//! (PAR-2) is committed in every block journal.

use alloc::string::String;
use alloc::vec::Vec;

use crate::encoding::{Decode, DecodeError, Decoder, Encode, Encoder};
use crate::hash::{tagged_hash, Hash32, Tag};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ChainParams {
    /// Human readable network name, also the bech32m HRP (e.g. "bhrt").
    pub name: String,
    /// BLK-7: max encoded size of the transaction list (without proofs).
    pub max_block_tx_bytes: u32,
    /// BLK-8: max SLH-DSA signature verifications per block.
    pub max_sig_checks: u32,
    /// BLK-9: max migration (legacy) inputs per block.
    pub max_migrations: u32,
    /// CB-4.
    pub coinbase_maturity: u32,
    /// CB-3.
    pub subsidy_halving_interval: u32,
    pub initial_subsidy: u64,
    /// POW-1: compact target every block must satisfy (constant difficulty).
    pub pow_bits: u32,
    pub genesis_time: u32,
    /// Root of the SMT built from the genesis state (GEN-2).
    #[cfg_attr(feature = "serde", serde(with = "crate::hash::serde_hex32"))]
    pub genesis_state_root: Hash32,
    /// PRF-5: if false, RISC Zero dev-mode (fake) receipts are accepted.
    pub require_real_proofs: bool,
}

impl ChainParams {
    /// PAR-2: `H(0x0A || enc(ChainParams))`.
    pub fn hash(&self) -> Hash32 {
        tagged_hash(Tag::Params, &[&self.to_bytes()])
    }

    /// Defaults for the regtest network (`bhrt`). The genesis state root is
    /// filled in by whoever builds the genesis state.
    pub fn regtest(genesis_state_root: Hash32) -> Self {
        Self {
            name: String::from("bhrt"),
            max_block_tx_bytes: 128 * 1024,
            max_sig_checks: 16,
            max_migrations: 16,
            coinbase_maturity: 100,
            subsidy_halving_interval: 150,
            initial_subsidy: 50 * 100_000_000,
            pow_bits: 0x207f_ffff,
            genesis_time: 1_760_000_000,
            genesis_state_root,
            require_real_proofs: false,
        }
    }

    /// CB-3.
    pub fn subsidy(&self, height: u32) -> u64 {
        let halvings = height / self.subsidy_halving_interval;
        if halvings >= 64 {
            0
        } else {
            self.initial_subsidy >> halvings
        }
    }

    /// POW-2: decode compact `bits` into a 256-bit big-endian target.
    pub fn target(&self) -> [u8; 32] {
        compact_to_target(self.pow_bits)
    }
}

/// Bitcoin compact encoding → 256-bit big-endian target (POW-2).
pub fn compact_to_target(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    let mut target = [0u8; 32];
    if exponent <= 3 {
        let m = mantissa >> (8 * (3 - exponent));
        target[29..32].copy_from_slice(&m.to_be_bytes()[1..]);
    } else {
        let shift = exponent - 3;
        let m = mantissa.to_be_bytes();
        // mantissa occupies bytes [32 - exponent, 32 - exponent + 3)
        let start = 32usize.saturating_sub(shift + 3);
        if shift + 3 <= 32 {
            target[start..start + 3].copy_from_slice(&m[1..]);
        } else {
            target = [0xff; 32];
        }
    }
    target
}

/// POW-1: hash (interpreted as big-endian 256-bit) <= target.
pub fn hash_meets_target(hash: &Hash32, target: &[u8; 32]) -> bool {
    hash <= target
}

impl Encode for ChainParams {
    fn encode(&self, e: &mut Encoder) {
        e.bytes(self.name.as_bytes())
            .u32(self.max_block_tx_bytes)
            .u32(self.max_sig_checks)
            .u32(self.max_migrations)
            .u32(self.coinbase_maturity)
            .u32(self.subsidy_halving_interval)
            .u64(self.initial_subsidy)
            .u32(self.pow_bits)
            .u32(self.genesis_time)
            .raw(&self.genesis_state_root)
            .bool(self.require_real_proofs);
    }
}
impl Decode for ChainParams {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let name_bytes: Vec<u8> = d.bytes()?;
        let name = String::from_utf8(name_bytes).map_err(|_| DecodeError::InvalidValue("utf8"))?;
        Ok(Self {
            name,
            max_block_tx_bytes: d.u32()?,
            max_sig_checks: d.u32()?,
            max_migrations: d.u32()?,
            coinbase_maturity: d.u32()?,
            subsidy_halving_interval: d.u32()?,
            initial_subsidy: d.u64()?,
            pow_bits: d.u32()?,
            genesis_time: d.u32()?,
            genesis_state_root: d.array()?,
            require_real_proofs: d.bool()?,
        })
    }
}

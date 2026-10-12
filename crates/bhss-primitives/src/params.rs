//! SPEC §7 — chain parameters. Everything here is consensus; `params_hash`
//! (PAR-2) is committed in every block journal.

use alloc::string::String;
use alloc::vec::Vec;

use crate::encoding::{Decode, DecodeError, Decoder, Encode, Encoder};
use crate::hash::{tagged_hash, Hash32, Tag};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct ChainParams {
    /// Human readable network name, also the bech32m HRP (e.g. "bhrt").
    pub name: String,
    /// BLK-7: max encoded size of the transaction list (without proofs).
    pub max_block_tx_bytes: u32,
    /// BLK-8: max SLH-DSA signature verifications per block.
    pub max_sig_checks: u32,
    /// BLK-9: max migration (legacy) inputs per block.
    pub max_migrations: u32,
    /// IN-2 (coins created by a coinbase, CB-4).
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
    /// PAR-5 / PRF-1: image ID of the block guest every receipt must verify for.
    #[cfg_attr(feature = "serde", serde(with = "crate::hash::serde_hex32"))]
    pub block_image_id: Hash32,
    /// PAR-5 / MIG-2: image ID of the migration guest.
    #[cfg_attr(feature = "serde", serde(with = "crate::hash::serde_hex32"))]
    pub migrate_image_id: Hash32,
}

impl ChainParams {
    /// PAR-2: `H(0x0A || enc(ChainParams))`.
    pub fn hash(&self) -> Hash32 {
        tagged_hash(Tag::Params, &[&self.to_bytes()])
    }

    /// Defaults for the regtest network (`bhrt`). The genesis state root is
    /// filled in by whoever builds the genesis state; the guest image IDs
    /// are zero until `with_images` (a node refuses zero IDs, PAR-5).
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
            block_image_id: [0u8; 32],
            migrate_image_id: [0u8; 32],
        }
    }

    /// Same, with the guest image IDs filled in (PAR-5).
    pub fn with_images(mut self, block_image_id: Hash32, migrate_image_id: Hash32) -> Self {
        self.block_image_id = block_image_id;
        self.migrate_image_id = migrate_image_id;
        self
    }

    /// PAR-4: reject parameter sets the rules cannot operate on.
    pub fn validate(&self) -> Result<(), &'static str> {
        // The name is also the bech32m HRP (PAR-3).
        if self.name.is_empty() || self.name.len() > 83 || !self.name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
            return Err("PAR-4: name must be 1..=83 characters of [a-z0-9]");
        }
        if self.subsidy_halving_interval == 0 {
            return Err("PAR-4: subsidy_halving_interval must be > 0");
        }
        if self.max_block_tx_bytes == 0 || self.max_sig_checks == 0 {
            return Err("PAR-4: block limits must be > 0");
        }
        if self.initial_subsidy > crate::types::MAX_MONEY {
            return Err("PAR-4: initial_subsidy > MAX_MONEY");
        }
        if self.target() == [0u8; 32] {
            return Err("PAR-4: target is zero (unsatisfiable)");
        }
        if (self.pow_bits >> 24) > 32 {
            return Err("PAR-4: pow_bits exponent overflows 256 bits");
        }
        Ok(())
    }

    /// CB-3.
    pub fn subsidy(&self, height: u32) -> u64 {
        let halvings = height / self.subsidy_halving_interval.max(1);
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
            .bool(self.require_real_proofs)
            .raw(&self.block_image_id)
            .raw(&self.migrate_image_id);
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
            block_image_id: d.array()?,
            migrate_image_id: d.array()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).unwrap();
        out
    }

    #[test]
    fn compact_target_vectors() {
        // Bitcoin main-net genesis difficulty.
        assert_eq!(compact_to_target(0x1d00ffff), hex32("00000000ffff0000000000000000000000000000000000000000000000000000"));
        // Regtest.
        assert_eq!(compact_to_target(0x207fffff), hex32("7fffff0000000000000000000000000000000000000000000000000000000000"));
        // Small exponents place the mantissa at the low end.
        assert_eq!(compact_to_target(0x03123456), hex32("0000000000000000000000000000000000000000000000000000000000123456"));
        assert_eq!(compact_to_target(0x01123456), hex32("0000000000000000000000000000000000000000000000000000000000000012"));
        assert!(hash_meets_target(&[0u8; 32], &compact_to_target(0x1d00ffff)));
        assert!(!hash_meets_target(&[0xffu8; 32], &compact_to_target(0x207fffff)));
    }

    #[test]
    fn params_validation() {
        let p = ChainParams::regtest([0u8; 32]);
        assert!(p.validate().is_ok());
        let mut bad = p.clone();
        bad.subsidy_halving_interval = 0;
        assert!(bad.validate().is_err());
        let mut bad = p.clone();
        bad.pow_bits = 0x2100ffff; // exponent 33
        assert!(bad.validate().is_err());
        let mut bad = p.clone();
        bad.pow_bits = 0x03000000; // zero target
        assert!(bad.validate().is_err());
        let mut bad = p.clone();
        bad.name = String::new();
        assert!(bad.validate().is_err());
        let mut bad = p.clone();
        bad.name = String::from("Bhrt");
        assert!(bad.validate().is_err());
        // The image ids are part of the parameter hash (PAR-5).
        let with = p.clone().with_images([1u8; 32], [2u8; 32]);
        assert_ne!(with.hash(), p.hash());
        assert_eq!(ChainParams::from_bytes(&with.to_bytes()).unwrap(), with);
    }
}

//! SPEC §11 — legacy (snapshot) coins and migration authorization.
//!
//! A Legacy coin carries a Bitcoin scriptPubKey. BHSS does not run Bitcoin
//! Script; instead each supported *template* (LEG-1) is recognised
//! structurally and authorised by a secp256k1 signature over the 32-byte
//! migration message `m` (MIG-3) — *not* over a Bitcoin sighash. ECDSA
//! signatures are 64-byte compact `r||s`; Schnorr signatures are BIP340.
//! This verification runs only inside the migration guest (MIG-2).
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use bhss_primitives::encoding::{Decode, DecodeError, Decoder, Encode, Encoder};
use bhss_primitives::Hash32;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::Digest;

#[cfg(feature = "sign")]
pub mod sign;

pub const MAX_MULTISIG_PUBKEYS: usize = 16;

/// LEG-1: recognised scriptPubKey templates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LegacyKind {
    /// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`
    P2pkh { pkh: [u8; 20] },
    /// `OP_0 <20>`
    P2wpkh { pkh: [u8; 20] },
    /// `OP_HASH160 <20> OP_EQUAL` (redeem script supplied by the spender)
    P2sh { sh: [u8; 20] },
    /// `OP_0 <32>` (witness script supplied by the spender)
    P2wsh { sh: [u8; 32] },
    /// `OP_1 <32>` key-path only
    P2tr { xonly: [u8; 32] },
    /// `<33|65 byte pubkey> OP_CHECKSIG`
    P2pk { pubkey: Vec<u8> },
}

pub fn classify(script: &[u8]) -> Option<LegacyKind> {
    match script {
        [0x76, 0xa9, 0x14, mid @ .., 0x88, 0xac] if mid.len() == 20 => {
            Some(LegacyKind::P2pkh { pkh: mid.try_into().unwrap() })
        }
        [0x00, 0x14, rest @ ..] if rest.len() == 20 => Some(LegacyKind::P2wpkh { pkh: rest.try_into().unwrap() }),
        [0xa9, 0x14, mid @ .., 0x87] if mid.len() == 20 => Some(LegacyKind::P2sh { sh: mid.try_into().unwrap() }),
        [0x00, 0x20, rest @ ..] if rest.len() == 32 => Some(LegacyKind::P2wsh { sh: rest.try_into().unwrap() }),
        [0x51, 0x20, rest @ ..] if rest.len() == 32 => Some(LegacyKind::P2tr { xonly: rest.try_into().unwrap() }),
        [0x21, mid @ .., 0xac] if mid.len() == 33 => Some(LegacyKind::P2pk { pubkey: mid.to_vec() }),
        [0x41, mid @ .., 0xac] if mid.len() == 65 => Some(LegacyKind::P2pk { pubkey: mid.to_vec() }),
        _ => None,
    }
}

/// Parse `OP_k <pk>... OP_n OP_CHECKMULTISIG` (LEG-2).
pub fn parse_multisig(script: &[u8]) -> Option<(usize, Vec<Vec<u8>>)> {
    if script.len() < 3 {
        return None;
    }
    let op_k = script[0];
    let op_n = script[script.len() - 2];
    if script[script.len() - 1] != 0xae {
        return None;
    }
    let k = small_int(op_k)?;
    let n = small_int(op_n)?;
    let mut pos = 1;
    let mut keys = Vec::new();
    while pos < script.len() - 2 {
        let len = script[pos] as usize;
        if len != 33 && len != 65 {
            return None;
        }
        let end = pos + 1 + len;
        if end > script.len() - 2 {
            return None;
        }
        keys.push(script[pos + 1..end].to_vec());
        pos = end;
    }
    if keys.len() != n || k == 0 || k > n || n > MAX_MULTISIG_PUBKEYS {
        return None;
    }
    Some((k, keys))
}

fn small_int(op: u8) -> Option<usize> {
    match op {
        0x51..=0x60 => Some((op - 0x50) as usize),
        _ => None,
    }
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = sha2::Sha256::digest(data);
    ripemd::Ripemd160::digest(sha).into()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

/// MIG-5: the private authorization data presented to the migration guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationAuth {
    /// 0x00 — P2PKH / P2WPKH / P2SH-P2WPKH: reveal pubkey, ECDSA over `m`.
    KeyHash { pubkey: Vec<u8>, sig: [u8; 64] },
    /// 0x01 — P2PK: ECDSA over `m` under the script's pubkey.
    PubKey { sig: [u8; 64] },
    /// 0x02 — P2TR key path: BIP340 over `m` under the output key.
    Taproot { sig: [u8; 64] },
    /// 0x03 — P2SH / P2WSH wrapping a bare multisig script.
    Multisig { script: Vec<u8>, sigs: Vec<[u8; 64]> },
}

impl Encode for MigrationAuth {
    fn encode(&self, e: &mut Encoder) {
        match self {
            MigrationAuth::KeyHash { pubkey, sig } => {
                e.u8(0x00).bytes(pubkey).raw(sig);
            }
            MigrationAuth::PubKey { sig } => {
                e.u8(0x01).raw(sig);
            }
            MigrationAuth::Taproot { sig } => {
                e.u8(0x02).raw(sig);
            }
            MigrationAuth::Multisig { script, sigs } => {
                e.u8(0x03).bytes(script).compact(sigs.len() as u64);
                for s in sigs {
                    e.raw(s);
                }
            }
        }
    }
}
impl Decode for MigrationAuth {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(match d.u8()? {
            0x00 => MigrationAuth::KeyHash { pubkey: d.bytes()?, sig: d.array()? },
            0x01 => MigrationAuth::PubKey { sig: d.array()? },
            0x02 => MigrationAuth::Taproot { sig: d.array()? },
            0x03 => {
                let script = d.bytes()?;
                let n = d.len()?;
                let mut sigs = Vec::with_capacity(n.min(MAX_MULTISIG_PUBKEYS));
                for _ in 0..n {
                    sigs.push(d.array()?);
                }
                MigrationAuth::Multisig { script, sigs }
            }
            t => return Err(DecodeError::InvalidTag(t)),
        })
    }
}

fn ecdsa_verify(pubkey: &[u8], msg: &Hash32, sig: &[u8; 64]) -> bool {
    let vk = match k256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = match k256::ecdsa::Signature::from_slice(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify_prehash(msg, &sig).is_ok()
}

fn schnorr_verify(xonly: &[u8; 32], msg: &Hash32, sig: &[u8; 64]) -> bool {
    let vk = match k256::schnorr::VerifyingKey::from_bytes(xonly) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = match k256::schnorr::Signature::try_from(&sig[..]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    use k256::schnorr::signature::hazmat::PrehashVerifier as _;
    vk.verify_prehash(msg, &sig).is_ok()
}

/// CHECKMULTISIG semantics without Script: signatures must match pubkeys in
/// script order, each pubkey consumed at most once (LEG-3).
fn multisig_verify(script: &[u8], msg: &Hash32, sigs: &[[u8; 64]]) -> bool {
    let (k, keys) = match parse_multisig(script) {
        Some(v) => v,
        None => return false,
    };
    if sigs.len() != k {
        return false;
    }
    let mut si = 0;
    for key in &keys {
        if si == sigs.len() {
            break;
        }
        if ecdsa_verify(key, msg, &sigs[si]) {
            si += 1;
        }
    }
    si == sigs.len()
}

/// MIG-2: does `auth` authorise message `m` for `script_pubkey`?
pub fn verify_migration(script_pubkey: &[u8], m: &Hash32, auth: &MigrationAuth) -> bool {
    let kind = match classify(script_pubkey) {
        Some(k) => k,
        None => return false,
    };
    match (kind, auth) {
        (LegacyKind::P2pkh { pkh }, MigrationAuth::KeyHash { pubkey, sig }) => {
            hash160(pubkey) == pkh && ecdsa_verify(pubkey, m, sig)
        }
        (LegacyKind::P2wpkh { pkh }, MigrationAuth::KeyHash { pubkey, sig }) => {
            pubkey.len() == 33 && hash160(pubkey) == pkh && ecdsa_verify(pubkey, m, sig)
        }
        (LegacyKind::P2sh { sh }, MigrationAuth::KeyHash { pubkey, sig }) => {
            // P2SH-P2WPKH: redeemScript = OP_0 <20 hash160(pubkey)>
            if pubkey.len() != 33 {
                return false;
            }
            let mut redeem = alloc::vec![0x00, 0x14];
            redeem.extend_from_slice(&hash160(pubkey));
            hash160(&redeem) == sh && ecdsa_verify(pubkey, m, sig)
        }
        (LegacyKind::P2sh { sh }, MigrationAuth::Multisig { script, sigs }) => {
            hash160(script) == sh && multisig_verify(script, m, sigs)
        }
        (LegacyKind::P2wsh { sh }, MigrationAuth::Multisig { script, sigs }) => {
            sha256(script) == sh && multisig_verify(script, m, sigs)
        }
        (LegacyKind::P2tr { xonly }, MigrationAuth::Taproot { sig }) => schnorr_verify(&xonly, m, sig),
        (LegacyKind::P2pk { pubkey }, MigrationAuth::PubKey { sig }) => ecdsa_verify(&pubkey, m, sig),
        _ => false,
    }
}

/// Input frame of the migration guest (MIG-6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationInput {
    pub msg: Hash32,
    pub script_pubkey: Vec<u8>,
    pub auth: MigrationAuth,
}

impl Encode for MigrationInput {
    fn encode(&self, e: &mut Encoder) {
        e.raw(&self.msg).bytes(&self.script_pubkey).item(&self.auth);
    }
}
impl Decode for MigrationInput {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self { msg: d.array()?, script_pubkey: d.bytes()?, auth: MigrationAuth::decode(d)? })
    }
}

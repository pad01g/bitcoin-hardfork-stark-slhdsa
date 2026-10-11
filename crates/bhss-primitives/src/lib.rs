//! BHSS primitives: hashing (SPEC §2), canonical encoding (SPEC §3) and the
//! consensus data model (SPEC §4-§6). `no_std` + `alloc` so the same code runs
//! natively and inside the RISC Zero guest.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "address")]
pub mod address;
pub mod encoding;
pub mod hash;
pub mod merkle;
pub mod params;
pub mod types;

pub use encoding::{Decode, DecodeError, Decoder, Encode, Encoder};
pub use hash::{tagged_hash, Hash32, Tag};
pub use params::ChainParams;
pub use types::*;

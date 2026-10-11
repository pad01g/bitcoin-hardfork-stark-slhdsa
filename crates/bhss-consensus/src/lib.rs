//! BHSS consensus. Every check cites its rule ID in `docs/SPEC.md`.
//!
//! The same `connect_block` runs (a) natively in the node against the real
//! UTXO set and (b) inside the RISC Zero guest against a proof-backed view of
//! the state root. The only behavioural difference is who implements
//! [`StateView`] and [`MigrationChecker`].
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod genesis;
pub mod state;
pub mod validate;

pub use bhss_primitives as primitives;
pub use state::{ProofBackedState, StateError, StateView};
pub use state::{DualState, FullState};
pub use validate::{
    apply_block_body, apply_tx, body_merkle_root, connect_block, BlockSummary, BodyResult, ConsensusError,
    MigrationChecker, NoMigrations, PrevState, Result, TxContext, TxResult,
};

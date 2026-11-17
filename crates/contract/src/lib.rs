//! Lichen's contract on Bitcoin: the parties and their keys ([`keys`]),
//! the contract's terms and leaves ([`leaves`]), and its transactions,
//! cooperative and pre-signed ([`graph`]). The dispute behind `escalate`
//! (BABE) builds on this, in `lichen_babe`.
//!
//! Begun as ln-gap's session contract (its `sessions` and `channel`
//! crates, at 8b057ed); the scripts are unchanged.

pub mod graph;
pub mod keys;
pub mod leaves;

pub use graph::*;
pub use keys::*;
pub use leaves::*;

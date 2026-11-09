//! An exit record (docs/HUB_PROVES_PLAN.md): once a claim holds, the
//! hub's record (`Tx::Exit`) retires its notes on the L2. A claim names
//! its notes by their positions in the commitment tree, and its
//! fingerprint `E` is what each note's owner signed:
//!
//! ```text
//! E = SHA256("lichen/exit" ‖ c ‖ O_D ‖ b ‖ i_1 ‖ … ‖ i_n)
//! ```
//!
//! for contract `c` of deposit coin `O_D`, claiming `b`, positions
//! increasing. The record carries each note's opening at its position
//! (shown in the tree, as a spend's), one signature on `E` per owner, in
//! the order the owners first appear ([`owners`]), and the hub's. The
//! owners' signatures are the authority, as for a spend, so a record
//! exists only for a claim the owners made.
//!
//! Integers are big-endian, as in the statements.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::{Hash, OutPoint, TNote};

/// At most this many notes in a claim.
pub const MAX_NOTES: usize = 64;

/// `E` for contract `c` of deposit coin `deposit`, claiming `b` with the
/// notes at `positions`.
pub fn fingerprint(c: u32, deposit: &OutPoint, b: u32, positions: &[u32]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/exit");
    h.update(c.to_be_bytes());
    h.update(deposit.to_bytes());
    h.update(b.to_be_bytes());
    for i in positions {
        h.update(i.to_be_bytes());
    }
    h.finalize().into()
}

/// What a note's owner signs to claim it in the claim `e`.
pub fn signed_digest(e: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/exit-sig");
    h.update(e);
    h.finalize().into()
}

/// What the hub signs for an exit record of the claim `e`, in the
/// deployment of `sequencer`, `hub` and `genesis`, as for a mint.
pub fn record_digest(sequencer: &Hash, hub: &Hash, genesis: &OutPoint, e: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/exit-record");
    h.update(sequencer);
    h.update(hub);
    h.update(genesis.to_bytes());
    h.update(e);
    h.finalize().into()
}

/// The notes' owners, each once, in the order they first appear: a
/// record's signatures are theirs, in this order.
pub fn owners(notes: &[(TNote, u32)]) -> Vec<Hash> {
    let mut o: Vec<Hash> = Vec::new();
    for (n, _) in notes {
        if !o.contains(&n.owner) {
            o.push(n.owner);
        }
    }
    o
}

/// Whether a record's notes are a claim's: one to [`MAX_NOTES`], positions
/// increasing.
pub fn well_formed(notes: &[(TNote, u32)]) -> bool {
    (1..=MAX_NOTES).contains(&notes.len()) && notes.windows(2).all(|w| w[0].1 < w[1].1)
}

//! An exit record (docs/HUB_PROVES_PLAN.md): once a claim holds, the
//! hub's record (`Tx::Exit`) retires its notes on the L2. A claim names
//! its notes by their positions in the commitment tree, and its
//! fingerprint `E` is what each note's owner signed:
//!
//! ```text
//! E = SHA256("lichen/exit" ‖ c ‖ O_D ‖ b ‖ n ‖ i_1 ‖ … ‖ i_n ‖ ack_1 ‖ … ‖ shielded)
//! ```
//!
//! for contract `c` of deposit coin `O_D`, claiming `b`, positions
//! increasing, with the acknowledgments of the spends whose locked outputs
//! it claims ([`crate::ack`]); `shielded` its shielded notes ([`SClaim`]:
//! one owner's keys, revealing all but its spend key, and each note's
//! position and opening), or a zero count. A shielded owner signs with
//! its exit key `x`, after the transparent owners. The record applies those, and carries each note's opening at its position
//! (shown in the tree, as a spend's), one signature on `E` per owner, in
//! the order the owners first appear ([`owners`]), and the hub's. The
//! owners' signatures are the authority, as for a spend, so a record
//! exists only for a claim the owners made.
//!
//! Integers are big-endian, as in the statements.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::ack::Ack;
use crate::{Hash, OutPoint, TNote};
use lichen_shielded as sh;

/// A claimed shielded note: its position, and its opening but for the
/// owner's keys (the [`SClaim`]'s).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SNoteClaim {
    pub index: u32,
    pub value: u64,
    pub rho: Hash,
    pub trap: Hash,
}

/// A claim's shielded notes (docs/HUB_PROVES_PLAN.md, "Shielded notes"):
/// their one owner's keys, `auth` (its spend key's public part), `nk` and
/// the exit key `x`, and the notes, positions increasing. Revealing `nk`
/// lets anyone check the notes unspent, and spend none: that needs the
/// spend key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SClaim {
    pub auth: Hash,
    pub nk: Hash,
    pub x: Hash,
    pub notes: Vec<SNoteClaim>,
}

impl SClaim {
    pub const KEYS: usize = 96;
    pub const NOTE: usize = 76;
    pub fn owner(&self) -> Hash {
        sh::owner(&self.auth, &self.nk, &self.x)
    }
    /// The note's leaf in the tree, if the claim is true.
    pub fn leaf(&self, n: &SNoteClaim) -> Hash {
        sh::s_leaf(&sh::SNote { value: n.value, owner: self.owner(), rho: n.rho, trap: n.trap }.commitment())
    }
    pub fn nullifier(&self, n: &SNoteClaim) -> Hash {
        sh::nullifier(&self.nk, &n.rho, &n.trap)
    }
    /// Its bytes: the keys, then `[s]` and each note, big-endian.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(Self::KEYS + 1 + Self::NOTE * self.notes.len());
        w.extend_from_slice(&self.auth);
        w.extend_from_slice(&self.nk);
        w.extend_from_slice(&self.x);
        w.push(self.notes.len() as u8);
        for n in &self.notes {
            w.extend_from_slice(&n.index.to_be_bytes());
            w.extend_from_slice(&n.value.to_be_bytes());
            w.extend_from_slice(&n.rho);
            w.extend_from_slice(&n.trap);
        }
        w
    }
    /// From the front of `b`; the rest.
    pub fn from_bytes(b: &[u8]) -> Option<(SClaim, &[u8])> {
        fn take(b: &[u8], n: usize) -> Option<(&[u8], &[u8])> {
            (b.len() >= n).then(|| b.split_at(n))
        }
        let (k, b) = take(b, Self::KEYS + 1)?;
        let mut b = b;
        let mut notes = Vec::new();
        for _ in 0..k[Self::KEYS] {
            let (n, rest) = take(b, Self::NOTE)?;
            notes.push(SNoteClaim { index: u32::from_be_bytes(n[..4].try_into().ok()?), value: u64::from_be_bytes(n[4..12].try_into().ok()?), rho: n[12..44].try_into().ok()?, trap: n[44..].try_into().ok()? });
            b = rest;
        }
        Some((SClaim { auth: k[..32].try_into().ok()?, nk: k[32..64].try_into().ok()?, x: k[64..96].try_into().ok()?, notes }, b))
    }
    /// Whether its notes are one or more, positions increasing.
    pub fn well_formed(&self) -> bool {
        !self.notes.is_empty() && self.notes.windows(2).all(|w| w[0].index < w[1].index)
    }
}

/// At most this many notes in a claim.
pub const MAX_NOTES: usize = 64;

/// `E` for contract `c` of deposit coin `deposit`, claiming `b` with the
/// transparent notes at `positions` and the `shielded` ones, carrying
/// `acks` (of the spends whose locked outputs it claims:
/// docs/HUB_PROVES_PLAN.md, "Data availability").
pub fn fingerprint(c: u32, deposit: &OutPoint, b: u32, positions: &[u32], acks: &[Ack], shielded: Option<&SClaim>) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/exit");
    h.update(c.to_be_bytes());
    h.update(deposit.to_bytes());
    h.update(b.to_be_bytes());
    h.update((positions.len() as u32).to_be_bytes());
    for i in positions {
        h.update(i.to_be_bytes());
    }
    for a in acks {
        h.update(a.to_bytes());
    }
    match shielded {
        Some(s) => h.update(s.to_bytes()),
        None => h.update([0]),
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

/// The keys that sign a claim of `notes` and `shielded`: the transparent
/// notes' owners, each once, in the order they first appear, then the
/// shielded owner's exit key. A record's signatures are theirs, in this
/// order.
pub fn owners(notes: &[(TNote, u32)], shielded: Option<&SClaim>) -> Vec<Hash> {
    let mut o: Vec<Hash> = Vec::new();
    for (n, _) in notes {
        if !o.contains(&n.owner) {
            o.push(n.owner);
        }
    }
    o.extend(shielded.map(|s| s.x));
    o
}

/// Whether a record's notes are a claim's: one to [`MAX_NOTES`] in all,
/// positions increasing in each kind, the shielded ones' none if there
/// are none.
pub fn well_formed(notes: &[(TNote, u32)], shielded: Option<&SClaim>) -> bool {
    let n = notes.len() + shielded.map_or(0, |s| s.notes.len());
    (1..=MAX_NOTES).contains(&n) && notes.windows(2).all(|w| w[0].1 < w[1].1) && shielded.is_none_or(|s| s.well_formed())
}

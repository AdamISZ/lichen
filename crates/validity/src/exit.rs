//! An exit claim as it is posted, and as it retires notes
//! (docs/EXIT_PLAN.md, "Exit authority on chain"). Alice's `request`
//! posts her claim ([`Posted`]), and its fingerprint `E` is what each
//! transparent note's owner signs:
//!
//! ```text
//! E = SHA256("lichen/exit" ‖ c ‖ O_D ‖ b ‖ h_S ‖ SR_S ‖ nf_1 ‖ … ‖ nf_n)
//! ```
//!
//! for contract `c` of deposit coin `O_D`, claiming `b` from the
//! state of height `h_S` and root `SR_S`. The hub's exit record
//! (`Tx::Exit`) carries the claim as posted, and retires its transparent
//! notes: their owners' signatures are the authority, as for a spend, so
//! a record exists only for a claim the owners made. A shielded note's
//! claim carries only its nullifier, its owner's authority being `nk`
//! inside the claim's proof, so a record doesn't retire it.
//!
//! Integers are big-endian, as in the statements.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::{Hash, OutPoint, Reject, TNote, R};

/// At most this many notes in a claim.
pub const MAX_NOTES: usize = 8;

/// `E` for contract `c` of deposit coin `deposit`, claiming `b` at the state of
/// height `h_s` and root `sr_s` with the notes of `nullifiers`.
pub fn fingerprint(c: u32, deposit: &OutPoint, b: u32, h_s: u64, sr_s: &Hash, nullifiers: &[Hash]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/exit");
    h.update(c.to_be_bytes());
    h.update(deposit.to_bytes());
    h.update(b.to_be_bytes());
    h.update(h_s.to_be_bytes());
    h.update(sr_s);
    for nf in nullifiers {
        h.update(nf);
    }
    h.finalize().into()
}

/// What a transparent note's owner signs to claim it in the claim `e`.
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

/// A claim as `request` posts it: the rest of `E`'s preimage (`h_S` and
/// `SR_S`; `c`, `O` and `b` are the contract's), and each note as anyone
/// can check it. A transparent note: its opening, so its nullifier and
/// owner, and the owner's signature on the claim. A shielded note: its
/// nullifier only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Posted {
    pub h_s: u64,
    pub sr_s: Hash,
    pub notes: Vec<PostedNote>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostedNote {
    Transparent { note: TNote, sig: [u8; 64] },
    Shielded { nf: Hash },
}

impl PostedNote {
    pub fn nullifier(&self) -> Hash {
        match self {
            PostedNote::Transparent { note, .. } => note.nullifier(),
            PostedNote::Shielded { nf } => *nf,
        }
    }
}

impl Posted {
    pub fn nullifiers(&self) -> Vec<Hash> {
        self.notes.iter().map(PostedNote::nullifier).collect()
    }

    /// `E` of this claim for contract `c` of deposit coin `deposit`, claiming
    /// `b`.
    pub fn fingerprint(&self, c: u32, deposit: &OutPoint, b: u32) -> Hash {
        fingerprint(c, deposit, b, self.h_s, &self.sr_s, &self.nullifiers())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(&self.h_s.to_be_bytes());
        w.extend_from_slice(&self.sr_s);
        w.push(self.notes.len() as u8);
        for n in &self.notes {
            match n {
                PostedNote::Transparent { note, sig } => {
                    w.push(0);
                    w.extend_from_slice(&note.owner);
                    w.extend_from_slice(&note.value.to_be_bytes());
                    w.extend_from_slice(&note.memo.to_be_bytes());
                    w.extend_from_slice(&note.rho);
                    w.extend_from_slice(sig);
                }
                PostedNote::Shielded { nf } => {
                    w.push(1);
                    w.extend_from_slice(nf);
                }
            }
        }
        w
    }

    pub fn from_bytes(b: &[u8]) -> Result<Posted, Reject> {
        let mut r = R(b);
        let (h_s, sr_s, [count]) = (r.u64()?, r.take()?, r.take()?);
        if count as usize > MAX_NOTES {
            return Err(Reject::Encoding);
        }
        let mut notes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            notes.push(match r.take()? {
                [0] => PostedNote::Transparent { note: r.note()?, sig: r.take()? },
                [1] => PostedNote::Shielded { nf: r.take()? },
                _ => return Err(Reject::Encoding),
            });
        }
        r.end()?;
        Ok(Posted { h_s, sr_s, notes })
    }
}

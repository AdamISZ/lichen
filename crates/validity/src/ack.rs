//! Sender acknowledgment (docs/HUB_PROVES_PLAN.md, "Data availability:
//! sender acknowledgment"): a user's spend counts against its sender only
//! once she has acknowledged it, which she does only with its data in
//! hand, naming an anchor on Bitcoin of a history that holds it. Until
//! then its outputs are locked.
//!
//! The state lives in the spent set ([`crate::smt`]) beside the
//! nullifiers, under keys of its own, insert only:
//!
//! | key | leaf |
//! |---|---|
//! | [`tx_key`]`(txid)` | [`pending`]`(ak, h)`: a user's spend sealed at `h` |
//! | [`lock_key`]`(i)` | `txid`: its output at position `i` |
//! | [`acked_key`]`(txid)` | [`acked`]`(a)`: acknowledged, naming anchor `a` |
//! | [`void_key`]`(txid)` | [`void`]: voided by an exit record |
//! | [`anchor_key`]`(a)` | `hist_a`: the anchor of height `a`, applied |
//!
//! A user's spend's nullifiers take its `txid` as their leaf, so the set
//! says which spend spent a note.

use sha2::{Digest, Sha256};

use crate::Hash;

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn tx_key(txid: &Hash) -> Hash {
    sha256(&[b"lichen/k/tx", txid])
}
pub fn pending(ak: &Hash, h: u64) -> Hash {
    sha256(&[b"lichen/pending", ak, &h.to_be_bytes()])
}
pub fn lock_key(i: u32) -> Hash {
    sha256(&[b"lichen/k/lock", &i.to_be_bytes()])
}
pub fn acked_key(txid: &Hash) -> Hash {
    sha256(&[b"lichen/k/acked", txid])
}
pub fn acked(a: u64) -> Hash {
    sha256(&[b"lichen/acked", &a.to_be_bytes()])
}
pub fn void_key(txid: &Hash) -> Hash {
    sha256(&[b"lichen/k/void", txid])
}
pub fn void() -> Hash {
    sha256(&[b"lichen/void"])
}
pub fn anchor_key(a: u64) -> Hash {
    sha256(&[b"lichen/k/anchor", &a.to_be_bytes()])
}

/// What the sender signs under `ak`: her spend `txid` holds in the history
/// `hist_a` anchored at height `a`.
pub fn digest(txid: &Hash, a: u64, hist_a: &Hash) -> Hash {
    sha256(&[b"lichen/ack", txid, &a.to_be_bytes(), hist_a])
}

/// An acknowledgment, with what the statement needs to check it: the
/// spend's key `ak` and sealed height `h` (its pending leaf's preimage).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub txid: Hash,
    pub ak: Hash,
    pub h: u64,
    pub a: u64,
    pub hist_a: Hash,
    pub sig: [u8; 64],
}

impl Ack {
    pub const LEN: usize = 32 + 32 + 8 + 8 + 32 + 64;

    pub fn to_bytes(&self) -> [u8; Ack::LEN] {
        let mut b = [0u8; Ack::LEN];
        b[..32].copy_from_slice(&self.txid);
        b[32..64].copy_from_slice(&self.ak);
        b[64..72].copy_from_slice(&self.h.to_be_bytes());
        b[72..80].copy_from_slice(&self.a.to_be_bytes());
        b[80..112].copy_from_slice(&self.hist_a);
        b[112..].copy_from_slice(&self.sig);
        b
    }

    pub fn from_bytes(b: &[u8; Ack::LEN]) -> Ack {
        Ack {
            txid: b[..32].try_into().unwrap(),
            ak: b[32..64].try_into().unwrap(),
            h: u64::from_be_bytes(b[64..72].try_into().unwrap()),
            a: u64::from_be_bytes(b[72..80].try_into().unwrap()),
            hist_a: b[80..112].try_into().unwrap(),
            sig: b[112..].try_into().unwrap(),
        }
    }

    /// Whether its signature is `ak`'s on [`digest`], and `h ≤ a`. (That
    /// `ak` and `h` are the spend's, and `a`'s anchor applied, is the
    /// state's to show.)
    pub fn signed(&self) -> bool {
        self.h <= self.a && crate::check_sig(&self.ak, &digest(&self.txid, self.a, &self.hist_a), &self.sig).is_ok()
    }
}

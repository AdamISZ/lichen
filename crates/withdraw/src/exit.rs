//! Alice's exit claim (docs/EXIT_PLAN.md, "Alice's claim" and "Under
//! BABE"): these notes of hers were unspent at an anchored state `S`.
//! The exit mode of the BABE statement checks it when the hub posts no
//! counter. Its fingerprint `E` is what she signs in `request`, and what
//! the hub's counter, if any, must name:
//!
//! ```text
//! E = SHA256("lichen/exit" ‖ c ‖ O ‖ b ‖ h_S ‖ SR_S ‖ nf_1 ‖ … ‖ nf_n)
//! ```
//!
//! `O` is the contract's funding outpoint: the counter's cutoff is the
//! confirmation of the transaction spending it (`request`). `b` is the
//! amount claimed, at most the notes' total: a return of at least `b` to
//! the contract can't counter the claim ([`crate::counter`]).
//!
//! Each note is in `S`'s commitment tree and its nullifier isn't in `S`'s
//! nullifier tree. Authority over a note is its owner's: knowing `nk` for
//! a shielded note; for a transparent one, whose nullifier anyone can
//! compute, the owner's signature on `E`. The nullifiers are listed in
//! increasing order, so the notes are distinct and `E` is one per claim.
//!
//! The claim is posted on chain: `request`, the transaction spending `O`,
//! carries [`Posted`] in its witness, in a block with the contract's work
//! on it, so that the hub can search for the notes and cite their
//! owners' signatures against a claim of the same notes through another
//! contract (docs/EXIT_PLAN.md, "Exit authority on chain").
//!
//! Integers are big-endian, as in the other statements.

use alloc::vec::Vec;
use k256::schnorr::{Signature, VerifyingKey};
use lichen_shielded::{self as sh, SNote};
use lichen_validity::{smt, OutPoint, TNote};
use sha2::{Digest, Sha256};

use crate::{root_from_path, Anchored, Hash, Reject, Request, TREE_DEPTH};
use lichen_validity::btc::Header;

/// At most this many notes in a claim.
pub const MAX_NOTES: usize = 8;

/// `request`'s witness carries [`Posted`] in its first this many items,
/// concatenated: at most 520 bytes each (tapscript's limit on a stack
/// item), and as many as the script drops, empty ones padding.
pub const POSTED_ITEMS: usize = 3;

/// A claimed note's opening, and its owner's authority over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Owned {
    /// The owner's BIP340 signature on [`signed_digest`] of `E`.
    Transparent { note: TNote, sig: [u8; 64] },
    /// The owner's nullifier key: the note's owner is `owner(nk)`.
    Shielded { value: u64, rho: Hash, nk: Hash },
}

impl Owned {
    pub fn value(&self) -> u64 {
        match self {
            Owned::Transparent { note, .. } => note.value,
            Owned::Shielded { value, .. } => *value,
        }
    }
    /// Its leaf in the commitment tree.
    pub fn commitment(&self) -> Hash {
        match self {
            Owned::Transparent { note, .. } => note.commitment(),
            Owned::Shielded { value, rho, nk } => SNote { value: *value, owner: sh::owner(nk), rho: *rho }.commitment(),
        }
    }
    pub fn nullifier(&self) -> Hash {
        match self {
            Owned::Transparent { note, .. } => note.nullifier(),
            Owned::Shielded { rho, nk, .. } => sh::nullifier(nk, rho),
        }
    }
}

/// A claimed note: its opening, where it sits in `S`'s commitment tree,
/// and its nullifier's absence from `S`'s nullifier tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claimed {
    pub owned: Owned,
    pub index: u32,
    pub path: Vec<Hash>,
    pub unspent: smt::Proof,
}

/// The claim's input: the anchored state `S` and its commitment tree's
/// root, the contract (`c`, and its funding outpoint `O`), the amount `b`,
/// the notes, and `request` posting them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitInput {
    pub state: Anchored,
    pub tree: Hash,
    pub c: u32,
    pub funding: OutPoint,
    pub b: u32,
    pub notes: Vec<Claimed>,
    pub request: Request,
}

/// What `request` posts of a claim: the rest of `E`'s preimage (`h_S` and
/// `SR_S`; `c`, `O` and `b` the hub knows), and each note as anyone can
/// check it. A transparent note: its opening, so its nullifier and owner,
/// and the owner's signature on the claim. A shielded note: its nullifier
/// only, since its owner's authority is knowing `nk`, inside the proof, so
/// its claim can't be cited (until the shielded address holds an owner
/// key: docs/EXIT_PLAN.md, "Exit authority on chain").
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

impl Posted {
    /// What `input`'s `request` must post.
    pub fn of(input: &ExitInput) -> Posted {
        let notes = input
            .notes
            .iter()
            .map(|n| match &n.owned {
                Owned::Transparent { note, sig } => PostedNote::Transparent { note: *note, sig: *sig },
                o @ Owned::Shielded { .. } => PostedNote::Shielded { nf: o.nullifier() },
            })
            .collect();
        Posted { h_s: input.state.height, sr_s: input.state.root(&input.tree), notes }
    }

    pub fn nullifiers(&self) -> Vec<Hash> {
        self.notes
            .iter()
            .map(|n| match n {
                PostedNote::Transparent { note, .. } => note.nullifier(),
                PostedNote::Shielded { nf } => *nf,
            })
            .collect()
    }

    /// `E` of this claim for contract `c` funded at `funding`, claiming
    /// `b`.
    pub fn fingerprint(&self, c: u32, funding: &OutPoint, b: u32) -> Hash {
        fingerprint(c, funding, b, self.h_s, &self.sr_s, &self.nullifiers())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.put(&self.h_s.to_be_bytes());
        w.put(&self.sr_s);
        w.put(&[self.notes.len() as u8]);
        for n in &self.notes {
            match n {
                PostedNote::Transparent { note, sig } => {
                    w.put(&[0]);
                    write_tnote(&mut w, note);
                    w.put(sig);
                }
                PostedNote::Shielded { nf } => {
                    w.put(&[1]);
                    w.put(nf);
                }
            }
        }
        w.0
    }

    pub fn from_bytes(b: &[u8]) -> Result<Posted, Reject> {
        let mut r = R(b);
        let (h_s, sr_s) = (u64::from_be_bytes(r.take()?), r.take()?);
        let [count] = r.take()?;
        if count as usize > MAX_NOTES {
            return Err(Reject::Notes);
        }
        let mut notes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            notes.push(match r.take()? {
                [0] => PostedNote::Transparent { note: read_tnote(&mut r)?, sig: r.take()? },
                [1] => PostedNote::Shielded { nf: r.take()? },
                _ => return Err(Reject::Encoding),
            });
        }
        if !r.0.is_empty() {
            return Err(Reject::Encoding);
        }
        Ok(Posted { h_s, sr_s, notes })
    }
}

/// What a claim proves: its contract's `c` and `D`, `b`, and `E`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub c: u32,
    pub d: Hash,
    pub b: u32,
    pub e: Hash,
}

/// `E` for contract `c` funded at `funding`, claiming `b` at the state of
/// height `h_s` and root `sr_s` with the notes of `nullifiers`.
pub fn fingerprint(c: u32, funding: &OutPoint, b: u32, h_s: u64, sr_s: &Hash, nullifiers: &[Hash]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/exit");
    h.update(c.to_be_bytes());
    h.update(funding.to_bytes());
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

/// The claim's nullifiers, in its order.
pub fn nullifiers(input: &ExitInput) -> Vec<Hash> {
    input.notes.iter().map(|n| n.owned.nullifier()).collect()
}

/// The claim: check `input` against a chain receipt of `chain_id`.
pub fn check(input: &ExitInput, chain_id: &Hash, verify_chain: &mut dyn FnMut(&[u8]) -> bool) -> Result<Claim, Reject> {
    if input.notes.is_empty() || input.notes.len() > MAX_NOTES {
        return Err(Reject::Notes);
    }
    let nfs = nullifiers(input);
    if nfs.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Reject::Order);
    }
    let e = fingerprint(input.c, &input.funding, input.b, input.state.height, &input.state.root(&input.tree), &nfs);
    let empties = smt::empties();
    let mut total = 0u64;
    for (n, nf) in input.notes.iter().zip(&nfs) {
        if n.path.len() != TREE_DEPTH || root_from_path(n.owned.commitment(), n.index, &n.path) != input.tree {
            return Err(Reject::NotInTree);
        }
        if !smt::unspent(&input.state.nullifiers, nf, &n.unspent, empties) {
            return Err(Reject::Spent);
        }
        if let Owned::Transparent { note, sig } = &n.owned {
            let key = VerifyingKey::from_bytes(&note.owner).map_err(|_| Reject::NotYours)?;
            let sig = Signature::try_from(&sig[..]).map_err(|_| Reject::NotYours)?;
            key.verify_raw(&signed_digest(&e), &sig).map_err(|_| Reject::NotYours)?;
        }
        total = total.checked_add(n.owned.value()).ok_or(Reject::TooLarge)?;
    }
    if total < u64::from(input.b) {
        return Err(Reject::Short);
    }
    let d = input.state.check(&input.tree, chain_id, verify_chain)?;
    // posted on chain where the hub can read it, and as costly to forge as
    // the anchor
    let posted = input.request.spending(&input.funding).filter(|w| w.len() >= POSTED_ITEMS).map(|w| w[..POSTED_ITEMS].concat());
    if !input.state.deep(&Header(input.request.header)) || posted != Some(Posted::of(input).to_bytes()) {
        return Err(Reject::Posted);
    }
    Ok(Claim { c: input.c, d, b: input.b, e })
}

// ----- the encoding -----

pub(crate) struct W(pub(crate) Vec<u8>);

impl W {
    pub(crate) fn put(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    pub(crate) fn list<const N: usize>(&mut self, items: &[[u8; N]]) {
        self.put(&(items.len() as u32).to_be_bytes());
        for i in items {
            self.put(i);
        }
    }
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.put(&(b.len() as u32).to_be_bytes());
        self.put(b);
    }
}

pub(crate) struct R<'a>(pub(crate) &'a [u8]);

impl R<'_> {
    pub(crate) fn take<const N: usize>(&mut self) -> Result<[u8; N], Reject> {
        if self.0.len() < N {
            return Err(Reject::Encoding);
        }
        let (a, rest) = self.0.split_at(N);
        self.0 = rest;
        Ok(a.try_into().unwrap())
    }
    pub(crate) fn list<const N: usize>(&mut self) -> Result<Vec<[u8; N]>, Reject> {
        let n = u32::from_be_bytes(self.take()?) as usize;
        if n > self.0.len() / N {
            return Err(Reject::Encoding);
        }
        (0..n).map(|_| self.take()).collect()
    }
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>, Reject> {
        let n = u32::from_be_bytes(self.take()?) as usize;
        if n > self.0.len() {
            return Err(Reject::Encoding);
        }
        let (a, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(a.to_vec())
    }
}

impl Anchored {
    pub(crate) fn write(&self, w: &mut W) {
        w.put(&self.height.to_be_bytes());
        w.put(&self.nullifiers);
        w.put(&self.signature);
        w.put(&self.sequencer);
        w.put(&self.hub);
        w.put(&self.chain_height.to_be_bytes());
        w.put(&self.chain_root);
        w.put(&self.recent);
        w.put(&self.hist);
        w.put(&self.anchor.to_bytes());
        w.list(&self.headers);
        w.put(&self.work.to_be_bytes());
    }
    pub(crate) fn read(r: &mut R) -> Result<Anchored, Reject> {
        Ok(Anchored {
            height: u64::from_be_bytes(r.take()?),
            nullifiers: r.take()?,
            signature: r.take()?,
            sequencer: r.take()?,
            hub: r.take()?,
            chain_height: u64::from_be_bytes(r.take()?),
            chain_root: r.take()?,
            recent: r.take()?,
            hist: r.take()?,
            anchor: lichen_validity::AnchorState::from_bytes(&r.take::<176>()?).map_err(|_| Reject::Encoding)?,
            headers: r.list()?,
            work: u128::from_be_bytes(r.take()?),
        })
    }
}

impl ExitInput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        self.state.write(&mut w);
        w.put(&self.tree);
        w.put(&self.c.to_be_bytes());
        w.put(&self.funding.to_bytes());
        w.put(&self.b.to_be_bytes());
        w.put(&[self.notes.len() as u8]);
        for n in &self.notes {
            match &n.owned {
                Owned::Transparent { note, sig } => {
                    w.put(&[0]);
                    write_tnote(&mut w, note);
                    w.put(sig);
                }
                Owned::Shielded { value, rho, nk } => {
                    w.put(&[1]);
                    w.put(&value.to_be_bytes());
                    w.put(rho);
                    w.put(nk);
                }
            }
            w.put(&n.index.to_be_bytes());
            w.list(&n.path);
            w.put(&n.unspent.bitmap);
            w.list(&n.unspent.siblings);
        }
        self.request.write(&mut w);
        w.0
    }

    pub fn from_bytes(b: &[u8]) -> Result<ExitInput, Reject> {
        let mut r = R(b);
        let state = Anchored::read(&mut r)?;
        let (tree, c, funding, b) = (r.take()?, u32::from_be_bytes(r.take()?), OutPoint::from_bytes(&r.take()?), u32::from_be_bytes(r.take()?));
        let [count] = r.take()?;
        if count as usize > MAX_NOTES {
            return Err(Reject::Notes);
        }
        let mut notes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let owned = match r.take()? {
                [0] => Owned::Transparent { note: read_tnote(&mut r)?, sig: r.take()? },
                [1] => Owned::Shielded { value: u64::from_be_bytes(r.take()?), rho: r.take()?, nk: r.take()? },
                _ => return Err(Reject::Encoding),
            };
            let index = u32::from_be_bytes(r.take()?);
            let path = r.list()?;
            let unspent = smt::Proof { bitmap: r.take()?, siblings: r.list()? };
            notes.push(Claimed { owned, index, path, unspent });
        }
        let request = Request::read(&mut r)?;
        if !r.0.is_empty() {
            return Err(Reject::Encoding);
        }
        Ok(ExitInput { state, tree, c, funding, b, notes, request })
    }
}

fn write_tnote(w: &mut W, note: &TNote) {
    w.put(&note.owner);
    w.put(&note.value.to_be_bytes());
    w.put(&note.memo.to_be_bytes());
    w.put(&note.rho);
}

fn read_tnote(r: &mut R) -> Result<TNote, Reject> {
    Ok(TNote { owner: r.take()?, value: u64::from_be_bytes(r.take()?), memo: u32::from_be_bytes(r.take()?), rho: r.take()? })
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use crate::tests::{block_with, headers_on, key, tx_spending, xonly};
    use lichen_validity::{state_root, AnchorState};

    /// Alice's notes at `S` (height 3): a transparent one of 5 at index 0
    /// (her key 3) and a shielded one of 7 at index 1 (`nk` 4s), in a
    /// nullifier tree holding two others' spends; `S` signed, anchored,
    /// ten headers on its block, the first holding `request`; contract
    /// 42, its funding outpoint; `b` the notes' total.
    pub(crate) fn input() -> (ExitInput, Hash) {
        let (seq, hub, alice) = (key(1), key(2), key(3));
        let t = TNote { owner: xonly(&alice), value: 5, memo: 0, rho: [7; 32] };
        let s = Owned::Shielded { value: 7, rho: [8; 32], nk: [4; 32] };
        let z = lichen_validity::tree_empties();
        let (cm0, cm1) = (t.commitment(), s.commitment());
        let path = |sib: Hash| -> Vec<Hash> { core::iter::once(sib).chain(z[1..TREE_DEPTH].iter().copied()).collect() };
        let tree = root_from_path(cm0, 0, &path(cm1));
        let e = smt::empties();
        let spent = [([0x11; 32], smt::spent()), ([0xee; 32], smt::spent())];
        let n_s = smt::root(&spent, e);
        let root = state_root(3, &tree, &n_s);
        let genesis = OutPoint { txid: [3; 32], vout: 1 };
        let anchor = AnchorState { genesis, sequencer: xonly(&seq), seal: OutPoint { txid: [4; 32], vout: 0 }, height: 3, root, block: [9; 32] };
        let state = Anchored {
            height: 3,
            nullifiers: n_s,
            signature: seq.sign_raw(&root, &[0; 32]).unwrap().to_bytes(),
            sequencer: xonly(&seq),
            hub: xonly(&hub),
            chain_height: 5,
            chain_root: [8; 32],
            recent: [6; 32],
            hist: [10; 32],
            anchor,
            headers: Vec::new(),
            work: 10 * lichen_validity::btc::work(0x207fffff),
        };
        let claimed = |owned: Owned, index: u32, sib: Hash| {
            let nf = owned.nullifier();
            Claimed { owned, index, path: path(sib), unspent: smt::proof(&spent, &nf, e) }
        };
        let mut notes = std::vec![claimed(Owned::Transparent { note: t, sig: [0; 64] }, 0, cm1), claimed(s, 1, cm0)];
        notes.sort_by_key(|n| n.owned.nullifier());
        let request = Request { tx: Vec::new(), header: [0; 80], index: 0, path: Vec::new(), coinbase: Vec::new(), coinbase_path: Vec::new(), reserved: [0; 32] };
        let mut input = ExitInput { state, tree, c: 42, funding: OutPoint { txid: [12; 32], vout: 2 }, b: 12, notes, request };
        sign(&mut input);
        (input, [8; 32])
    }

    /// Alice signs her transparent notes' claim, as it now stands, and
    /// posts it.
    pub(crate) fn sign(input: &mut ExitInput) {
        let e = fingerprint(input.c, &input.funding, input.b, input.state.height, &input.state.root(&input.tree), &nullifiers(input));
        for n in &mut input.notes {
            if let Owned::Transparent { sig, .. } = &mut n.owned {
                *sig = key(3).sign_raw(&signed_digest(&e), &[0; 32]).unwrap().to_bytes();
            }
        }
        post(input, &Posted::of(input).to_bytes());
    }

    /// `bytes` as `request` posts them, in [`POSTED_ITEMS`] items of up
    /// to 520 bytes.
    pub(crate) fn items(bytes: &[u8]) -> Vec<&[u8]> {
        (0..POSTED_ITEMS).map(|i| bytes.get(i * 520..).map_or(&[][..], |b| &b[..b.len().min(520)])).collect()
    }

    /// `request` posting `bytes`, in a block on the anchor's, nine headers
    /// on it.
    pub(crate) fn post(input: &mut ExitInput, bytes: &[u8]) {
        let (block, request) = block_with(&input.state.anchor.block, tx_spending(&input.funding, &items(bytes)));
        input.state.headers = core::iter::once(block).chain(headers_on(&Header(block).hash(), 9)).collect();
        input.request = request;
    }

    fn ok(input: &ExitInput, id: &Hash) -> impl FnMut(&[u8]) -> bool {
        let good = input.state.chain_journal(id).to_bytes();
        move |c: &[u8]| c == good
    }

    #[test]
    fn a_claim_of_unspent_notes() {
        let (i, id) = input();
        let claim = check(&i, &id, &mut ok(&i, &id)).unwrap();
        assert_eq!((claim.c, claim.b), (42, 12));
        assert_eq!(claim.d, crate::contract_id(&crate::deployment_id(&i.state.sequencer, &i.state.hub), &i.state.anchor.genesis, i.state.work));
        assert_eq!(claim.e, fingerprint(42, &i.funding, 12, 3, &i.state.anchor.root, &nullifiers(&i)));
        // E is the claim's: another contract, outpoint, amount or note set,
        // another E
        let mut c = i.clone();
        c.c = 43;
        sign(&mut c);
        assert_ne!(check(&c, &id, &mut ok(&c, &id)).unwrap().e, claim.e);
        let mut o = i.clone();
        o.funding.vout = 3;
        sign(&mut o);
        assert_ne!(check(&o, &id, &mut ok(&o, &id)).unwrap().e, claim.e);
        let mut less = i.clone();
        less.b = 11;
        sign(&mut less);
        assert_ne!(check(&less, &id, &mut ok(&less, &id)).unwrap().e, claim.e);
        let mut one = i.clone();
        one.notes.retain(|n| matches!(n.owned, Owned::Shielded { .. }));
        one.b = 7;
        sign(&mut one);
        let one = check(&one, &id, &mut ok(&one, &id)).unwrap();
        assert_eq!(one.d, claim.d);
        assert_ne!(one.e, claim.e);
        // the encoding round-trips, and refuses a byte more or less
        assert_eq!(ExitInput::from_bytes(&i.to_bytes()).unwrap(), i);
        assert_eq!(ExitInput::from_bytes(&i.to_bytes()[1..]), Err(Reject::Encoding));
        let mut long = i.to_bytes();
        long.push(0);
        assert_eq!(ExitInput::from_bytes(&long), Err(Reject::Encoding));
    }

    #[test]
    fn what_a_claim_refuses() {
        let (i, id) = input();
        // notes worth less than b
        let mut short = i.clone();
        short.b = 13;
        sign(&mut short);
        assert_eq!(check(&short, &id, &mut |_| true), Err(Reject::Short));
        // no notes, too many, a note twice, out of order
        let mut n = i.clone();
        n.notes.clear();
        assert_eq!(check(&n, &id, &mut |_| true), Err(Reject::Notes));
        let mut n = i.clone();
        n.notes = core::iter::repeat_n(i.notes[0].clone(), MAX_NOTES + 1).collect();
        assert_eq!(check(&n, &id, &mut |_| true), Err(Reject::Notes));
        let mut n = i.clone();
        n.notes.push(i.notes[1].clone());
        assert_eq!(check(&n, &id, &mut |_| true), Err(Reject::Order));
        let mut n = i.clone();
        n.notes.reverse();
        assert_eq!(check(&n, &id, &mut |_| true), Err(Reject::Order));
        // a note not in the tree: another value, another index, a short path
        let mut n = i.clone();
        if let Owned::Shielded { value, .. } = &mut n.notes.iter_mut().find(|n| matches!(n.owned, Owned::Shielded { .. })).unwrap().owned {
            *value = 70;
        }
        assert_eq!(check(&n, &id, &mut |_| true), Err(Reject::NotInTree));
        let mut n = i.clone();
        n.notes[0].index ^= 1;
        assert_eq!(check(&n, &id, &mut |_| true), Err(Reject::NotInTree));
        let mut n = i.clone();
        n.notes[0].path.pop();
        assert_eq!(check(&n, &id, &mut |_| true), Err(Reject::NotInTree));
        // a shielded note under another nk: another owner, so another leaf
        let mut n = i.clone();
        for c in &mut n.notes {
            if let Owned::Shielded { nk, .. } = &mut c.owned {
                *nk = [5; 32];
            }
        }
        n.notes.sort_by_key(|n| n.owned.nullifier());
        assert_eq!(check(&n, &id, &mut |_| true), Err(Reject::NotInTree));
        // a note spent at S: its nullifier in the tree, so no proof of absence
        let mut s = i.clone();
        let mut set = std::vec![([0x11; 32], smt::spent()), ([0xee; 32], smt::spent()), (s.notes[0].owned.nullifier(), smt::spent())];
        set.sort();
        s.state.nullifiers = smt::root(&set, smt::empties());
        for c in &mut s.notes {
            c.unspent = smt::proof(&set, &c.owned.nullifier(), smt::empties());
        }
        assert_eq!(check(&s, &id, &mut |_| true), Err(Reject::Spent));
        let mut n = i.clone();
        n.notes[1].unspent.siblings[0][0] ^= 1;
        assert_eq!(check(&n, &id, &mut |_| true), Err(Reject::Spent));
        // a transparent note: no signature, someone else's, or on another
        // claim (the signature binds c, so it can't be replayed)
        let t = i.notes.iter().position(|n| matches!(n.owned, Owned::Transparent { .. })).unwrap();
        let mut n = i.clone();
        if let Owned::Transparent { sig, .. } = &mut n.notes[t].owned {
            *sig = [0; 64];
        }
        assert_eq!(check(&n, &id, &mut |_| true), Err(Reject::NotYours));
        let mut n = i.clone();
        if let Owned::Transparent { sig, .. } = &mut n.notes[t].owned {
            *sig = key(9).sign_raw(&signed_digest(&check(&i, &id, &mut |_| true).unwrap().e), &[0; 32]).unwrap().to_bytes();
        }
        assert_eq!(check(&n, &id, &mut |_| true), Err(Reject::NotYours));
        let mut n = i.clone();
        n.c = 43;
        assert_eq!(check(&n, &id, &mut |_| true), Err(Reject::NotYours));
        // the state: as the withdrawal's (no receipt, not anchored)
        assert_eq!(check(&i, &id, &mut |_| false), Err(Reject::Chain));
        let mut a = i.clone();
        a.state.anchor.root = [0; 32];
        assert_eq!(check(&a, &id, &mut |_| true), Err(Reject::NotAnchored));
        let mut h = i.clone();
        h.state.height = 4;
        sign(&mut h);
        assert_eq!(check(&h, &id, &mut |_| true), Err(Reject::BadSignature));
    }

    #[test]
    fn the_claim_is_posted() {
        let (i, id) = input();
        let posted = Posted::of(&i);
        assert_eq!(posted.nullifiers(), nullifiers(&i));
        assert_eq!(posted.fingerprint(i.c, &i.funding, i.b), check(&i, &id, &mut |_| true).unwrap().e);
        assert_eq!(Posted::from_bytes(&posted.to_bytes()), Ok(posted.clone()));
        assert_eq!(Posted::from_bytes(&[posted.to_bytes(), std::vec![0]].concat()), Err(Reject::Encoding));
        // eight transparent notes fit in the items
        let t = PostedNote::Transparent { note: TNote { owner: [1; 32], value: 1, memo: 0, rho: [2; 32] }, sig: [3; 64] };
        let full = Posted { notes: std::vec![t; MAX_NOTES], ..posted.clone() }.to_bytes();
        assert_eq!(full.len(), 8 + 32 + 1 + MAX_NOTES * (1 + 76 + 64));
        assert!(full.len() <= POSTED_ITEMS * 520);
        // the script's own items after them don't matter
        let mut x = i.clone();
        let bytes = posted.to_bytes();
        let (block, request) = block_with(&x.state.anchor.block, tx_spending(&x.funding, &[items(&bytes), std::vec![&b"sig"[..], b"script", b"control"]].concat()));
        x.state.headers = core::iter::once(block).chain(headers_on(&Header(block).hash(), 9)).collect();
        x.request = request;
        assert!(check(&x, &id, &mut |_| true).is_ok());
        // something else posted: another signature, a note left out,
        // nothing
        let mut x = i.clone();
        let mut other = posted.clone();
        let t = other.notes.iter_mut().find(|n| matches!(n, PostedNote::Transparent { .. })).unwrap();
        if let PostedNote::Transparent { sig, .. } = t {
            sig[0] ^= 1;
        }
        post(&mut x, &other.to_bytes());
        assert_eq!(check(&x, &id, &mut |_| true), Err(Reject::Posted));
        let mut x = i.clone();
        let mut other = posted.clone();
        other.notes.pop();
        post(&mut x, &other.to_bytes());
        assert_eq!(check(&x, &id, &mut |_| true), Err(Reject::Posted));
        let mut x = i.clone();
        post(&mut x, &[]);
        assert_eq!(check(&x, &id, &mut |_| true), Err(Reject::Posted));
        // posted by a transaction spending another outpoint
        let mut x = i.clone();
        let (block, request) = block_with(&x.state.anchor.block, tx_spending(&OutPoint { txid: [12; 32], vout: 3 }, &items(&bytes)));
        x.state.headers = core::iter::once(block).chain(headers_on(&Header(block).hash(), 9)).collect();
        x.request = request;
        assert_eq!(check(&x, &id, &mut |_| true), Err(Reject::Posted));
        // in a block at the tip, without the contract's work on it: one
        // a dishonest Alice could forge, the real request posting junk
        let mut x = i.clone();
        let tip = Header(*x.state.headers.last().unwrap()).hash();
        let (block, request) = block_with(&tip, tx_spending(&x.funding, &items(&bytes)));
        x.state.headers.push(block);
        x.request = request;
        assert_eq!(check(&x, &id, &mut |_| true), Err(Reject::Posted));
        // the request in the anchor's own block: deep enough
        let mut x = i.clone();
        let (block, request) = block_with(&[0x98; 32], tx_spending(&x.funding, &items(&bytes)));
        x.state.anchor.block = Header(block).hash();
        x.state.headers = headers_on(&x.state.anchor.block, 10);
        x.request = request;
        assert_eq!(check(&x, &id, &mut |_| true).map(|c| c.e), check(&i, &id, &mut |_| true).map(|c| c.e));
    }
}

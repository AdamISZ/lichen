//! Shielded notes and the spend statement (docs/SHIELDED_PLAN.md): what
//! the spend guest proves, the sequencer checks a receipt against, and
//! the wallet builds.
//!
//! ```text
//! auth  = SHA256("lichen/auth" ‖ ask)            ask: the owner's spend key
//! owner = SHA256("lichen/owner" ‖ auth ‖ nk ‖ x) nk: its nullifier key; x: its exit key
//! cm    = SHA256("lichen/snote" ‖ owner ‖ value ‖ rho ‖ r)
//! nf    = SHA256("lichen/snf" ‖ nk ‖ rho ‖ r)
//! rho_i = SHA256("lichen/rho" ‖ nf_0 ‖ i)        the i-th new note of a transaction
//! ```
//!
//! The keys are split (docs/HUB_PROVES_PLAN.md, "Shielded notes"): `ask`
//! authorizes spends, in the proof, and is never revealed; `nk` derives
//! nullifiers, and an exit reveals it (with `auth` and `x`) so that the
//! hub can check a claimed note unspent; `x`, an x-only Schnorr key, signs
//! exit claims and nothing else. `r` (the code's `trap`) is a trapdoor the
//! sender picks and encrypts to the recipient with the value: it hides the
//! commitment (without it, anyone with an address could test each leaf for
//! every likely value), and after an exit only a note's sender, who knows
//! its `r`, can link its spend to the owner whose `nk` the exit revealed.
//!
//! Shielded notes are leaves of the ledger's commitment tree beside
//! transparent ones (`lngap/note`, domain-separated), and their nullifiers
//! go in the same set. The statement: each shielded spend's note is in the
//! tree under the anchor and its owner's keys known; the new notes' `rho`s are
//! derived from the transaction's first nullifier (so no two notes share
//! one); and the values balance with the transparent spends' total and
//! outputs. Its journal ([`Journal`]) is everything public: what the
//! sequencer recomputes from the transaction. Spend authority is knowing
//! `ask`; there is no signature.
//!
//! Integers are big-endian, as in the withdrawal statement.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// The commitment tree's depth (the withdrawal statement's).
pub const TREE_DEPTH: usize = 16;
/// At most this many spends (transparent and shielded) and outputs.
pub const MAX_SPENDS: usize = 4;
pub const MAX_OUTPUTS: usize = 4;

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The public part of the spend key `ask`.
pub fn auth(ask: &Hash) -> Hash {
    sha256(&[b"lichen/auth", ask])
}

/// The owner of notes spendable with the spend key whose public part is
/// `auth`, of nullifier key `nk` and exit key `x`.
pub fn owner(auth: &Hash, nk: &Hash, x: &Hash) -> Hash {
    sha256(&[b"lichen/owner", auth, nk, x])
}

/// A shielded note: `trap` its trapdoor (the plan's `r`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SNote {
    pub value: u64,
    pub owner: Hash,
    pub rho: Hash,
    pub trap: Hash,
}

impl SNote {
    pub fn commitment(&self) -> Hash {
        sha256(&[b"lichen/snote", &self.owner, &self.value.to_be_bytes(), &self.rho, &self.trap])
    }
}

/// A shielded note's nullifier.
pub fn nullifier(nk: &Hash, rho: &Hash, trap: &Hash) -> Hash {
    sha256(&[b"lichen/snf", nk, rho, trap])
}

/// The `rho` of a transaction's `i`-th new shielded note.
pub fn rho(nf0: &Hash, i: u32) -> Hash {
    sha256(&[b"lichen/rho", nf0, &i.to_be_bytes()])
}

/// A transparent note's commitment (`lngap-r0-core`'s `Note::commitment`).
pub fn transparent_commitment(owner: &Hash, value: u64, memo: u32, rho: &Hash) -> Hash {
    sha256(&[b"lngap/note", owner, &value.to_be_bytes(), &memo.to_be_bytes(), rho])
}

/// A leaf of the commitment tree: a commitment with its top bit set to
/// its kind, 0 a transparent note's, 1 a shielded note's
/// (docs/HUB_PROVES_PLAN.md), so that a leaf says which it is. The chain
/// statement sets it as it appends; paths are to leaves.
pub fn t_leaf(cm: &Hash) -> Hash {
    let mut l = *cm;
    l[0] &= 0x7f;
    l
}

/// A shielded note's leaf ([`t_leaf`]).
pub fn s_leaf(cm: &Hash) -> Hash {
    let mut l = *cm;
    l[0] |= 0x80;
    l
}

/// Whether a leaf is a shielded note's ([`t_leaf`]).
pub fn is_shielded(leaf: &Hash) -> bool {
    leaf[0] & 0x80 != 0
}

/// A node of the commitment tree (`lngap-r0-core`'s `node`).
pub fn node(left: &Hash, right: &Hash) -> Hash {
    sha256(&[left, right])
}

/// The root a leaf at `index` reaches through `path`, leaf level first.
pub fn root_from_path(leaf: Hash, index: u32, path: &[Hash]) -> Hash {
    let mut h = leaf;
    for (level, sib) in path.iter().enumerate() {
        h = if (index >> level) & 1 == 1 { node(sib, &h) } else { node(&h, sib) };
    }
    h
}

/// A shielded note being spent: its opening, its owner's keys (the spend
/// key `ask`, `nk`, the exit key `x`), where it sits in the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spend {
    pub value: u64,
    pub rho: Hash,
    pub trap: Hash,
    pub ask: Hash,
    pub nk: Hash,
    pub x: Hash,
    pub index: u32,
    pub path: Vec<Hash>,
}

/// A new shielded note: its value, owner and trapdoor (its `rho` is
/// derived).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Output {
    pub value: u64,
    pub owner: Hash,
    pub trap: Hash,
}

/// A transparent note created (a return to the hub): its opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TOut {
    pub owner: Hash,
    pub value: u64,
    pub memo: u32,
    pub rho: Hash,
}

impl TOut {
    pub fn commitment(&self) -> Hash {
        transparent_commitment(&self.owner, self.value, self.memo, &self.rho)
    }
}

/// The statement's input. Private: the shielded spends and the new
/// shielded notes' values and owners. Public: the rest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendInput {
    /// A sealed root of the commitment tree.
    pub anchor: Hash,
    /// The transparent spends' nullifiers and total value (their
    /// signatures are the sequencer's to check).
    pub t_nfs: Vec<Hash>,
    pub t_total: u64,
    pub spends: Vec<Spend>,
    /// New shielded notes; their `rho`s are derived.
    pub outputs: Vec<Output>,
    pub t_outputs: Vec<TOut>,
    /// The sender's one-time acknowledgment key (docs/HUB_PROVES_PLAN.md,
    /// "Data availability"): public, so that the sequencer can't swap it.
    pub ak: Hash,
}

/// What the statement makes public: the anchor, the transparent spends'
/// nullifiers and total, the shielded nullifiers, the new shielded
/// commitments, the transparent outputs' commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub anchor: Hash,
    pub t_nfs: Vec<Hash>,
    pub t_total: u64,
    pub nfs: Vec<Hash>,
    pub cms: Vec<Hash>,
    pub t_cms: Vec<Hash>,
    pub ak: Hash,
}

/// Why an input is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// No spend, or too many spends or outputs.
    Shape,
    PathLength,
    /// A shielded note not under the anchor (or not its owner's keys).
    NotInTree,
    /// A new note of no value.
    Empty,
    Unbalanced,
    /// The input doesn't decode.
    Encoding,
}

impl Journal {
    /// The transaction's first nullifier: its first transparent spend's,
    /// else its first shielded spend's.
    pub fn nf0(&self) -> Option<&Hash> {
        self.t_nfs.first().or(self.nfs.first())
    }
}

/// The statement: check `input`; on success, its journal.
pub fn check(input: &SpendInput) -> Result<Journal, Reject> {
    let n_in = input.t_nfs.len() + input.spends.len();
    let n_out = input.outputs.len() + input.t_outputs.len();
    if n_in == 0 || n_in > MAX_SPENDS || n_out > MAX_OUTPUTS || (input.t_nfs.is_empty() && input.t_total != 0) {
        return Err(Reject::Shape);
    }
    let mut vin = u128::from(input.t_total);
    let mut nfs = Vec::with_capacity(input.spends.len());
    for s in &input.spends {
        if s.path.len() != TREE_DEPTH {
            return Err(Reject::PathLength);
        }
        let note = SNote { value: s.value, owner: owner(&auth(&s.ask), &s.nk, &s.x), rho: s.rho, trap: s.trap };
        if root_from_path(s_leaf(&note.commitment()), s.index, &s.path) != input.anchor {
            return Err(Reject::NotInTree);
        }
        nfs.push(nullifier(&s.nk, &s.rho, &s.trap));
        vin += u128::from(s.value);
    }
    let nf0 = *input.t_nfs.first().or(nfs.first()).ok_or(Reject::Shape)?;
    let mut vout = 0u128;
    let mut cms = Vec::with_capacity(input.outputs.len());
    for (i, o) in input.outputs.iter().enumerate() {
        if o.value == 0 {
            return Err(Reject::Empty);
        }
        cms.push(SNote { value: o.value, owner: o.owner, rho: rho(&nf0, i as u32), trap: o.trap }.commitment());
        vout += u128::from(o.value);
    }
    for t in &input.t_outputs {
        if t.value == 0 {
            return Err(Reject::Empty);
        }
        vout += u128::from(t.value);
    }
    if vin != vout {
        return Err(Reject::Unbalanced);
    }
    Ok(Journal { anchor: input.anchor, t_nfs: input.t_nfs.clone(), t_total: input.t_total, nfs, cms, t_cms: input.t_outputs.iter().map(|t| t.commitment()).collect(), ak: input.ak })
}

// ----- encodings: what the guest reads and commits -----

struct W(Vec<u8>);
impl W {
    fn put(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    fn list(&mut self, hs: &[Hash]) {
        self.0.push(hs.len() as u8);
        for h in hs {
            self.put(h);
        }
    }
}

struct R<'a>(&'a [u8]);
impl R<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Reject> {
        if self.0.len() < N {
            return Err(Reject::Encoding);
        }
        let (a, b) = self.0.split_at(N);
        self.0 = b;
        Ok(a.try_into().unwrap())
    }
    fn u8(&mut self) -> Result<usize, Reject> {
        Ok(self.take::<1>()?[0] as usize)
    }
    fn u32(&mut self) -> Result<u32, Reject> {
        Ok(u32::from_be_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64, Reject> {
        Ok(u64::from_be_bytes(self.take()?))
    }
    fn list(&mut self) -> Result<Vec<Hash>, Reject> {
        let n = self.u8()?;
        (0..n).map(|_| self.take()).collect()
    }
    fn end(&self) -> Result<(), Reject> {
        if self.0.is_empty() { Ok(()) } else { Err(Reject::Encoding) }
    }
}

impl SpendInput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.put(&self.anchor);
        w.list(&self.t_nfs);
        w.put(&self.t_total.to_be_bytes());
        w.0.push(self.spends.len() as u8);
        for s in &self.spends {
            w.put(&s.value.to_be_bytes());
            w.put(&s.rho);
            w.put(&s.trap);
            w.put(&s.ask);
            w.put(&s.nk);
            w.put(&s.x);
            w.put(&s.index.to_be_bytes());
            w.list(&s.path);
        }
        w.0.push(self.outputs.len() as u8);
        for o in &self.outputs {
            w.put(&o.value.to_be_bytes());
            w.put(&o.owner);
            w.put(&o.trap);
        }
        w.0.push(self.t_outputs.len() as u8);
        for t in &self.t_outputs {
            w.put(&t.owner);
            w.put(&t.value.to_be_bytes());
            w.put(&t.memo.to_be_bytes());
            w.put(&t.rho);
        }
        w.put(&self.ak);
        w.0
    }
    pub fn from_bytes(b: &[u8]) -> Result<SpendInput, Reject> {
        let mut r = R(b);
        let anchor = r.take()?;
        let t_nfs = r.list()?;
        let t_total = r.u64()?;
        let n = r.u8()?;
        let spends = (0..n).map(|_| Ok(Spend { value: r.u64()?, rho: r.take()?, trap: r.take()?, ask: r.take()?, nk: r.take()?, x: r.take()?, index: r.u32()?, path: r.list()? })).collect::<Result<_, _>>()?;
        let n = r.u8()?;
        let outputs = (0..n).map(|_| Ok(Output { value: r.u64()?, owner: r.take()?, trap: r.take()? })).collect::<Result<_, _>>()?;
        let n = r.u8()?;
        let t_outputs = (0..n).map(|_| Ok(TOut { owner: r.take()?, value: r.u64()?, memo: r.u32()?, rho: r.take()? })).collect::<Result<_, _>>()?;
        let ak = r.take()?;
        r.end()?;
        Ok(SpendInput { anchor, t_nfs, t_total, spends, outputs, t_outputs, ak })
    }
}

impl Journal {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.put(&self.anchor);
        w.list(&self.t_nfs);
        w.put(&self.t_total.to_be_bytes());
        w.list(&self.nfs);
        w.list(&self.cms);
        w.list(&self.t_cms);
        w.put(&self.ak);
        w.0
    }
    pub fn from_bytes(b: &[u8]) -> Result<Journal, Reject> {
        let mut r = R(b);
        let j = Journal { anchor: r.take()?, t_nfs: r.list()?, t_total: r.u64()?, nfs: r.list()?, cms: r.list()?, t_cms: r.list()?, ak: r.take()? };
        r.end()?;
        Ok(j)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec;

    fn h(n: u8) -> Hash {
        [n; 32]
    }

    /// A tree of `leaves` (zero beyond), its root and each leaf's path, as
    /// the ledger builds them.
    fn tree(leaves: &[Hash]) -> (Hash, Vec<Vec<Hash>>) {
        let mut zero = vec![[0u8; 32]];
        for l in 0..TREE_DEPTH {
            zero.push(node(&zero[l], &zero[l]));
        }
        let mut levels = vec![leaves.to_vec()];
        for l in 0..TREE_DEPTH {
            let next = levels[l].chunks(2).map(|p| node(&p[0], p.get(1).unwrap_or(&zero[l]))).collect();
            levels.push(next);
        }
        let paths = (0..leaves.len()).map(|i| (0..TREE_DEPTH).map(|l| levels[l].get((i >> l) ^ 1).copied().unwrap_or(zero[l])).collect()).collect();
        (levels[TREE_DEPTH][0], paths)
    }

    /// The owner of keys `n`: spend key, nullifier key, exit key.
    fn who(n: u8) -> Hash {
        owner(&auth(&h(n)), &h(n + 1), &h(n + 2))
    }

    fn out(value: u64, owner: Hash, trap: u8) -> Output {
        Output { value, owner, trap: h(trap) }
    }

    /// A spend of a note of Alice's (keys 1), at `index`.
    fn spend(value: u64, rho: u8, trap: u8, index: u32, path: &[Hash]) -> Spend {
        Spend { value, rho: h(rho), trap: h(trap), ask: h(1), nk: h(2), x: h(3), index, path: path.to_vec() }
    }

    /// Alice (keys 1) holds notes of 5 and 7 at leaves 1 and 2, beside a
    /// transparent note at 0; she pays Bob (keys 4) 9 and keeps 3.
    fn payment() -> (SpendInput, Hash) {
        let (alice, bob) = (who(1), who(4));
        let n5 = SNote { value: 5, owner: alice, rho: h(10), trap: h(20) };
        let n7 = SNote { value: 7, owner: alice, rho: h(11), trap: h(21) };
        let (root, paths) = tree(&[t_leaf(&transparent_commitment(&h(9), 4, 0, &h(8))), s_leaf(&n5.commitment()), s_leaf(&n7.commitment())]);
        let spends = vec![spend(5, 10, 20, 1, &paths[1]), spend(7, 11, 21, 2, &paths[2])];
        let input = SpendInput { anchor: root, t_nfs: vec![], t_total: 0, spends, outputs: vec![out(9, bob, 30), out(3, alice, 31)], t_outputs: vec![], ak: h(0xa0) };
        (input, root)
    }

    #[test]
    fn a_payment_and_its_journal() {
        let (input, root) = payment();
        let j = check(&input).unwrap();
        assert_eq!(j.anchor, root);
        assert_eq!(j.nfs, vec![nullifier(&h(2), &h(10), &h(20)), nullifier(&h(2), &h(11), &h(21))]);
        // the new notes' rhos come from the first nullifier: Bob, told the
        // value and the trapdoor, can recompute his note's commitment
        let nf0 = j.nf0().unwrap();
        assert_eq!(j.cms[0], SNote { value: 9, owner: who(4), rho: rho(nf0, 0), trap: h(30) }.commitment());
        assert_eq!(j.cms[1], SNote { value: 3, owner: who(1), rho: rho(nf0, 1), trap: h(31) }.commitment());
        // without the trapdoor, no value tests as Bob's note
        assert!((0..100).all(|v| SNote { value: v, owner: who(4), rho: rho(nf0, 0), trap: h(0) }.commitment() != j.cms[0]));
        // the encodings round-trip
        assert_eq!(SpendInput::from_bytes(&input.to_bytes()).unwrap(), input);
        assert_eq!(Journal::from_bytes(&j.to_bytes()).unwrap(), j);
        assert_eq!(SpendInput::from_bytes(&input.to_bytes()[1..]), Err(Reject::Encoding));
        let mut long = input.to_bytes();
        long.push(0);
        assert_eq!(SpendInput::from_bytes(&long), Err(Reject::Encoding));
    }

    #[test]
    fn what_the_statement_refuses() {
        let (input, _) = payment();
        // another spend key, nullifier key or exit key (Bob's) for Alice's
        // note: not its owner; another trapdoor: not the note
        let changes: [fn(&mut Spend); 4] = [|s| s.ask = h(4), |s| s.nk = h(5), |s| s.x = h(6), |s| s.trap = h(22)];
        for f in changes {
            let mut i = input.clone();
            f(&mut i.spends[0]);
            assert_eq!(check(&i), Err(Reject::NotInTree));
        }
        // a value she doesn't hold
        let mut i = input.clone();
        i.spends[0].value = 6;
        assert_eq!(check(&i), Err(Reject::NotInTree));
        // another anchor
        let mut i = input.clone();
        i.anchor = h(0);
        assert_eq!(check(&i), Err(Reject::NotInTree));
        // more out than in, a zero note, a short path
        let mut i = input.clone();
        i.outputs[0].value = 10;
        assert_eq!(check(&i), Err(Reject::Unbalanced));
        let mut i = input.clone();
        i.outputs = vec![out(12, who(4), 30), out(0, who(1), 31)];
        assert_eq!(check(&i), Err(Reject::Empty));
        let mut i = input.clone();
        i.spends[1].path.pop();
        assert_eq!(check(&i), Err(Reject::PathLength));
        // nothing spent; too many outputs; transparent value with no spend
        let mut i = input.clone();
        i.spends.clear();
        i.outputs.clear();
        assert_eq!(check(&i), Err(Reject::Shape));
        let mut i = input.clone();
        i.outputs = vec![out(3, who(4), 30); 4];
        i.t_outputs = vec![TOut { owner: h(9), value: 0, memo: 0, rho: h(0) }];
        assert_eq!(check(&i), Err(Reject::Shape));
        let mut i = input.clone();
        i.t_total = 1;
        assert_eq!(check(&i), Err(Reject::Shape));
    }

    #[test]
    fn shielding_and_returning() {
        // shielding: a transparent note of 20 (the sequencer checks its
        // signature) into notes of 15 and 5
        let t_nf = h(30);
        let shield = SpendInput { anchor: h(0), t_nfs: vec![t_nf], t_total: 20, spends: vec![], outputs: vec![out(15, who(1), 30), out(5, who(1), 31)], t_outputs: vec![], ak: h(0xa0) };
        let j = check(&shield).unwrap();
        assert_eq!(j.nf0(), Some(&t_nf));
        assert_eq!(j.cms[0], SNote { value: 15, owner: who(1), rho: rho(&t_nf, 0), trap: h(30) }.commitment());
        // a return: shielded notes to a transparent note of the hub's,
        // memo c, change shielded
        let (mut ret, _) = payment();
        let hub = TOut { owner: h(7), value: 10, memo: 1000, rho: h(12) };
        ret.outputs = vec![out(2, who(1), 32)];
        ret.t_outputs = vec![hub];
        let j = check(&ret).unwrap();
        assert_eq!(j.t_cms, vec![transparent_commitment(&h(7), 10, 1000, &h(12))]);
        assert_eq!(j.cms.len(), 1);
    }
}

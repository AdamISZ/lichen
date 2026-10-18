//! Shielded notes and the spend statement (docs/SHIELDED_PLAN.md): what
//! the spend guest proves, the sequencer checks a receipt against, and
//! the wallet builds.
//!
//! ```text
//! owner = SHA256("lichen/owner" ‖ nk)            nk: the owner's nullifier key
//! cm    = SHA256("lichen/snote" ‖ owner ‖ value ‖ rho)
//! nf    = SHA256("lichen/snf" ‖ nk ‖ rho)
//! rho_i = SHA256("lichen/rho" ‖ nf_0 ‖ i)        the i-th new note of a transaction
//! ```
//!
//! Shielded notes are leaves of the ledger's commitment tree beside
//! transparent ones (`lngap/note`, domain-separated), and their nullifiers
//! go in the same set. The statement: each shielded spend's note is in the
//! tree under the anchor and its `nk` is known; the new notes' `rho`s are
//! derived from the transaction's first nullifier (so no two notes share
//! one); and the values balance with the transparent spends' total and
//! outputs. Its journal ([`Journal`]) is everything public: what the
//! sequencer recomputes from the transaction. Spend authority is knowing
//! `nk`; there is no signature.
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

/// The owner of notes spendable with `nk`.
pub fn owner(nk: &Hash) -> Hash {
    sha256(&[b"lichen/owner", nk])
}

/// A shielded note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SNote {
    pub value: u64,
    pub owner: Hash,
    pub rho: Hash,
}

impl SNote {
    pub fn commitment(&self) -> Hash {
        sha256(&[b"lichen/snote", &self.owner, &self.value.to_be_bytes(), &self.rho])
    }
}

/// A shielded note's nullifier.
pub fn nullifier(nk: &Hash, rho: &Hash) -> Hash {
    sha256(&[b"lichen/snf", nk, rho])
}

/// The `rho` of a transaction's `i`-th new shielded note.
pub fn rho(nf0: &Hash, i: u32) -> Hash {
    sha256(&[b"lichen/rho", nf0, &i.to_be_bytes()])
}

/// A transparent note's commitment (`lngap-r0-core`'s `Note::commitment`).
pub fn transparent_commitment(owner: &Hash, value: u64, memo: u32, rho: &Hash) -> Hash {
    sha256(&[b"lngap/note", owner, &value.to_be_bytes(), &memo.to_be_bytes(), rho])
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

/// A shielded note being spent: its opening, its owner's `nk`, where it
/// sits in the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spend {
    pub value: u64,
    pub rho: Hash,
    pub nk: Hash,
    pub index: u32,
    pub path: Vec<Hash>,
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
    /// New shielded notes: (value, owner); their `rho`s are derived.
    pub outputs: Vec<(u64, Hash)>,
    pub t_outputs: Vec<TOut>,
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
}

/// Why an input is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// No spend, or too many spends or outputs.
    Shape,
    PathLength,
    /// A shielded note not under the anchor (or not its owner's `nk`).
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
        let note = SNote { value: s.value, owner: owner(&s.nk), rho: s.rho };
        if root_from_path(note.commitment(), s.index, &s.path) != input.anchor {
            return Err(Reject::NotInTree);
        }
        nfs.push(nullifier(&s.nk, &s.rho));
        vin += u128::from(s.value);
    }
    let nf0 = *input.t_nfs.first().or(nfs.first()).ok_or(Reject::Shape)?;
    let mut vout = 0u128;
    let mut cms = Vec::with_capacity(input.outputs.len());
    for (i, &(value, owner)) in input.outputs.iter().enumerate() {
        if value == 0 {
            return Err(Reject::Empty);
        }
        cms.push(SNote { value, owner, rho: rho(&nf0, i as u32) }.commitment());
        vout += u128::from(value);
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
    Ok(Journal { anchor: input.anchor, t_nfs: input.t_nfs.clone(), t_total: input.t_total, nfs, cms, t_cms: input.t_outputs.iter().map(|t| t.commitment()).collect() })
}

/// The nullifier set as a sparse Merkle tree (docs/SHIELDED_PLAN.md,
/// phase 2), so that a block guest can show a nullifier unspent and add
/// it. 256 levels, a leaf per nullifier by its bits (most significant
/// first, from the root); a leaf is zero if unspent, [`smt::spent`] if
/// spent; empty subtrees are the precomputed [`smt::empties`]. Its root
/// is the state root's `N`, which the withdrawal statement takes as
/// opaque.
pub mod smt {
    use super::{sha256, Hash};
    use alloc::vec::Vec;

    pub const DEPTH: usize = 256;

    /// SHA-256's initial state.
    const IV: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

    /// A node: one SHA-256 compression of `left ‖ right` from the initial
    /// state, no padding (every input is 64 bytes): half the commitment
    /// tree's `node`, and in the guest RISC Zero's accelerated compression
    /// alone.
    pub fn node(left: &Hash, right: &Hash) -> Hash {
        let mut block = [0u8; 64];
        block[..32].copy_from_slice(left);
        block[32..].copy_from_slice(right);
        let mut st = IV;
        sha2::compress256(&mut st, &[sha2::digest::generic_array::GenericArray::clone_from_slice(&block)]);
        let mut out = [0u8; 32];
        for (o, w) in out.chunks_mut(4).zip(st) {
            o.copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    /// A spent nullifier's leaf.
    pub fn spent() -> Hash {
        sha256(&[b"lichen/nf-spent"])
    }

    /// `empties()[h]`: the root of an empty subtree of height `h`
    /// (`h = 0`: an unspent leaf).
    pub fn empties() -> Vec<Hash> {
        let mut e = Vec::with_capacity(DEPTH + 1);
        e.push([0u8; 32]);
        for h in 0..DEPTH {
            let x = node(&e[h], &e[h]);
            e.push(x);
        }
        e
    }

    /// Bit `d` of `key`, counted from the root (the most significant
    /// first).
    pub fn bit(key: &Hash, d: usize) -> bool {
        key[d / 8] >> (7 - d % 8) & 1 == 1
    }

    /// A path from a leaf to the root: the sibling at each height from
    /// the leaf up, those not empty listed (`bitmap` bit `h` set).
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Proof {
        pub bitmap: [u8; 32],
        pub siblings: Vec<Hash>,
    }

    impl Proof {
        fn has(&self, h: usize) -> bool {
            self.bitmap[h / 8] >> (h % 8) & 1 == 1
        }
    }

    /// The root after spending `key` in a tree of root `root`, if `proof`
    /// shows it unspent there.
    pub fn insert(root: &Hash, key: &Hash, proof: &Proof, empties: &[Hash]) -> Option<Hash> {
        let (mut absent, mut with) = (empties[0], spent());
        let mut sibs = proof.siblings.iter();
        for h in 0..DEPTH {
            let sib = if proof.has(h) { *sibs.next()? } else { empties[h] };
            if bit(key, DEPTH - 1 - h) {
                absent = node(&sib, &absent);
                with = node(&sib, &with);
            } else {
                absent = node(&absent, &sib);
                with = node(&with, &sib);
            }
        }
        (sibs.next().is_none() && absent == *root).then_some(with)
    }

    /// The root of the subtree at depth `d` holding `keys` (sorted, all
    /// sharing their first `d` bits).
    pub fn subtree(keys: &[Hash], d: usize, empties: &[Hash]) -> Hash {
        if keys.is_empty() {
            return empties[DEPTH - d];
        }
        if d == DEPTH {
            return spent();
        }
        let i = keys.partition_point(|k| !bit(k, d));
        node(&subtree(&keys[..i], d + 1, empties), &subtree(&keys[i..], d + 1, empties))
    }

    /// The root of the set `keys` (sorted).
    pub fn root(keys: &[Hash], empties: &[Hash]) -> Hash {
        subtree(keys, 0, empties)
    }

    /// The path of `key` in the set `keys` (sorted).
    pub fn proof(keys: &[Hash], key: &Hash, empties: &[Hash]) -> Proof {
        let mut top_down = Vec::with_capacity(DEPTH);
        let mut here = keys;
        for d in 0..DEPTH {
            let i = here.partition_point(|k| !bit(k, d));
            let (zero, one) = here.split_at(i);
            let (same, other) = if bit(key, d) { (one, zero) } else { (zero, one) };
            top_down.push((!other.is_empty()).then(|| subtree(other, d + 1, empties)));
            here = same;
        }
        let mut p = Proof::default();
        for (h, sib) in top_down.into_iter().rev().enumerate() {
            if let Some(s) = sib {
                p.bitmap[h / 8] |= 1 << (h % 8);
                p.siblings.push(s);
            }
        }
        p
    }
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
            w.put(&s.nk);
            w.put(&s.index.to_be_bytes());
            w.list(&s.path);
        }
        w.0.push(self.outputs.len() as u8);
        for (v, o) in &self.outputs {
            w.put(&v.to_be_bytes());
            w.put(o);
        }
        w.0.push(self.t_outputs.len() as u8);
        for t in &self.t_outputs {
            w.put(&t.owner);
            w.put(&t.value.to_be_bytes());
            w.put(&t.memo.to_be_bytes());
            w.put(&t.rho);
        }
        w.0
    }
    pub fn from_bytes(b: &[u8]) -> Result<SpendInput, Reject> {
        let mut r = R(b);
        let anchor = r.take()?;
        let t_nfs = r.list()?;
        let t_total = r.u64()?;
        let n = r.u8()?;
        let spends = (0..n).map(|_| Ok(Spend { value: r.u64()?, rho: r.take()?, nk: r.take()?, index: r.u32()?, path: r.list()? })).collect::<Result<_, _>>()?;
        let n = r.u8()?;
        let outputs = (0..n).map(|_| Ok((r.u64()?, r.take()?))).collect::<Result<_, _>>()?;
        let n = r.u8()?;
        let t_outputs = (0..n).map(|_| Ok(TOut { owner: r.take()?, value: r.u64()?, memo: r.u32()?, rho: r.take()? })).collect::<Result<_, _>>()?;
        r.end()?;
        Ok(SpendInput { anchor, t_nfs, t_total, spends, outputs, t_outputs })
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
        w.0
    }
    pub fn from_bytes(b: &[u8]) -> Result<Journal, Reject> {
        let mut r = R(b);
        let j = Journal { anchor: r.take()?, t_nfs: r.list()?, t_total: r.u64()?, nfs: r.list()?, cms: r.list()?, t_cms: r.list()? };
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

    /// Alice (nk 1) holds notes of 5 and 7 at leaves 1 and 2, beside a
    /// transparent note at 0; she pays Bob (nk 2) 9 and keeps 3.
    fn payment() -> (SpendInput, Hash) {
        let (alice, bob) = (owner(&h(1)), owner(&h(2)));
        let n5 = SNote { value: 5, owner: alice, rho: h(10) };
        let n7 = SNote { value: 7, owner: alice, rho: h(11) };
        let (root, paths) = tree(&[transparent_commitment(&h(9), 4, 0, &h(8)), n5.commitment(), n7.commitment()]);
        let spends = vec![Spend { value: 5, rho: h(10), nk: h(1), index: 1, path: paths[1].clone() }, Spend { value: 7, rho: h(11), nk: h(1), index: 2, path: paths[2].clone() }];
        let input = SpendInput { anchor: root, t_nfs: vec![], t_total: 0, spends, outputs: vec![(9, bob), (3, alice)], t_outputs: vec![] };
        (input, root)
    }

    #[test]
    fn a_payment_and_its_journal() {
        let (input, root) = payment();
        let j = check(&input).unwrap();
        assert_eq!(j.anchor, root);
        assert_eq!(j.nfs, vec![nullifier(&h(1), &h(10)), nullifier(&h(1), &h(11))]);
        // the new notes' rhos come from the first nullifier: Bob can
        // recompute his note's commitment
        let nf0 = j.nf0().unwrap();
        assert_eq!(j.cms[0], SNote { value: 9, owner: owner(&h(2)), rho: rho(nf0, 0) }.commitment());
        assert_eq!(j.cms[1], SNote { value: 3, owner: owner(&h(1)), rho: rho(nf0, 1) }.commitment());
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
        // another nk (Bob's) for Alice's note: not its owner
        let mut i = input.clone();
        i.spends[0].nk = h(2);
        assert_eq!(check(&i), Err(Reject::NotInTree));
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
        i.outputs[0].0 = 10;
        assert_eq!(check(&i), Err(Reject::Unbalanced));
        let mut i = input.clone();
        i.outputs = vec![(12, owner(&h(2))), (0, owner(&h(1)))];
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
        i.outputs = vec![(3, owner(&h(2))); 4];
        i.t_outputs = vec![TOut { owner: h(9), value: 0, memo: 0, rho: h(0) }];
        assert_eq!(check(&i), Err(Reject::Shape));
        let mut i = input.clone();
        i.t_total = 1;
        assert_eq!(check(&i), Err(Reject::Shape));
    }

    #[test]
    fn a_tree_node_is_one_compression() {
        // one compression of the zero block from the initial state (a
        // known value), not SHA256 of 64 zero bytes: no padding
        let n = smt::node(&[0; 32], &[0; 32]);
        assert_ne!(n, node(&[0; 32], &[0; 32]));
        assert_eq!(hex_of(&n), "da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8");
    }

    fn hex_of(h: &Hash) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        for b in h {
            write!(s, "{b:02x}").unwrap();
        }
        s
    }

    #[test]
    fn the_nullifier_tree() {
        use smt::*;
        let e = empties();
        let mut keys: Vec<Hash> = vec![];
        let mut root = smt::root(&keys, &e);
        assert_eq!(root, e[DEPTH]);
        // spend them one by one, each shown unspent first, in an order
        // the sorted set isn't
        for k in [h(9), h(1), [0x80; 32], h(2), [0x81; 32], h(0)] {
            let p = proof(&keys, &k, &e);
            let next = insert(&root, &k, &p, &e).expect("unspent");
            keys.push(k);
            keys.sort();
            assert_eq!(next, smt::root(&keys, &e), "the insert's root is the set's");
            root = next;
            // spent now: no proof of it unspent
            assert_eq!(insert(&root, &k, &proof(&keys, &k, &e), &e), None);
        }
        // a proof against another root, or tampered, is refused
        let k = h(5);
        let p = proof(&keys, &k, &e);
        assert!(insert(&root, &k, &p, &e).is_some());
        assert_eq!(insert(&e[DEPTH], &k, &p, &e), None);
        let mut bad = p.clone();
        bad.siblings[0][0] ^= 1;
        assert_eq!(insert(&root, &k, &bad, &e), None);
        let mut short = p;
        short.siblings.pop();
        assert_eq!(insert(&root, &k, &short, &e), None);
    }

    #[test]
    fn shielding_and_returning() {
        // shielding: a transparent note of 20 (the sequencer checks its
        // signature) into notes of 15 and 5
        let t_nf = h(30);
        let shield = SpendInput { anchor: h(0), t_nfs: vec![t_nf], t_total: 20, spends: vec![], outputs: vec![(15, owner(&h(1))), (5, owner(&h(1)))], t_outputs: vec![] };
        let j = check(&shield).unwrap();
        assert_eq!(j.nf0(), Some(&t_nf));
        assert_eq!(j.cms[0], SNote { value: 15, owner: owner(&h(1)), rho: rho(&t_nf, 0) }.commitment());
        // a return: shielded notes to a transparent note of the hub's,
        // memo c, change shielded
        let (mut ret, _) = payment();
        let hub = TOut { owner: h(7), value: 10, memo: 1000, rho: h(12) };
        ret.outputs = vec![(2, owner(&h(1)))];
        ret.t_outputs = vec![hub];
        let j = check(&ret).unwrap();
        assert_eq!(j.t_cms, vec![transparent_commitment(&h(7), 10, 1000, &h(12))]);
        assert_eq!(j.cms.len(), 1);
    }
}

//! The spent set as a compact sparse Merkle tree (docs/SHIELDED_PLAN.md,
//! phase 2; compact since 2026-11-10), so that a block guest can show a
//! key absent and add it, and the hub's statement read a key's leaf. Keys
//! are 256 bits, read from the most significant (the root's choice) down;
//! a leaf is zero if absent, and if present says how (the hub's statement
//! reads it, docs/HUB_PROVES_PLAN.md): a spend's `txid`, [`exited`] by a
//! contract's exit record, and the acknowledgment state's.
//!
//! Compact: a subtree holding no key is zero; one holding a single key is
//! that key's [`leaf_node`], wherever it sits; one holding more is the
//! [`node`] of its halves. A key's path is then as deep as its keys'
//! common prefixes (some log₂ of the set's size), not 256 levels: about
//! ten times fewer compressions an access than the full tree, which
//! dominated the chain guest. A leaf node is a tagged SHA-256 of the key
//! and its leaf, a node one compression of its halves: the two can't be
//! confused, and a leaf node commits to its whole key.
//!
//! An [`Opening`] of a key: its leaf, and the path to its slot (the
//! subtree its prefix leads to that holds it or would): the siblings from
//! the slot up and, if the key is absent, the other key whose leaf node
//! fills the slot, if one does (else the slot is empty).

use super::{sha256, Hash};
use alloc::vec::Vec;

/// The most levels a path has: a key's bits.
pub const DEPTH: usize = 256;

/// The empty set's root, and an empty subtree.
pub const EMPTY: Hash = [0; 32];

/// SHA-256's initial state.
const IV: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

/// A node: one SHA-256 compression of `left ‖ right` from the initial
/// state, no padding (every input is 64 bytes): in the guest RISC Zero's
/// accelerated compression alone. The block is word-aligned, so the
/// guest's compression reads it in place. (`generic-array` 0.14.9
/// deprecates its own type, which `sha2` 0.10's `compress256` takes, RISC
/// Zero's fork too.)
#[allow(deprecated)]
pub fn node(left: &Hash, right: &Hash) -> Hash {
    #[repr(C, align(4))]
    struct Block([u8; 64]);
    let mut b = Block([0; 64]);
    b.0[..32].copy_from_slice(left);
    b.0[32..].copy_from_slice(right);
    let mut st = IV;
    sha2::compress256(&mut st, core::slice::from_ref(sha2::digest::generic_array::GenericArray::from_slice(&b.0)));
    let mut out = [0u8; 32];
    for (o, w) in out.chunks_exact_mut(4).zip(st) {
        o.copy_from_slice(&w.to_be_bytes());
    }
    out
}

/// A subtree holding `key` alone, its leaf `leaf`.
pub fn leaf_node(key: &Hash, leaf: &Hash) -> Hash {
    sha256(&[b"lichen/smt-leaf", key, leaf])
}

/// A nullifier's leaf, retired by contract `c`'s exit record.
pub fn exited(c: u32) -> Hash {
    sha256(&[b"lichen/nf-exit", &c.to_be_bytes()])
}

/// Bit `d` of `key`, counted from the root (the most significant
/// first).
pub fn bit(key: &Hash, d: usize) -> bool {
    key[d / 8] >> (7 - d % 8) & 1 == 1
}

/// The first bit at which `a` and `b` differ, if they do.
fn split(a: &Hash, b: &Hash) -> Option<usize> {
    (0..DEPTH).find(|&d| bit(a, d) != bit(b, d))
}

/// A key's path to its slot: the siblings from the slot up (the slot is
/// as deep as there are), and, for an absent key, the other key and its
/// leaf whose leaf node fills the slot, if one does.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proof {
    pub siblings: Vec<Hash>,
    pub other: Option<(Hash, Hash)>,
}

/// A key's leaf in the set (zero: absent) and its path: what the
/// statement reads, or checks absent before inserting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Opening {
    pub leaf: Hash,
    pub proof: Proof,
}

impl Opening {
    /// `leaf ‖ flag [‖ key ‖ leaf] ‖ n (2 bytes) ‖ siblings`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(99 + 32 * self.proof.siblings.len());
        w.extend_from_slice(&self.leaf);
        match &self.proof.other {
            Some((k, l)) => {
                w.push(1);
                w.extend_from_slice(k);
                w.extend_from_slice(l);
            }
            None => w.push(0),
        }
        w.extend_from_slice(&(self.proof.siblings.len() as u16).to_be_bytes());
        for s in &self.proof.siblings {
            w.extend_from_slice(s);
        }
        w
    }
    /// From the front of `b`; the rest.
    pub fn from_bytes(b: &[u8]) -> Option<(Opening, &[u8])> {
        fn take<const N: usize>(b: &mut &[u8]) -> Option<[u8; N]> {
            let (a, rest) = (b.len() >= N).then(|| b.split_at(N))?;
            *b = rest;
            a.try_into().ok()
        }
        let mut b = b;
        let leaf = take::<32>(&mut b)?;
        let other = match take::<1>(&mut b)? {
            [0] => None,
            [1] => Some((take::<32>(&mut b)?, take::<32>(&mut b)?)),
            _ => return None,
        };
        let n = u16::from_be_bytes(take::<2>(&mut b)?) as usize;
        if n > DEPTH {
            return None;
        }
        let siblings = (0..n).map(|_| take::<32>(&mut b)).collect::<Option<Vec<_>>>()?;
        Some((Opening { leaf, proof: Proof { siblings, other } }, b))
    }
}

/// The root `sub` reaches as `key`'s slot through `siblings` (from the
/// slot up).
fn climb(key: &Hash, mut sub: Hash, siblings: &[Hash]) -> Hash {
    let d = siblings.len();
    for (i, s) in siblings.iter().enumerate() {
        sub = if bit(key, d - 1 - i) { node(s, &sub) } else { node(&sub, s) };
    }
    sub
}

/// What fills `key`'s slot by `proof`, its leaf `leaf` (zero: absent):
/// none if the proof is malformed.
fn slot(key: &Hash, leaf: &Hash, proof: &Proof) -> Option<Hash> {
    let d = proof.siblings.len();
    if d > DEPTH {
        return None;
    }
    match (leaf == &EMPTY, &proof.other) {
        (false, None) => Some(leaf_node(key, leaf)),
        (true, None) => Some(EMPTY),
        // another key in the slot: of the same prefix, present
        (true, Some((k, l))) => (k != key && *l != EMPTY && split(k, key).is_some_and(|s| s >= d)).then(|| leaf_node(k, l)),
        (false, Some(_)) => None,
    }
}

/// Whether `proof` shows `key`'s leaf to be `leaf` in the set of root
/// `root` (zero: absent).
pub fn holds(root: &Hash, key: &Hash, leaf: &Hash, proof: &Proof) -> bool {
    slot(key, leaf, proof).is_some_and(|s| climb(key, s, &proof.siblings) == *root)
}

/// Whether `proof` shows `key` absent from the set of root `root`.
pub fn unspent(root: &Hash, key: &Hash, proof: &Proof) -> bool {
    holds(root, key, &EMPTY, proof)
}

/// The root after inserting `key` with leaf `leaf` (not zero) in the set
/// of root `root`, if `proof` shows it absent there: its slot then holds
/// it alone, or it and the other key there, split where they differ.
pub fn insert(root: &Hash, key: &Hash, leaf: &Hash, proof: &Proof) -> Option<Hash> {
    if *leaf == EMPTY || !unspent(root, key, proof) {
        return None;
    }
    let d = proof.siblings.len();
    let mine = leaf_node(key, leaf);
    let sub = match &proof.other {
        None => mine,
        Some((k, l)) => {
            let s = split(k, key)?;
            let theirs = leaf_node(k, l);
            let mut sub = if bit(key, s) { node(&theirs, &mine) } else { node(&mine, &theirs) };
            for e in (d..s).rev() {
                sub = if bit(key, e) { node(&EMPTY, &sub) } else { node(&sub, &EMPTY) };
            }
            sub
        }
    };
    Some(climb(key, sub, &proof.siblings))
}

/// The root of the subtree at depth `d` holding `keys` (sorted, each
/// with its leaf, all sharing their first `d` bits).
fn subtree(keys: &[(Hash, Hash)], d: usize) -> Hash {
    match keys {
        [] => EMPTY,
        [(k, l)] => leaf_node(k, l),
        _ => {
            let i = keys.partition_point(|k| !bit(&k.0, d));
            node(&subtree(&keys[..i], d + 1), &subtree(&keys[i..], d + 1))
        }
    }
}

/// The root of the set `keys` (sorted, distinct, each with its leaf, none
/// zero).
pub fn root(keys: &[(Hash, Hash)]) -> Hash {
    subtree(keys, 0)
}

/// The path of `key` in the set `keys` (sorted, each with its leaf).
pub fn proof(keys: &[(Hash, Hash)], key: &Hash) -> Proof {
    let mut top_down = Vec::new();
    let mut here = keys;
    let mut d = 0;
    loop {
        match here {
            [] => break,
            [(k, l)] => {
                let other = (k != key).then_some((*k, *l));
                return Proof { siblings: top_down.into_iter().rev().collect(), other };
            }
            _ => {
                let i = here.partition_point(|k| !bit(&k.0, d));
                let (zero, one) = here.split_at(i);
                let (same, other) = if bit(key, d) { (one, zero) } else { (zero, one) };
                top_down.push(subtree(other, d + 1));
                here = same;
                d += 1;
            }
        }
    }
    Proof { siblings: top_down.into_iter().rev().collect(), other: None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn h(n: u8) -> Hash {
        [n; 32]
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
    fn a_tree_node_is_one_compression() {
        // one compression of the zero block from the initial state (a
        // known value), not SHA256 of 64 zero bytes: no padding
        let n = node(&[0; 32], &[0; 32]);
        assert_ne!(n, lichen_shielded::node(&[0; 32], &[0; 32]));
        assert_eq!(hex_of(&n), "da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8");
    }

    #[test]
    fn the_spent_set() {
        let mut keys: Vec<(Hash, Hash)> = vec![];
        let mut root = super::root(&keys);
        assert_eq!(root, EMPTY);
        // insert them one by one, each shown absent first, in an order
        // the sorted set isn't, with each kind of leaf; keys sharing long
        // prefixes ([0x80; 32] and [0x81; 32] differ at bit 7, h(0) and
        // [0, .., 1] at bit 255)
        let mut last = [0u8; 32];
        last[31] = 1;
        let leaves = [h(0xee), exited(1000), exited(1001), h(0xee), exited(1002), h(0xee), h(0xef)];
        for (k, leaf) in [h(9), h(1), [0x80; 32], h(2), [0x81; 32], h(0), last].into_iter().zip(leaves) {
            let p = proof(&keys, &k);
            assert!(unspent(&root, &k, &p));
            let next = insert(&root, &k, &leaf, &p).expect("absent");
            keys.push((k, leaf));
            keys.sort();
            assert_eq!(next, super::root(&keys), "the insert's root is the set's");
            root = next;
            // present now: no proof of it absent, a proof of its leaf
            let p = proof(&keys, &k);
            assert_eq!(insert(&root, &k, &h(0xee), &p), None);
            assert!(!unspent(&root, &k, &p));
            assert!(holds(&root, &k, &leaf, &p));
        }
        // a path is as deep as the keys' prefixes, not 256 levels
        assert_eq!(proof(&keys, &h(9)).siblings.len(), 5, "0x09 parts from 0x00, 0x01, 0x02 at bit 4");
        assert_eq!(proof(&keys, &last).siblings.len(), 256);
        // a leaf says how: not another kind, nor another contract
        let p = proof(&keys, &h(1));
        assert!(holds(&root, &h(1), &exited(1000), &p));
        for other in [h(0xee), exited(1001), EMPTY] {
            assert!(!holds(&root, &h(1), &other, &p));
        }
        // absent: an empty slot, or another key's
        for k in [h(5), h(0x7f), [0x82; 32], h(0x0b)] {
            let p = proof(&keys, &k);
            assert!(unspent(&root, &k, &p), "{k:?}");
        }
        assert!(proof(&keys, &h(5)).other.is_none(), "0x05's slot is empty");
        assert_eq!(proof(&keys, &h(0x0b)).other, Some((h(9), h(0xee))), "0x0b's slot holds 0x09 alone");
        assert!(unspent(&root, &h(0x0b), &proof(&keys, &h(0x0b))));
        // another key's leaf can't pass for this one's, nor this one's
        // absence be shown by a key of another prefix, nor by itself
        let p = proof(&keys, &h(1));
        let pretend = Proof { siblings: p.siblings.clone(), other: Some((h(1), exited(1000))) };
        assert!(!unspent(&root, &h(1), &pretend));
        let pb = proof(&keys, &h(0x0b));
        assert!(!holds(&root, &h(9), &h(0xee), &Proof { siblings: pb.siblings.clone(), other: Some((h(0x0b), h(1))) }));
        let mut far = pb.clone();
        far.other = Some((h(1), h(0xee)));
        assert!(!unspent(&root, &h(0x0b), &far), "a key of another prefix in the slot");
        // a proof against another root, tampered, short or long, is refused
        let k = h(5);
        let p = proof(&keys, &k);
        assert!(insert(&root, &k, &h(0xee), &p).is_some());
        assert_eq!(insert(&EMPTY, &k, &h(0xee), &p), None);
        assert_eq!(insert(&root, &k, &EMPTY, &p), None, "a zero leaf");
        let mut bad = p.clone();
        bad.siblings[0][0] ^= 1;
        assert_eq!(insert(&root, &k, &h(0xee), &bad), None);
        let mut short = p.clone();
        short.siblings.pop();
        assert_eq!(insert(&root, &k, &h(0xee), &short), None);
        let mut long = p.clone();
        long.siblings.insert(0, EMPTY);
        assert_eq!(insert(&root, &k, &h(0xee), &long), None);
        // an opening's bytes, and back
        let o = Opening { leaf: EMPTY, proof: p };
        let mut b = o.to_bytes();
        b.push(7);
        assert_eq!(Opening::from_bytes(&b), Some((o, &[7u8][..])));
    }
}

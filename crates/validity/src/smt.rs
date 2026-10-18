//! The nullifier set as a sparse Merkle tree (docs/SHIELDED_PLAN.md,
//! phase 2), so that a block guest can show a nullifier unspent and add
//! it. 256 levels, a leaf per nullifier by its bits (most significant
//! first, from the root); a leaf is zero if unspent, [`spent`] if
//! spent; empty subtrees are the precomputed [`empties`]. Its root
//! is the state root's `N`, which the withdrawal statement takes as
//! opaque.

use super::{sha256, Hash};
use alloc::vec::Vec;

pub const DEPTH: usize = 256;

/// SHA-256's initial state.
const IV: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

/// A node: one SHA-256 compression of `left ‖ right` from the initial
/// state, no padding (every input is 64 bytes): half the commitment
/// tree's `node`, and in the guest RISC Zero's accelerated compression
/// alone. (`generic-array` 0.14.9 deprecates its own type, which
/// `sha2` 0.10's `compress256` takes, RISC Zero's fork too.)
#[allow(deprecated)]
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
    fn the_nullifier_tree() {
        let e = empties();
        let mut keys: Vec<Hash> = vec![];
        let mut root = super::root(&keys, &e);
        assert_eq!(root, e[DEPTH]);
        // spend them one by one, each shown unspent first, in an order
        // the sorted set isn't
        for k in [h(9), h(1), [0x80; 32], h(2), [0x81; 32], h(0)] {
            let p = proof(&keys, &k, &e);
            let next = insert(&root, &k, &p, &e).expect("unspent");
            keys.push(k);
            keys.sort();
            assert_eq!(next, super::root(&keys, &e), "the insert's root is the set's");
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
}

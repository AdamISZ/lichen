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
/// alone. The block is word-aligned, so the guest's compression reads it
/// in place. (`generic-array` 0.14.9 deprecates its own type, which
/// `sha2` 0.10's `compress256` takes, RISC Zero's fork too.)
#[allow(deprecated)]
pub fn node(left: &Hash, right: &Hash) -> Hash {
    #[repr(C, align(4))]
    struct Block([u8; 64]);
    let mut b = Block([0; 64]);
    b.0[..32].copy_from_slice(left);
    b.0[32..].copy_from_slice(right);
    let mut st = IV;
    sha2::compress256(&mut st, core::slice::from_ref(sha2::digest::generic_array::GenericArray::from_slice(&b.0)));
    words_be(&st)
}

const fn words_be(st: &[u32; 8]) -> Hash {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 8 {
        let w = st[i].to_be_bytes();
        out[4 * i] = w[0];
        out[4 * i + 1] = w[1];
        out[4 * i + 2] = w[2];
        out[4 * i + 3] = w[3];
        i += 1;
    }
    out
}

/// A spent nullifier's leaf.
pub fn spent() -> Hash {
    sha256(&[b"lichen/nf-spent"])
}

/// `empties()[h]`: the root of an empty subtree of height `h`
/// (`h = 0`: an unspent leaf). A table built when compiling ([`EMPTIES`]):
/// in the guest, 256 compressions every block otherwise.
pub fn empties() -> &'static [Hash] {
    &EMPTIES
}

/// The empty subtrees' roots, computed at compile time with
/// [`const_node`].
pub static EMPTIES: [Hash; DEPTH + 1] = {
    let mut e = [[0u8; 32]; DEPTH + 1];
    let mut h = 0;
    while h < DEPTH {
        e[h + 1] = const_node(&e[h], &e[h]);
        h += 1;
    }
    e
};

/// [`node`], as a `const fn`: SHA-256's compression in plain Rust (FIPS
/// 180-4), for [`EMPTIES`].
pub const fn const_node(left: &Hash, right: &Hash) -> Hash {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut w = [0u32; 64];
    let mut i = 0;
    while i < 16 {
        let b = if i < 8 { left } else { right };
        let j = (i % 8) * 4;
        w[i] = u32::from_be_bytes([b[j], b[j + 1], b[j + 2], b[j + 3]]);
        i += 1;
    }
    while i < 64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        i += 1;
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = IV;
    i = 0;
    while i < 64 {
        let t1 = h.wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25)).wrapping_add((e & f) ^ (!e & g)).wrapping_add(K[i]).wrapping_add(w[i]);
        let t2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22)).wrapping_add((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        i += 1;
    }
    let st = [IV[0].wrapping_add(a), IV[1].wrapping_add(b), IV[2].wrapping_add(c), IV[3].wrapping_add(d), IV[4].wrapping_add(e), IV[5].wrapping_add(f), IV[6].wrapping_add(g), IV[7].wrapping_add(h)];
    words_be(&st)
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

/// Whether `proof` shows `key` unspent in a tree of root `root`: what
/// [`insert`] checks before spending it.
pub fn unspent(root: &Hash, key: &Hash, proof: &Proof, empties: &[Hash]) -> bool {
    let mut absent = empties[0];
    let mut sibs = proof.siblings.iter();
    for h in 0..DEPTH {
        let sib = if proof.has(h) {
            match sibs.next() {
                Some(s) => *s,
                None => return false,
            }
        } else {
            empties[h]
        };
        absent = if bit(key, DEPTH - 1 - h) { node(&sib, &absent) } else { node(&absent, &sib) };
    }
    sibs.next().is_none() && absent == *root
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
    fn the_empty_roots_are_the_runtime_nodes() {
        let mut x = [0u8; 32];
        for (h, e) in EMPTIES.iter().enumerate() {
            assert_eq!(*e, x, "height {h}");
            assert_eq!(const_node(&x, &h_bytes(h)), node(&x, &h_bytes(h)));
            x = node(&x, &x);
        }
    }

    fn h_bytes(h: usize) -> Hash {
        core::array::from_fn(|i| (h * 31 + i * 7) as u8)
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
            assert!(!unspent(&root, &k, &proof(&keys, &k, &e), &e));
        }
        // unspent agrees with insert
        assert!(unspent(&root, &h(5), &proof(&keys, &h(5), &e), &e));
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

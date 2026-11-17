//! The ledger's commitments, keys and roots, as the withdrawal statement
//! checks them (from ln-gap's `lngap-r0-core`, at 8b057ed). The hashing
//! tags keep ln-gap's names: the commitments and roots are unchanged.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};


/// The commitment tree's depth: 2^16 notes.
pub const TREE_DEPTH: usize = 16;

/// The toy deployment's sequencer key (x-only), from the seed
/// "lngap-toy/sequencer": for tests and regtest demos only (anyone can
/// derive its secret).
pub const SEQUENCER_KEY: [u8; 32] = [
    0xa7, 0xad, 0x0e, 0xb4, 0xbc, 0xc5, 0xdf, 0x74, 0xd9, 0x6c, 0xb0, 0x35, 0xfd, 0xcc, 0x75, 0x3e,
    0x47, 0x2a, 0xfa, 0x7f, 0x54, 0x73, 0xfc, 0xcf, 0x9e, 0xe5, 0x6f, 0xc7, 0x92, 0x03, 0xd1, 0x7f,
];

/// The toy deployment's hub key (x-only), from the seed "lngap-toy/hub":
/// for tests and regtest demos only.
pub const HUB_KEY: [u8; 32] = [
    0xd3, 0xb3, 0x18, 0xbc, 0x30, 0x36, 0x56, 0x6f, 0x33, 0xf5, 0xea, 0x00, 0x0a, 0x7e, 0xee, 0xfc,
    0x41, 0xcb, 0x6d, 0xac, 0x09, 0xfd, 0x3a, 0x23, 0x76, 0xf2, 0x43, 0x79, 0x84, 0xea, 0xdf, 0xea,
];

/// A deployment's id: its sequencer's and hub's keys (x-only), hashed.
pub fn deployment_id(sequencer: &[u8; 32], hub: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"lngap/deployment");
    h.update(sequencer);
    h.update(hub);
    h.finalize().into()
}

/// A note.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub owner: [u8; 32],
    pub value: u64,
    pub memo: u32,
    pub rho: [u8; 32],
}

impl Note {
    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"lngap/note");
        h.update(self.owner);
        h.update(self.value.to_be_bytes());
        h.update(self.memo.to_be_bytes());
        h.update(self.rho);
        h.finalize().into()
    }
}

/// A node of the commitment tree.
pub fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The root a leaf at `index` reaches through `path` (siblings, leaf
/// level first).
pub fn root_from_path(leaf: [u8; 32], index: u32, path: &[[u8; 32]]) -> [u8; 32] {
    let mut h = leaf;
    for (level, sib) in path.iter().enumerate() {
        h = if (index >> level) & 1 == 1 { node(sib, &h) } else { node(&h, sib) };
    }
    h
}

/// The state root the sequencer signs.
pub fn state_root(height: u64, tree: &[u8; 32], nullifiers: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"lngap/root");
    h.update(height.to_be_bytes());
    h.update(tree);
    h.update(nullifiers);
    h.finalize().into()
}

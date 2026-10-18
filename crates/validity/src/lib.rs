//! The block statement (docs/SHIELDED_PLAN.md, phase 2): one sealed
//! height's transition `i -> i+1`, checked as the sequencer checks it.
//!
//! The state at a height is the commitment tree (its root `T`, its size,
//! its frontier), the nullifier tree's root `N` ([`lichen_shielded::smt`])
//! and the last [`RECENT`] sealed tree roots, the anchors a spend may use.
//! The withdrawal statement sees only `SR = state_root(height, T, N)`; the
//! recent roots travel beside it in the journal ([`BlockJournal`]).
//!
//! A block is the transactions applied between two seals, in order:
//! mints (signed by the hub), transparent transfers (each spend signed by
//! its note's owner, BIP340), and shielded transactions, whose receipts
//! the caller checks (`verify_spend`: `env::verify` in the guest) against
//! the journal recomputed here. Every nullifier is shown unspent and
//! inserted, in order; every new leaf is appended. Unlike the sequencer
//! it doesn't check new commitments unique: that would take every
//! commitment, and a duplicate shares its nullifier with the original, so
//! it can only cost its owner, never make value.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use k256::schnorr::{Signature, VerifyingKey};
use lichen_shielded::{self as sh, smt, Hash, TREE_DEPTH};
pub use lichen_shielded::RECENT;
use sha2::{Digest, Sha256};

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// A transparent note (`lngap-r0-core`'s `Note`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TNote {
    pub owner: Hash,
    pub value: u64,
    pub memo: u32,
    pub rho: Hash,
}

impl TNote {
    pub fn commitment(&self) -> Hash {
        sh::transparent_commitment(&self.owner, self.value, self.memo, &self.rho)
    }
    /// Its nullifier (the ledger's `nullifier`).
    pub fn nullifier(&self) -> Hash {
        sha256(&[b"lngap/nf", &self.commitment()])
    }
}

/// The state root the sequencer signs (`lngap-r0-core`'s `state_root`).
pub fn state_root(height: u64, tree: &Hash, nullifiers: &Hash) -> Hash {
    sha256(&[b"lngap/root", &height.to_be_bytes(), tree, nullifiers])
}

/// The recent roots, hashed for the journal.
pub fn recent_hash(roots: &[Hash]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/recent");
    for r in roots {
        h.update(r);
    }
    h.finalize().into()
}

/// The ledger's `Mint::digest`.
pub fn mint_digest(outputs: &[TNote]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/mint");
    for n in outputs {
        h.update(n.commitment());
    }
    h.finalize().into()
}

/// The ledger's `Transfer::digest`.
pub fn transfer_digest(spends: &[(TNote, u32)], outputs: &[TNote]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/transfer");
    for (n, i) in spends {
        h.update(n.commitment());
        h.update(i.to_be_bytes());
    }
    h.update(b"/");
    for n in outputs {
        h.update(n.commitment());
    }
    h.finalize().into()
}

/// The ledger's `Shielded::digest`, from the journal and the ciphertexts.
pub fn shielded_digest(journal: &[u8], ciphertexts: &[Vec<u8>]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/shielded");
    h.update(journal);
    for c in ciphertexts {
        h.update((c.len() as u32).to_be_bytes());
        h.update(c);
    }
    h.finalize().into()
}

/// The commitment tree's empty subtrees (`empties[l]`: height `l`).
pub fn tree_empties() -> [Hash; TREE_DEPTH + 1] {
    let mut z = [[0u8; 32]; TREE_DEPTH + 1];
    for l in 0..TREE_DEPTH {
        z[l + 1] = sh::node(&z[l], &z[l]);
    }
    z
}

/// The commitment tree as the next append needs it: its size, and at
/// each level the left node a right child there pairs with (set where
/// the size's bit is; else unread before an append writes it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontier {
    pub size: u32,
    pub branch: Vec<Hash>,
}

impl Frontier {
    pub fn root(&self, z: &[Hash]) -> Hash {
        let mut node = z[0];
        for l in 0..TREE_DEPTH {
            node = if self.size >> l & 1 == 1 { sh::node(&self.branch[l], &node) } else { sh::node(&node, &z[l]) };
        }
        node
    }
    pub fn append(&mut self, leaf: Hash) -> Result<u32, Reject> {
        if self.size >= 1 << TREE_DEPTH {
            return Err(Reject::TreeFull);
        }
        let index = self.size;
        let (mut node, mut i) = (leaf, index);
        for l in 0..TREE_DEPTH {
            if i & 1 == 0 {
                self.branch[l] = node;
                break;
            }
            node = sh::node(&self.branch[l], &node);
            i >>= 1;
        }
        self.size += 1;
        Ok(index)
    }
}

/// A transaction as the block statement reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tx {
    Mint { outputs: Vec<TNote>, sig: [u8; 64] },
    Transfer { spends: Vec<(TNote, u32)>, outputs: Vec<TNote>, sigs: Vec<[u8; 64]> },
    /// Its receipt is checked by the caller, against the journal
    /// recomputed from these fields.
    Shielded { anchor: Hash, t_spends: Vec<(TNote, u32)>, t_sigs: Vec<[u8; 64]>, nfs: Vec<Hash>, cms: Vec<Hash>, ciphertexts: Vec<Vec<u8>>, t_outputs: Vec<TNote> },
}

/// The statement's input: the state at height `i`, the block, and the
/// witnesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockInput {
    /// The hub's key: who mints.
    pub hub: Hash,
    pub height: u64,
    pub tree: Frontier,
    pub nullifiers: Hash,
    /// The last sealed tree roots, oldest first (at most `RECENT`).
    pub recent: Vec<Hash>,
    pub txs: Vec<Tx>,
    /// An insert proof per nullifier, in order: each transaction's
    /// transparent spends', then its shielded ones.
    pub nf_proofs: Vec<smt::Proof>,
    /// A path under `T_i` per transparent spend of a note from before the
    /// block, in order.
    pub paths: Vec<Vec<Hash>>,
}

/// What the statement shows: from height `i` to `i+1`, under the hub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockJournal {
    pub hub: Hash,
    pub height: u64,
    pub from: Hash,
    pub recent_from: Hash,
    pub to: Hash,
    pub recent_to: Hash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Encoding,
    BadSignature,
    /// A spent note not in the tree (or not the one at its index).
    NotInTree,
    /// A nullifier already spent, or its proof wrong.
    Spent,
    /// An anchor not among the recent roots.
    Anchor,
    /// A shielded transaction's receipt doesn't verify.
    Receipt,
    Unbalanced,
    Empty,
    TreeFull,
    Shape,
}

fn check_sig(key: &Hash, msg: &Hash, sig: &[u8; 64]) -> Result<(), Reject> {
    let k = VerifyingKey::from_bytes(key).map_err(|_| Reject::BadSignature)?;
    let s = Signature::try_from(&sig[..]).map_err(|_| Reject::BadSignature)?;
    k.verify_raw(msg, &s).map_err(|_| Reject::BadSignature)
}

struct State<'a> {
    input: &'a BlockInput,
    z: [Hash; TREE_DEPTH + 1],
    e: Vec<Hash>,
    t_i: Hash,
    tree: Frontier,
    nullifiers: Hash,
    /// The leaves appended in this block: (index, commitment).
    made: Vec<(u32, Hash)>,
    nf_proofs: core::slice::Iter<'a, smt::Proof>,
    paths: core::slice::Iter<'a, Vec<Hash>>,
}

impl State<'_> {
    fn spend_nf(&mut self, nf: &Hash) -> Result<(), Reject> {
        let p = self.nf_proofs.next().ok_or(Reject::Shape)?;
        self.nullifiers = smt::insert(&self.nullifiers, nf, p, &self.e).ok_or(Reject::Spent)?;
        Ok(())
    }
    /// A transparent note at `index`: under `T_i` (a path), or made
    /// earlier in this block.
    fn in_tree(&mut self, n: &TNote, index: u32) -> Result<(), Reject> {
        let cm = n.commitment();
        if index < self.input.tree.size {
            let path = self.paths.next().ok_or(Reject::Shape)?;
            if path.len() != TREE_DEPTH || sh::root_from_path(cm, index, path) != self.t_i {
                return Err(Reject::NotInTree);
            }
            Ok(())
        } else if self.made.iter().any(|&(i, c)| i == index && c == cm) {
            Ok(())
        } else {
            Err(Reject::NotInTree)
        }
    }
    fn make(&mut self, cm: Hash) -> Result<(), Reject> {
        let i = self.tree.append(cm)?;
        self.made.push((i, cm));
        Ok(())
    }
}

fn sum(mut ns: impl Iterator<Item = u64>) -> Result<u64, Reject> {
    ns.try_fold(0u64, |a, v| a.checked_add(v)).ok_or(Reject::Unbalanced)
}

/// The statement: check the block in `input`; its journal. `verify_spend`
/// checks a shielded transaction's receipt with the given journal (the
/// spend statement's, encoded).
pub fn check(input: &BlockInput, verify_spend: &mut dyn FnMut(&[u8]) -> bool) -> Result<BlockJournal, Reject> {
    if input.tree.branch.len() != TREE_DEPTH || input.recent.len() > RECENT {
        return Err(Reject::Shape);
    }
    let z = tree_empties();
    let t_i = input.tree.root(&z);
    let mut st = State { input, z, e: smt::empties(), t_i, tree: input.tree.clone(), nullifiers: input.nullifiers, made: Vec::new(), nf_proofs: input.nf_proofs.iter(), paths: input.paths.iter() };
    for tx in &input.txs {
        match tx {
            Tx::Mint { outputs, sig } => {
                check_sig(&input.hub, &mint_digest(outputs), sig)?;
                for n in outputs {
                    if n.value == 0 {
                        return Err(Reject::Empty);
                    }
                    st.make(n.commitment())?;
                }
            }
            Tx::Transfer { spends, outputs, sigs } => {
                if spends.is_empty() || sigs.len() != spends.len() {
                    return Err(Reject::Shape);
                }
                let d = transfer_digest(spends, outputs);
                for ((n, i), sig) in spends.iter().zip(sigs) {
                    st.in_tree(n, *i)?;
                    check_sig(&n.owner, &d, sig)?;
                    st.spend_nf(&n.nullifier())?;
                }
                if sum(spends.iter().map(|s| s.0.value))? != sum(outputs.iter().map(|n| n.value))? {
                    return Err(Reject::Unbalanced);
                }
                for n in outputs {
                    if n.value == 0 {
                        return Err(Reject::Empty);
                    }
                    st.make(n.commitment())?;
                }
            }
            Tx::Shielded { anchor, t_spends, t_sigs, nfs, cms, ciphertexts, t_outputs } => {
                if !input.recent.contains(anchor) {
                    return Err(Reject::Anchor);
                }
                if t_sigs.len() != t_spends.len() || ciphertexts.len() != cms.len() {
                    return Err(Reject::Shape);
                }
                let journal = sh::Journal {
                    anchor: *anchor,
                    t_nfs: t_spends.iter().map(|s| s.0.nullifier()).collect(),
                    t_total: sum(t_spends.iter().map(|s| s.0.value))?,
                    nfs: nfs.clone(),
                    cms: cms.clone(),
                    t_cms: t_outputs.iter().map(|n| n.commitment()).collect(),
                }
                .to_bytes();
                if !verify_spend(&journal) {
                    return Err(Reject::Receipt);
                }
                let d = shielded_digest(&journal, ciphertexts);
                for ((n, i), sig) in t_spends.iter().zip(t_sigs) {
                    st.in_tree(n, *i)?;
                    check_sig(&n.owner, &d, sig)?;
                }
                for n in t_spends.iter().map(|s| s.0.nullifier()).chain(nfs.iter().copied()) {
                    st.spend_nf(&n)?;
                }
                for cm in cms {
                    st.make(*cm)?;
                }
                for n in t_outputs {
                    st.make(n.commitment())?;
                }
            }
        }
    }
    if st.nf_proofs.next().is_some() || st.paths.next().is_some() {
        return Err(Reject::Shape);
    }
    let t_next = st.tree.root(&st.z);
    let mut recent = input.recent.clone();
    recent.push(t_next);
    if recent.len() > RECENT {
        recent.remove(0);
    }
    Ok(BlockJournal {
        hub: input.hub,
        height: input.height,
        from: state_root(input.height, &t_i, &input.nullifiers),
        recent_from: recent_hash(&input.recent),
        to: state_root(input.height + 1, &t_next, &st.nullifiers),
        recent_to: recent_hash(&recent),
    })
}

//! The L2 ledger: transparent notes in an append-only commitment tree, a
//! nullifier set, and a sequencer that seals batches into state roots and
//! signs them (BIP340).
//!
//! The note, the tree's hashing and the state root are the withdrawal
//! statement's own (`lngap-r0-core`), so a return recorded here is exactly
//! what the proof checks: [`Ledger::withdraw_input`] is the prover's input.
//!
//! Two kinds of transaction:
//! - a [`Mint`]: the hub issues notes (it may issue as many as it likes;
//!   every redemption is against its own collateral, capped per user);
//! - a [`Transfer`]: spends notes, each authorised by its owner's BIP340
//!   signature over the transfer, and creates notes of equal total value.
//!   A withdrawal starts with a transfer to the hub carrying the
//!   contract's memo `c`: a return.

use std::collections::{BTreeSet, HashSet};

use anyhow::{bail, ensure, Context, Result};
pub use k256;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use lngap_r0_core::{check, deployment_id, node, root_from_path, state_root, Note, Reject, WithdrawInput, HUB_KEY, JOURNAL_LEN, SEQUENCER_KEY, TREE_DEPTH};

pub type Hash = [u8; 32];

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// A key from a label: anyone can derive it, so for tests and the toy
/// deployment only.
pub fn key_from_label(label: &str) -> SigningKey {
    SigningKey::from_bytes(&sha256(&[label.as_bytes()])).expect("a valid scalar")
}

/// The toy deployment's sequencer key (`SEQUENCER_KEY`): tests, the demo.
pub fn regtest_sequencer() -> SigningKey {
    key_from_label("lngap-toy/sequencer")
}

/// The toy deployment's hub key (`HUB_KEY`): tests, the demo.
pub fn regtest_hub() -> SigningKey {
    key_from_label("lngap-toy/hub")
}

/// A fresh random key.
pub fn fresh_key() -> SigningKey {
    loop {
        if let Ok(k) = SigningKey::from_bytes(&fresh_rho()) {
            return k;
        }
    }
}

/// The key kept (hex) in `path`, made and saved there if there is none.
pub fn load_or_create_key(path: &std::path::Path) -> Result<SigningKey> {
    if path.exists() {
        let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        return SigningKey::from_bytes(&hex::decode(s.trim()).context("a hex key")?).context("a valid key");
    }
    let k = fresh_key();
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(path, hex::encode(k.to_bytes()))?;
    Ok(k)
}

/// An L2 deployment: who seals (the sequencer) and who mints and receives
/// returns (the hub), as x-only keys. The withdrawal statement's journal
/// commits to them as [`Deployment::id`]; a contract pins that id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deployment {
    pub sequencer: Hash,
    pub hub: Hash,
}

impl Deployment {
    /// The toy deployment's (tests, the demo): keys anyone can derive.
    pub fn toy() -> Deployment {
        Deployment { sequencer: SEQUENCER_KEY, hub: HUB_KEY }
    }
    pub fn id(&self) -> Hash {
        deployment_id(&self.sequencer, &self.hub)
    }
}

impl Default for Deployment {
    fn default() -> Deployment {
        Deployment::toy()
    }
}

pub fn xonly(k: &SigningKey) -> Hash {
    k.verifying_key().to_bytes().into()
}

/// A BIP340 signature with fresh auxiliary randomness.
pub fn sign(k: &SigningKey, msg: &Hash) -> Vec<u8> {
    let mut aux = [0u8; 32];
    getrandom::getrandom(&mut aux).expect("randomness");
    k.sign_raw(msg, &aux).expect("signing").to_bytes().to_vec()
}

pub fn verify(owner: &Hash, msg: &Hash, sig: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_bytes(owner).context("not a public key")?;
    let sig = Signature::try_from(sig).context("not a signature")?;
    key.verify_raw(msg, &sig).context("bad signature")
}

/// A fresh random `rho`.
pub fn fresh_rho() -> Hash {
    let mut r = [0u8; 32];
    getrandom::getrandom(&mut r).expect("randomness");
    r
}

/// A note's nullifier (transparent: anyone can compute it).
pub fn nullifier(note: &Note) -> Hash {
    sha256(&[b"lngap/nf", &note.commitment()])
}

/// The append-only commitment tree, depth `TREE_DEPTH`; empty leaves are
/// zero. Roots and paths can be taken at any earlier size, so a note can
/// be shown under the root of the height that sealed it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Tree {
    leaves: Vec<Hash>,
}

impl Tree {
    pub fn len(&self) -> u32 {
        self.leaves.len() as u32
    }
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
    pub fn leaf(&self, i: u32) -> Option<Hash> {
        self.leaves.get(i as usize).copied()
    }
    pub fn append(&mut self, cm: Hash) -> Result<u32> {
        ensure!(self.leaves.len() < 1 << TREE_DEPTH, "the tree is full");
        self.leaves.push(cm);
        Ok(self.len() - 1)
    }
    /// Every level over the first `size` leaves, leaves first, and the
    /// empty subtrees' hashes.
    fn levels(&self, size: u32) -> (Vec<Vec<Hash>>, Vec<Hash>) {
        let mut zero = vec![[0u8; 32]];
        for l in 0..TREE_DEPTH {
            zero.push(node(&zero[l], &zero[l]));
        }
        let mut levels = vec![self.leaves[..size as usize].to_vec()];
        for l in 0..TREE_DEPTH {
            let next: Vec<Hash> = levels[l].chunks(2).map(|p| node(&p[0], p.get(1).unwrap_or(&zero[l]))).collect();
            levels.push(next);
        }
        (levels, zero)
    }
    pub fn root_at(&self, size: u32) -> Hash {
        let (levels, zero) = self.levels(size);
        levels[TREE_DEPTH].first().copied().unwrap_or(zero[TREE_DEPTH])
    }
    pub fn path_at(&self, index: u32, size: u32) -> Vec<Hash> {
        let (levels, zero) = self.levels(size);
        (0..TREE_DEPTH).map(|l| levels[l].get(((index >> l) ^ 1) as usize).copied().unwrap_or(zero[l])).collect()
    }
}

/// The nullifier set. Its root is a hash over the sorted set (the
/// withdrawal statement takes it as opaque); the empty set's is the toy
/// L2's.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Nullifiers {
    set: BTreeSet<Hash>,
}

impl Nullifiers {
    pub fn contains(&self, nf: &Hash) -> bool {
        self.set.contains(nf)
    }
    pub fn insert(&mut self, nf: Hash) -> bool {
        self.set.insert(nf)
    }
    pub fn root(&self) -> Hash {
        if self.set.is_empty() {
            return sha256(&[b"lngap/nullifiers/empty"]);
        }
        let mut h = Sha256::new();
        h.update(b"lngap/nullifiers");
        for nf in &self.set {
            h.update(nf);
        }
        h.finalize().into()
    }
    pub fn iter(&self) -> impl Iterator<Item = &Hash> {
        self.set.iter()
    }
}

/// The hub issues notes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mint {
    pub outputs: Vec<Note>,
    /// The hub's signature over [`Mint::digest`].
    pub sig: Vec<u8>,
}

impl Mint {
    pub fn digest(outputs: &[Note]) -> Hash {
        let mut h = Sha256::new();
        h.update(b"lichen/mint");
        for n in outputs {
            h.update(n.commitment());
        }
        h.finalize().into()
    }
    pub fn new(hub: &SigningKey, outputs: Vec<Note>) -> Mint {
        let sig = sign(hub, &Mint::digest(&outputs));
        Mint { outputs, sig }
    }
}

/// A note being spent, and where it sits in the tree.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Spend {
    pub note: Note,
    pub index: u32,
}

/// Spends notes and creates notes of equal total value; each spent note's
/// owner signs [`Transfer::digest`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transfer {
    pub spends: Vec<Spend>,
    pub outputs: Vec<Note>,
    /// One signature per spend, by its note's owner.
    pub sigs: Vec<Vec<u8>>,
}

impl Transfer {
    pub fn digest(spends: &[Spend], outputs: &[Note]) -> Hash {
        let mut h = Sha256::new();
        h.update(b"lichen/transfer");
        for s in spends {
            h.update(s.note.commitment());
            h.update(s.index.to_be_bytes());
        }
        h.update(b"/");
        for n in outputs {
            h.update(n.commitment());
        }
        h.finalize().into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Tx {
    Mint(Mint),
    Transfer(Transfer),
}

/// A sealed height: the tree's size then, and the sequencer's signature on
/// the state root.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRoot {
    pub height: u64,
    pub size: u32,
    pub tree: Hash,
    pub nullifiers: Hash,
    pub signature: Vec<u8>,
}

impl SignedRoot {
    pub fn root(&self) -> Hash {
        state_root(self.height, &self.tree, &self.nullifiers)
    }
    pub fn verify(&self, sequencer: &Hash) -> Result<()> {
        verify(sequencer, &self.root(), &self.signature)
    }
}

/// The ledger's state, as the sequencer keeps it: everything applied, and
/// the heights sealed so far.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Ledger {
    pub tree: Tree,
    /// Every note's opening, by index (the ledger is transparent).
    pub notes: Vec<Note>,
    pub nullifiers: Nullifiers,
    commitments: HashSet<Hash>,
    pub sealed: Vec<SignedRoot>,
    /// Who seals and who may mint.
    pub deployment: Deployment,
}

impl Ledger {
    pub fn new(deployment: Deployment) -> Ledger {
        Ledger { deployment, ..Ledger::default() }
    }

    fn append(&mut self, outputs: &[Note]) -> Result<Vec<u32>> {
        let mut seen = HashSet::new();
        for n in outputs {
            let cm = n.commitment();
            ensure!(!self.commitments.contains(&cm) && seen.insert(cm), "a note that already exists");
            ensure!(n.value > 0, "an empty note");
        }
        let mut idx = vec![];
        for n in outputs {
            idx.push(self.tree.append(n.commitment())?);
            self.commitments.insert(n.commitment());
            self.notes.push(*n);
        }
        Ok(idx)
    }

    /// Check and apply a transaction; the indices of its new notes.
    pub fn apply(&mut self, tx: &Tx) -> Result<Vec<u32>> {
        match tx {
            Tx::Mint(m) => {
                verify(&self.deployment.hub, &Mint::digest(&m.outputs), &m.sig).context("a mint not signed by the hub")?;
                self.append(&m.outputs)
            }
            Tx::Transfer(t) => {
                ensure!(!t.spends.is_empty(), "a transfer spends nothing");
                ensure!(t.sigs.len() == t.spends.len(), "one signature per spend");
                let digest = Transfer::digest(&t.spends, &t.outputs);
                let mut nfs = HashSet::new();
                for (s, sig) in t.spends.iter().zip(&t.sigs) {
                    ensure!(self.tree.leaf(s.index) == Some(s.note.commitment()), "spending a note not at index {}", s.index);
                    let nf = nullifier(&s.note);
                    ensure!(!self.nullifiers.contains(&nf) && nfs.insert(nf), "the note at {} is already spent", s.index);
                    verify(&s.note.owner, &digest, sig).with_context(|| format!("the spend of note {}", s.index))?;
                }
                let vin = t.spends.iter().try_fold(0u64, |a, s| a.checked_add(s.note.value));
                let vout = t.outputs.iter().try_fold(0u64, |a, n| a.checked_add(n.value));
                ensure!(vin.is_some() && vin == vout, "values don't balance");
                let idx = self.append(&t.outputs)?;
                for nf in nfs {
                    self.nullifiers.insert(nf);
                }
                Ok(idx)
            }
        }
    }

    /// Seal a height: the state now, signed by the sequencer.
    pub fn seal(&mut self, sequencer: &SigningKey) -> SignedRoot {
        let height = self.sealed.last().map_or(1, |s| s.height + 1);
        let size = self.tree.len();
        let (tree, nullifiers) = (self.tree.root_at(size), self.nullifiers.root());
        let signature = sign(sequencer, &state_root(height, &tree, &nullifiers));
        let s = SignedRoot { height, size, tree, nullifiers, signature };
        self.sealed.push(s.clone());
        s
    }

    /// The first sealed height that includes note `index`.
    pub fn sealed_with(&self, index: u32) -> Option<&SignedRoot> {
        self.sealed.iter().find(|s| s.size > index)
    }

    /// The withdrawal statement's input for the return at `index` (a note
    /// owned by the hub, its memo the contract's `c`): under the first
    /// sealed root that includes it.
    pub fn withdraw_input(&self, index: u32) -> Result<WithdrawInput> {
        let note = *self.notes.get(index as usize).context("no such note")?;
        let s = self.sealed_with(index).context("the return is not sealed yet")?;
        let d = self.deployment;
        let input = WithdrawInput { height: s.height, nullifiers: s.nullifiers, signature: s.signature.clone(), note, index, path: self.tree.path_at(index, s.size), sequencer: d.sequencer, hub: d.hub };
        if let Err(r) = check(&input) {
            bail!("the statement would reject this return: {r:?}");
        }
        Ok(input)
    }
}

/// A note for `owner`.
pub fn note(owner: Hash, value: u64, memo: u32) -> Note {
    Note { owner, value, memo, rho: fresh_rho() }
}

impl std::fmt::Display for SignedRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "height {} ({} notes): {}", self.height, self.size, hex::encode(self.root()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer(spends: Vec<(Spend, &SigningKey)>, outputs: Vec<Note>) -> Tx {
        let s: Vec<Spend> = spends.iter().map(|x| x.0).collect();
        let d = Transfer::digest(&s, &outputs);
        Tx::Transfer(Transfer { sigs: spends.iter().map(|x| sign(x.1, &d)).collect(), spends: s, outputs })
    }

    #[test]
    fn the_regtest_keys_are_the_statements() {
        assert_eq!(xonly(&regtest_sequencer()), SEQUENCER_KEY);
        assert_eq!(xonly(&regtest_hub()), HUB_KEY);
    }

    #[test]
    fn a_deployment_of_its_own() {
        // fresh keys, no labels: the statement's input carries them and its
        // journal commits to them
        let (hub, seq) = (fresh_key(), fresh_key());
        let d = Deployment { sequencer: xonly(&seq), hub: xonly(&hub) };
        assert_ne!(d.id(), Deployment::toy().id());
        let mut l = Ledger::new(d);
        assert!(l.apply(&Tx::Mint(Mint::new(&regtest_hub(), vec![note(d.hub, 7, 0)]))).is_err(), "the toy hub can't mint here");
        let r = l.apply(&Tx::Mint(Mint::new(&hub, vec![note(d.hub, 7, 9)]))).unwrap()[0];
        l.seal(&seq);
        let input = l.withdraw_input(r).unwrap();
        assert_eq!(check(&input).unwrap()[8..], d.id());
        // sealed by another key: no withdrawal input
        let mut l2 = Ledger::new(d);
        let r2 = l2.apply(&Tx::Mint(Mint::new(&hub, vec![note(d.hub, 7, 9)]))).unwrap()[0];
        l2.seal(&regtest_sequencer());
        assert!(l2.withdraw_input(r2).is_err());
    }

    #[test]
    fn mint_transfer_return_and_the_statements_input() {
        let (hub, seq) = (regtest_hub(), regtest_sequencer());
        let (alice, bob) = (key_from_label("test/alice"), key_from_label("test/bob"));
        let mut l = Ledger::new(Deployment { sequencer: xonly(&seq), hub: xonly(&hub) });
        let n0 = note(xonly(&alice), 10, 0);
        let i0 = l.apply(&Tx::Mint(Mint::new(&hub, vec![n0]))).unwrap()[0];
        // nobody but the hub mints
        assert!(l.apply(&Tx::Mint(Mint::new(&alice, vec![note(xonly(&alice), 5, 0)]))).is_err());
        l.seal(&seq);
        // Alice pays Bob 4, keeps 6
        let (to_bob, change) = (note(xonly(&bob), 4, 0), note(xonly(&alice), 6, 0));
        let idx = l.apply(&transfer(vec![(Spend { note: n0, index: i0 }, &alice)], vec![to_bob, change])).unwrap();
        // not twice, not by Bob, not unbalanced
        assert!(l.apply(&transfer(vec![(Spend { note: n0, index: i0 }, &alice)], vec![note(xonly(&alice), 10, 0)])).is_err(), "double spend");
        assert!(l.apply(&transfer(vec![(Spend { note: change, index: idx[1] }, &bob)], vec![note(xonly(&bob), 6, 0)])).is_err(), "not Bob's");
        assert!(l.apply(&transfer(vec![(Spend { note: change, index: idx[1] }, &alice)], vec![note(xonly(&alice), 7, 0)])).is_err(), "unbalanced");
        // Alice returns 6 to the hub with memo 42
        let ret = note(HUB_KEY, 6, 42);
        let r = l.apply(&transfer(vec![(Spend { note: change, index: idx[1] }, &alice)], vec![ret])).unwrap()[0];
        assert!(l.withdraw_input(r).is_err(), "not sealed yet");
        let s = l.seal(&seq);
        s.verify(&SEQUENCER_KEY).unwrap();
        let input = l.withdraw_input(r).unwrap();
        let journal = check(&input).unwrap();
        assert_eq!(journal[..8], [6, 0, 0, 0, 42, 0, 0, 0]);
        assert_eq!(journal[8..], Deployment::toy().id());
        // a note that isn't the hub's is no return
        assert!(l.withdraw_input(idx[0]).is_err());
    }
}

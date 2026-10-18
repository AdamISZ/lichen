//! The L2 ledger: transparent notes in an append-only commitment tree, a
//! nullifier set, and a sequencer that seals batches into state roots and
//! signs them (BIP340).
//!
//! The note, the tree's hashing and the state root are the withdrawal
//! statement's own (`lngap-r0-core`), so a return recorded here is exactly
//! what the proof checks: [`Ledger::withdraw_input`] is the prover's input.
//!
//! Three kinds of transaction:
//! - a [`Mint`]: the hub issues notes (it may issue as many as it likes;
//!   every redemption is against its own collateral, capped per user);
//! - a [`Transfer`]: spends notes, each authorised by its owner's BIP340
//!   signature over the transfer, and creates notes of equal total value.
//!   A withdrawal starts with a transfer to the hub carrying the
//!   contract's memo `c`: a return.
//! - a [`Shielded`] transaction (docs/SHIELDED_PLAN.md): spends shielded
//!   notes (`lichen-shielded`) and transparent ones, and creates both,
//!   with a proof of the spend statement; the tree holds both kinds of
//!   leaf ([`Leaf`]).

use std::collections::{BTreeSet, HashSet};

use anyhow::{bail, ensure, Context, Result};
pub use k256;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use lngap_r0_core::{check, deployment_id, node, root_from_path, state_root, Note, Reject, WithdrawInput, HUB_KEY, JOURNAL_LEN, SEQUENCER_KEY, TREE_DEPTH};
pub use lichen_shielded as shielded;

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
    #[serde(with = "hex32")]
    pub sequencer: Hash,
    #[serde(with = "hex32")]
    pub hub: Hash,
}

/// A 32-byte key as hex in JSON; read from hex or, as files and peers
/// from before wrote it, a list of numbers.
pub mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(h: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(h))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either {
            Hex(String),
            Bytes([u8; 32]),
        }
        match Either::deserialize(d)? {
            Either::Bytes(b) => Ok(b),
            Either::Hex(h) => hex::decode(&h).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| serde::de::Error::custom(format!("not a 32-byte hex key: {h}"))),
        }
    }
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

/// The key a deposit's tokens are minted to before the contract is
/// funded: Alice's L2 key `A` (x-only, lifted to even y) and the hub's
/// adaptor point `T` (compressed), as `P = H(A ‖ T)·A + T`, x-only. Only
/// Alice can spend it, and only once she knows `t`, which the funding
/// transaction reveals. The coefficient keeps Alice from choosing `A`
/// against a `T` she has seen (`A = Y − T` would make `P = Y` hers alone).
pub fn mint_key(alice: &Hash, t_point: &[u8; 33]) -> Result<Hash> {
    use k256::elliptic_curve::point::AffineCoordinates;
    let a = VerifyingKey::from_bytes(alice).context("Alice's key")?;
    let t = k256::PublicKey::from_sec1_bytes(t_point).context("the adaptor point")?;
    let p = k256::ProjectivePoint::from(*a.as_affine()) * mint_coefficient(alice, t_point) + t.to_projective();
    ensure!(p != k256::ProjectivePoint::IDENTITY, "the mint key is the point at infinity");
    Ok(p.to_affine().x().into())
}

/// The key that spends a note owned by [`mint_key`]: `H(A ‖ T)·a + t`,
/// with `a` Alice's secret for the even-y `A` (k256 keeps it so) and `t`
/// the adaptor secret.
pub fn mint_secret(alice: &SigningKey, t: &Hash) -> Result<SigningKey> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let t = k256::NonZeroScalar::try_from(&t[..]).context("the adaptor secret")?;
    let t_point: [u8; 33] = k256::PublicKey::from_secret_scalar(&t).to_encoded_point(true).as_bytes().try_into().expect("33 bytes compressed");
    let p = mint_coefficient(&xonly(alice), &t_point) * **alice.as_nonzero_scalar() + *t;
    let p = Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::new(p)).context("the mint secret is zero")?;
    Ok(SigningKey::from(p))
}

fn mint_coefficient(alice: &Hash, t_point: &[u8; 33]) -> k256::Scalar {
    use k256::elliptic_curve::ops::Reduce;
    <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(&sha256(&[b"lichen/mint-key", alice, t_point]).into())
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
    /// The node at `level`, position `i`, of the tree's first `size`
    /// leaves.
    pub fn node_at(&self, level: usize, i: u32, size: u32) -> Hash {
        let (levels, zero) = self.levels(size);
        levels[level].get(i as usize).copied().unwrap_or(zero[level])
    }
    pub fn path_at(&self, index: u32, size: u32) -> Vec<Hash> {
        let (levels, zero) = self.levels(size);
        (0..TREE_DEPTH).map(|l| levels[l].get(((index >> l) ^ 1) as usize).copied().unwrap_or(zero[l])).collect()
    }
}

/// The nullifier set. Its root is the sparse Merkle tree's
/// ([`lichen_validity::smt`]), so that a nullifier can be shown unspent and
/// added (a block guest's job); the withdrawal statement takes it as
/// opaque. (Until 2026-10-18 a hash over the sorted set: heights sealed
/// before keep that root.)
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Nullifiers {
    set: BTreeSet<Hash>,
    #[serde(skip)]
    root: std::sync::OnceLock<Hash>,
}

/// The empty subtrees of the nullifier tree.
fn empties() -> &'static [Hash] {
    lichen_validity::smt::empties()
}

impl Nullifiers {
    pub fn contains(&self, nf: &Hash) -> bool {
        self.set.contains(nf)
    }
    pub fn insert(&mut self, nf: Hash) -> bool {
        self.root = std::sync::OnceLock::new();
        self.set.insert(nf)
    }
    pub fn root(&self) -> Hash {
        *self.root.get_or_init(|| lichen_validity::smt::root(&self.set.iter().copied().collect::<Vec<_>>(), empties()))
    }
    /// The path of `nf` in the tree (unspent: a proof that it is).
    pub fn proof(&self, nf: &Hash) -> lichen_validity::smt::Proof {
        lichen_validity::smt::proof(&self.set.iter().copied().collect::<Vec<_>>(), nf, empties())
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

/// A new shielded note: its commitment, and its opening encrypted to its
/// recipient (the wallet's business; the ledger only keeps it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SOut {
    #[serde(with = "hex32")]
    pub cm: Hash,
    #[serde(with = "hexvec")]
    pub ciphertext: Vec<u8>,
}

/// A proof of the spend statement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Proof {
    /// For tests: the statement's input itself (no privacy), checked by
    /// the sequencer with the statement's own code, if it accepts these.
    Native(#[serde(with = "hexvec")] Vec<u8>),
    /// A RISC Zero receipt of the spend guest.
    Risc0(#[serde(with = "hexvec")] Vec<u8>),
}

/// Spends shielded and transparent notes and creates both kinds, with a
/// proof of the spend statement over its public part
/// ([`Shielded::journal`]). Each transparent spend's owner signs
/// [`Shielded::digest`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Shielded {
    /// A sealed root of the commitment tree.
    #[serde(with = "hex32")]
    pub anchor: Hash,
    pub t_spends: Vec<Spend>,
    pub t_sigs: Vec<Vec<u8>>,
    /// The shielded spends' nullifiers.
    pub nfs: Vec<Hash>,
    pub outputs: Vec<SOut>,
    pub t_outputs: Vec<Note>,
    pub proof: Proof,
}

impl Shielded {
    /// The statement's journal, as this transaction must prove it.
    pub fn journal(&self) -> Result<shielded::Journal> {
        let t_total = self.t_spends.iter().try_fold(0u64, |a, s| a.checked_add(s.note.value)).context("the transparent spends overflow")?;
        Ok(shielded::Journal {
            anchor: self.anchor,
            t_nfs: self.t_spends.iter().map(|s| nullifier(&s.note)).collect(),
            t_total,
            nfs: self.nfs.clone(),
            cms: self.outputs.iter().map(|o| o.cm).collect(),
            t_cms: self.t_outputs.iter().map(|n| n.commitment()).collect(),
        })
    }
    /// What each transparent spend's owner signs: the journal and the
    /// ciphertexts.
    pub fn digest(&self) -> Result<Hash> {
        let mut h = Sha256::new();
        h.update(b"lichen/shielded");
        h.update(self.journal()?.to_bytes());
        for o in &self.outputs {
            h.update((o.ciphertext.len() as u32).to_be_bytes());
            h.update(&o.ciphertext);
        }
        Ok(h.finalize().into())
    }
}

/// Bytes as hex in JSON.
pub mod hexvec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Tx {
    Mint(Mint),
    Transfer(Transfer),
    Shielded(Shielded),
}

/// A leaf of the commitment tree: a transparent note's opening, or a
/// shielded note's commitment, its ciphertext, and what its `rho` comes
/// from (its transaction's first nullifier and its place among the new
/// shielded notes), for the recipient to check. Untagged in JSON, so
/// ledgers kept before shielded notes read as they were.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Leaf {
    Note(Note),
    Shielded {
        #[serde(with = "hex32")]
        cm: Hash,
        #[serde(with = "hexvec")]
        ciphertext: Vec<u8>,
        #[serde(with = "hex32")]
        nf0: Hash,
        i: u32,
    },
}

impl Leaf {
    pub fn commitment(&self) -> Hash {
        match self {
            Leaf::Note(n) => n.commitment(),
            Leaf::Shielded { cm, .. } => *cm,
        }
    }
    /// The transparent note, if this is one.
    pub fn note(&self) -> Option<&Note> {
        match self {
            Leaf::Note(n) => Some(n),
            Leaf::Shielded { .. } => None,
        }
    }
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
    /// Every leaf, by index: a transparent note's opening, or a shielded
    /// note's commitment and ciphertext.
    pub notes: Vec<Leaf>,
    pub nullifiers: Nullifiers,
    commitments: HashSet<Hash>,
    pub sealed: Vec<SignedRoot>,
    /// Who seals and who may mint.
    pub deployment: Deployment,
    /// Whether [`Proof::Native`] is accepted (tests only).
    #[serde(skip)]
    pub native_proofs: bool,
    /// The transactions applied since the last seal: the next height's
    /// block.
    #[serde(default)]
    pub pending: Vec<Tx>,
}

impl Ledger {
    pub fn new(deployment: Deployment) -> Ledger {
        Ledger { deployment, ..Ledger::default() }
    }

    fn append(&mut self, outputs: &[Note]) -> Result<Vec<u32>> {
        let leaves: Vec<Leaf> = outputs.iter().map(|n| Leaf::Note(*n)).collect();
        self.append_leaves(&leaves)
    }

    fn append_leaves(&mut self, leaves: &[Leaf]) -> Result<Vec<u32>> {
        let mut seen = HashSet::new();
        for l in leaves {
            let cm = l.commitment();
            ensure!(!self.commitments.contains(&cm) && seen.insert(cm), "a note that already exists");
            if let Leaf::Note(n) = l {
                ensure!(n.value > 0, "an empty note");
            }
        }
        let mut idx = vec![];
        for l in leaves {
            idx.push(self.tree.append(l.commitment())?);
            self.commitments.insert(l.commitment());
            self.notes.push(l.clone());
        }
        Ok(idx)
    }

    /// The transparent note at `index`, if it is one.
    pub fn note(&self, index: u32) -> Option<&Note> {
        self.notes.get(index as usize).and_then(Leaf::note)
    }

    /// Check a proof of the spend statement with journal `journal`.
    fn verify_proof(&self, journal: &shielded::Journal, proof: &Proof) -> Result<()> {
        match proof {
            Proof::Native(input) => {
                ensure!(self.native_proofs, "this sequencer accepts no native proofs (tests only)");
                let input = shielded::SpendInput::from_bytes(input).map_err(|r| anyhow::anyhow!("the native proof: {r:?}"))?;
                let j = shielded::check(&input).map_err(|r| anyhow::anyhow!("the statement rejects the spend: {r:?}"))?;
                ensure!(j == *journal, "the native proof is of another transaction");
                Ok(())
            }
            Proof::Risc0(r) => verify_receipt(r, &journal.to_bytes()),
        }
    }

    /// Check and apply a transaction; the indices of its new notes. It
    /// joins the next height's block.
    pub fn apply(&mut self, tx: &Tx) -> Result<Vec<u32>> {
        let idx = self.apply_tx(tx)?;
        self.pending.push(tx.clone());
        Ok(idx)
    }

    fn apply_tx(&mut self, tx: &Tx) -> Result<Vec<u32>> {
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
                    ensure!(self.note(s.index) == Some(&s.note), "spending a note not at index {}", s.index);
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
            Tx::Shielded(t) => {
                ensure!(self.sealed.iter().rev().take(lichen_validity::RECENT).any(|s| s.tree == t.anchor), "the anchor is none of the last {} sealed roots of the tree", lichen_validity::RECENT);
                ensure!(t.t_sigs.len() == t.t_spends.len(), "one signature per transparent spend");
                let journal = t.journal()?;
                let digest = t.digest()?;
                for (s, sig) in t.t_spends.iter().zip(&t.t_sigs) {
                    ensure!(self.note(s.index) == Some(&s.note), "spending a note not at index {}", s.index);
                    verify(&s.note.owner, &digest, sig).with_context(|| format!("the spend of note {}", s.index))?;
                }
                let mut nfs = HashSet::new();
                for nf in journal.t_nfs.iter().chain(&journal.nfs) {
                    ensure!(!self.nullifiers.contains(nf) && nfs.insert(*nf), "a note already spent");
                }
                self.verify_proof(&journal, &t.proof)?;
                let nf0 = *journal.nf0().context("a transaction that spends nothing")?;
                let mut leaves: Vec<Leaf> = t.outputs.iter().enumerate().map(|(i, o)| Leaf::Shielded { cm: o.cm, ciphertext: o.ciphertext.clone(), nf0, i: i as u32 }).collect();
                leaves.extend(t.t_outputs.iter().map(|n| Leaf::Note(*n)));
                let idx = self.append_leaves(&leaves)?;
                for nf in nfs {
                    self.nullifiers.insert(nf);
                }
                Ok(idx)
            }
        }
    }

    /// Seal a height: the state now, signed by the sequencer.
    pub fn seal(&mut self, sequencer: &SigningKey) -> SignedRoot {
        self.seal_block(sequencer).0
    }

    /// Seal a height; its signed root and its block (the transactions
    /// since the last seal, in order).
    pub fn seal_block(&mut self, sequencer: &SigningKey) -> (SignedRoot, Vec<Tx>) {
        let block = std::mem::take(&mut self.pending);
        (self.seal_root(sequencer), block)
    }

    /// The block statement's input for the pending block (call before
    /// sealing it): the state at the last seal rebuilt (the nullifiers
    /// less the block's own, the tree's frontier at its size then, the
    /// recent roots), each nullifier's insert proof in order, each
    /// transparent spend's path from before the block.
    pub fn block_input(&self) -> Result<lichen_validity::BlockInput> {
        use lichen_validity as v;
        let size0 = self.sealed.last().map_or(0, |s| s.size);
        let height = self.sealed.last().map_or(0, |s| s.height);
        let txs: Vec<v::Tx> = self.pending.iter().map(block_tx).collect::<Result<_>>()?;
        // the block's nullifiers, in the statement's order
        let mut nfs = vec![];
        let mut spent_before = vec![];
        for t in &txs {
            match t {
                v::Tx::Mint { .. } => {}
                v::Tx::Transfer { spends, .. } => {
                    nfs.extend(spends.iter().map(|s| s.0.nullifier()));
                    spent_before.extend(spends.iter().map(|s| s.1).filter(|&i| i < size0));
                }
                v::Tx::Shielded { t_spends, nfs: s_nfs, .. } => {
                    nfs.extend(t_spends.iter().map(|s| s.0.nullifier()));
                    nfs.extend(s_nfs.iter().copied());
                    spent_before.extend(t_spends.iter().map(|s| s.1).filter(|&i| i < size0));
                }
            }
        }
        let mut before = self.nullifiers.clone();
        before.set.retain(|nf| !nfs.contains(nf));
        before.root = std::sync::OnceLock::new();
        let nullifiers = before.root();
        let mut nf_proofs = vec![];
        for nf in &nfs {
            nf_proofs.push(before.proof(nf));
            before.insert(*nf);
        }
        // the frontier at size0: at each level whose bit is set, the left
        // node there
        let mut branch = vec![[0u8; 32]; TREE_DEPTH];
        for (l, b) in branch.iter_mut().enumerate() {
            if size0 >> l & 1 == 1 {
                *b = self.tree.node_at(l, (size0 >> l) - 1, size0);
            }
        }
        Ok(v::BlockInput {
            hub: self.deployment.hub,
            height,
            tree: v::Frontier { size: size0, branch },
            nullifiers,
            recent: self.sealed.iter().rev().take(lichen_validity::RECENT).rev().map(|s| s.tree).collect(),
            txs,
            nf_proofs,
            paths: spent_before.iter().map(|&i| self.tree.path_at(i, size0)).collect(),
        })
    }

    fn seal_root(&mut self, sequencer: &SigningKey) -> SignedRoot {
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
        let note = *self.note(index).context("no such note")?;
        let s = self.sealed_with(index).context("the return is not sealed yet")?;
        let d = self.deployment;
        let input = WithdrawInput { height: s.height, nullifiers: s.nullifiers, signature: s.signature.clone(), note, index, path: self.tree.path_at(index, s.size), sequencer: d.sequencer, hub: d.hub };
        if let Err(r) = check(&input) {
            bail!("the statement would reject this return: {r:?}");
        }
        Ok(input)
    }
}

/// A ledger transaction as the block statement reads it.
fn block_tx(tx: &Tx) -> Result<lichen_validity::Tx> {
    use lichen_validity::{TNote, Tx as V};
    let tn = |n: &Note| TNote { owner: n.owner, value: n.value, memo: n.memo, rho: n.rho };
    let sig = |s: &Vec<u8>| -> Result<[u8; 64]> { s.as_slice().try_into().context("a signature of 64 bytes") };
    Ok(match tx {
        Tx::Mint(m) => V::Mint { outputs: m.outputs.iter().map(tn).collect(), sig: sig(&m.sig)? },
        Tx::Transfer(t) => V::Transfer { spends: t.spends.iter().map(|s| (tn(&s.note), s.index)).collect(), outputs: t.outputs.iter().map(tn).collect(), sigs: t.sigs.iter().map(sig).collect::<Result<_>>()? },
        Tx::Shielded(t) => V::Shielded {
            anchor: t.anchor,
            t_spends: t.t_spends.iter().map(|s| (tn(&s.note), s.index)).collect(),
            t_sigs: t.t_sigs.iter().map(sig).collect::<Result<_>>()?,
            nfs: t.nfs.clone(),
            cms: t.outputs.iter().map(|o| o.cm).collect(),
            ciphertexts: t.outputs.iter().map(|o| o.ciphertext.clone()).collect(),
            t_outputs: t.t_outputs.iter().map(tn).collect(),
        },
    })
}

/// The spend guest's image id (`r0/guests/spend.id`, `lichen-r0 image-id`).
pub const SPEND_IMAGE_ID: &str = include_str!("../../../r0/guests/spend.id");

/// Check a RISC Zero receipt (bincode) of the spend guest with `journal`.
#[cfg(feature = "risc0")]
fn verify_receipt(receipt: &[u8], journal: &[u8]) -> Result<()> {
    let r: risc0_zkvm::Receipt = bincode::deserialize(receipt).context("not a RISC Zero receipt")?;
    let id: [u8; 32] = hex::decode(SPEND_IMAGE_ID.trim()).ok().and_then(|v| v.try_into().ok()).context("the spend guest's image id")?;
    r.verify(risc0_zkvm::sha::Digest::from_bytes(id)).context("the receipt doesn't verify against the spend guest")?;
    ensure!(r.journal.bytes == journal, "the receipt proves another transaction");
    Ok(())
}

#[cfg(not(feature = "risc0"))]
fn verify_receipt(_: &[u8], _: &[u8]) -> Result<()> {
    bail!("this build can't verify RISC Zero receipts (lichen-ledger's feature risc0: the sequencer's)")
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
    fn a_deployment_in_json() {
        let d = Deployment::toy();
        let j = serde_json::to_string(&d).unwrap();
        assert_eq!(j, format!(r#"{{"sequencer":"{}","hub":"{}"}}"#, hex::encode(SEQUENCER_KEY), hex::encode(HUB_KEY)));
        assert_eq!(serde_json::from_str::<Deployment>(&j).unwrap(), d);
        // as before: lists of numbers
        let old = format!(r#"{{"sequencer":{:?},"hub":{:?}}}"#, SEQUENCER_KEY, HUB_KEY);
        assert_eq!(serde_json::from_str::<Deployment>(&old).unwrap(), d);
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

    /// The spend statement's input for spending shielded notes (value,
    /// rho, index) of `nk` under the last sealed root, with `t_spends`
    /// beside them.
    fn spend_input(l: &Ledger, t_spends: &[Spend], nk: &Hash, notes: &[(u64, Hash, u32)], outputs: Vec<(u64, Hash)>, t_outputs: Vec<shielded::TOut>) -> shielded::SpendInput {
        let s = l.sealed.last().unwrap();
        let spends = notes.iter().map(|&(value, rho, index)| shielded::Spend { value, rho, nk: *nk, index, path: l.tree.path_at(index, s.size) }).collect();
        let t_total = t_spends.iter().map(|s| s.note.value).sum();
        shielded::SpendInput { anchor: s.tree, t_nfs: t_spends.iter().map(|s| nullifier(&s.note)).collect(), t_total, spends, outputs, t_outputs }
    }

    /// The transaction for `input`, with a native proof, each transparent
    /// spend signed by `signer`.
    fn shielded_tx(input: &shielded::SpendInput, t_spends: Vec<Spend>, t_outputs: Vec<Note>, signer: Option<&SigningKey>) -> Tx {
        let j = shielded::check(input).unwrap();
        let outputs = j.cms.iter().map(|cm| SOut { cm: *cm, ciphertext: vec![7; 8] }).collect();
        let mut t = Shielded { anchor: input.anchor, t_spends, t_sigs: vec![], nfs: j.nfs.clone(), outputs, t_outputs, proof: Proof::Native(input.to_bytes()) };
        let d = t.digest().unwrap();
        t.t_sigs = t.t_spends.iter().map(|_| sign(signer.unwrap(), &d)).collect();
        Tx::Shielded(t)
    }

    /// Check the pending block with the block statement (receipts: the
    /// pending shielded transactions' journals), then seal it: the
    /// statement's journal, which must run from `from` to the new root.
    fn seal_checked(l: &mut Ledger, seq: &SigningKey, from: (Hash, Hash)) -> lichen_validity::BlockJournal {
        let input = l.block_input().unwrap();
        let journals: Vec<Vec<u8>> = l.pending.iter().filter_map(|t| if let Tx::Shielded(s) = t { Some(s.journal().unwrap().to_bytes()) } else { None }).collect();
        let j = lichen_validity::check(&input, &mut |jb| journals.iter().any(|x| x == jb)).unwrap();
        assert_eq!(lichen_validity::BlockInput::from_bytes(&input.to_bytes()), Ok(input.clone()), "the guest reads what the sequencer writes");
        assert_eq!(lichen_validity::BlockJournal::from_bytes(&j.to_bytes()), Ok(j.clone()));
        // the chain statement: from genesis, or from the chain journal
        // the last block's ended
        let id = [0xc4; 32];
        let prev = lichen_validity::ChainJournal { hub: j.hub, height: j.height, root: from.0, recent: from.1, chain_id: id }.to_bytes();
        let c = lichen_validity::chain(&id, &input, &mut |jb| journals.iter().any(|x| x == jb), &mut |jb| {
            assert!(input.height > 0, "genesis needs no receipt");
            jb == prev
        })
        .unwrap();
        assert_eq!((c.height, c.root, c.recent, c.chain_id), (j.height + 1, j.to, j.recent_to, id));
        assert_eq!(lichen_validity::ChainJournal::from_bytes(&c.to_bytes()), Ok(c));
        if input.height == 0 {
            let mut bad = input.clone();
            bad.recent = vec![[3; 32]];
            assert_eq!(lichen_validity::chain(&id, &bad, &mut |_| true, &mut |_| true), Err(lichen_validity::Reject::Genesis), "genesis is the empty ledger");
        } else {
            assert_eq!(lichen_validity::chain(&id, &input, &mut |_| true, &mut |_| false), Err(lichen_validity::Reject::Chain));
        }
        let s = l.seal(seq);
        assert_eq!((j.from, j.recent_from), from, "the block starts where the last ended");
        assert_eq!((j.height + 1, j.to), (s.height, s.root()), "and ends at the root the sequencer signs");
        j
    }

    #[test]
    fn every_block_is_the_block_statements() {
        use lichen_validity as v;
        let (hub, seq) = (regtest_hub(), regtest_sequencer());
        let alice = key_from_label("test/alice");
        let (alice_nk, bob_nk) = (sha256(&[b"alice nk"]), sha256(&[b"bob nk"]));
        let (a_owner, b_owner) = (shielded::owner(&alice_nk), shielded::owner(&bob_nk));
        let mut l = Ledger::new(Deployment { sequencer: xonly(&seq), hub: xonly(&hub) });
        l.native_proofs = true;
        let z = v::tree_empties();
        let genesis = (v::state_root(0, &z[TREE_DEPTH], &lichen_validity::smt::EMPTIES[lichen_validity::smt::DEPTH]), v::recent_hash(&[]));

        // block 1: two mints, and a transfer of one of them within the block
        let (m0, m1) = (note(xonly(&alice), 20, 0), note(xonly(&alice), 7, 0));
        let i0 = l.apply(&Tx::Mint(Mint::new(&hub, vec![m0]))).unwrap()[0];
        l.apply(&Tx::Mint(Mint::new(&hub, vec![m1]))).unwrap();
        let moved = note(xonly(&alice), 20, 0);
        let i2 = l.apply(&transfer(vec![(Spend { note: m0, index: i0 }, &alice)], vec![moved])).unwrap()[0];
        let j1 = seal_checked(&mut l, &seq, genesis);

        // block 2: shield the moved note (from block 1: a path), and the
        // other mint by transfer
        let t_spends = vec![Spend { note: moved, index: i2 }];
        let input = spend_input(&l, &t_spends, &alice_nk, &[], vec![(15, a_owner), (5, a_owner)], vec![]);
        let idx = l.apply(&shielded_tx(&input, t_spends, vec![], Some(&alice))).unwrap();
        l.apply(&transfer(vec![(Spend { note: m1, index: 1 }, &alice)], vec![note(xonly(&alice), 3, 0), note(xonly(&alice), 4, 0)])).unwrap();
        let nf0 = nullifier(&moved);
        let j2 = seal_checked(&mut l, &seq, (j1.to, j1.recent_to));

        // block 3: Alice pays Bob shielded (Bob's return waits for block
        // 4: his note must be under a sealed root first)
        let input = spend_input(&l, &[], &alice_nk, &[(15, shielded::rho(&nf0, 0), idx[0])], vec![(12, b_owner), (3, a_owner)], vec![]);
        let pay = shielded_tx(&input, vec![], vec![], None);
        let paid = l.apply(&pay).unwrap();
        let nf_pay = *shielded::check(&input).unwrap().nf0().unwrap();

        // what the statement refuses, on this block
        let good = l.block_input().unwrap();
        let ok = |jb: &[u8]| -> bool { if let Tx::Shielded(t) = &l.pending[0] { t.journal().unwrap().to_bytes() == jb } else { false } };
        assert!(v::check(&good, &mut |jb| ok(jb)).is_ok());
        assert_eq!(v::check(&good, &mut |_| false), Err(v::Reject::Receipt), "a receipt that doesn't verify");
        let mut bad = good.clone();
        bad.nf_proofs[0].siblings.push([1; 32]);
        assert_eq!(v::check(&bad, &mut |jb| ok(jb)), Err(v::Reject::Spent), "a bad insert proof");
        let mut bad = good.clone();
        bad.recent = vec![[9; 32]];
        assert_eq!(v::check(&bad, &mut |jb| ok(jb)), Err(v::Reject::Anchor), "an anchor not recent");
        let mut bad = good.clone();
        bad.nullifiers = [7; 32];
        assert_eq!(v::check(&bad, &mut |jb| ok(jb)), Err(v::Reject::Spent), "another nullifier root");
        let j3 = seal_checked(&mut l, &seq, (j2.to, j2.recent_to));

        // block 4: Bob returns 12 to the hub, a transparent note, and a
        // forged transparent signature is refused
        let ret = shielded::TOut { owner: HUB_KEY, value: 12, memo: 42, rho: fresh_rho() };
        let input = spend_input(&l, &[], &bob_nk, &[(12, shielded::rho(&nf_pay, 0), paid[0])], vec![], vec![ret]);
        l.apply(&shielded_tx(&input, vec![], vec![Note { owner: ret.owner, value: 12, memo: 42, rho: ret.rho }], None)).unwrap();
        let mint = Mint::new(&hub, vec![note(xonly(&alice), 1, 0)]);
        l.apply(&Tx::Mint(mint)).unwrap();
        let mut bad = l.block_input().unwrap();
        if let v::Tx::Mint { sig, .. } = &mut bad.txs[1] {
            sig[0] ^= 1;
        }
        assert_eq!(v::check(&bad, &mut |_| true), Err(v::Reject::BadSignature));
        seal_checked(&mut l, &seq, (j3.to, j3.recent_to));
    }

    #[test]
    fn the_nullifier_root_follows_each_spend() {
        // each spend's nullifier shown unspent under the root before, the
        // root after: what a block guest will check
        let (hub, seq) = (regtest_hub(), regtest_sequencer());
        let alice = key_from_label("test/alice");
        let mut l = Ledger::new(Deployment { sequencer: xonly(&seq), hub: xonly(&hub) });
        let empty = l.nullifiers.root();
        assert_eq!(empty, lichen_validity::smt::empties()[lichen_validity::smt::DEPTH]);
        let n0 = note(xonly(&alice), 10, 0);
        let i0 = l.apply(&Tx::Mint(Mint::new(&hub, vec![n0]))).unwrap()[0];
        let nf = nullifier(&n0);
        let p = l.nullifiers.proof(&nf);
        l.apply(&transfer(vec![(Spend { note: n0, index: i0 }, &alice)], vec![note(xonly(&alice), 10, 0)])).unwrap();
        assert_eq!(lichen_validity::smt::insert(&empty, &nf, &p, lichen_validity::smt::empties()), Some(l.nullifiers.root()));
        assert_ne!(l.seal(&seq).nullifiers, empty);
        // kept and read back: the same root
        let back: Ledger = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(back.nullifiers.root(), l.nullifiers.root());
    }

    #[test]
    fn the_shielded_crates_hashes_are_the_withdrawal_statements() {
        let n = Note { owner: [3; 32], value: 77, memo: 42, rho: [4; 32] };
        assert_eq!(shielded::transparent_commitment(&n.owner, n.value, n.memo, &n.rho), n.commitment());
        assert_eq!(shielded::TOut { owner: n.owner, value: n.value, memo: n.memo, rho: n.rho }.commitment(), n.commitment());
        assert_eq!(shielded::node(&[5; 32], &[6; 32]), node(&[5; 32], &[6; 32]));
        assert_eq!(shielded::TREE_DEPTH, TREE_DEPTH);
    }

    #[test]
    fn shield_pay_and_return_under_the_same_statement() {
        let (hub, seq) = (regtest_hub(), regtest_sequencer());
        let alice = key_from_label("test/alice");
        let (alice_nk, bob_nk) = (sha256(&[b"alice nk"]), sha256(&[b"bob nk"]));
        let (a_owner, b_owner) = (shielded::owner(&alice_nk), shielded::owner(&bob_nk));
        let mut l = Ledger::new(Deployment { sequencer: xonly(&seq), hub: xonly(&hub) });
        l.native_proofs = true;
        let minted = note(xonly(&alice), 20, 0);
        let i0 = l.apply(&Tx::Mint(Mint::new(&hub, vec![minted]))).unwrap()[0];
        l.seal(&seq);

        // Alice shields her 20: notes of 15 and 5 of her own
        let t_spends = vec![Spend { note: minted, index: i0 }];
        let input = spend_input(&l, &t_spends, &alice_nk, &[], vec![(15, a_owner), (5, a_owner)], vec![]);
        let tx = shielded_tx(&input, t_spends.clone(), vec![], Some(&alice));
        // not without native proofs accepted, nor signed by another
        let mut strict = l.clone();
        strict.native_proofs = false;
        assert!(strict.apply(&tx).unwrap_err().to_string().contains("no native proofs"));
        assert!(l.apply(&shielded_tx(&input, t_spends.clone(), vec![], Some(&regtest_hub()))).is_err(), "not Alice's signature");
        let idx = l.apply(&tx).unwrap();
        assert!(matches!(l.notes[idx[0] as usize], Leaf::Shielded { .. }));
        assert!(l.apply(&tx).is_err(), "the mint is spent");
        let nf0 = nullifier(&minted);
        let rho15 = shielded::rho(&nf0, 0);
        assert_eq!(l.tree.leaf(idx[0]), Some(shielded::SNote { value: 15, owner: a_owner, rho: rho15 }.commitment()));
        // not yet sealed: no anchor reaches it
        let early = spend_input(&l, &[], &alice_nk, &[(15, rho15, idx[0])], vec![(15, b_owner)], vec![]);
        assert!(shielded::check(&early).is_err(), "the last sealed root doesn't hold it");
        l.seal(&seq);

        // Alice pays Bob 12 from her 15, keeps 3
        let input = spend_input(&l, &[], &alice_nk, &[(15, rho15, idx[0])], vec![(12, b_owner), (3, a_owner)], vec![]);
        let pay = shielded_tx(&input, vec![], vec![], None);
        let paid = l.apply(&pay).unwrap();
        assert!(l.apply(&pay).is_err(), "spent twice");
        // a native proof of another transaction
        let other = spend_input(&l, &[], &alice_nk, &[(5, shielded::rho(&nf0, 1), idx[1])], vec![(5, b_owner)], vec![]);
        if let Tx::Shielded(mut t) = shielded_tx(&other, vec![], vec![], None) {
            t.proof = Proof::Native(input.to_bytes());
            assert!(l.apply(&Tx::Shielded(t)).unwrap_err().to_string().contains("another transaction"));
        }
        // an anchor that was never sealed
        if let Tx::Shielded(mut t) = shielded_tx(&other, vec![], vec![], None) {
            t.anchor = [9; 32];
            assert!(l.apply(&Tx::Shielded(t)).unwrap_err().to_string().contains("anchor"));
        }
        l.seal(&seq);

        // Bob returns 12 to the hub, memo 42: a transparent note, the
        // withdrawal statement's as ever
        let nf_pay = *shielded::check(&input).unwrap().nf0().unwrap();
        let ret = shielded::TOut { owner: HUB_KEY, value: 12, memo: 42, rho: fresh_rho() };
        let input = spend_input(&l, &[], &bob_nk, &[(12, shielded::rho(&nf_pay, 0), paid[0])], vec![], vec![ret]);
        let ret_note = Note { owner: ret.owner, value: ret.value, memo: ret.memo, rho: ret.rho };
        let r = l.apply(&shielded_tx(&input, vec![], vec![ret_note], None)).unwrap()[0];
        l.seal(&seq);
        let journal = check(&l.withdraw_input(r).unwrap()).unwrap();
        assert_eq!(journal[..8], [12, 0, 0, 0, 42, 0, 0, 0]);
        // a shielded leaf is no return
        assert!(l.withdraw_input(paid[1]).is_err());
        // a ledger kept before shielded notes reads as it was
        let old = format!(r#"{{"tree":{{"leaves":[]}},"notes":[{}],"nullifiers":{{"set":[]}},"commitments":[],"sealed":[],"deployment":{}}}"#, serde_json::to_string(&minted).unwrap(), serde_json::to_string(&l.deployment).unwrap());
        let back: Ledger = serde_json::from_str(&old).unwrap();
        assert_eq!(back.notes, vec![Leaf::Note(minted)]);
        let again: Ledger = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(again.notes, l.notes);
    }

    #[test]
    fn a_mint_key_is_spent_by_alice_with_t() {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let msg = sha256(&[b"a transfer"]);
        // 64 draws: every combination of the parities of Alice's point, T
        // and the sum, all but certainly
        for _ in 0..64 {
            let (alice, t) = (fresh_key(), fresh_key());
            let t_point: [u8; 33] = k256::PublicKey::from_secret_scalar(t.as_nonzero_scalar()).to_encoded_point(true).as_bytes().try_into().unwrap();
            let p = mint_key(&xonly(&alice), &t_point).unwrap();
            let k = mint_secret(&alice, &t.to_bytes().into()).unwrap();
            assert_eq!(xonly(&k), p);
            verify(&p, &msg, &sign(&k, &msg)).unwrap();
            // Alice alone, or t alone, is not the key
            assert_ne!(xonly(&alice), p);
            assert_ne!(xonly(&t), p);
        }
        // another Alice, the same T: another key
        let (a, b, t) = (fresh_key(), fresh_key(), fresh_key());
        let t_point: [u8; 33] = k256::PublicKey::from_secret_scalar(t.as_nonzero_scalar()).to_encoded_point(true).as_bytes().try_into().unwrap();
        assert_ne!(mint_key(&xonly(&a), &t_point).unwrap(), mint_key(&xonly(&b), &t_point).unwrap());
    }
}

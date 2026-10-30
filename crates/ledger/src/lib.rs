//! The L2 ledger: transparent notes in an append-only commitment tree, a
//! nullifier set, and a sequencer that seals batches into state roots and
//! signs them (BIP340).
//!
//! The note, the tree's hashing and the state root are the withdrawal
//! statement's own (`lngap-r0-core`), so a return recorded here is exactly
//! what the proof checks: [`Ledger::withdraw_input`] is the prover's input.
//!
//! The kinds of transaction:
//! - a [`Mint`]: the hub issues notes (it may issue as many as it likes;
//!   every redemption is against its own collateral, capped per user);
//! - a [`Transfer`]: spends notes, each authorised by its owner's BIP340
//!   signature over the transfer, and creates notes of equal total value.
//!   A withdrawal starts with a transfer to the hub carrying the
//!   contract's memo `c`: a return.
//! - a [`Shielded`] transaction (docs/SHIELDED_PLAN.md): spends shielded
//!   notes (`lichen-shielded`) and transparent ones, and creates both,
//!   with a proof of the spend statement; the tree holds both kinds of
//!   leaf ([`Leaf`]);
//! - an [`Exit`] record (docs/EXIT_PLAN.md, "Exit authority on chain"):
//!   the hub records a contract's exit claim as its `request` posted it,
//!   and the claim's transparent notes are retired, each authorised by its
//!   owner's signature on the claim;
//! - an anchor's record, from the sequencer's anchorer.

pub mod files;

use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::{bail, ensure, Context, Result};
pub use k256;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use lngap_r0_core::{check, deployment_id, node, root_from_path, state_root, Note, Reject, WithdrawInput, HUB_KEY, JOURNAL_LEN, SEQUENCER_KEY, TREE_DEPTH};
pub use lichen_shielded as shielded;
pub use lichen_validity::{self, AnchorState, OutPoint};
pub use lichen_withdraw::contract_id as lichen_withdraw_contract_id;

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
    files::write_private(path, hex::encode(k.to_bytes()).as_bytes())?;
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
    /// The genesis seal, if the sequencer anchors its history on Bitcoin
    /// (docs/ANCHOR_PLAN.md): the outpoint the first anchor spends.
    #[serde(default, with = "outpoint_opt", skip_serializing_if = "Option::is_none")]
    pub seal: Option<OutPoint>,
}

/// An outpoint as Bitcoin shows it, `<txid>:<vout>` (the txid reversed
/// from its internal order).
pub mod outpoint {
    use super::OutPoint;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn to_string(o: &OutPoint) -> String {
        let mut t = o.txid;
        t.reverse();
        format!("{}:{}", hex::encode(t), o.vout)
    }
    pub fn parse(s: &str) -> Option<OutPoint> {
        let (t, v) = s.split_once(':')?;
        let mut txid: [u8; 32] = hex::decode(t).ok()?.try_into().ok()?;
        txid.reverse();
        Some(OutPoint { txid, vout: v.parse().ok()? })
    }
    pub fn serialize<S: Serializer>(o: &OutPoint, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&to_string(o))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<OutPoint, D::Error> {
        let s = String::deserialize(d)?;
        parse(&s).ok_or_else(|| serde::de::Error::custom(format!("not an outpoint <txid>:<vout>: {s}")))
    }
}

mod outpoint_opt {
    use super::OutPoint;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(o: &Option<OutPoint>, s: S) -> Result<S::Ok, S::Error> {
        match o {
            Some(o) => super::outpoint::serialize(o, s),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<OutPoint>, D::Error> {
        match Option::<String>::deserialize(d)? {
            Some(s) => super::outpoint::parse(&s).map(Some).ok_or_else(|| serde::de::Error::custom(format!("not an outpoint <txid>:<vout>: {s}"))),
            None => Ok(None),
        }
    }
}

/// The anchoring's state, as hex of its encoding.
mod anchor_hex {
    use lichen_validity::AnchorState;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(a: &AnchorState, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(a.to_bytes()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<AnchorState, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).ok().and_then(|b| AnchorState::from_bytes(&b).ok()).ok_or_else(|| serde::de::Error::custom("not an anchor state"))
    }
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
        Deployment { sequencer: SEQUENCER_KEY, hub: HUB_KEY, seal: None }
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
    /// The leaves that aren't an ordinary spend's: returns' (and exit
    /// records'). Absent from ledgers kept before 2026-10-30.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty", with = "pairs")]
    tags: BTreeMap<Hash, Hash>,
    /// The height whose block spent each nullifier, for proofs at an
    /// earlier height (exit kits). Absent from ledgers kept before
    /// 2026-10-30, whose nullifiers count as spent from the start.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty", with = "pairs")]
    at: BTreeMap<Hash, u64>,
    #[serde(skip)]
    root: std::sync::OnceLock<Hash>,
}

/// A map of hashes in JSON, as a list of pairs (JSON's keys are strings).
mod pairs {
    use super::Hash;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;
    pub fn serialize<S: Serializer, V: Serialize>(m: &BTreeMap<Hash, V>, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(m.iter())
    }
    pub fn deserialize<'de, D: Deserializer<'de>, V: Deserialize<'de>>(d: D) -> Result<BTreeMap<Hash, V>, D::Error> {
        Ok(Vec::<(Hash, V)>::deserialize(d)?.into_iter().collect())
    }
}

/// The empty subtrees of the nullifier tree.
fn empties() -> &'static [Hash] {
    lichen_validity::smt::empties()
}

impl Nullifiers {
    pub fn contains(&self, nf: &Hash) -> bool {
        self.set.contains(nf)
    }
    /// Spend `nf` in the block of `height`, its leaf `leaf`.
    pub fn insert_at(&mut self, nf: Hash, leaf: Hash, height: u64) -> bool {
        self.at.insert(nf, height);
        self.insert(nf, leaf)
    }
    /// Spend `nf`, its leaf `leaf` (`lichen_validity::smt`: how it was
    /// spent).
    pub fn insert(&mut self, nf: Hash, leaf: Hash) -> bool {
        self.root = std::sync::OnceLock::new();
        if leaf != lichen_validity::smt::spent() {
            self.tags.insert(nf, leaf);
        }
        self.set.insert(nf)
    }
    /// The leaf of a spent `nf`.
    pub fn leaf(&self, nf: &Hash) -> Hash {
        self.tags.get(nf).copied().unwrap_or_else(lichen_validity::smt::spent)
    }
    fn remove(&mut self, nf: &Hash) {
        self.root = std::sync::OnceLock::new();
        self.set.remove(nf);
        self.tags.remove(nf);
        self.at.remove(nf);
    }
    fn entries(&self) -> Vec<(Hash, Hash)> {
        self.set.iter().map(|nf| (*nf, self.leaf(nf))).collect()
    }
    /// The nullifiers spent by height `h`, with their leaves.
    fn entries_at(&self, h: u64) -> Vec<(Hash, Hash)> {
        self.set.iter().filter(|nf| self.at.get(*nf).is_none_or(|&a| a <= h)).map(|nf| (*nf, self.leaf(nf))).collect()
    }
    /// The tree's root at height `h`, and `nf`'s path in it.
    pub fn proof_at(&self, nf: &Hash, h: u64) -> (Hash, lichen_validity::smt::Proof) {
        let e = self.entries_at(h);
        (lichen_validity::smt::root(&e, empties()), lichen_validity::smt::proof(&e, nf, empties()))
    }
    /// How `nf` was spent, if it was: its leaf, and the height whose block
    /// spent it (0 for a ledger kept before heights were).
    pub fn spent(&self, nf: &Hash) -> Option<(Hash, u64)> {
        self.set.contains(nf).then(|| (self.leaf(nf), self.at.get(nf).copied().unwrap_or(0)))
    }
    /// Whether `nf` was spent by height `h`.
    pub fn spent_by(&self, nf: &Hash, h: u64) -> bool {
        self.set.contains(nf) && self.at.get(nf).is_none_or(|&a| a <= h)
    }
    pub fn root(&self) -> Hash {
        *self.root.get_or_init(|| lichen_validity::smt::root(&self.entries(), empties()))
    }
    /// The path of `nf` in the tree (unspent: a proof that it is; spent,
    /// a proof of its leaf).
    pub fn proof(&self, nf: &Hash) -> lichen_validity::smt::Proof {
        lichen_validity::smt::proof(&self.entries(), nf, empties())
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
    /// What the hub signs: the notes, in deployment `d` (its keys and
    /// genesis seal: `lichen_validity::mint_digest`), so a mint replays in
    /// no other.
    pub fn digest(d: &Deployment, outputs: &[Note]) -> Hash {
        let mut h = Sha256::new();
        h.update(b"lichen/mint");
        h.update(d.sequencer);
        h.update(d.hub);
        h.update(d.seal.unwrap_or_default().to_bytes());
        for n in outputs {
            h.update(n.commitment());
        }
        h.finalize().into()
    }
    pub fn new(hub: &SigningKey, d: &Deployment, outputs: Vec<Note>) -> Mint {
        let sig = sign(hub, &Mint::digest(d, &outputs));
        Mint { outputs, sig }
    }
}

/// An exit record: contract `c`, of deposit coin `deposit`, was claimed for `b`
/// with the notes its `request` posted (`lichen_validity::exit::Posted`'s
/// encoding), and the hub records it. The claim's transparent notes are
/// retired as `exited(c)`, each on its owner's signature on the claim; a
/// shielded note's claim carries no authority to check, so the record
/// leaves it (the sequencer refuses its spends instead).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Exit {
    pub c: u32,
    #[serde(with = "outpoint")]
    pub deposit: OutPoint,
    pub b: u32,
    #[serde(with = "hexvec")]
    pub posted: Vec<u8>,
    /// The hub's signature over [`Exit::digest`].
    pub sig: Vec<u8>,
}

impl Exit {
    /// What the hub signs: the claim's `E`, in deployment `d`
    /// (`lichen_validity::exit::record_digest`).
    pub fn digest(d: &Deployment, e: &Hash) -> Hash {
        lichen_validity::exit::record_digest(&d.sequencer, &d.hub, &d.seal.unwrap_or_default(), e)
    }
    pub fn new(hub: &SigningKey, d: &Deployment, c: u32, deposit: OutPoint, b: u32, posted: &lichen_validity::exit::Posted) -> Exit {
        let sig = sign(hub, &Exit::digest(d, &posted.fingerprint(c, &deposit, b)));
        Exit { c, deposit, b, posted: posted.to_bytes(), sig }
    }
    pub fn claim(&self) -> Result<lichen_validity::exit::Posted> {
        lichen_validity::exit::Posted::from_bytes(&self.posted).map_err(|e| anyhow::anyhow!("an exit claim: {e:?}"))
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
    /// An anchor of this history on Bitcoin, confirmed: its record
    /// (`lichen_validity::AnchorRecord`'s encoding).
    Anchor(#[serde(with = "hexvec")] Vec<u8>),
    Exit(Exit),
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
    /// The anchoring's state now, and at the last seal (the pending
    /// block's starting state).
    #[serde(default, with = "anchor_hex")]
    pub anchor: AnchorState,
    #[serde(default, with = "anchor_hex")]
    pub anchor_sealed: AnchorState,
    /// Each new anchoring state with the height whose seal first carried
    /// it: the chain receipts from that height on hold it as their last
    /// anchor, until the next.
    #[serde(default)]
    pub anchors: Vec<Anchored>,
    /// Nullifiers claimed in an exit whose record hasn't retired them (a
    /// `request` not yet confirmed, or a shielded note's claim, which no
    /// record retires): their spends are refused, so that a spend can't
    /// race the claim (docs/EXIT_PLAN.md, "A claim racing a spend").
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub held: BTreeSet<Hash>,
}

/// An anchoring state, from the height whose seal first carried it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchored {
    pub from: u64,
    #[serde(with = "anchor_hex")]
    pub anchor: AnchorState,
}

impl Ledger {
    pub fn new(deployment: Deployment) -> Ledger {
        let anchor = AnchorState::genesis(deployment.seal.unwrap_or_default(), deployment.sequencer);
        Ledger { deployment, anchor, anchor_sealed: anchor, ..Ledger::default() }
    }

    /// The history hash at height `h` (`lichen_validity::hist_next` over
    /// the roots sealed to it).
    pub fn hist_at(&self, h: u64) -> Hash {
        self.sealed.iter().take(h as usize).fold([0; 32], |acc, s| lichen_validity::hist_next(&acc, &s.root()))
    }

    /// The record of an anchor confirmed on Bitcoin, as the block
    /// statement checks it: the transaction (non-witness serialization),
    /// its block's header, its index there and Merkle path, the block's
    /// coinbase (non-witness) and its path, and the roots from the height
    /// it commits to the last sealed one.
    pub fn anchor_record(&self, tx: Vec<u8>, header: [u8; 80], index: u32, path: Vec<Hash>, coinbase: Vec<u8>, coinbase_path: Vec<Hash>) -> Result<lichen_validity::AnchorRecord> {
        let t = lichen_validity::btc::parse_tx(&tx).context("not a transaction")?;
        let c = t.outputs.get(1).context("no commitment output")?.1;
        ensure!(c.len() == 48, "not an anchor's commitment");
        let at = u64::from_be_bytes(c[8..16].try_into().unwrap());
        let last = self.sealed.last().map_or(0, |s| s.height);
        ensure!(at >= 1 && at <= last, "an anchor of height {at}, beyond the last sealed ({last})");
        let roots = self.sealed[at as usize - 1..last as usize].iter().map(|s| s.root()).collect();
        Ok(lichen_validity::AnchorRecord { tx, header, index, path, coinbase, coinbase_path, before: self.hist_at(at - 1), roots })
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
        // all or nothing: a transaction that doesn't fit leaves no leaf
        ensure!(self.tree.len() as usize + leaves.len() <= 1 << TREE_DEPTH, "the tree is full");
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
        policy(tx, self.pending.len())?;
        let idx = self.apply_tx(tx)?;
        self.pending.push(tx.clone());
        Ok(idx)
    }

    fn apply_tx(&mut self, tx: &Tx) -> Result<Vec<u32>> {
        // the height whose block this joins
        let next = self.sealed.last().map_or(1, |s| s.height + 1);
        match tx {
            Tx::Anchor(r) => {
                let rec = lichen_validity::AnchorRecord::from_bytes(r).map_err(|e| anyhow::anyhow!("an anchor record: {e:?}"))?;
                let last = self.sealed.last().map_or(0, |s| s.height);
                self.anchor = lichen_validity::check_anchor(&self.anchor, last, &self.hist_at(last), &rec).map_err(|e| anyhow::anyhow!("the anchor doesn't check: {e:?}"))?;
                Ok(vec![])
            }
            Tx::Mint(m) => {
                verify(&self.deployment.hub, &Mint::digest(&self.deployment, &m.outputs), &m.sig).context("a mint not signed by the hub")?;
                self.append(&m.outputs)
            }
            Tx::Exit(x) => {
                let posted = x.claim()?;
                let e = posted.fingerprint(x.c, &x.deposit, x.b);
                verify(&self.deployment.hub, &Exit::digest(&self.deployment, &e), &x.sig).context("an exit record not signed by the hub")?;
                let mut nfs = vec![];
                for n in &posted.notes {
                    if let lichen_validity::exit::PostedNote::Transparent { note, sig } = n {
                        verify(&note.owner, &lichen_validity::exit::signed_digest(&e), sig).context("an exit claim not signed by its note's owner")?;
                        let nf = note.nullifier();
                        ensure!(!self.nullifiers.contains(&nf) && !nfs.contains(&nf), "a claimed note already spent");
                        nfs.push(nf);
                    }
                }
                for nf in nfs {
                    self.nullifiers.insert_at(nf, lichen_validity::smt::exited(x.c), next);
                }
                Ok(vec![])
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
                    ensure!(!self.held.contains(&nf), "the note at {} is claimed in an exit", s.index);
                    verify(&s.note.owner, &digest, sig).with_context(|| format!("the spend of note {}", s.index))?;
                }
                let vin = t.spends.iter().try_fold(0u64, |a, s| a.checked_add(s.note.value));
                let vout = t.outputs.iter().try_fold(0u64, |a, n| a.checked_add(n.value));
                ensure!(vin.is_some() && vin == vout, "values don't balance");
                let idx = self.append(&t.outputs)?;
                let leaf = lichen_validity::spend_leaf(&self.deployment.hub, &t.outputs.iter().map(tnote).collect::<Vec<_>>());
                for nf in nfs {
                    self.nullifiers.insert_at(nf, leaf, next);
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
                    ensure!(!self.held.contains(nf), "a note claimed in an exit");
                }
                self.verify_proof(&journal, &t.proof)?;
                let nf0 = *journal.nf0().context("a transaction that spends nothing")?;
                let mut leaves: Vec<Leaf> = t.outputs.iter().enumerate().map(|(i, o)| Leaf::Shielded { cm: o.cm, ciphertext: o.ciphertext.clone(), nf0, i: i as u32 }).collect();
                leaves.extend(t.t_outputs.iter().map(|n| Leaf::Note(*n)));
                let idx = self.append_leaves(&leaves)?;
                let leaf = lichen_validity::spend_leaf(&self.deployment.hub, &t.t_outputs.iter().map(tnote).collect::<Vec<_>>());
                for nf in nfs {
                    self.nullifiers.insert_at(nf, leaf, next);
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
        let changed = self.anchor_sealed != self.anchor;
        self.anchor_sealed = self.anchor;
        let s = self.seal_root(sequencer);
        if changed {
            self.anchors.push(Anchored { from: s.height, anchor: self.anchor });
        }
        (s, block)
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
        // the block's nullifiers, in the statement's order, with their
        // leaves
        let mut nfs = vec![];
        let mut spent_before = vec![];
        for t in &txs {
            match t {
                v::Tx::Mint { .. } | v::Tx::Anchor(_) => {}
                v::Tx::Exit { c, posted, .. } => {
                    for n in &posted.notes {
                        if let v::exit::PostedNote::Transparent { note, .. } = n {
                            nfs.push((note.nullifier(), v::smt::exited(*c)));
                        }
                    }
                }
                v::Tx::Transfer { spends, outputs, .. } => {
                    let leaf = v::spend_leaf(&self.deployment.hub, outputs);
                    nfs.extend(spends.iter().map(|s| (s.0.nullifier(), leaf)));
                    spent_before.extend(spends.iter().map(|s| s.1).filter(|&i| i < size0));
                }
                v::Tx::Shielded { t_spends, nfs: s_nfs, t_outputs, .. } => {
                    let leaf = v::spend_leaf(&self.deployment.hub, t_outputs);
                    nfs.extend(t_spends.iter().map(|s| (s.0.nullifier(), leaf)));
                    nfs.extend(s_nfs.iter().map(|nf| (*nf, leaf)));
                    spent_before.extend(t_spends.iter().map(|s| s.1).filter(|&i| i < size0));
                }
            }
        }
        let mut before = self.nullifiers.clone();
        for (nf, _) in &nfs {
            before.remove(nf);
        }
        let nullifiers = before.root();
        let mut nf_proofs = vec![];
        for (nf, leaf) in &nfs {
            nf_proofs.push(before.proof(nf));
            before.insert(*nf, *leaf);
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
            hist: self.hist_at(height),
            anchor: self.anchor_sealed,
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

    /// Hold the nullifiers of an exit claim the hub has seen (`sig`, its
    /// signature over [`hold_digest`]): their spends are refused from now
    /// on.
    pub fn hold(&mut self, nfs: &[Hash], sig: &[u8]) -> Result<()> {
        verify(&self.deployment.hub, &hold_digest(&self.deployment, nfs), sig).context("a hold not signed by the hub")?;
        self.held.extend(nfs);
        Ok(())
    }

    /// The exit kit's part for one note (docs/EXIT_PLAN.md, "What Alice
    /// must hold"): at sealed height `h`, the path of the note at `index`
    /// to the tree's root then, and its nullifier `nf`'s absence from the
    /// nullifier tree then.
    pub fn kit(&self, index: u32, nf: &Hash, h: u64) -> Result<Kit> {
        let s = self.sealed.get(usize::try_from(h).ok().and_then(|h| h.checked_sub(1)).context("no height 0")?).context("no such height sealed")?;
        ensure!(index < s.size, "note {index} is not in height {h}'s tree");
        ensure!(!self.nullifiers.spent_by(nf, h), "the note is spent by height {h}");
        let (root, unspent) = self.nullifiers.proof_at(nf, h);
        ensure!(root == s.nullifiers, "height {h}'s nullifiers can't be rebuilt");
        Ok(Kit { height: h, index, path: self.tree.path_at(index, s.size), bitmap: unspent.bitmap, siblings: unspent.siblings })
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

    /// The chain journal's `recent` at height `h`: the hash of the last
    /// [`lichen_validity::RECENT`] sealed tree roots up to it.
    pub fn recent_at(&self, h: u64) -> Option<Hash> {
        let upto = self.sealed.get(..usize::try_from(h).ok()?)?;
        Some(lichen_validity::recent_hash(&upto.iter().rev().take(lichen_validity::RECENT).rev().map(|s| s.tree).collect::<Vec<_>>()))
    }
}

/// What the hub signs to hold an exit claim's nullifiers `nfs`, in
/// deployment `d`.
pub fn hold_digest(d: &Deployment, nfs: &[Hash]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/hold");
    h.update(d.id());
    for nf in nfs {
        h.update(nf);
    }
    h.finalize().into()
}

/// One note's part of an exit kit: at sealed height `height`, the note's
/// path to the tree's root, and its nullifier's absence from the nullifier
/// tree (`lichen_validity::smt::Proof`'s bitmap and siblings).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kit {
    pub height: u64,
    pub index: u32,
    pub path: Vec<Hash>,
    pub bitmap: Hash,
    pub siblings: Vec<Hash>,
}

impl Kit {
    /// Whether the note of commitment `cm` and nullifier `nf` is in the
    /// tree of `sealed` (this kit's height) at the kit's index, its
    /// nullifier absent from the nullifier tree.
    pub fn check(&self, sealed: &SignedRoot, cm: &Hash, nf: &Hash) -> bool {
        let unspent = lichen_validity::smt::Proof { bitmap: self.bitmap, siblings: self.siblings.clone() };
        sealed.height == self.height
            && self.index < sealed.size
            && self.path.len() == TREE_DEPTH
            && root_from_path(*cm, self.index, &self.path) == sealed.tree
            && lichen_validity::smt::unspent(&sealed.nullifiers, nf, &unspent, lichen_validity::smt::empties())
    }
}

/// What a prover of the withdrawal statement is given beside the chain
/// receipt (`lichen-r0 claim`'s JSON): ln-gap's input (at the anchored
/// height), the headers on the anchor's block (hex) and the contract's
/// `W` (decimal).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverInput {
    #[serde(flatten)]
    pub input: WithdrawInput,
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub work: String,
}

/// The withdrawal statement's input (`lichen-withdraw`): ln-gap's at the
/// anchored height, the chain receipt's journal (its anchoring state's
/// last anchor that height's root), the headers on top of the anchor's
/// block, and the contract's `W`.
pub fn with_chain(input: &WithdrawInput, chain: &lichen_validity::ChainJournal, headers: Vec<[u8; 80]>, work: u128) -> Result<lichen_withdraw::WithdrawInput> {
    let n = &input.note;
    Ok(lichen_withdraw::WithdrawInput {
        height: input.height,
        nullifiers: input.nullifiers,
        signature: input.signature.as_slice().try_into().context("a signature of 64 bytes")?,
        note: lichen_validity::TNote { owner: n.owner, value: n.value, memo: n.memo, rho: n.rho },
        index: input.index,
        path: input.path.clone(),
        sequencer: input.sequencer,
        hub: input.hub,
        chain_height: chain.height,
        chain_root: chain.root,
        recent: chain.recent,
        hist: chain.hist,
        anchor: chain.anchor,
        headers,
        work,
    })
}

/// A ledger transaction as the block statement reads it.
fn tnote(n: &Note) -> lichen_validity::TNote {
    lichen_validity::TNote { owner: n.owner, value: n.value, memo: n.memo, rho: n.rho }
}

fn block_tx(tx: &Tx) -> Result<lichen_validity::Tx> {
    use lichen_validity::Tx as V;
    let tn = tnote;
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
        Tx::Anchor(r) => V::Anchor(lichen_validity::AnchorRecord::from_bytes(r).map_err(|e| anyhow::anyhow!("an anchor record: {e:?}"))?),
        Tx::Exit(x) => V::Exit { c: x.c, deposit: x.deposit, b: x.b, posted: x.claim()?, sig: sig(&x.sig)? },
    })
}

/// At most this many transactions in a height (an anchor's record aside),
/// so that each block stays one the chain guest can prove.
pub const MAX_BLOCK_TXS: usize = 512;
/// At most this many new notes in a mint or a transfer.
pub const MAX_TX_OUTPUTS: usize = 16;
/// The largest shielded note ciphertext (the wallet's are 57 bytes).
pub const MAX_CIPHERTEXT: usize = 256;
/// The largest spend receipt (a succinct one is about 220 kB).
pub const MAX_RECEIPT: usize = 1 << 20;

/// The sequencer's limits on what it takes, beyond the statement's rules:
/// stricter than the chain guest, so that every block it seals stays
/// provable (in memory and cycles) whatever its users send.
fn policy(tx: &Tx, pending: usize) -> Result<()> {
    if !matches!(tx, Tx::Anchor(_)) {
        ensure!(pending < MAX_BLOCK_TXS, "the next height is full ({MAX_BLOCK_TXS} transactions): send again after the next seal");
    }
    match tx {
        Tx::Mint(m) => ensure!(m.outputs.len() <= MAX_TX_OUTPUTS, "more than {MAX_TX_OUTPUTS} new notes"),
        Tx::Transfer(t) => ensure!(t.outputs.len() <= MAX_TX_OUTPUTS && t.spends.len() <= MAX_TX_OUTPUTS, "more than {MAX_TX_OUTPUTS} spends or new notes"),
        Tx::Shielded(t) => {
            ensure!(t.outputs.len() + t.t_outputs.len() <= MAX_TX_OUTPUTS && t.t_spends.len() + t.nfs.len() <= MAX_TX_OUTPUTS, "more than {MAX_TX_OUTPUTS} spends or new notes");
            ensure!(t.outputs.iter().all(|o| o.ciphertext.len() <= MAX_CIPHERTEXT), "a ciphertext longer than {MAX_CIPHERTEXT} bytes");
            if let Proof::Risc0(r) = &t.proof {
                ensure!(r.len() <= MAX_RECEIPT, "a receipt larger than {MAX_RECEIPT} bytes");
            }
        }
        Tx::Anchor(_) | Tx::Exit(_) => {}
    }
    Ok(())
}

/// The spend guest's image id (`r0/guests/spend.id`, `lichen-r0 image-id`).
pub const SPEND_IMAGE_ID: &str = include_str!("../../../r0/guests/spend.id");

/// Check a RISC Zero receipt (bincode) of the spend guest with `journal`.
#[cfg(feature = "risc0")]
fn verify_receipt(receipt: &[u8], journal: &[u8]) -> Result<()> {
    let r: risc0_zkvm::Receipt = bincode::deserialize(receipt).context("not a RISC Zero receipt")?;
    // the chain prover takes it as an assumption, which RISC Zero can't
    // do for a Groth16 receipt: a block holding one could never be proved
    ensure!(matches!(r.inner, risc0_zkvm::InnerReceipt::Succinct(_) | risc0_zkvm::InnerReceipt::Composite(_)), "a spend receipt must be succinct or composite");
    let id: [u8; 32] = hex::decode(SPEND_IMAGE_ID.trim()).ok().and_then(|v| v.try_into().ok()).context("the spend guest's image id")?;
    r.verify(risc0_zkvm::sha::Digest::from_bytes(id)).context("the receipt doesn't verify against the spend guest")?;
    ensure!(r.journal.bytes == journal, "the receipt proves another transaction");
    Ok(())
}

#[cfg(not(feature = "risc0"))]
fn verify_receipt(_: &[u8], _: &[u8]) -> Result<()> {
    bail!("this build can't verify RISC Zero receipts (lichen-ledger's feature risc0: the sequencer's)")
}

/// The chain guest's image id (`r0/guests/chain.id`).
pub const CHAIN_IMAGE_ID: &str = include_str!("../../../r0/guests/chain.id");

/// The chain journal of a chain receipt (bincode), verified against the
/// chain guest.
#[cfg(feature = "risc0")]
pub fn chain_journal(chain_receipt: &[u8]) -> Result<lichen_validity::ChainJournal> {
    let r: risc0_zkvm::Receipt = bincode::deserialize(chain_receipt).context("not a RISC Zero receipt")?;
    let id: Hash = hex::decode(CHAIN_IMAGE_ID.trim()).ok().and_then(|v| v.try_into().ok()).context("the chain guest's image id")?;
    r.verify(risc0_zkvm::sha::Digest::from_bytes(id)).context("the chain receipt doesn't verify against the chain guest")?;
    let c = lichen_validity::ChainJournal::from_bytes(&r.journal.bytes).map_err(|e| anyhow::anyhow!("not a chain journal: {e:?}"))?;
    ensure!(c.chain_id == id, "the chain receipt names another chain guest");
    Ok(c)
}

/// The withdrawal statement natively, as its guest checks it: the chain
/// receipt (bincode) verified against the chain guest, then
/// `lichen_withdraw::check` with the headers on top of its last anchor and
/// the contract's `W`. Its journal `b ‖ c ‖ D`: what a proof of this
/// withdrawal would commit, so what a dispute would accept.
#[cfg(feature = "risc0")]
pub fn check_withdrawal(input: &WithdrawInput, chain_receipt: &[u8], headers: Vec<[u8; 80]>, work: u128) -> Result<[u8; lichen_withdraw::JOURNAL_LEN]> {
    let c = chain_journal(chain_receipt)?;
    ensure!(c.anchor.height == input.height, "the chain receipt's last anchor is of height {}, the withdrawal's root of {}", c.anchor.height, input.height);
    let journal = c.to_bytes();
    lichen_withdraw::check(&with_chain(input, &c, headers, work)?, &c.chain_id, &mut |j| j == journal.as_slice()).map_err(|e| anyhow::anyhow!("the withdrawal statement rejects it: {e:?}"))
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

    /// The hub's check before a fold, on a real chain receipt (the
    /// real-receipt test's, kept with LICHEN_KEEP=1; remade when the chain
    /// guest is): the statement's journal for the return of 60 with memo
    /// 42 under its anchor, ten blocks on it; refusals for another height,
    /// another note, too few blocks.
    #[cfg(feature = "risc0")]
    #[test]
    fn the_withdrawal_checked_with_a_chain_receipt() {
        let receipt = include_bytes!("../tests/data/chain.receipt");
        let p: ProverInput = serde_json::from_str(include_str!("../tests/data/withdraw-60-42.json")).unwrap();
        let headers: Vec<[u8; 80]> = p.headers.iter().map(|h| hex::decode(h).unwrap().try_into().unwrap()).collect();
        let work: u128 = p.work.parse().unwrap();
        let input = p.input;
        let j = check_withdrawal(&input, receipt, headers.clone(), work).unwrap();
        assert_eq!(j[..8], [60, 0, 0, 0, 42, 0, 0, 0]);
        let mut other = input.clone();
        other.height -= 1;
        assert!(format!("{:#}", check_withdrawal(&other, receipt, headers.clone(), work).unwrap_err()).contains("of height"));
        let mut other = input.clone();
        other.note.value = 61;
        assert!(format!("{:#}", check_withdrawal(&other, receipt, headers.clone(), work).unwrap_err()).contains("rejects"));
        assert!(format!("{:#}", check_withdrawal(&input, receipt, headers[..1].to_vec(), work).unwrap_err()).contains("Depth"));
        let mut bad = receipt.to_vec();
        bad[1000] ^= 1;
        assert!(check_withdrawal(&input, &bad, headers, work).is_err(), "a damaged receipt");
    }

    /// An anchor of height `at`'s history, spending `seal`: the
    /// transaction (one input, the seal and the commitment) and a header
    /// of regtest's difficulty on `prev` holding it alone.
    fn anchor_tx(l: &Ledger, seal: &OutPoint, at: u64, prev: &Hash) -> (Vec<u8>, [u8; 80]) {
        let mut tx = vec![2, 0, 0, 0, 1];
        tx.extend(seal.to_bytes());
        tx.extend([0, 0xff, 0xff, 0xff, 0xff, 2]);
        tx.extend(330u64.to_le_bytes());
        tx.push(34);
        tx.extend(lichen_validity::seal_script(&l.deployment.sequencer));
        tx.extend(0u64.to_le_bytes());
        tx.push(48);
        tx.extend(lichen_validity::commitment_script(at, &l.hist_at(at)));
        tx.extend([0, 0, 0, 0]);
        let mut h = [0u8; 80];
        h[4..36].copy_from_slice(prev);
        let leaves = [lichen_validity::btc::sha256d(&coinbase()), lichen_validity::btc::sha256d(&tx)].concat();
        h[36..68].copy_from_slice(&lichen_validity::btc::sha256d(&leaves));
        h[72..76].copy_from_slice(&0x207fffffu32.to_le_bytes());
        while !lichen_validity::btc::Header(h).pow_ok() {
            h[76] += 1;
        }
        (tx, h)
    }

    /// A coinbase (65 bytes: one input spending the null outpoint).
    fn coinbase() -> Vec<u8> {
        let mut cb = vec![2, 0, 0, 0, 1];
        cb.extend([0; 32]);
        cb.extend([0xff; 4]);
        cb.extend([4, 1, 2, 3, 4]);
        cb.extend([0xff; 4]);
        cb.push(1);
        cb.extend(50u64.to_le_bytes());
        cb.extend([1, 0x51]);
        cb.extend([0; 4]);
        cb
    }

    /// The record of `tx`, an anchor in `header`'s block after its
    /// coinbase ([`anchor_tx`]'s blocks).
    fn record_of(l: &Ledger, tx: Vec<u8>, header: [u8; 80]) -> Result<lichen_validity::AnchorRecord> {
        let (cb, txid) = (coinbase(), lichen_validity::btc::sha256d(&tx));
        l.anchor_record(tx, header, 1, vec![lichen_validity::btc::sha256d(&cb)], cb, vec![txid])
    }

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
        let d = Deployment { sequencer: xonly(&seq), hub: xonly(&hub), seal: None };
        assert_ne!(d.id(), Deployment::toy().id());
        let mut l = Ledger::new(d);
        assert!(l.apply(&Tx::Mint(Mint::new(&regtest_hub(), &l.deployment, vec![note(d.hub, 7, 0)]))).is_err(), "the toy hub can't mint here");
        let r = l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, vec![note(d.hub, 7, 9)]))).unwrap()[0];
        l.seal(&seq);
        let input = l.withdraw_input(r).unwrap();
        assert_eq!(check(&input).unwrap()[8..], d.id());
        // sealed by another key: no withdrawal input
        let mut l2 = Ledger::new(d);
        let r2 = l2.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, vec![note(d.hub, 7, 9)]))).unwrap()[0];
        l2.seal(&regtest_sequencer());
        assert!(l2.withdraw_input(r2).is_err());
    }

    #[test]
    fn mint_transfer_return_and_the_statements_input() {
        let (hub, seq) = (regtest_hub(), regtest_sequencer());
        let (alice, bob) = (key_from_label("test/alice"), key_from_label("test/bob"));
        let mut l = Ledger::new(Deployment { sequencer: xonly(&seq), hub: xonly(&hub), seal: None });
        let n0 = note(xonly(&alice), 10, 0);
        let i0 = l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, vec![n0]))).unwrap()[0];
        // nobody but the hub mints
        assert!(l.apply(&Tx::Mint(Mint::new(&alice, &l.deployment, vec![note(xonly(&alice), 5, 0)]))).is_err());
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

    /// What the block statement refuses of blocks the sequencer never
    /// seals (a chain prover's forgeries): each refusal honest blocks
    /// never reach.
    #[test]
    fn the_block_statement_refuses() {
        use lichen_validity as v;
        let (hub, seq) = (regtest_hub(), regtest_sequencer());
        let alice = key_from_label("test/alice");
        let mut l = Ledger::new(Deployment { sequencer: xonly(&seq), hub: xonly(&hub), seal: None });
        let m0 = note(xonly(&alice), 20, 0);
        let i0 = l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, vec![m0]))).unwrap()[0];
        l.seal(&seq);
        // block 2: a transfer of the mint, from before the block (a path)
        l.apply(&transfer(vec![(Spend { note: m0, index: i0 }, &alice)], vec![note(xonly(&alice), 15, 0), note(xonly(&alice), 5, 0)])).unwrap();
        let good = l.block_input().unwrap();
        let check = |b: &v::BlockInput| v::check(b, &mut |_| true).map(|_| ());
        assert_eq!(check(&good), Ok(()));
        // the mint spent for other outputs, signed by its owner
        let signed = |outs: Vec<Note>| block_tx(&transfer(vec![(Spend { note: m0, index: i0 }, &alice)], outs)).unwrap();
        let with = |tx: v::Tx| {
            let mut b = good.clone();
            b.txs[0] = tx;
            b
        };
        assert_eq!(check(&with(signed(vec![note(xonly(&alice), 21, 0)]))), Err(v::Reject::Unbalanced), "more out than in");
        assert_eq!(check(&with(signed(vec![note(xonly(&alice), u64::MAX, 0), note(xonly(&alice), 21, 0)]))), Err(v::Reject::Unbalanced), "a sum that overflows");
        assert_eq!(check(&with(signed(vec![note(xonly(&alice), 20, 0), note(xonly(&alice), 0, 0)]))), Err(v::Reject::Empty), "an empty note");
        let mut bad = good.clone();
        bad.paths[0][0][0] ^= 1;
        assert_eq!(check(&bad), Err(v::Reject::NotInTree), "a path to another tree");
        // shapes
        let mut bad = good.clone();
        if let v::Tx::Transfer { sigs, .. } = &mut bad.txs[0] {
            sigs.pop();
        }
        assert_eq!(check(&bad), Err(v::Reject::Shape), "a signature missing");
        let mut bad = good.clone();
        bad.nf_proofs.push(bad.nf_proofs[0].clone());
        assert_eq!(check(&bad), Err(v::Reject::Shape), "an insert proof left over");
        let mut bad = good.clone();
        bad.paths.push(bad.paths[0].clone());
        assert_eq!(check(&bad), Err(v::Reject::Shape), "a path left over");
        let mut bad = good.clone();
        bad.recent = vec![[0; 32]; v::RECENT + 1];
        assert_eq!(check(&bad), Err(v::Reject::Shape), "too many recent roots");
        // the same note spent twice in one block
        let mut bad = good.clone();
        bad.txs.push(bad.txs[0].clone());
        bad.nf_proofs.push(bad.nf_proofs[0].clone());
        bad.paths.push(bad.paths[0].clone());
        assert!(check(&bad).is_err(), "a double spend within a block");
        // a frontier claiming a full tree: no room for the outputs
        let mut bad = good.clone();
        bad.tree.size = 1 << TREE_DEPTH;
        assert!(check(&bad).is_err(), "a full tree");
        // the encoding: a byte more, a byte less
        let mut b = good.to_bytes();
        b.push(0);
        assert_eq!(v::BlockInput::from_bytes(&b), Err(v::Reject::Encoding));
        let b = good.to_bytes();
        assert_eq!(v::BlockInput::from_bytes(&b[..b.len() - 1]), Err(v::Reject::Encoding));
    }

    /// The sequencer's limits: a mint of too many notes, a full height;
    /// and a transaction that doesn't fit the tree leaves nothing behind.
    #[test]
    fn limits_and_a_full_tree() {
        let (hub, seq) = (regtest_hub(), regtest_sequencer());
        let mut l = Ledger::new(Deployment { sequencer: xonly(&seq), hub: xonly(&hub), seal: None });
        let notes = |n: usize, v0: u64| (0..n as u64).map(|i| note([7; 32], v0 + i, 0)).collect::<Vec<_>>();
        assert!(format!("{:#}", l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, notes(MAX_TX_OUTPUTS + 1, 1)))).unwrap_err()).contains("new notes"));
        // the tree one short of full: a mint of two refused whole
        for i in 0..(1u32 << TREE_DEPTH) - 1 {
            l.tree.append(sha256(&[&i.to_be_bytes()])).unwrap();
        }
        let (len, notes_before) = (l.tree.len(), l.notes.len());
        assert!(format!("{:#}", l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, notes(2, 100)))).unwrap_err()).contains("full"));
        assert_eq!((l.tree.len(), l.notes.len(), l.pending.len()), (len, notes_before, 0), "nothing of it left behind");
        l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, notes(1, 100)))).unwrap();
        // a height holds at most MAX_BLOCK_TXS
        let mut l = Ledger::new(Deployment { sequencer: xonly(&seq), hub: xonly(&hub), seal: None });
        for i in 0..MAX_BLOCK_TXS as u64 {
            l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, vec![note([7; 32], i + 1, 0)]))).unwrap();
        }
        assert!(format!("{:#}", l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, vec![note([7; 32], 1_000_000, 0)]))).unwrap_err()).contains("full"));
        l.seal(&seq);
        l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, vec![note([7; 32], 1_000_000, 0)]))).unwrap();
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
        assert_eq!((input.hist, input.anchor), (l.hist_at(input.height), l.anchor_sealed));
        let prev = lichen_validity::ChainJournal { hub: j.hub, height: j.height, root: from.0, recent: from.1, chain_id: id, hist: j.hist_from, anchor: j.anchor_from }.to_bytes();
        let c = lichen_validity::chain(&id, &input, &mut |jb| journals.iter().any(|x| x == jb), &mut |jb| {
            assert!(input.height > 0, "genesis needs no receipt");
            jb == prev
        })
        .unwrap();
        assert_eq!((c.height, c.root, c.recent, c.chain_id, c.hist, c.anchor), (j.height + 1, j.to, j.recent_to, id, j.hist_to, j.anchor_to));
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
        assert_eq!((j.hist_to, j.anchor_to), (l.hist_at(s.height), l.anchor_sealed), "and its history and anchoring");
        j
    }

    #[test]
    fn every_block_is_the_block_statements() {
        use lichen_validity as v;
        let (hub, seq) = (regtest_hub(), regtest_sequencer());
        let alice = key_from_label("test/alice");
        let (alice_nk, bob_nk) = (sha256(&[b"alice nk"]), sha256(&[b"bob nk"]));
        let (a_owner, b_owner) = (shielded::owner(&alice_nk), shielded::owner(&bob_nk));
        let genesis_seal = OutPoint { txid: [0x5e; 32], vout: 1 };
        let mut l = Ledger::new(Deployment { sequencer: xonly(&seq), hub: xonly(&hub), seal: Some(genesis_seal) });
        l.native_proofs = true;
        let z = v::tree_empties();
        let genesis = (v::state_root(0, &z[TREE_DEPTH], &lichen_validity::smt::EMPTIES[lichen_validity::smt::DEPTH]), v::recent_hash(&[]));

        // block 1: two mints, and a transfer of one of them within the block
        let (m0, m1) = (note(xonly(&alice), 20, 0), note(xonly(&alice), 7, 0));
        let i0 = l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, vec![m0]))).unwrap()[0];
        l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, vec![m1]))).unwrap();
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
        let mint = Mint::new(&hub, &l.deployment, vec![note(xonly(&alice), 1, 0)]);
        l.apply(&Tx::Mint(mint)).unwrap();
        let mut bad = l.block_input().unwrap();
        if let v::Tx::Mint { sig, .. } = &mut bad.txs[1] {
            sig[0] ^= 1;
        }
        assert_eq!(v::check(&bad, &mut |_| true), Err(v::Reject::BadSignature));
        let j4 = seal_checked(&mut l, &seq, (j3.to, j3.recent_to));
        let nf_ret = shielded::nullifier(&bob_nk, &shielded::rho(&nf_pay, 0));
        assert_eq!(l.nullifiers.leaf(&nf_ret), v::smt::returned(42, 12), "the return's spend says so, and the statement agrees");

        // block 5: an anchor of height 4 (a mined block holding it), a
        // forged one refused
        let (tx, header) = anchor_tx(&l, &genesis_seal, 4, &[0xb0; 32]);
        let rec = record_of(&l, tx.clone(), header).unwrap();
        assert_eq!(coinbase().len(), 65);
        // the depth: a path other than the coinbase's length, or the
        // coinbase made to look like a node, refused
        let mut deep = rec.clone();
        deep.path.push([3; 32]);
        assert_eq!(v::check_anchor(&l.anchor, 4, &l.hist_at(4), &deep), Err(v::Reject::Seal), "a path deeper than the coinbase's");
        let mut no_cb = rec.clone();
        no_cb.coinbase = tx.clone();
        assert_eq!(v::check_anchor(&l.anchor, 4, &l.hist_at(4), &no_cb), Err(v::Reject::Seal), "no coinbase");
        assert!(v::check_anchor(&l.anchor, 4, &l.hist_at(4), &rec).is_ok());
        assert_eq!((rec.before, rec.roots.len()), (l.hist_at(3), 1));
        let (wrong, _) = anchor_tx(&l, &OutPoint { txid: [1; 32], vout: 0 }, 4, &[0xb0; 32]);
        assert!(l.apply(&Tx::Anchor(record_of(&l, wrong, header).unwrap().to_bytes())).is_err(), "not the seal");
        let mut late = tx.clone();
        let n = late.len();
        late[n - 4 - 32] ^= 1; // the committed history
        assert!(l.apply(&Tx::Anchor(record_of(&l, late, header).unwrap().to_bytes())).is_err(), "not this history");
        assert!(l.apply(&Tx::Anchor(record_of(&l, tx.clone(), [0; 80]).unwrap().to_bytes())).is_err(), "not in the block named");
        l.apply(&Tx::Anchor(rec.to_bytes())).unwrap();
        assert_eq!((l.anchor.height, l.anchor.root, l.anchor.seal.txid), (4, j4.to, lichen_validity::btc::sha256d(&tx)));
        let j5 = seal_checked(&mut l, &seq, (j4.to, j4.recent_to));
        assert_eq!(j5.anchor_to, l.anchor);
        assert_eq!(j5.anchor_from, v::AnchorState::genesis(genesis_seal, xonly(&seq)));

        // Bob's return withdrawn under the anchored root of height 4, the
        // chain receipt at 5 carrying the anchor, ten headers on the
        // anchor's block
        let index = (0..l.tree.len() as u32).find(|&i| l.note(i).is_some_and(|n| n.memo == 42)).unwrap();
        let ln = l.withdraw_input(index).unwrap();
        assert_eq!(ln.height, 4);
        assert_eq!(l.recent_at(5), Some(j5.recent_to));
        let id = [0xc4; 32];
        let c5 = v::ChainJournal { hub: j5.hub, height: 5, root: j5.to, recent: j5.recent_to, chain_id: id, hist: j5.hist_to, anchor: j5.anchor_to };
        let mut headers: Vec<[u8; 80]> = vec![];
        for _ in 0..10 {
            let prev = headers.last().map_or(j5.anchor_to.block, |h| v::btc::sha256d(h));
            headers.push(anchor_tx(&l, &genesis_seal, 4, &prev).1);
        }
        let w = with_chain(&ln, &c5, headers.clone(), 20).unwrap();
        let ends = c5.to_bytes();
        assert_eq!(lichen_withdraw::chain_journal(&w, &id).to_bytes(), ends);
        let journal = lichen_withdraw::check(&w, &id, &mut |jb| jb == ends).unwrap();
        assert_eq!(journal[..8], check(&ln).unwrap()[..8], "ln-gap's b ‖ c");
        assert_eq!(journal[8..], lichen_withdraw::contract_id(&l.deployment.id(), &genesis_seal, 20), "D, the contract's");
        // asking more work than the headers carry: refused
        let w = with_chain(&ln, &c5, headers, 22).unwrap();
        assert_eq!(lichen_withdraw::check(&w, &id, &mut |jb| jb == ends), Err(lichen_withdraw::Reject::Depth));
        // under height 4's chain receipt, before the anchor: refused
        let c4 = v::ChainJournal { hub: j4.hub, height: 4, root: j4.to, recent: j4.recent_to, chain_id: id, hist: j4.hist_to, anchor: j4.anchor_to };
        let w = with_chain(&ln, &c4, vec![], 0).unwrap();
        assert_eq!(lichen_withdraw::check(&w, &id, &mut |_| true), Err(lichen_withdraw::Reject::NotAnchored));
    }

    /// Alice's claim through contract `c`, of deposit coin `deposit`, of `b`
    /// from her transparent note `n` and a shielded note's nullifier, as
    /// its `request` posts it: signed by `signer`.
    fn claim(n: &Note, c: u32, deposit: &OutPoint, b: u32, signer: &SigningKey) -> lichen_validity::exit::Posted {
        use lichen_validity::exit::{signed_digest, Posted, PostedNote};
        let mut p = Posted { h_s: 1, sr_s: [0x33; 32], notes: vec![PostedNote::Transparent { note: tnote(n), sig: [0; 64] }, PostedNote::Shielded { nf: [0x44; 32] }] };
        let e = p.fingerprint(c, deposit, b);
        if let PostedNote::Transparent { sig, .. } = &mut p.notes[0] {
            *sig = sign(signer, &signed_digest(&e)).try_into().unwrap();
        }
        p
    }

    #[test]
    fn an_exit_record_retires_the_claimed_notes() {
        use lichen_validity as v;
        let (hub, seq) = (regtest_hub(), regtest_sequencer());
        let (alice, bob) = (key_from_label("test/alice"), key_from_label("test/bob"));
        let mut l = Ledger::new(Deployment { sequencer: xonly(&seq), hub: xonly(&hub), seal: Some(OutPoint { txid: [0x5e; 32], vout: 1 }) });
        let z = v::tree_empties();
        let genesis = (v::state_root(0, &z[TREE_DEPTH], &v::smt::EMPTIES[v::smt::DEPTH]), v::recent_hash(&[]));
        let n0 = note(xonly(&alice), 10, 0);
        let i0 = l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, vec![n0]))).unwrap()[0];
        let j1 = seal_checked(&mut l, &seq, genesis);

        // the claim through 1000: only the hub records it, only with its
        // owner's signature
        let deposit = OutPoint { txid: [12; 32], vout: 2 };
        let posted = claim(&n0, 1000, &deposit, 10, &alice);
        assert!(format!("{:#}", l.apply(&Tx::Exit(Exit::new(&alice, &l.deployment, 1000, deposit, 10, &posted))).unwrap_err()).contains("not signed by the hub"));
        let forged = claim(&n0, 1000, &deposit, 10, &bob);
        assert!(format!("{:#}", l.apply(&Tx::Exit(Exit::new(&hub, &l.deployment, 1000, deposit, 10, &forged))).unwrap_err()).contains("its note's owner"));
        let other_b = claim(&n0, 1000, &deposit, 11, &alice);
        assert!(l.apply(&Tx::Exit(Exit::new(&hub, &l.deployment, 1000, deposit, 10, &other_b))).is_err(), "signed for another b");
        let x = Tx::Exit(Exit::new(&hub, &l.deployment, 1000, deposit, 10, &posted));
        assert_eq!(l.apply(&x).unwrap(), Vec::<u32>::new());
        assert_eq!(l.nullifiers.leaf(&nullifier(&n0)), v::smt::exited(1000));
        assert!(!l.nullifiers.contains(&[0x44; 32]), "a shielded note's claim has no authority to retire it");
        // the note is gone: no spend, no second record
        assert!(l.apply(&transfer(vec![(Spend { note: n0, index: i0 }, &alice)], vec![note(xonly(&alice), 10, 0)])).is_err());
        let again = claim(&n0, 1001, &deposit, 10, &alice);
        assert!(format!("{:#}", l.apply(&Tx::Exit(Exit::new(&hub, &l.deployment, 1001, deposit, 10, &again))).unwrap_err()).contains("already spent"));
        // kept and read back
        let back: Ledger = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(back.pending.len(), 1);

        // the block statement agrees, and refuses what the ledger refuses
        let good = l.block_input().unwrap();
        let refused = |f: &dyn Fn(&mut v::Tx)| {
            let mut bad = good.clone();
            f(&mut bad.txs[0]);
            v::check(&bad, &mut |_| false)
        };
        assert_eq!(refused(&|t| if let v::Tx::Exit { c, .. } = t { *c = 1001 }), Err(v::Reject::BadSignature), "the hub signed another claim");
        assert_eq!(refused(&|t| if let v::Tx::Exit { posted, .. } = t { posted.notes.swap(0, 1) }), Err(v::Reject::BadSignature), "another E");
        assert_eq!(
            refused(&|t| if let v::Tx::Exit { posted, sig, .. } = t {
                *posted = claim(&n0, 1000, &deposit, 10, &bob);
                *sig = sign(&hub, &Exit::digest(&Deployment { sequencer: xonly(&seq), hub: xonly(&hub), seal: Some(OutPoint { txid: [0x5e; 32], vout: 1 }) }, &posted.fingerprint(1000, &deposit, 10))).try_into().unwrap();
            }),
            Err(v::Reject::BadSignature),
            "the hub's record of someone else's signature"
        );
        let j2 = seal_checked(&mut l, &seq, (j1.to, j1.recent_to));
        assert_ne!(j2.to, j1.to);
    }

    #[test]
    fn exit_kits_at_past_heights_and_holds() {
        let (hub, seq) = (regtest_hub(), regtest_sequencer());
        let alice = key_from_label("test/alice");
        let mut l = Ledger::new(Deployment { sequencer: xonly(&seq), hub: xonly(&hub), seal: None });
        let (n0, n1) = (note(xonly(&alice), 10, 0), note(xonly(&alice), 4, 0));
        let idx = l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, vec![n0, n1]))).unwrap();
        let s1 = l.seal(&seq);
        // height 2: n0 spent
        l.apply(&transfer(vec![(Spend { note: n0, index: idx[0] }, &alice)], vec![note(xonly(&alice), 10, 0)])).unwrap();
        let s2 = l.seal(&seq);
        let (nf0, nf1) = (nullifier(&n0), nullifier(&n1));
        // at height 1 both are unspent, and the kit shows it under that
        // height's signed root; at 2, n0 isn't
        let k = l.kit(idx[0], &nf0, 1).unwrap();
        assert!(k.check(&s1, &n0.commitment(), &nf0));
        assert!(!k.check(&s2, &n0.commitment(), &nf0), "another height's root");
        assert!(!k.check(&s1, &n1.commitment(), &nf0), "another note");
        assert!(format!("{:#}", l.kit(idx[0], &nf0, 2).unwrap_err()).contains("spent by height 2"));
        let k = l.kit(idx[1], &nf1, 2).unwrap();
        assert!(k.check(&s2, &n1.commitment(), &nf1));
        assert!(l.kit(idx[1] + 5, &nf1, 2).is_err() && l.kit(idx[1], &nf1, 3).is_err() && l.kit(idx[1], &nf1, 0).is_err());
        // kept and read back: the heights with it
        let back: Ledger = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(back.kit(idx[0], &nf0, 1).unwrap(), l.kit(idx[0], &nf0, 1).unwrap());
        // the hub holds n1 for a claim: its spend is refused; only the
        // hub's hold counts
        assert!(l.hold(&[nf1], &sign(&alice, &hold_digest(&l.deployment, &[nf1]))).is_err());
        l.hold(&[nf1], &sign(&hub, &hold_digest(&l.deployment, &[nf1]))).unwrap();
        let e = l.apply(&transfer(vec![(Spend { note: n1, index: idx[1] }, &alice)], vec![note(xonly(&alice), 4, 0)])).unwrap_err();
        assert!(format!("{e:#}").contains("claimed in an exit"));
    }

    #[test]
    fn the_nullifier_root_follows_each_spend() {
        // each spend's nullifier shown unspent under the root before, the
        // root after: what a block guest will check
        let (hub, seq) = (regtest_hub(), regtest_sequencer());
        let alice = key_from_label("test/alice");
        let mut l = Ledger::new(Deployment { sequencer: xonly(&seq), hub: xonly(&hub), seal: None });
        let empty = l.nullifiers.root();
        assert_eq!(empty, lichen_validity::smt::empties()[lichen_validity::smt::DEPTH]);
        let n0 = note(xonly(&alice), 10, 0);
        let i0 = l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, vec![n0]))).unwrap()[0];
        let nf = nullifier(&n0);
        let p = l.nullifiers.proof(&nf);
        l.apply(&transfer(vec![(Spend { note: n0, index: i0 }, &alice)], vec![note(xonly(&alice), 10, 0)])).unwrap();
        assert_eq!(lichen_validity::smt::insert(&empty, &nf, &lichen_validity::smt::spent(), &p, lichen_validity::smt::empties()), Some(l.nullifiers.root()));
        assert_ne!(l.seal(&seq).nullifiers, empty);
        // a return (one note to the hub, a contract's memo) leaves its
        // spends' leaves saying so; a payment to the hub with memo 0, or
        // two notes to it, doesn't
        let i1 = l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, vec![note(xonly(&alice), 30, 0)]))).unwrap()[0];
        let n1 = *l.note(i1).unwrap();
        let ret = l.apply(&transfer(vec![(Spend { note: n1, index: i1 }, &alice)], vec![note(xonly(&hub), 20, 1000), note(xonly(&alice), 10, 0)])).unwrap();
        assert_eq!(l.nullifiers.leaf(&nullifier(&n1)), lichen_validity::smt::returned(1000, 20));
        let n2 = *l.note(ret[1]).unwrap();
        l.apply(&transfer(vec![(Spend { note: n2, index: ret[1] }, &alice)], vec![note(xonly(&hub), 5, 1000), note(xonly(&hub), 5, 1001)])).unwrap();
        assert_eq!(l.nullifiers.leaf(&nullifier(&n2)), lichen_validity::smt::spent());
        // kept and read back: the same root, the tags with it
        let back: Ledger = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(back.nullifiers.root(), l.nullifiers.root());
        assert_eq!(back.nullifiers.leaf(&nullifier(&n1)), lichen_validity::smt::returned(1000, 20));
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
        let mut l = Ledger::new(Deployment { sequencer: xonly(&seq), hub: xonly(&hub), seal: None });
        l.native_proofs = true;
        let minted = note(xonly(&alice), 20, 0);
        let i0 = l.apply(&Tx::Mint(Mint::new(&hub, &l.deployment, vec![minted]))).unwrap()[0];
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

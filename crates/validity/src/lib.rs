//! The block statement (docs/SHIELDED_PLAN.md, phase 2): one sealed
//! height's transition `i -> i+1`, checked as the sequencer checks it.
//!
//! The state at a height is the commitment tree (its root `T`, its size,
//! its frontier), the nullifier tree's root `N` ([`smt`])
//! and the last [`RECENT`] sealed tree roots, the anchors a spend may use.
//! The withdrawal statement sees only `SR = state_root(height, T, N)`; the
//! recent roots travel beside it in the journal ([`BlockJournal`]).
//!
//! A block is the transactions applied between two seals, in order:
//! mints (signed by the hub), transparent transfers (each spend signed by
//! its note's owner, BIP340), exit records (signed by the hub and by the
//! claimed notes' owners, [`exit`]), and shielded transactions, whose receipts
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
use lichen_shielded::{self as sh, Hash, TREE_DEPTH};
use sha2::{Digest, Sha256};

pub mod btc;
pub mod exit;
pub mod smt;

pub use btc::OutPoint;

/// A spend's anchor must be one of the last this many sealed tree roots
/// (docs/SHIELDED_PLAN.md).
pub const RECENT: usize = 64;

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

/// The ledger's `Mint::digest`: the deployment's (its sequencer, its hub,
/// its genesis seal), so that a hub's signature mints in that deployment
/// alone.
pub fn mint_digest(sequencer: &Hash, hub: &Hash, genesis: &OutPoint, outputs: &[TNote]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/mint");
    h.update(sequencer);
    h.update(hub);
    h.update(genesis.to_bytes());
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
    /// An anchor on Bitcoin of this history ([`AnchorRecord`]).
    Anchor(AnchorRecord),
    /// An exit record: contract `c`, funded at `funding`, paid a claim of
    /// `b` as its `request` posted it; the hub's signature
    /// ([`exit::record_digest`]). Its transparent notes are retired,
    /// leaf `exited(c)`.
    Exit { c: u32, funding: OutPoint, b: u32, posted: exit::Posted, sig: [u8; 64] },
}

/// The history hash after `root`: `hist_h = H(hist_{h-1} ‖ root_h)`, from
/// `hist_0 = 0` (docs/ANCHOR_PLAN.md).
pub fn hist_next(hist: &Hash, root: &Hash) -> Hash {
    sha256(&[b"lichen/hist", hist, root])
}

/// The anchoring's state, carried from height to height in the chain
/// journal: the genesis seal and the sequencer's key (fixed at height 0),
/// the current seal (the outpoint the next anchor must spend), and the
/// last anchor's height, root and block (zero before the first).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AnchorState {
    pub genesis: OutPoint,
    pub sequencer: Hash,
    pub seal: OutPoint,
    pub height: u64,
    pub root: Hash,
    pub block: Hash,
}

impl AnchorState {
    /// The state at height 0, before any anchor.
    pub fn genesis(seal: OutPoint, sequencer: Hash) -> AnchorState {
        AnchorState { genesis: seal, sequencer, seal, height: 0, root: [0; 32], block: [0; 32] }
    }
    fn is_genesis(&self) -> bool {
        *self == AnchorState::genesis(self.genesis, self.sequencer)
    }
    /// Whether any anchor was recorded.
    pub fn anchored(&self) -> bool {
        self.height > 0
    }
    /// 176 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = W(Vec::with_capacity(176));
        w.anchor(self);
        w.0
    }
    pub fn from_bytes(b: &[u8]) -> Result<AnchorState, Reject> {
        let mut r = R(b);
        let a = r.anchor()?;
        r.end()?;
        Ok(a)
    }
}

/// The seal's script: P2TR with the sequencer's key as the output key
/// itself (untweaked), so only the sequencer spends it.
pub fn seal_script(sequencer: &Hash) -> [u8; 34] {
    let mut s = [0u8; 34];
    s[0] = 0x51;
    s[1] = 0x20;
    s[2..].copy_from_slice(sequencer);
    s
}

/// An anchor's commitment, its second output's script: `OP_RETURN
/// "lichen" ‖ at ‖ hist_at` (46 bytes pushed).
pub fn commitment_script(at: u64, hist: &Hash) -> [u8; 48] {
    let mut s = [0u8; 48];
    s[0] = 0x6a;
    s[1] = 46;
    s[2..8].copy_from_slice(b"lichen");
    s[8..16].copy_from_slice(&at.to_be_bytes());
    s[16..].copy_from_slice(hist);
    s
}

/// An anchor's record: the transaction (non-witness serialization) that
/// spent the seal, committing `hist_at` of this history; the header of
/// its block, its index there and Merkle path; the block's coinbase
/// (non-witness) and its path, which fix the tree's depth; and to show
/// `hist_at` an ancestor of this block's starting history, `hist_{at-1}`
/// and the roots `at..=i` (`i` the block's starting height).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorRecord {
    pub tx: Vec<u8>,
    pub header: [u8; 80],
    pub index: u32,
    pub path: Vec<Hash>,
    pub coinbase: Vec<u8>,
    pub coinbase_path: Vec<Hash>,
    pub before: Hash,
    pub roots: Vec<Hash>,
}

impl AnchorRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.record(self);
        w.0
    }
    pub fn from_bytes(b: &[u8]) -> Result<AnchorRecord, Reject> {
        let mut r = R(b);
        let a = r.record()?;
        r.end()?;
        Ok(a)
    }
}

/// Check an anchor record against the anchoring's state, in a block
/// starting at `height` with history hash `hist`: the next state.
pub fn check_anchor(state: &AnchorState, height: u64, hist: &Hash, rec: &AnchorRecord) -> Result<AnchorState, Reject> {
    // a 64-byte transaction could pass for a Merkle node
    if rec.tx.len() == 64 {
        return Err(Reject::Seal);
    }
    let tx = btc::parse_tx(&rec.tx).ok_or(Reject::Seal)?;
    if tx.inputs.first() != Some(&state.seal) || tx.outputs.len() < 2 || tx.outputs[0].1 != seal_script(&state.sequencer) {
        return Err(Reject::Seal);
    }
    let c = tx.outputs[1].1;
    if c.len() != 48 || c[..8] != commitment_script(0, &[0; 32])[..8] {
        return Err(Reject::Seal);
    }
    let at = u64::from_be_bytes(c[8..16].try_into().unwrap());
    let hist_at: Hash = c[16..].try_into().unwrap();
    // a later height than the last anchor's, of this history
    if at <= state.height || at > height || rec.roots.len() as u64 != height - at + 1 {
        return Err(Reject::Seal);
    }
    let mut h = hist_next(&rec.before, &rec.roots[0]);
    if h != hist_at {
        return Err(Reject::Seal);
    }
    for r in &rec.roots[1..] {
        h = hist_next(&h, r);
    }
    if h != *hist {
        return Err(Reject::Seal);
    }
    // in the block it names, at a leaf
    let header = btc::Header(rec.header);
    if !btc::in_block(&rec.tx, &header, rec.index, &rec.path, &rec.coinbase, &rec.coinbase_path) {
        return Err(Reject::Seal);
    }
    Ok(AnchorState { seal: OutPoint { txid: btc::sha256d(&rec.tx), vout: 0 }, height: at, root: rec.roots[0], block: header.hash(), ..*state })
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
    /// The history hash and the anchoring's state at `height`.
    pub hist: Hash,
    pub anchor: AnchorState,
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
    pub hist_from: Hash,
    pub hist_to: Hash,
    pub anchor_from: AnchorState,
    pub anchor_to: AnchorState,
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
    /// Height 0 not the empty ledger.
    Genesis,
    /// The previous chain receipt doesn't verify.
    Chain,
    /// An anchor record that doesn't check.
    Seal,
}

fn check_sig(key: &Hash, msg: &Hash, sig: &[u8; 64]) -> Result<(), Reject> {
    let k = VerifyingKey::from_bytes(key).map_err(|_| Reject::BadSignature)?;
    let s = Signature::try_from(&sig[..]).map_err(|_| Reject::BadSignature)?;
    k.verify_raw(msg, &s).map_err(|_| Reject::BadSignature)
}

struct State<'a> {
    input: &'a BlockInput,
    z: [Hash; TREE_DEPTH + 1],
    e: &'static [Hash],
    t_i: Hash,
    tree: Frontier,
    nullifiers: Hash,
    /// The leaves appended in this block: (index, commitment).
    made: Vec<(u32, Hash)>,
    nf_proofs: core::slice::Iter<'a, smt::Proof>,
    paths: core::slice::Iter<'a, Vec<Hash>>,
}

impl State<'_> {
    fn spend_nf(&mut self, nf: &Hash, leaf: &Hash) -> Result<(), Reject> {
        let p = self.nf_proofs.next().ok_or(Reject::Shape)?;
        self.nullifiers = smt::insert(&self.nullifiers, nf, leaf, p, self.e).ok_or(Reject::Spent)?;
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

/// The leaf a transaction's spends get in the nullifier tree: a return of
/// `r` with memo `c` if it pays the hub one note, `r` with a contract's
/// memo (not 0); else an ordinary spend.
pub fn spend_leaf(hub: &Hash, outputs: &[TNote]) -> Hash {
    let mut to_hub = outputs.iter().filter(|n| n.owner == *hub);
    match (to_hub.next(), to_hub.next()) {
        (Some(n), None) if n.memo != 0 => smt::returned(n.memo, n.value),
        _ => smt::spent(),
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
    let mut anchor = input.anchor;
    for tx in &input.txs {
        match tx {
            Tx::Anchor(rec) => anchor = check_anchor(&anchor, input.height, &input.hist, rec)?,
            Tx::Exit { c, funding, b, posted, sig } => {
                let e = posted.fingerprint(*c, funding, *b);
                check_sig(&input.hub, &exit::record_digest(&input.anchor.sequencer, &input.hub, &input.anchor.genesis, &e), sig)?;
                for n in &posted.notes {
                    if let exit::PostedNote::Transparent { note, sig } = n {
                        check_sig(&note.owner, &exit::signed_digest(&e), sig)?;
                        st.spend_nf(&note.nullifier(), &smt::exited(*c))?;
                    }
                }
            }
            Tx::Mint { outputs, sig } => {
                check_sig(&input.hub, &mint_digest(&input.anchor.sequencer, &input.hub, &input.anchor.genesis, outputs), sig)?;
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
                let leaf = spend_leaf(&input.hub, outputs);
                for ((n, i), sig) in spends.iter().zip(sigs) {
                    st.in_tree(n, *i)?;
                    check_sig(&n.owner, &d, sig)?;
                    st.spend_nf(&n.nullifier(), &leaf)?;
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
                // the spend statement's own bounds, so the journal's list
                // lengths (bytes) are what it proved
                if t_sigs.len() != t_spends.len() || ciphertexts.len() != cms.len() || t_spends.len() + nfs.len() > sh::MAX_SPENDS || cms.len() + t_outputs.len() > sh::MAX_OUTPUTS {
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
                let leaf = spend_leaf(&input.hub, t_outputs);
                for n in t_spends.iter().map(|s| s.0.nullifier()).chain(nfs.iter().copied()) {
                    st.spend_nf(&n, &leaf)?;
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
    let to = state_root(input.height + 1, &t_next, &st.nullifiers);
    Ok(BlockJournal {
        hub: input.hub,
        height: input.height,
        from: state_root(input.height, &t_i, &input.nullifiers),
        recent_from: recent_hash(&input.recent),
        to,
        recent_to: recent_hash(&recent),
        hist_from: input.hist,
        hist_to: hist_next(&input.hist, &to),
        anchor_from: input.anchor,
        anchor_to: anchor,
    })
}

/// What the chain statement shows: the state at `height` (its root `SR`
/// and its recent roots) ends a valid history from genesis, under the
/// hub, as proved by the guest of image id `chain_id`. The guest can't
/// hold its own image id, so it is an input, carried in the journal and
/// required equal in the previous one: whoever checks a receipt against
/// `CHAIN_ID` checks the journal's `chain_id` is `CHAIN_ID` too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainJournal {
    pub hub: Hash,
    pub height: u64,
    pub root: Hash,
    pub recent: Hash,
    pub chain_id: Hash,
    pub hist: Hash,
    pub anchor: AnchorState,
}

/// The chain statement: the block in `input` checked ([`check`]), from
/// the genesis state (height 0: the empty ledger, no recent roots) or
/// from a state a previous chain receipt ends: `verify_chain` checks one
/// (`env::verify(chain_id, journal)` in the guest).
pub fn chain(chain_id: &Hash, input: &BlockInput, verify_spend: &mut dyn FnMut(&[u8]) -> bool, verify_chain: &mut dyn FnMut(&[u8]) -> bool) -> Result<ChainJournal, Reject> {
    let j = check(input, verify_spend)?;
    if input.height == 0 {
        let empty = smt::EMPTIES[smt::DEPTH];
        if input.tree.size != 0 || input.nullifiers != empty || !input.recent.is_empty() || input.hist != [0; 32] || !input.anchor.is_genesis() {
            return Err(Reject::Genesis);
        }
    } else {
        let prev = ChainJournal { hub: j.hub, height: j.height, root: j.from, recent: j.recent_from, chain_id: *chain_id, hist: j.hist_from, anchor: j.anchor_from };
        if !verify_chain(&prev.to_bytes()) {
            return Err(Reject::Chain);
        }
    }
    Ok(ChainJournal { hub: j.hub, height: j.height + 1, root: j.to, recent: j.recent_to, chain_id: *chain_id, hist: j.hist_to, anchor: j.anchor_to })
}

// ----- encodings: what the chain guest reads and commits -----
//
// Integers big-endian; a list is its length (u32) and its items.

struct W(Vec<u8>);
impl W {
    fn put(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    fn len(&mut self, n: usize) {
        self.put(&(n as u32).to_be_bytes());
    }
    fn hashes(&mut self, hs: &[Hash]) {
        self.len(hs.len());
        for h in hs {
            self.put(h);
        }
    }
    fn note(&mut self, n: &TNote) {
        self.put(&n.owner);
        self.put(&n.value.to_be_bytes());
        self.put(&n.memo.to_be_bytes());
        self.put(&n.rho);
    }
    fn notes(&mut self, ns: &[TNote]) {
        self.len(ns.len());
        for n in ns {
            self.note(n);
        }
    }
    fn spends(&mut self, ss: &[(TNote, u32)]) {
        self.len(ss.len());
        for (n, i) in ss {
            self.note(n);
            self.put(&i.to_be_bytes());
        }
    }
    fn sigs(&mut self, ss: &[[u8; 64]]) {
        self.len(ss.len());
        for s in ss {
            self.put(s);
        }
    }
    fn anchor(&mut self, a: &AnchorState) {
        self.put(&a.genesis.to_bytes());
        self.put(&a.sequencer);
        self.put(&a.seal.to_bytes());
        self.put(&a.height.to_be_bytes());
        self.put(&a.root);
        self.put(&a.block);
    }
    fn bytes(&mut self, b: &[u8]) {
        self.len(b.len());
        self.put(b);
    }
    fn record(&mut self, a: &AnchorRecord) {
        self.bytes(&a.tx);
        self.put(&a.header);
        self.put(&a.index.to_be_bytes());
        self.hashes(&a.path);
        self.bytes(&a.coinbase);
        self.hashes(&a.coinbase_path);
        self.put(&a.before);
        self.hashes(&a.roots);
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
    fn u32(&mut self) -> Result<u32, Reject> {
        Ok(u32::from_be_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64, Reject> {
        Ok(u64::from_be_bytes(self.take()?))
    }
    /// A list's length: no more items than bytes left (each takes one at
    /// least), so a bad length can't make a huge allocation.
    fn len(&mut self) -> Result<usize, Reject> {
        let n = self.u32()? as usize;
        if n > self.0.len() {
            return Err(Reject::Encoding);
        }
        Ok(n)
    }
    fn list<T>(&mut self, mut item: impl FnMut(&mut Self) -> Result<T, Reject>) -> Result<Vec<T>, Reject> {
        let n = self.len()?;
        (0..n).map(|_| item(self)).collect()
    }
    fn hashes(&mut self) -> Result<Vec<Hash>, Reject> {
        self.list(|r| r.take())
    }
    fn note(&mut self) -> Result<TNote, Reject> {
        Ok(TNote { owner: self.take()?, value: self.u64()?, memo: self.u32()?, rho: self.take()? })
    }
    fn notes(&mut self) -> Result<Vec<TNote>, Reject> {
        self.list(|r| r.note())
    }
    fn spends(&mut self) -> Result<Vec<(TNote, u32)>, Reject> {
        self.list(|r| Ok((r.note()?, r.u32()?)))
    }
    fn sigs(&mut self) -> Result<Vec<[u8; 64]>, Reject> {
        self.list(|r| r.take())
    }
    fn anchor(&mut self) -> Result<AnchorState, Reject> {
        Ok(AnchorState { genesis: OutPoint::from_bytes(&self.take()?), sequencer: self.take()?, seal: OutPoint::from_bytes(&self.take()?), height: self.u64()?, root: self.take()?, block: self.take()? })
    }
    fn record(&mut self) -> Result<AnchorRecord, Reject> {
        Ok(AnchorRecord { tx: self.bytes()?, header: self.take()?, index: self.u32()?, path: self.hashes()?, coinbase: self.bytes()?, coinbase_path: self.hashes()?, before: self.take()?, roots: self.hashes()? })
    }
    fn bytes(&mut self) -> Result<Vec<u8>, Reject> {
        let n = self.len()?;
        let (b, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(b.to_vec())
    }
    fn end(&self) -> Result<(), Reject> {
        if self.0.is_empty() { Ok(()) } else { Err(Reject::Encoding) }
    }
}

const MINT: u8 = 0;
const TRANSFER: u8 = 1;
const SHIELDED: u8 = 2;
const ANCHOR: u8 = 3;
const EXIT: u8 = 4;

impl BlockInput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.put(&self.hub);
        w.put(&self.height.to_be_bytes());
        w.put(&self.tree.size.to_be_bytes());
        w.hashes(&self.tree.branch);
        w.put(&self.nullifiers);
        w.hashes(&self.recent);
        w.put(&self.hist);
        w.anchor(&self.anchor);
        w.len(self.txs.len());
        for tx in &self.txs {
            match tx {
                Tx::Mint { outputs, sig } => {
                    w.0.push(MINT);
                    w.notes(outputs);
                    w.put(sig);
                }
                Tx::Transfer { spends, outputs, sigs } => {
                    w.0.push(TRANSFER);
                    w.spends(spends);
                    w.notes(outputs);
                    w.sigs(sigs);
                }
                Tx::Shielded { anchor, t_spends, t_sigs, nfs, cms, ciphertexts, t_outputs } => {
                    w.0.push(SHIELDED);
                    w.put(anchor);
                    w.spends(t_spends);
                    w.sigs(t_sigs);
                    w.hashes(nfs);
                    w.hashes(cms);
                    w.len(ciphertexts.len());
                    for c in ciphertexts {
                        w.len(c.len());
                        w.put(c);
                    }
                    w.notes(t_outputs);
                }
                Tx::Anchor(a) => {
                    w.0.push(ANCHOR);
                    w.record(a);
                }
                Tx::Exit { c, funding, b, posted, sig } => {
                    w.0.push(EXIT);
                    w.put(&c.to_be_bytes());
                    w.put(&funding.to_bytes());
                    w.put(&b.to_be_bytes());
                    w.bytes(&posted.to_bytes());
                    w.put(sig);
                }
            }
        }
        w.len(self.nf_proofs.len());
        for p in &self.nf_proofs {
            w.put(&p.bitmap);
            w.hashes(&p.siblings);
        }
        w.len(self.paths.len());
        for p in &self.paths {
            w.hashes(p);
        }
        w.0
    }

    pub fn from_bytes(b: &[u8]) -> Result<BlockInput, Reject> {
        let mut r = R(b);
        let hub = r.take()?;
        let height = r.u64()?;
        let tree = Frontier { size: r.u32()?, branch: r.hashes()? };
        let nullifiers = r.take()?;
        let recent = r.hashes()?;
        let hist = r.take()?;
        let anchor = r.anchor()?;
        let txs = r.list(|r| {
            Ok(match r.take::<1>()?[0] {
                MINT => Tx::Mint { outputs: r.notes()?, sig: r.take()? },
                TRANSFER => Tx::Transfer { spends: r.spends()?, outputs: r.notes()?, sigs: r.sigs()? },
                SHIELDED => Tx::Shielded {
                    anchor: r.take()?,
                    t_spends: r.spends()?,
                    t_sigs: r.sigs()?,
                    nfs: r.hashes()?,
                    cms: r.hashes()?,
                    ciphertexts: r.list(|r| {
                        let n = r.len()?;
                        let (c, rest) = r.0.split_at(n);
                        r.0 = rest;
                        Ok(c.to_vec())
                    })?,
                    t_outputs: r.notes()?,
                },
                ANCHOR => Tx::Anchor(r.record()?),
                EXIT => Tx::Exit { c: r.u32()?, funding: OutPoint::from_bytes(&r.take()?), b: r.u32()?, posted: exit::Posted::from_bytes(&r.bytes()?)?, sig: r.take()? },
                _ => return Err(Reject::Encoding),
            })
        })?;
        let nf_proofs = r.list(|r| Ok(smt::Proof { bitmap: r.take()?, siblings: r.hashes()? }))?;
        let paths = r.list(|r| r.hashes())?;
        r.end()?;
        Ok(BlockInput { hub, height, tree, nullifiers, recent, hist, anchor, txs, nf_proofs, paths })
    }
}

impl BlockJournal {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = W(Vec::with_capacity(168));
        w.put(&self.hub);
        w.put(&self.height.to_be_bytes());
        w.put(&self.from);
        w.put(&self.recent_from);
        w.put(&self.to);
        w.put(&self.recent_to);
        w.put(&self.hist_from);
        w.put(&self.hist_to);
        w.anchor(&self.anchor_from);
        w.anchor(&self.anchor_to);
        w.0
    }
    pub fn from_bytes(b: &[u8]) -> Result<BlockJournal, Reject> {
        let mut r = R(b);
        let j = BlockJournal { hub: r.take()?, height: r.u64()?, from: r.take()?, recent_from: r.take()?, to: r.take()?, recent_to: r.take()?, hist_from: r.take()?, hist_to: r.take()?, anchor_from: r.anchor()?, anchor_to: r.anchor()? };
        r.end()?;
        Ok(j)
    }
}

impl ChainJournal {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = W(Vec::with_capacity(136));
        w.put(&self.hub);
        w.put(&self.height.to_be_bytes());
        w.put(&self.root);
        w.put(&self.recent);
        w.put(&self.chain_id);
        w.put(&self.hist);
        w.anchor(&self.anchor);
        w.0
    }
    pub fn from_bytes(b: &[u8]) -> Result<ChainJournal, Reject> {
        let mut r = R(b);
        let j = ChainJournal { hub: r.take()?, height: r.u64()?, root: r.take()?, recent: r.take()?, chain_id: r.take()?, hist: r.take()?, anchor: r.anchor()? };
        r.end()?;
        Ok(j)
    }
}

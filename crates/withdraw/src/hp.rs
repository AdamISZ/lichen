//! The exit where only the hub proves (docs/HUB_PROVES_PLAN.md): Alice
//! claims definite notes and an amount `b`, and the hub proves, if it
//! can, that her claim is false. Its statement is fixed when the contract
//! opens; BABE checks it with the roles swapped (Alice garbles).
//!
//! **The claim** ([`Claim`]), posted in `request`'s witness: its notes
//! by their positions in the commitment tree, increasing, and one
//! signature per owner key on the claim's fingerprint
//!
//! ```text
//! E = SHA256("lichen/exit" ‖ c ‖ O_D ‖ b ‖ i_1 ‖ … ‖ i_n)
//! ```
//!
//! (`lichen_validity::exit`), so that the hub's exit record on the L2
//! retires the notes under the same `E`. Alice signs `b` and `E` with her
//! one-time keys; the claim's bytes, which script can't check, must hash
//! to that `E`. A leaf's top bit says its kind, so a position alone names
//! a transparent note: the hub, which holds every opening, shows one
//! where a ground needs it.
//!
//! **The claim is true** if its notes are hers (each owner signed `E`),
//! worth at least `b` (in the contract's units), and live at `A*`, the
//! last anchor confirmed at least `margin` blocks before `request`'s
//! block: each in the tree at its position, its nullifier unspent (this
//! contract's own exit record not counting as a spend: the hub records
//! one when it takes her claim to withdraw cooperatively, and if it then
//! won't fold, her exit posts the same claim). The margin keeps the operator from
//! slipping a held spend of hers into an anchor while her `request`
//! confirms.
//!
//! **The statement** ([`check`]) holds on any ground ([`Ground`]) that
//! the claim is false: malformed, or, at `A*`, a position that isn't a
//! transparent note, a note not hers, notes worth too little, a note
//! spent, or a note claimed through another contract too. `A*` is shown
//! last by the first spend of its seal output, in a block after the
//! cutoff: anchors spend the seal one after another, and Bitcoin allows
//! one spend. Its journal is `c ‖ D ‖ H(O_D ‖ margin)`, fixed at opening.
//!
//! `request` is read from Bitcoin, in a block with the contract's work on
//! it. Alice's signatures on `b` and `E` aren't checked here: Bitcoin
//! checked them, in `request`'s script; only their digits are read.

use alloc::vec::Vec;
use k256::schnorr::{Signature, VerifyingKey};
use lichen_validity::btc::{self, Header};
use lichen_validity::ack::{self, Ack};
use lichen_validity::{smt, OutPoint, TNote};
use sha2::{Digest, Sha256};

pub use lichen_validity::exit::{fingerprint, owners, signed_digest, SClaim, SNoteClaim};
use crate::{contract_id, deployment_id, root_from_path, work_on, Anchored, Hash, Reject, Request, TREE_DEPTH};
use lichen_shielded::is_shielded;

/// `request`'s witness carries the claim in its first this many items,
/// concatenated: as many as the script drops, empty ones padding.
pub const POSTED_ITEMS: usize = 15;

/// The largest item: Bitcoin Core relays no tapscript witness item larger.
pub const POSTED_ITEM: usize = 80;

/// A claim's bytes as `request`'s witness carries them: [`POSTED_ITEMS`]
/// items of up to [`POSTED_ITEM`] bytes, bottom first. None if they don't
/// fit.
pub fn posted_items(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    (bytes.len() <= POSTED_ITEMS * POSTED_ITEM).then(|| (0..POSTED_ITEMS).map(|i| bytes.get(i * POSTED_ITEM..).map_or(&[][..], |b| &b[..b.len().min(POSTED_ITEM)])).collect())
}

/// The spent set where `A*`'s own anchor record is applied (the chain
/// receipt's height, `Anchored::chain_height`): its commitment tree's and
/// spent set's roots, under the chain journal's state root. Anchor records
/// are applied in seal order, so every anchor up to `A*`'s is in it, each
/// confirmed before the cutoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainSet {
    pub tree: Hash,
    pub set: Hash,
}

/// How the spend of a claimed note counts against her at `A*`
/// (docs/HUB_PROVES_PLAN.md, "Data availability").
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Counts {
    /// Another contract's exit record (the note's leaf `exited(c)`).
    Exit { c: u32 },
    /// A user's spend (the note's leaf its `txid`) acknowledged at `A*`:
    /// its `acked` key's opening.
    Acked { acked: smt::Opening },
    /// A user's spend pending at `A*` (its pending leaf, not void), with an
    /// acknowledgment whose anchor is applied in `chain`.
    Shown { ack: Ack, pending: smt::Opening, void: smt::Opening, anchor: smt::Opening, chain: ChainSet },
}

/// Why an acknowledgment a claim carries doesn't hold: its signature
/// (checked here, no evidence), or shown by an opening: not its spend's
/// pending leaf at `A*`, or its anchor not applied in `chain`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bad {
    Signature,
    Pending(smt::Opening),
    Anchor(smt::Opening, ChainSet),
}

/// At most this many notes in a claim: an exit record's most
/// (`lichen_validity::exit::MAX_NOTES`).
pub const MAX_NOTES: usize = lichen_validity::exit::MAX_NOTES;

/// The journal's length in bytes: `c ‖ D ‖ H(O_D ‖ margin)`.
pub const JOURNAL_LEN: usize = 68;

/// A claim as `request` posts it: its transparent notes' positions,
/// increasing, the acknowledgments of the spends whose locked outputs it
/// claims, one signature per owner key on [`signed_digest`] of its `E`
/// (a shielded owner's by its exit key), and its shielded notes, if any
/// ([`SClaim`]: one owner's keys and each note's position and opening).
/// Its notes, as a ground's `which` counts them: the transparent ones,
/// then the shielded ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub positions: Vec<u32>,
    pub acks: Vec<Ack>,
    pub sigs: Vec<[u8; 64]>,
    pub shielded: Option<SClaim>,
}

fn verifies(owner: &Hash, digest: &Hash, sig: &[u8; 64]) -> bool {
    let (Ok(key), Ok(sig)) = (VerifyingKey::from_bytes(owner), Signature::try_from(&sig[..])) else { return false };
    key.verify_raw(digest, &sig).is_ok()
}

impl Claim {
    /// `E` for contract `c` of deposit coin `deposit`, claiming `b`.
    pub fn fingerprint(&self, c: u32, deposit: &OutPoint, b: u32) -> Hash {
        fingerprint(c, deposit, b, &self.positions, &self.acks, self.shielded.as_ref())
    }

    /// How many notes it claims, transparent and shielded.
    pub fn len(&self) -> usize {
        self.positions.len() + self.shielded.as_ref().map_or(0, |s| s.notes.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The position of its `which`th note (the transparent ones first).
    pub fn position(&self, which: usize) -> Option<u32> {
        match self.positions.get(which) {
            Some(i) => Some(*i),
            None => self.shielded_note(which).map(|n| n.index),
        }
    }

    /// Its `which`th note, if a shielded one.
    pub fn shielded_note(&self, which: usize) -> Option<&SNoteClaim> {
        self.shielded.as_ref()?.notes.get(which.checked_sub(self.positions.len())?)
    }

    /// Whether it claims the note at position `index` of the kind
    /// `shielded`.
    pub fn claims(&self, index: u32, shielded: bool) -> bool {
        if shielded {
            self.shielded.as_ref().is_some_and(|s| s.notes.iter().any(|n| n.index == index))
        } else {
            self.positions.contains(&index)
        }
    }

    /// Whether it is well formed: one to [`MAX_NOTES`] notes, positions
    /// increasing in each kind and in the tree's range, one to as many
    /// signatures as notes.
    pub fn well_formed(&self) -> bool {
        let n = self.len();
        (1..=MAX_NOTES).contains(&n)
            && self.positions.windows(2).all(|w| w[0] < w[1])
            && self.shielded.as_ref().is_none_or(|s| s.well_formed())
            && (0..n).all(|w| self.position(w).is_some_and(|i| i >> TREE_DEPTH == 0))
            && (1..=n).contains(&self.sigs.len())
            && self.acks.len() <= n
            && self.acks.iter().enumerate().all(|(i, a)| !self.acks[..i].iter().any(|b| b.txid == a.txid))
    }

    /// The signature of `owner`'s on the claim `e`, if any.
    pub fn signed_by(&self, owner: &Hash, e: &Hash) -> Option<[u8; 64]> {
        let d = signed_digest(e);
        self.sigs.iter().find(|s| verifies(owner, &d, s)).copied()
    }

    /// The exit record's transparent notes and signatures
    /// (`lichen_validity::Tx::Exit`; its acknowledgments and shielded notes
    /// are the claim's) from the transparent notes at the claim's
    /// positions, in order: each owner's signature, in [`owners`]' order.
    /// None unless every owner signed `e`.
    #[allow(clippy::type_complexity)]
    pub fn record(&self, notes: &[TNote], e: &Hash) -> Option<(Vec<(TNote, u32)>, Vec<[u8; 64]>)> {
        if notes.len() != self.positions.len() {
            return None;
        }
        let notes: Vec<(TNote, u32)> = notes.iter().copied().zip(self.positions.iter().copied()).collect();
        let sigs = owners(&notes, self.shielded.as_ref()).iter().map(|o| self.signed_by(o, e)).collect::<Option<Vec<_>>>()?;
        Some((notes, sigs))
    }

    /// `[n] iⁿ [m] ackᵐ [k] sigᵏ [s] shielded`, big-endian: 4 bytes a note,
    /// 176 an acknowledgment, 64 a signature; `s` 1 and the shielded notes
    /// ([`SClaim::to_bytes`]: 97 bytes, and 76 a note) or 0.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(3 + 4 * self.positions.len() + Ack::LEN * self.acks.len() + 64 * self.sigs.len());
        w.push(self.positions.len() as u8);
        for i in &self.positions {
            w.extend_from_slice(&i.to_be_bytes());
        }
        w.push(self.acks.len() as u8);
        for a in &self.acks {
            w.extend_from_slice(&a.to_bytes());
        }
        w.push(self.sigs.len() as u8);
        for s in &self.sigs {
            w.extend_from_slice(s);
        }
        match &self.shielded {
            Some(s) => {
                w.push(1);
                w.extend_from_slice(&s.to_bytes());
            }
            None => w.push(0),
        }
        w
    }

    pub fn from_bytes(b: &[u8]) -> Result<Claim, Reject> {
        let mut r = crate::R(b);
        let [n] = r.take()?;
        let positions = (0..n).map(|_| Ok(u32::from_be_bytes(r.take()?))).collect::<Result<Vec<_>, Reject>>()?;
        let [m] = r.take()?;
        let acks = (0..m).map(|_| Ok(Ack::from_bytes(&r.take()?))).collect::<Result<Vec<_>, Reject>>()?;
        let [k] = r.take()?;
        let sigs = (0..k).map(|_| r.take()).collect::<Result<Vec<_>, _>>()?;
        let shielded = match r.take()? {
            [0] => None,
            [1] => {
                let (s, rest) = SClaim::from_bytes(r.0).ok_or(Reject::Encoding)?;
                r.0 = rest;
                Some(s)
            }
            _ => return Err(Reject::Encoding),
        };
        if !r.0.is_empty() {
            return Err(Reject::Encoding);
        }
        Ok(Claim { positions, acks, sigs, shielded })
    }
}
/// What `request` carries: `b`, `E` and the claim's bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requested {
    pub b: u32,
    pub e: Hash,
    pub posted: Vec<u8>,
}

/// A Winternitz signature's message from its witness items, bottom first
/// (`hash_0, digit_0, hash_1, digit_1, …`): its first `bytes` bytes'
/// digits.
fn signed_message(items: &[&[u8]], bytes: usize) -> Option<Vec<u8>> {
    let digit = |i: usize| -> Option<u8> {
        match items.get(2 * i + 1)? {
            [] => Some(0),
            [d] if *d <= 15 => Some(*d),
            _ => None,
        }
    };
    (0..bytes).map(|k| Some((digit(2 * k)? << 4) | digit(2 * k + 1)?)).collect()
}

/// The checksum digits of a signature on `bytes` bytes (ln-gap's
/// `WotsParams::for_bytes`).
fn checksum_digits(bytes: usize) -> usize {
    let most = 15 * 2 * bytes as u64;
    (1..).find(|n| 16u64.pow(*n) > most).unwrap() as usize
}

/// `request`'s witness (the input spending the contract's funding output,
/// bottom first): the claim in its first [`POSTED_ITEMS`] items, then
/// Alice's signature on `E` (32 bytes), then on `b` (4), each a hash and a
/// digit a digit, below the 2-of-2's two signatures, the script and the
/// control block.
pub fn requested(witness: &[&[u8]]) -> Option<Requested> {
    let e_items = 2 * (64 + checksum_digits(32));
    let b_items = 2 * (8 + checksum_digits(4));
    if witness.len() != POSTED_ITEMS + e_items + b_items + 4 {
        return None;
    }
    let posted = witness[..POSTED_ITEMS].concat();
    let e = signed_message(&witness[POSTED_ITEMS..POSTED_ITEMS + e_items], 32)?;
    let b = signed_message(&witness[POSTED_ITEMS + e_items..POSTED_ITEMS + e_items + b_items], 4)?;
    Some(Requested { b: u32::from_be_bytes(b.try_into().ok()?), e: e.try_into().ok()?, posted })
}

/// What fixes `D`: the deployment's keys, its genesis seal, the work `W`
/// the contract asks on top of a block, its unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms {
    pub sequencer: Hash,
    pub hub: Hash,
    pub genesis: OutPoint,
    pub work: u128,
    pub unit: u64,
}

impl Terms {
    pub fn d(&self) -> Hash {
        contract_id(&deployment_id(&self.sequencer, &self.hub), &self.genesis, self.work, self.unit)
    }
}

/// The first spend of `A*`'s seal output: the transaction (non-witness)
/// in the block of `A*`'s header `at` (from 0, the block after the
/// anchor's), by its path, with the block's coinbase and its path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealSpend {
    pub tx: Vec<u8>,
    pub at: u32,
    pub index: u32,
    pub path: Vec<Hash>,
    pub coinbase: Vec<u8>,
    pub coinbase_path: Vec<Hash>,
}

/// `A*`: the anchored state and its commitment tree's root, its headers
/// on from the anchor's block through `request`'s and on (the contract's
/// work on top of `request`'s), and the first spend of its seal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Last {
    pub state: Anchored,
    pub tree: Hash,
    pub seal: SealSpend,
}

/// A claimed note's opening in `A*`'s tree: the transparent note at its
/// position (none for a shielded note: the claim opens it), and the path
/// from its leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    pub note: Option<TNote>,
    pub path: Vec<Hash>,
}

/// A claimed note, opened at its position: its value, its nullifier, and
/// the key whose signature on `E` makes it hers (its owner, or a shielded
/// owner's exit key).
struct Claimed {
    index: u32,
    shielded: bool,
    value: u64,
    nf: Hash,
    key: Hash,
}

/// Why the claim is false at `A*`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Why {
    /// The leaf at the `which`th note's position isn't it: for a
    /// transparent note, a shielded note's or empty (past the tree's end);
    /// for a shielded one, not the leaf of the claim's opening. The leaf
    /// and its path.
    NotANote { which: u8, leaf: Hash, path: Vec<Hash> },
    /// The `which`th note's owner (a shielded note's exit key) signed none
    /// of the claim's signatures.
    NotHers { which: u8, opening: Opening },
    /// The notes, all opened, are worth less than `b` units.
    TooMuch { openings: Vec<Opening> },
    /// The `which`th note's nullifier is spent at `A*` (its opening in the
    /// spent set: the spender), by a spend that counts.
    Spent { which: u8, opening: Opening, leaf: smt::Opening, counts: Counts },
    /// The `which`th note is locked at `A*`: an output of the spend its
    /// lock names, not acknowledged then, and the claim carries no
    /// acknowledgment of it that holds.
    Locked { which: u8, lock: smt::Opening, acked: smt::Opening, bad: Option<Bad> },
    /// The `which`th note is an output of a spend void at `A*`.
    Voided { which: u8, lock: smt::Opening, void: smt::Opening },
    /// The `which`th note's owner signed a claim of it through another
    /// contract `c'` (of deposit coin `deposit'`, for `b'`).
    Second { which: u8, opening: Opening, other_c: u32, other_deposit: OutPoint, other_b: u32, other: Claim },
}

/// Why the claim is false.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Ground {
    /// The claim's bytes don't parse, aren't well formed, or don't hash to
    /// the `E` she signed.
    Malformed,
    /// At `A*`, shown the last anchor before the cutoff.
    At { last: Last, why: Why },
}

/// The statement's input: the contract (`c`, its deposit coin, the
/// margin, what fixes its `D`), `request` in its block with headers on it
/// carrying the contract's work, and the ground.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HubInput {
    pub c: u32,
    pub deposit: OutPoint,
    pub margin: u32,
    pub terms: Terms,
    pub request: Request,
    pub headers: Vec<[u8; 80]>,
    pub ground: Ground,
}

/// `H(O_D ‖ margin)`, as the journal commits it.
pub fn contract_digest(deposit: &OutPoint, margin: u32) -> Hash {
    let mut h = Sha256::new();
    h.update(b"lichen/hp/contract");
    h.update(deposit.to_bytes());
    h.update(margin.to_be_bytes());
    h.finalize().into()
}

/// The journal `c ‖ D ‖ H(O_D ‖ margin)`, `c` little-endian.
pub fn journal(c: u32, d: &Hash, deposit: &OutPoint, margin: u32) -> [u8; JOURNAL_LEN] {
    let mut j = [0u8; JOURNAL_LEN];
    j[..4].copy_from_slice(&c.to_le_bytes());
    j[4..36].copy_from_slice(d);
    j[36..].copy_from_slice(&contract_digest(deposit, margin));
    j
}

/// The claim posted, if it is one: parsed, well formed, its `E` the one
/// she signed.
fn claim_of(input: &HubInput, r: &Requested) -> Option<Claim> {
    let claim = Claim::from_bytes(&r.posted).ok()?;
    (claim.well_formed() && claim.fingerprint(input.c, &input.deposit, r.b) == r.e).then_some(claim)
}

/// Whether `A*` is the last anchor before the cutoff, with `request` in
/// its headers: the anchor at least `margin` blocks before `request`'s
/// block, which has the contract's work on top; the first spend of the
/// seal output in a block after the cutoff.
fn is_last(last: &Last, request: &Header, margin: u32) -> bool {
    let s = &last.state;
    let Some(r) = s.headers.iter().position(|h| Header(*h).hash() == request.hash()) else { return false };
    let (r, at) = (r as u64, u64::from(last.seal.at));
    let Some(h) = s.headers.get(at as usize) else { return false };
    // A* at least `margin` below request's block (height r + 1 above the
    // anchor's), the spend after r + 1 − margin
    r + 1 >= u64::from(margin)
        && at + 1 + u64::from(margin) > r + 1
        && s.deep(request)
        && btc::in_block(&last.seal.tx, &Header(*h), last.seal.index, &last.seal.path, &last.seal.coinbase, &last.seal.coinbase_path)
        && btc::parse_tx(&last.seal.tx).is_some_and(|t| t.inputs.contains(&s.anchor.seal))
}

/// `key`'s leaf in the spent set of root `set`, by its opening (zero:
/// absent).
fn shows(set: &Hash, key: &Hash, o: &smt::Opening) -> Result<Hash, Reject> {
    if !smt::holds(set, key, &o.leaf, &o.proof) {
        return Err(Reject::PathLength);
    }
    Ok(o.leaf)
}

/// The spent set at `A*`'s chain receipt's height, shown under its root.
fn chain_set(s: &Anchored, c: &ChainSet) -> Result<Hash, Reject> {
    if lichen_validity::state_root(s.chain_height, &c.tree, &c.set) != s.chain_root {
        return Err(Reject::NotAnchored);
    }
    Ok(c.set)
}

/// The leaf at `index` of the tree `root`, by `path`.
fn at(root: &Hash, index: u32, leaf: &Hash, path: &[Hash]) -> Result<(), Reject> {
    if path.len() != TREE_DEPTH || root_from_path(*leaf, index, path) != *root {
        return Err(Reject::PathLength);
    }
    Ok(())
}

/// The hub's statement: check `input` against a chain receipt of
/// `chain_id`; on success, the journal `c ‖ D ‖ H(O_D ‖ margin)`.
pub fn check(input: &HubInput, chain_id: &Hash, verify_chain: &mut dyn FnMut(&[u8]) -> bool) -> Result<[u8; JOURNAL_LEN], Reject> {
    let t = &input.terms;
    if t.unit == 0 {
        return Err(Reject::Encoding);
    }
    let d = t.d();
    // request: the funding's spend, in a block with the contract's work
    let witness = input.request.spending(&input.deposit).ok_or(Reject::Posted)?;
    let header = Header(input.request.header);
    if work_on(&header.hash(), &input.headers).is_none_or(|w| w < t.work) {
        return Err(Reject::Depth);
    }
    let r = requested(&witness).ok_or(Reject::Posted)?;
    let claim = claim_of(input, &r);
    let Ground::At { last, why } = &input.ground else {
        return match claim {
            Some(_) => Err(Reject::Holds),
            None => Ok(journal(input.c, &d, &input.deposit, input.margin)),
        };
    };
    let claim = claim.ok_or(Reject::Posted)?;
    // A*: this deployment's and contract's, anchored, the last
    let s = &last.state;
    if (s.sequencer, s.hub, s.anchor.genesis, s.work, s.unit) != (t.sequencer, t.hub, t.genesis, t.work, t.unit) {
        return Err(Reject::NotAnchored);
    }
    if s.check(&last.tree, chain_id, verify_chain)? != d {
        return Err(Reject::NotAnchored);
    }
    if !is_last(last, &header, input.margin) {
        return Err(Reject::Last);
    }
    let position = |which: u8| claim.position(which as usize).ok_or(Reject::Encoding);
    // the `which`th note at its position: a transparent one by its
    // opening, a shielded one by the claim's
    let opened = |which: u8, o: &Opening| -> Result<Claimed, Reject> {
        let index = position(which)?;
        let (c, leaf) = match (claim.shielded_note(which as usize), &o.note, &claim.shielded) {
            (None, Some(n), _) => (Claimed { index, shielded: false, value: n.value, nf: n.nullifier(), key: n.owner }, n.leaf()),
            (Some(n), None, Some(sc)) => (Claimed { index, shielded: true, value: n.value, nf: sc.nullifier(n), key: sc.x }, sc.leaf(n)),
            _ => return Err(Reject::Encoding),
        };
        at(&last.tree, index, &leaf, &o.path)?;
        Ok(c)
    };
    match why {
        Why::NotANote { which, leaf, path } => {
            at(&last.tree, position(*which)?, leaf, path)?;
            let not = match (claim.shielded_note(*which as usize), &claim.shielded) {
                (Some(n), Some(sc)) => *leaf != sc.leaf(n),
                _ => *leaf == [0; 32] || is_shielded(leaf),
            };
            if !not {
                return Err(Reject::Holds);
            }
        }
        Why::NotHers { which, opening } => {
            let c = opened(*which, opening)?;
            if claim.signed_by(&c.key, &r.e).is_some() {
                return Err(Reject::Holds);
            }
        }
        Why::TooMuch { openings } => {
            if openings.len() != claim.len() {
                return Err(Reject::Encoding);
            }
            let mut total = 0u64;
            for (k, o) in openings.iter().enumerate() {
                total = total.checked_add(opened(k as u8, o)?.value).ok_or(Reject::TooLarge)?;
            }
            if total / t.unit >= u64::from(r.b) {
                return Err(Reject::Holds);
            }
        }
        Why::Spent { which, opening, leaf, counts } => {
            let spender = shows(&s.nullifiers, &opened(*which, opening)?.nf, leaf)?;
            if spender == [0; 32] {
                return Err(Reject::NotSpent);
            }
            match counts {
                Counts::Exit { c } => {
                    if spender != smt::exited(*c) {
                        return Err(Reject::NotSpent);
                    }
                    if *c == input.c {
                        return Err(Reject::Own);
                    }
                }
                Counts::Acked { acked } => {
                    if shows(&s.nullifiers, &ack::acked_key(&spender), acked)? == [0; 32] {
                        return Err(Reject::NotSpent);
                    }
                }
                Counts::Shown { ack: a, pending, void, anchor, chain } => {
                    let ok = a.txid == spender
                        && a.signed()
                        && shows(&s.nullifiers, &ack::tx_key(&spender), pending)? == ack::pending(&a.ak, a.h)
                        && shows(&s.nullifiers, &ack::void_key(&spender), void)? == [0; 32]
                        && shows(&chain_set(s, chain)?, &ack::anchor_key(a.a), anchor)? == a.hist_a;
                    if !ok {
                        return Err(Reject::NotSpent);
                    }
                }
            }
        }
        Why::Locked { which, lock, acked, bad } => {
            let txid = shows(&s.nullifiers, &ack::lock_key(position(*which)?), lock)?;
            if txid == [0; 32] || shows(&s.nullifiers, &ack::acked_key(&txid), acked)? != [0; 32] {
                return Err(Reject::Holds);
            }
            // an acknowledgment carried must be shown not to hold
            if let Some(a) = claim.acks.iter().find(|a| a.txid == txid) {
                let fails = match bad {
                    None => false,
                    Some(Bad::Signature) => !a.signed(),
                    Some(Bad::Pending(o)) => shows(&s.nullifiers, &ack::tx_key(&txid), o)? != ack::pending(&a.ak, a.h),
                    Some(Bad::Anchor(o, chain)) => shows(&chain_set(s, chain)?, &ack::anchor_key(a.a), o)? != a.hist_a,
                };
                if !fails {
                    return Err(Reject::Holds);
                }
            }
        }
        Why::Voided { which, lock, void } => {
            let txid = shows(&s.nullifiers, &ack::lock_key(position(*which)?), lock)?;
            if txid == [0; 32] || shows(&s.nullifiers, &ack::void_key(&txid), void)? == [0; 32] {
                return Err(Reject::Holds);
            }
        }
        Why::Second { which, opening, other_c, other_deposit, other_b, other } => {
            let c = opened(*which, opening)?;
            if *other_c == input.c || !other.well_formed() || !other.claims(c.index, c.shielded) {
                return Err(Reject::NotSpent);
            }
            if other.signed_by(&c.key, &other.fingerprint(*other_c, other_deposit, *other_b)).is_none() {
                return Err(Reject::NotYours);
            }
        }
    }
    Ok(journal(input.c, &d, &input.deposit, input.margin))
}

// ----- the encoding, the guest's input (big-endian, as the other statements') -----

fn put_opening(w: &mut crate::W, o: &Opening) {
    match &o.note {
        Some(n) => {
            w.put(&[1]);
            w.put(&n.owner);
            w.put(&n.value.to_be_bytes());
            w.put(&n.memo.to_be_bytes());
            w.put(&n.rho);
        }
        None => w.put(&[0]),
    }
    w.list(&o.path);
}

fn put_set(w: &mut crate::W, o: &smt::Opening) {
    w.put(&o.to_bytes());
}

fn read_set(r: &mut crate::R) -> Result<smt::Opening, Reject> {
    let (o, rest) = smt::Opening::from_bytes(r.0).ok_or(Reject::Encoding)?;
    r.0 = rest;
    Ok(o)
}

fn read_opening(r: &mut crate::R) -> Result<Opening, Reject> {
    let note = match r.take()? {
        [0] => None,
        [1] => Some(TNote { owner: r.take()?, value: u64::from_be_bytes(r.take()?), memo: u32::from_be_bytes(r.take()?), rho: r.take()? }),
        _ => return Err(Reject::Encoding),
    };
    Ok(Opening { note, path: r.list()? })
}

impl HubInput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = crate::W(Vec::new());
        w.put(&self.c.to_be_bytes());
        w.put(&self.deposit.to_bytes());
        w.put(&self.margin.to_be_bytes());
        let t = &self.terms;
        w.put(&t.sequencer);
        w.put(&t.hub);
        w.put(&t.genesis.to_bytes());
        w.put(&t.work.to_be_bytes());
        w.put(&t.unit.to_be_bytes());
        self.request.write(&mut w);
        w.list(&self.headers);
        let (last, why) = match &self.ground {
            Ground::Malformed => {
                w.put(&[0]);
                return w.0;
            }
            Ground::At { last, why } => (last, why),
        };
        w.put(&[1]);
        last.state.write(&mut w);
        w.put(&last.tree);
        let s = &last.seal;
        w.bytes(&s.tx);
        w.put(&s.at.to_be_bytes());
        w.put(&s.index.to_be_bytes());
        w.list(&s.path);
        w.bytes(&s.coinbase);
        w.list(&s.coinbase_path);
        match why {
            Why::NotANote { which, leaf, path } => {
                w.put(&[0, *which]);
                w.put(leaf);
                w.list(path);
            }
            Why::NotHers { which, opening } => {
                w.put(&[1, *which]);
                put_opening(&mut w, opening);
            }
            Why::TooMuch { openings } => {
                w.put(&[2, openings.len() as u8]);
                for o in openings {
                    put_opening(&mut w, o);
                }
            }
            Why::Spent { which, opening, leaf, counts } => {
                w.put(&[3, *which]);
                put_opening(&mut w, opening);
                put_set(&mut w, leaf);
                match counts {
                    Counts::Exit { c } => {
                        w.put(&[0]);
                        w.put(&c.to_be_bytes());
                    }
                    Counts::Acked { acked } => {
                        w.put(&[1]);
                        put_set(&mut w, acked);
                    }
                    Counts::Shown { ack: a, pending, void, anchor, chain } => {
                        w.put(&[2]);
                        w.put(&a.to_bytes());
                        put_set(&mut w, pending);
                        put_set(&mut w, void);
                        put_set(&mut w, anchor);
                        w.put(&chain.tree);
                        w.put(&chain.set);
                    }
                }
            }
            Why::Locked { which, lock, acked, bad } => {
                w.put(&[5, *which]);
                put_set(&mut w, lock);
                put_set(&mut w, acked);
                match bad {
                    None => w.put(&[0]),
                    Some(Bad::Signature) => w.put(&[1]),
                    Some(Bad::Pending(o)) => {
                        w.put(&[2]);
                        put_set(&mut w, o);
                    }
                    Some(Bad::Anchor(o, chain)) => {
                        w.put(&[3]);
                        put_set(&mut w, o);
                        w.put(&chain.tree);
                        w.put(&chain.set);
                    }
                }
            }
            Why::Voided { which, lock, void } => {
                w.put(&[6, *which]);
                put_set(&mut w, lock);
                put_set(&mut w, void);
            }
            Why::Second { which, opening, other_c, other_deposit, other_b, other } => {
                w.put(&[4, *which]);
                put_opening(&mut w, opening);
                w.put(&other_c.to_be_bytes());
                w.put(&other_deposit.to_bytes());
                w.put(&other_b.to_be_bytes());
                w.bytes(&other.to_bytes());
            }
        }
        w.0
    }

    pub fn from_bytes(b: &[u8]) -> Result<HubInput, Reject> {
        let mut r = crate::R(b);
        let (c, deposit, margin) = (u32::from_be_bytes(r.take()?), OutPoint::from_bytes(&r.take()?), u32::from_be_bytes(r.take()?));
        let terms = Terms { sequencer: r.take()?, hub: r.take()?, genesis: OutPoint::from_bytes(&r.take()?), work: u128::from_be_bytes(r.take()?), unit: u64::from_be_bytes(r.take()?) };
        let request = Request::read(&mut r)?;
        let headers = r.list()?;
        let ground = match r.take()? {
            [0] => Ground::Malformed,
            [1] => {
                let state = Anchored::read(&mut r)?;
                let tree = r.take()?;
                let seal = SealSpend { tx: r.bytes()?, at: u32::from_be_bytes(r.take()?), index: u32::from_be_bytes(r.take()?), path: r.list()?, coinbase: r.bytes()?, coinbase_path: r.list()? };
                let [kind, which] = r.take()?;
                let why = match kind {
                    0 => Why::NotANote { which, leaf: r.take()?, path: r.list()? },
                    1 => Why::NotHers { which, opening: read_opening(&mut r)? },
                    2 => Why::TooMuch { openings: (0..which).map(|_| read_opening(&mut r)).collect::<Result<_, _>>()? },
                    3 => {
                        let opening = read_opening(&mut r)?;
                        let leaf = read_set(&mut r)?;
                        let counts = match r.take()? {
                            [0] => Counts::Exit { c: u32::from_be_bytes(r.take()?) },
                            [1] => Counts::Acked { acked: read_set(&mut r)? },
                            [2] => Counts::Shown { ack: Ack::from_bytes(&r.take()?), pending: read_set(&mut r)?, void: read_set(&mut r)?, anchor: read_set(&mut r)?, chain: ChainSet { tree: r.take()?, set: r.take()? } },
                            _ => return Err(Reject::Encoding),
                        };
                        Why::Spent { which, opening, leaf, counts }
                    }
                    5 => {
                        let (lock, acked) = (read_set(&mut r)?, read_set(&mut r)?);
                        let bad = match r.take()? {
                            [0] => None,
                            [1] => Some(Bad::Signature),
                            [2] => Some(Bad::Pending(read_set(&mut r)?)),
                            [3] => Some(Bad::Anchor(read_set(&mut r)?, ChainSet { tree: r.take()?, set: r.take()? })),
                            _ => return Err(Reject::Encoding),
                        };
                        Why::Locked { which, lock, acked, bad }
                    }
                    6 => Why::Voided { which, lock: read_set(&mut r)?, void: read_set(&mut r)? },
                    4 => {
                        let opening = read_opening(&mut r)?;
                        let (other_c, other_deposit, other_b) = (u32::from_be_bytes(r.take()?), OutPoint::from_bytes(&r.take()?), u32::from_be_bytes(r.take()?));
                        Why::Second { which, opening, other_c, other_deposit, other_b, other: Claim::from_bytes(&r.bytes()?)? }
                    }
                    _ => return Err(Reject::Encoding),
                };
                Ground::At { last: Last { state, tree, seal }, why }
            }
            _ => return Err(Reject::Encoding),
        };
        if !r.0.is_empty() {
            return Err(Reject::Encoding);
        }
        Ok(HubInput { c, deposit, margin, terms, request, headers, ground })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::tests::{block_with, headers_on, key, request_on, xonly};
    use k256::schnorr::SigningKey;
    use lichen_validity::btc::sha256d;
    use lichen_validity::{state_root, AnchorState};
    use std::vec;

    fn scriptnum(d: u8) -> Vec<u8> {
        if d == 0 {
            vec![]
        } else {
            vec![d]
        }
    }

    /// A Winternitz signature's witness items on `msg` (hashes faked:
    /// only the digits are read), bottom first.
    fn wots_items(msg: &[u8]) -> Vec<Vec<u8>> {
        let mut digits: Vec<u8> = msg.iter().flat_map(|b| [b >> 4, b & 0xf]).collect();
        let n = checksum_digits(msg.len());
        let mut sum: u32 = digits.iter().map(|d| 15 - u32::from(*d)).sum();
        let at = digits.len();
        digits.resize(at + n, 0);
        for x in digits[at..].iter_mut().rev() {
            *x = (sum % 16) as u8;
            sum /= 16;
        }
        digits.iter().flat_map(|d| [vec![0x11; 20], scriptnum(*d)]).collect()
    }

    /// `request`'s witness for `claim` of `b` with `E` `e`.
    fn witness(posted: &[u8], e: &Hash, b: u32) -> Vec<Vec<u8>> {
        let mut w: Vec<Vec<u8>> = posted_items(posted).unwrap().into_iter().map(<[u8]>::to_vec).collect();
        w.extend(wots_items(e));
        w.extend(wots_items(&b.to_be_bytes()));
        w.extend([vec![1; 64], vec![2; 64], vec![0x51], vec![0xc0; 33]]);
        w
    }

    /// A transaction (non-witness) spending `op`.
    fn spend_of(op: &OutPoint) -> Vec<u8> {
        let mut t = vec![2, 0, 0, 0, 1];
        t.extend_from_slice(&op.to_bytes());
        t.extend_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 1]);
        t.extend_from_slice(&900u64.to_le_bytes());
        t.extend_from_slice(&[1, 0x51, 0, 0, 0, 0]);
        t
    }

    struct World {
        alice: SigningKey,
        deposit: OutPoint,
        note: TNote,
        input: HubInput,
        id: Hash,
    }

    const MARGIN: u32 = 2;

    fn alices_note() -> TNote {
        TNote { owner: xonly(&key(3)), value: 600, memo: 0, rho: [7; 32] }
    }

    /// Alice's claim of position 0 for `b` units of 100, `leaf` alone at
    /// position 0 in A*'s tree (height 3); `A*` anchored in block [9; 32],
    /// ten headers on it; `request` in the third, the seal spent in the
    /// fourth; `f` to change the claim before it is posted.
    fn world_with(b: u32, leaf: Hash, mut f: impl FnMut(&mut Claim)) -> World {
        let (seq, hub, alice) = (key(1), key(2), key(3));
        let deposit = OutPoint { txid: [0xd0; 32], vout: 1 };
        let c = 1007;
        let mut claim = Claim { positions: vec![0], acks: vec![], sigs: vec![], shielded: None };
        let e = claim.fingerprint(c, &deposit, b);
        claim.sigs = vec![alice.sign_raw(&signed_digest(&e), &[0; 32]).unwrap().to_bytes()];
        f(&mut claim);
        let e = claim.fingerprint(c, &deposit, b);
        let tree = root_from_path(leaf, 0, &empties());
        let nullifiers = smt::root(&[]);
        let root = state_root(3, &tree, &nullifiers);
        let signature = seq.sign_raw(&root, &[0; 32]).unwrap().to_bytes();
        let genesis = OutPoint { txid: [3; 32], vout: 1 };
        let seal = OutPoint { txid: [4; 32], vout: 0 };
        let anchor = AnchorState { genesis, sequencer: xonly(&seq), seal, height: 3, root, block: [9; 32] };
        // headers 0, 1 on the anchor; request's block third; the seal's
        // spend fourth; then on
        let mut headers = headers_on(&anchor.block, 2);
        let w = witness(&claim.to_bytes(), &e, b);
        let items: Vec<&[u8]> = w.iter().map(Vec::as_slice).collect();
        let (rh, request) = request_on(&sha256d(headers.last().unwrap()), &deposit, &items);
        headers.push(rh);
        let bare = spend_of(&seal);
        let (sh, spend) = block_with(&sha256d(&rh), (bare.clone(), sha256d(&bare)));
        headers.push(sh);
        headers.extend(headers_on(&sha256d(&sh), 10));
        let work = 10 * btc::work(0x207fffff);
        let state = Anchored { height: 3, nullifiers, signature, sequencer: xonly(&seq), hub: xonly(&hub), chain_height: 5, chain_root: [8; 32], recent: [6; 32], hist: [10; 32], anchor, headers: headers.clone(), work, unit: 100 };
        // the txid tree's path: the coinbase's id beside it
        let path = vec![sha256d(&spend.coinbase)];
        let last = Last { state, tree, seal: SealSpend { tx: bare, at: 3, index: spend.index, path, coinbase: spend.coinbase, coinbase_path: spend.coinbase_path } };
        let terms = Terms { sequencer: xonly(&seq), hub: xonly(&hub), genesis, work, unit: 100 };
        let input = HubInput { c, deposit, margin: MARGIN, terms, request, headers: headers[3..].to_vec(), ground: Ground::At { last, why: Why::TooMuch { openings: vec![] } } };
        World { alice, deposit, note: alices_note(), input, id: [0xc4; 32] }
    }

    fn world(b: u32, f: impl FnMut(&mut Claim)) -> World {
        world_with(b, alices_note().leaf(), f)
    }

    fn empties() -> Vec<Hash> {
        lichen_validity::tree_empties()[..TREE_DEPTH].to_vec()
    }

    /// Position 1's path in A*'s tree: the note at 0 beside it.
    fn past_end() -> Vec<Hash> {
        let mut p = empties();
        p[0] = alices_note().leaf();
        p
    }

    fn last(w: &World) -> Last {
        match &w.input.ground {
            Ground::At { last, .. } => last.clone(),
            _ => unreachable!(),
        }
    }

    fn opening(w: &World) -> Opening {
        Opening { note: Some(w.note), path: empties() }
    }

    fn check_ground(w: &World, ground: Ground) -> Result<[u8; JOURNAL_LEN], Reject> {
        let mut i = w.input.clone();
        i.ground = ground;
        check(&i, &w.id, &mut |_| true)
    }

    fn check_why(w: &World, why: Why) -> Result<[u8; JOURNAL_LEN], Reject> {
        check_ground(w, Ground::At { last: last(w), why })
    }

    fn claim_of(w: &World) -> Claim {
        Claim::from_bytes(&requested(&w.input.request.spending(&w.deposit).unwrap()).unwrap().posted).unwrap()
    }

    #[test]
    fn the_request_and_the_claim_read_back() {
        let w = world(5, |_| {});
        let wit = w.input.request.spending(&w.deposit).unwrap();
        let r = requested(&wit).unwrap();
        assert_eq!(r.b, 5);
        let claim = Claim::from_bytes(&r.posted).unwrap();
        assert!(claim.well_formed());
        assert_eq!(claim.fingerprint(w.input.c, &w.deposit, 5), r.e);
        assert_eq!(claim.signed_by(&xonly(&w.alice), &r.e), Some(claim.sigs[0]));
        let (notes, sigs) = claim.record(&[w.note], &r.e).unwrap();
        assert_eq!((notes, sigs), (vec![(w.note, 0)], claim.sigs.clone()), "the exit record's notes and signatures");
        assert_eq!(lichen_validity::exit::fingerprint(w.input.c, &w.deposit, 5, &[0], &[], None), r.e, "the exit record's E is the claim's");
        assert_eq!(Claim::from_bytes(&claim.to_bytes()[1..]), Err(Reject::Encoding));
    }

    #[test]
    fn a_claim_is_well_formed() {
        let sig = [0; 64];
        let c = |positions: Vec<u32>, n: usize| Claim { positions, acks: vec![], sigs: vec![sig; n], shielded: None };
        assert!(c(vec![0, 5], 1).well_formed());
        assert!(c((0..MAX_NOTES as u32).collect(), 1).well_formed(), "the most notes");
        assert!(!c((0..=MAX_NOTES as u32).collect(), 1).well_formed(), "too many notes");
        assert!(!c(vec![], 1).well_formed(), "no notes");
        assert!(!c(vec![5, 5], 1).well_formed(), "a position twice");
        assert!(!c(vec![5, 0], 1).well_formed(), "positions not increasing");
        assert!(!c(vec![1 << TREE_DEPTH], 1).well_formed(), "past the tree's range");
        assert!(!c(vec![0], 0).well_formed(), "no signature");
        assert!(!c(vec![0], 2).well_formed(), "more signatures than notes");
        // the most notes and signatures fit request's witness
        assert!(posted_items(&c((0..MAX_NOTES as u32).collect(), 14).to_bytes()).is_some());
    }

    #[test]
    fn a_true_claim_has_no_ground() {
        let w = world(5, |_| {});
        assert_eq!(check_ground(&w, Ground::Malformed), Err(Reject::Holds));
        assert_eq!(check_why(&w, Why::NotHers { which: 0, opening: opening(&w) }), Err(Reject::Holds));
        assert_eq!(check_why(&w, Why::TooMuch { openings: vec![opening(&w)] }), Err(Reject::Holds));
        // the note's own leaf: a transparent note
        assert_eq!(check_why(&w, Why::NotANote { which: 0, leaf: w.note.leaf(), path: empties() }), Err(Reject::Holds));
        // unspent, unlocked, not void
        let nf = w.note.nullifier();
        let absent = |k: &Hash| smt::Opening { leaf: [0; 32], proof: smt::proof(&[], k) };
        assert_eq!(check_why(&w, Why::Spent { which: 0, opening: opening(&w), leaf: absent(&nf), counts: Counts::Exit { c: 9 } }), Err(Reject::NotSpent));
        assert_eq!(check_why(&w, Why::Locked { which: 0, lock: absent(&ack::lock_key(0)), acked: absent(&ack::acked_key(&[0; 32])), bad: None }), Err(Reject::Holds));
    }

    #[test]
    fn an_opening_must_be_at_its_position() {
        let w = world(7, |_| {});
        // another note than the one there
        let mut o = opening(&w);
        o.note.as_mut().unwrap().value = 700;
        assert_eq!(check_why(&w, Why::TooMuch { openings: vec![o] }), Err(Reject::PathLength));
        // a short path
        let mut o = opening(&w);
        o.path.pop();
        assert_eq!(check_why(&w, Why::NotHers { which: 0, opening: o }), Err(Reject::PathLength));
        // not every note opened
        assert_eq!(check_why(&w, Why::TooMuch { openings: vec![] }), Err(Reject::Encoding));
        // a position the claim hasn't
        assert_eq!(check_why(&w, Why::NotHers { which: 1, opening: opening(&w) }), Err(Reject::Encoding));
    }

    #[test]
    fn the_grounds_of_a_false_claim() {
        // too much: 600 is 6 units, not 7
        let w = world(7, |_| {});
        let j = check_why(&w, Why::TooMuch { openings: vec![opening(&w)] }).unwrap();
        assert_eq!(j, journal(w.input.c, &w.input.terms.d(), &w.deposit, MARGIN));
        // not hers: signed by another key
        let w = world(5, |c| c.sigs = vec![key(9).sign_raw(&[0; 32], &[0; 32]).unwrap().to_bytes()]);
        assert!(check_why(&w, Why::NotHers { which: 0, opening: opening(&w) }).is_ok());
        // malformed: not hashing to the E signed
        let mut w = world(5, |_| {});
        let wit = witness(&Claim { positions: vec![], acks: vec![], sigs: vec![], shielded: None }.to_bytes(), &[0; 32], 5);
        let items: Vec<&[u8]> = wit.iter().map(Vec::as_slice).collect();
        let prev = Header(w.input.request.header).prev();
        let (rh, req) = request_on(&prev, &w.deposit, &items);
        w.input.request = req;
        w.input.headers = headers_on(&sha256d(&rh), 10);
        assert!(check_ground(&w, Ground::Malformed).is_ok());
        // not a note: a position past the tree's end
        let w = world(5, |c| c.positions[0] = 1);
        assert!(check_why(&w, Why::NotANote { which: 0, leaf: [0; 32], path: past_end() }).is_ok());
        // not a note: a shielded note's leaf
        let sleaf = lichen_shielded::s_leaf(&[0x55; 32]);
        let w = world_with(5, sleaf, |_| {});
        assert!(check_why(&w, Why::NotANote { which: 0, leaf: sleaf, path: empties() }).is_ok());
        // a transparent leaf with the shielded bit cleared is a note
        let w = world_with(5, lichen_shielded::t_leaf(&[0xd5; 32]), |_| {});
        assert_eq!(check_why(&w, Why::NotANote { which: 0, leaf: lichen_shielded::t_leaf(&[0xd5; 32]), path: empties() }), Err(Reject::Holds));
    }

    #[test]
    fn a_shielded_claim() {
        let xk = key(5);
        let sc = SClaim { auth: [0xa1; 32], nk: [0xa2; 32], x: xonly(&xk), notes: vec![SNoteClaim { index: 0, value: 600, rho: [0x71; 32], trap: [0x72; 32] }] };
        let leaf = sc.leaf(&sc.notes[0]);
        let deposit = OutPoint { txid: [0xd0; 32], vout: 1 };
        // Alice's claim of the shielded note at 0 alone, signed by `signer`
        let mk = |b: u32, sc: &SClaim, signer: &SigningKey| {
            world_with(b, leaf, |c| {
                c.positions = vec![];
                c.shielded = Some(sc.clone());
                let e = c.fingerprint(1007, &deposit, b);
                c.sigs = vec![signer.sign_raw(&signed_digest(&e), &[0; 32]).unwrap().to_bytes()];
            })
        };
        let so = || Opening { note: None, path: empties() };
        // true: no ground
        let w = mk(5, &sc, &xk);
        let claim = claim_of(&w);
        assert!(claim.well_formed() && claim.len() == 1 && claim.position(0) == Some(0));
        assert_eq!(Claim::from_bytes(&claim.to_bytes()).unwrap(), claim);
        assert_eq!(check_why(&w, Why::NotHers { which: 0, opening: so() }), Err(Reject::Holds));
        assert_eq!(check_why(&w, Why::TooMuch { openings: vec![so()] }), Err(Reject::Holds));
        assert_eq!(check_why(&w, Why::NotANote { which: 0, leaf, path: empties() }), Err(Reject::Holds));
        let absent = |k: &Hash| smt::Opening { leaf: [0; 32], proof: smt::proof(&[], k) };
        assert_eq!(check_why(&w, Why::Spent { which: 0, opening: so(), leaf: absent(&sc.nullifier(&sc.notes[0])), counts: Counts::Exit { c: 9 } }), Err(Reject::NotSpent));
        // a transparent opening for a shielded note: not the claim's
        assert_eq!(check_why(&w, Why::NotHers { which: 0, opening: Opening { note: Some(alices_note()), path: empties() } }), Err(Reject::Encoding));
        // too much: 600 is 6 units, not 7
        assert!(check_why(&mk(7, &sc, &xk), Why::TooMuch { openings: vec![so()] }).is_ok());
        // not hers: signed by another key than the exit key
        assert!(check_why(&mk(5, &sc, &key(9)), Why::NotHers { which: 0, opening: so() }).is_ok());
        // not the note: the claim's opening (another trapdoor) isn't the
        // leaf there, nor do other keys open it
        let mut other = sc.clone();
        other.notes[0].trap = [0x73; 32];
        let w = mk(5, &other, &xk);
        assert!(check_why(&w, Why::NotANote { which: 0, leaf, path: empties() }).is_ok());
        assert_eq!(check_why(&w, Why::NotHers { which: 0, opening: so() }), Err(Reject::PathLength));
        let mut other = sc.clone();
        other.nk = [0xa3; 32];
        assert!(check_why(&mk(5, &other, &xk), Why::NotANote { which: 0, leaf, path: empties() }).is_ok());
        // how many fit request's witness: 13 shielded notes and a signature
        let many = |k: u32| Claim { positions: vec![], acks: vec![], sigs: vec![[0; 64]], shielded: Some(SClaim { notes: (0..k).map(|i| SNoteClaim { index: i, ..sc.notes[0] }).collect(), ..sc.clone() }) };
        assert!(posted_items(&many(13).to_bytes()).is_some() && posted_items(&many(14).to_bytes()).is_none());
    }

    #[test]
    fn a_ground_needs_the_last_anchor() {
        let w = world(5, |c| c.positions[0] = 1);
        let why = Why::NotANote { which: 0, leaf: [0; 32], path: past_end() };
        let ok = |l: Last| check_ground(&w, Ground::At { last: l, why: why.clone() });
        assert!(ok(last(&w)).is_ok());
        // a margin request's block is too close to the anchor for
        let mut far = w.input.clone();
        far.margin = 4;
        far.ground = Ground::At { last: last(&w), why: why.clone() };
        assert_eq!(check(&far, &w.id, &mut |_| true), Err(Reject::Last));
        // a margin of one block: the spend, a block after request's, still
        // after the cutoff
        let mut l = last(&w);
        let mut near = w.input.clone();
        near.margin = 1;
        near.ground = Ground::At { last: l.clone(), why: why.clone() };
        assert!(check(&near, &w.id, &mut |_| true).is_ok(), "the spend one block after request's");
        // the spend shown in another block than its own
        l.seal.at = 4;
        assert_eq!(ok(l.clone()), Err(Reject::Last));
        // a spend of another outpoint
        let mut l = last(&w);
        l.state.anchor.seal.vout = 1;
        assert!(ok(l).is_err());
        // no chain receipt
        let mut i = w.input.clone();
        i.ground = Ground::At { last: last(&w), why };
        assert_eq!(check(&i, &w.id, &mut |_| false), Err(Reject::Chain));
    }

    /// `w` with A*'s spent set `keys`, signed and anchored again; each
    /// key's opening in it.
    fn with_set(w: &mut World, keys: &[(Hash, Hash)]) -> impl Fn(&Hash) -> smt::Opening {
        let mut keys = keys.to_vec();
        keys.sort();
        let root = smt::root(&keys);
        let Ground::At { last, .. } = &mut w.input.ground else { unreachable!() };
        let st = &mut last.state;
        st.nullifiers = root;
        let r = state_root(3, &last.tree, &root);
        st.signature = key(1).sign_raw(&r, &[0; 32]).unwrap().to_bytes();
        st.anchor.root = r;
        move |k: &Hash| smt::Opening { leaf: keys.iter().find(|(x, _)| x == k).map_or([0; 32], |e| e.1), proof: smt::proof(&keys, k) }
    }

    /// An acknowledgment of `txid` (sealed at 2) by the key `k`, naming
    /// anchor 3 of history [10; 32].
    fn ack_of(txid: Hash, k: &SigningKey) -> Ack {
        let (a, hist_a) = (3, [10; 32]);
        let sig = k.sign_raw(&ack::digest(&txid, a, &hist_a), &[0; 32]).unwrap().to_bytes();
        Ack { txid, ak: xonly(k), h: 2, a, hist_a, sig }
    }

    /// The chain receipt's state with anchor 3 applied (or not): A*'s
    /// chain root made its root.
    fn chain_with(w: &mut World, anchored: bool) -> (ChainSet, smt::Opening) {
        let k = ack::anchor_key(3);
        let keys = if anchored { vec![(k, [10; 32])] } else { vec![] };
        let set = smt::root(&keys);
        let tree = [0x77; 32];
        let Ground::At { last, .. } = &mut w.input.ground else { unreachable!() };
        last.state.chain_root = state_root(last.state.chain_height, &tree, &set);
        (ChainSet { tree, set }, smt::Opening { leaf: if anchored { [10; 32] } else { [0; 32] }, proof: smt::proof(&keys, &k) })
    }

    #[test]
    fn a_spend_and_what_doesnt_count() {
        let nf = alices_note().nullifier();
        let txid = [0x7a; 32];
        // another contract's exit record: a spend; this contract's: not
        let mut w = world(5, |_| {});
        let o = with_set(&mut w, &[(nf, smt::exited(1008))]);
        assert!(check_why(&w, Why::Spent { which: 0, opening: opening(&w), leaf: o(&nf), counts: Counts::Exit { c: 1008 } }).is_ok());
        let o = with_set(&mut w, &[(nf, smt::exited(1007))]);
        assert_eq!(check_why(&w, Why::Spent { which: 0, opening: opening(&w), leaf: o(&nf), counts: Counts::Exit { c: 1007 } }), Err(Reject::Own));
        // a user's spend acknowledged at A*: counts; pending: not by itself
        let o = with_set(&mut w, &[(nf, txid), (ack::acked_key(&txid), ack::acked(3))]);
        assert!(check_why(&w, Why::Spent { which: 0, opening: opening(&w), leaf: o(&nf), counts: Counts::Acked { acked: o(&ack::acked_key(&txid)) } }).is_ok());
        let ak = key(8);
        let o = with_set(&mut w, &[(nf, txid), (ack::tx_key(&txid), ack::pending(&xonly(&ak), 2))]);
        assert_eq!(check_why(&w, Why::Spent { which: 0, opening: opening(&w), leaf: o(&nf), counts: Counts::Acked { acked: o(&ack::acked_key(&txid)) } }), Err(Reject::NotSpent));
        // pending, with an acknowledgment shown whose anchor is applied
        let (chain, anchor) = chain_with(&mut w, true);
        let shown = |a: Ack, anchor: smt::Opening, chain: ChainSet| Counts::Shown { ack: a, pending: o(&ack::tx_key(&txid)), void: o(&ack::void_key(&txid)), anchor, chain };
        assert!(check_why(&w, Why::Spent { which: 0, opening: opening(&w), leaf: o(&nf), counts: shown(ack_of(txid, &ak), anchor.clone(), chain) }).is_ok());
        // by another key than the spend's, or of another spend
        assert_eq!(check_why(&w, Why::Spent { which: 0, opening: opening(&w), leaf: o(&nf), counts: shown(ack_of(txid, &key(9)), anchor.clone(), chain) }), Err(Reject::NotSpent));
        assert_eq!(check_why(&w, Why::Spent { which: 0, opening: opening(&w), leaf: o(&nf), counts: shown(ack_of([0x7b; 32], &ak), anchor.clone(), chain) }), Err(Reject::NotSpent));
        // its anchor not applied by A*'s own record
        let (chain, anchor) = chain_with(&mut w, false);
        assert_eq!(check_why(&w, Why::Spent { which: 0, opening: opening(&w), leaf: o(&nf), counts: shown(ack_of(txid, &ak), anchor, chain) }), Err(Reject::NotSpent));
        // void: doesn't count
        let o = with_set(&mut w, &[(nf, txid), (ack::tx_key(&txid), ack::pending(&xonly(&ak), 2)), (ack::void_key(&txid), ack::void())]);
        let (chain, anchor) = chain_with(&mut w, true);
        let counts = Counts::Shown { ack: ack_of(txid, &ak), pending: o(&ack::tx_key(&txid)), void: o(&ack::void_key(&txid)), anchor, chain };
        assert_eq!(check_why(&w, Why::Spent { which: 0, opening: opening(&w), leaf: o(&nf), counts }), Err(Reject::NotSpent));
    }

    #[test]
    fn a_locked_note_and_a_void_one() {
        let txid = [0x7a; 32];
        let ak = key(8);
        let pend = (ack::tx_key(&txid), ack::pending(&xonly(&ak), 2));
        // locked at A*, no acknowledgment carried
        let mut w = world(5, |_| {});
        let o = with_set(&mut w, &[(ack::lock_key(0), txid), pend]);
        let locked = |o: &dyn Fn(&Hash) -> smt::Opening, bad: Option<Bad>| Why::Locked { which: 0, lock: o(&ack::lock_key(0)), acked: o(&ack::acked_key(&txid)), bad };
        assert!(check_why(&w, locked(&o, None)).is_ok());
        // acknowledged at A*: not locked
        let o2 = with_set(&mut w, &[(ack::lock_key(0), txid), pend, (ack::acked_key(&txid), ack::acked(3))]);
        assert_eq!(check_why(&w, locked(&o2, None)), Err(Reject::Holds));
        // carrying an acknowledgment that holds: not locked
        let carrying = |a: Ack| {
            let mut w = world(5, |c| c.acks = vec![a]);
            let o = with_set(&mut w, &[(ack::lock_key(0), txid), pend]);
            let (chain, anchor) = chain_with(&mut w, true);
            (w, o, chain, anchor)
        };
        let (w, o, chain, anchor) = carrying(ack_of(txid, &ak));
        assert_eq!(check_why(&w, locked(&o, None)), Err(Reject::Holds));
        assert_eq!(check_why(&w, locked(&o, Some(Bad::Signature))), Err(Reject::Holds));
        assert_eq!(check_why(&w, locked(&o, Some(Bad::Pending(o(&ack::tx_key(&txid)))))), Err(Reject::Holds));
        assert_eq!(check_why(&w, locked(&o, Some(Bad::Anchor(anchor, chain)))), Err(Reject::Holds));
        // one that doesn't: another key's, or its anchor not applied
        let (w, o, _, _) = carrying(ack_of(txid, &key(9)));
        assert_eq!(check_why(&w, locked(&o, Some(Bad::Pending(o(&ack::tx_key(&txid)))))).map(|_| ()), Ok(()));
        let mut forged = ack_of(txid, &ak);
        forged.sig[0] ^= 1;
        let (w, o, _, _) = carrying(forged);
        assert!(check_why(&w, locked(&o, Some(Bad::Signature))).is_ok());
        let (mut w, o, _, _) = carrying(ack_of(txid, &ak));
        let (chain, anchor) = chain_with(&mut w, false);
        assert!(check_why(&w, locked(&o, Some(Bad::Anchor(anchor, chain)))).is_ok());
        // void at A*
        let mut w = world(5, |_| {});
        let o = with_set(&mut w, &[(ack::lock_key(0), txid), pend, (ack::void_key(&txid), ack::void())]);
        assert!(check_why(&w, Why::Voided { which: 0, lock: o(&ack::lock_key(0)), void: o(&ack::void_key(&txid)) }).is_ok());
        let o = with_set(&mut w, &[(ack::lock_key(0), txid), pend]);
        assert_eq!(check_why(&w, Why::Voided { which: 0, lock: o(&ack::lock_key(0)), void: o(&ack::void_key(&txid)) }), Err(Reject::Holds));
    }

    #[test]
    fn the_input_round_trips() {
        let w = world(5, |_| {});
        let proof = smt::proof(&[], &[1; 32]);
        let other = Claim { positions: vec![0, 3], acks: vec![ack_of([1; 32], &key(8))], sigs: vec![[5; 64]], shielded: None };
        for ground in [
            Why::NotANote { which: 0, leaf: [1; 32], path: empties() },
            Why::NotHers { which: 0, opening: opening(&w) },
            Why::TooMuch { openings: vec![opening(&w), opening(&w)] },
            Why::Spent { which: 0, opening: opening(&w), leaf: smt::Opening { leaf: [1; 32], proof: proof.clone() }, counts: Counts::Exit { c: 9 } },
            Why::Spent { which: 0, opening: opening(&w), leaf: smt::Opening::default(), counts: Counts::Shown { ack: ack_of([2; 32], &key(8)), pending: smt::Opening::default(), void: smt::Opening::default(), anchor: smt::Opening::default(), chain: ChainSet { tree: [3; 32], set: [4; 32] } } },
            Why::Locked { which: 0, lock: smt::Opening::default(), acked: smt::Opening::default(), bad: Some(Bad::Anchor(smt::Opening::default(), ChainSet { tree: [3; 32], set: [4; 32] })) },
            Why::Voided { which: 0, lock: smt::Opening::default(), void: smt::Opening { leaf: [5; 32], proof } },
            Why::Second { which: 0, opening: opening(&w), other_c: 8, other_deposit: OutPoint { txid: [1; 32], vout: 2 }, other_b: 3, other },
        ]
        .into_iter()
        .map(|why| Ground::At { last: last(&w), why })
        .chain([Ground::Malformed])
        .collect::<Vec<_>>()
        {
            let mut i = w.input.clone();
            i.ground = ground;
            let b = i.to_bytes();
            assert_eq!(HubInput::from_bytes(&b), Ok(i));
            assert_eq!(HubInput::from_bytes(&b[..b.len() - 1]), Err(Reject::Encoding));
            assert_eq!(HubInput::from_bytes(&[&b[..], &[0]].concat()), Err(Reject::Encoding));
        }
    }

    #[test]
    fn a_second_claim() {
        let w = world(5, |_| {});
        let other_deposit = OutPoint { txid: [0xd1; 32], vout: 0 };
        let mut other = Claim { positions: claim_of(&w).positions, acks: vec![], sigs: vec![], shielded: None };
        let e2 = other.fingerprint(1008, &other_deposit, 3);
        other.sigs = vec![w.alice.sign_raw(&signed_digest(&e2), &[0; 32]).unwrap().to_bytes()];
        let g = |c: u32, o: &Claim| Why::Second { which: 0, opening: opening(&w), other_c: c, other_deposit, other_b: 3, other: o.clone() };
        assert!(check_why(&w, g(1008, &other)).is_ok());
        // through this contract: not a second claim
        assert_eq!(check_why(&w, g(1007, &other)), Err(Reject::NotSpent));
        // not signed by her
        let mut forged = other.clone();
        forged.sigs = vec![key(9).sign_raw(&signed_digest(&e2), &[0; 32]).unwrap().to_bytes()];
        assert_eq!(check_why(&w, g(1008, &forged)), Err(Reject::NotYours));
        // of another position
        let mut elsewhere = Claim { positions: vec![4], acks: vec![], sigs: vec![], shielded: None };
        let e3 = elsewhere.fingerprint(1008, &other_deposit, 3);
        elsewhere.sigs = vec![w.alice.sign_raw(&signed_digest(&e3), &[0; 32]).unwrap().to_bytes()];
        assert_eq!(check_why(&w, g(1008, &elsewhere)), Err(Reject::NotSpent));
    }
}

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
use lichen_validity::{smt, OutPoint, TNote};
use sha2::{Digest, Sha256};

pub use lichen_validity::exit::{fingerprint, owners, signed_digest};
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

/// How a nullifier was spent: its leaf in the nullifier tree
/// (`lichen_validity::smt`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spent {
    Spend,
    Exit { c: u32 },
}

impl Spent {
    pub fn leaf(&self) -> Hash {
        match *self {
            Spent::Spend => smt::spent(),
            Spent::Exit { c } => smt::exited(c),
        }
    }
}

/// At most this many notes in a claim: an exit record's most
/// (`lichen_validity::exit::MAX_NOTES`).
pub const MAX_NOTES: usize = lichen_validity::exit::MAX_NOTES;

/// The journal's length in bytes: `c ‖ D ‖ H(O_D ‖ margin)`.
pub const JOURNAL_LEN: usize = 68;

/// A claim as `request` posts it: its notes' positions, increasing, and
/// one signature per owner key on [`signed_digest`] of its `E`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub positions: Vec<u32>,
    pub sigs: Vec<[u8; 64]>,
}

fn verifies(owner: &Hash, digest: &Hash, sig: &[u8; 64]) -> bool {
    let (Ok(key), Ok(sig)) = (VerifyingKey::from_bytes(owner), Signature::try_from(&sig[..])) else { return false };
    key.verify_raw(digest, &sig).is_ok()
}

impl Claim {
    /// `E` for contract `c` of deposit coin `deposit`, claiming `b`.
    pub fn fingerprint(&self, c: u32, deposit: &OutPoint, b: u32) -> Hash {
        fingerprint(c, deposit, b, &self.positions)
    }

    /// Whether it is well formed: one to [`MAX_NOTES`] positions,
    /// increasing and in the tree's range, one to as many signatures as
    /// notes.
    pub fn well_formed(&self) -> bool {
        (1..=MAX_NOTES).contains(&self.positions.len())
            && self.positions.windows(2).all(|w| w[0] < w[1])
            && self.positions.iter().all(|i| i >> TREE_DEPTH == 0)
            && (1..=self.positions.len()).contains(&self.sigs.len())
    }

    /// The signature of `owner`'s on the claim `e`, if any.
    pub fn signed_by(&self, owner: &Hash, e: &Hash) -> Option<[u8; 64]> {
        let d = signed_digest(e);
        self.sigs.iter().find(|s| verifies(owner, &d, s)).copied()
    }

    /// The exit record's notes and signatures (`lichen_validity::Tx::Exit`)
    /// from the notes at the claim's positions, in order: each owner's
    /// signature, in [`owners`]' order. None unless every owner signed
    /// `e`.
    #[allow(clippy::type_complexity)]
    pub fn record(&self, notes: &[TNote], e: &Hash) -> Option<(Vec<(TNote, u32)>, Vec<[u8; 64]>)> {
        if notes.len() != self.positions.len() {
            return None;
        }
        let notes: Vec<(TNote, u32)> = notes.iter().copied().zip(self.positions.iter().copied()).collect();
        let sigs = owners(&notes).iter().map(|o| self.signed_by(o, e)).collect::<Option<Vec<_>>>()?;
        Some((notes, sigs))
    }

    /// `[n] iⁿ [k] sigᵏ`, big-endian: 4 bytes a note, 64 a signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(2 + 4 * self.positions.len() + 64 * self.sigs.len());
        w.push(self.positions.len() as u8);
        for i in &self.positions {
            w.extend_from_slice(&i.to_be_bytes());
        }
        w.push(self.sigs.len() as u8);
        for s in &self.sigs {
            w.extend_from_slice(s);
        }
        w
    }

    pub fn from_bytes(b: &[u8]) -> Result<Claim, Reject> {
        let mut r = crate::R(b);
        let [n] = r.take()?;
        let positions = (0..n).map(|_| Ok(u32::from_be_bytes(r.take()?))).collect::<Result<Vec<_>, Reject>>()?;
        let [k] = r.take()?;
        let sigs = (0..k).map(|_| r.take()).collect::<Result<Vec<_>, _>>()?;
        if !r.0.is_empty() {
            return Err(Reject::Encoding);
        }
        Ok(Claim { positions, sigs })
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
/// position, and the path from its leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    pub note: TNote,
    pub path: Vec<Hash>,
}

/// Why the claim is false at `A*`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Why {
    /// The leaf at the `which`th position isn't a transparent note's: a
    /// shielded note's, or empty (past the tree's end); the leaf and its
    /// path.
    NotANote { which: u8, leaf: Hash, path: Vec<Hash> },
    /// The `which`th note's owner signed none of the claim's signatures.
    NotHers { which: u8, opening: Opening },
    /// The notes, all opened, are worth less than `b` units.
    TooMuch { openings: Vec<Opening> },
    /// The `which`th note's nullifier is spent, so, by this path in
    /// `A*`'s nullifier tree.
    Spent { which: u8, opening: Opening, spent: Spent, proof: smt::Proof },
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
    let position = |which: u8| claim.positions.get(which as usize).copied().ok_or(Reject::Encoding);
    let opened = |which: u8, o: &Opening| -> Result<(), Reject> { at(&last.tree, position(which)?, &o.note.leaf(), &o.path) };
    match why {
        Why::NotANote { which, leaf, path } => {
            at(&last.tree, position(*which)?, leaf, path)?;
            if *leaf != [0; 32] && !is_shielded(leaf) {
                return Err(Reject::Holds);
            }
        }
        Why::NotHers { which, opening } => {
            opened(*which, opening)?;
            if claim.signed_by(&opening.note.owner, &r.e).is_some() {
                return Err(Reject::Holds);
            }
        }
        Why::TooMuch { openings } => {
            if openings.len() != claim.positions.len() {
                return Err(Reject::Encoding);
            }
            for (k, o) in openings.iter().enumerate() {
                opened(k as u8, o)?;
            }
            let total = openings.iter().try_fold(0u64, |s, o| s.checked_add(o.note.value)).ok_or(Reject::TooLarge)?;
            if total / t.unit >= u64::from(r.b) {
                return Err(Reject::Holds);
            }
        }
        Why::Spent { which, opening, spent, proof } => {
            opened(*which, opening)?;
            if *spent == (Spent::Exit { c: input.c }) {
                return Err(Reject::Own);
            }
            if !smt::holds(&s.nullifiers, &opening.note.nullifier(), &spent.leaf(), proof, smt::empties()) {
                return Err(Reject::NotSpent);
            }
        }
        Why::Second { which, opening, other_c, other_deposit, other_b, other } => {
            opened(*which, opening)?;
            if *other_c == input.c || !other.well_formed() || !other.positions.contains(&position(*which)?) {
                return Err(Reject::NotSpent);
            }
            if other.signed_by(&opening.note.owner, &other.fingerprint(*other_c, other_deposit, *other_b)).is_none() {
                return Err(Reject::NotYours);
            }
        }
    }
    Ok(journal(input.c, &d, &input.deposit, input.margin))
}

// ----- the encoding, the guest's input (big-endian, as the other statements') -----

fn put_opening(w: &mut crate::W, o: &Opening) {
    w.put(&o.note.owner);
    w.put(&o.note.value.to_be_bytes());
    w.put(&o.note.memo.to_be_bytes());
    w.put(&o.note.rho);
    w.list(&o.path);
}

fn read_opening(r: &mut crate::R) -> Result<Opening, Reject> {
    let note = TNote { owner: r.take()?, value: u64::from_be_bytes(r.take()?), memo: u32::from_be_bytes(r.take()?), rho: r.take()? };
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
            Why::Spent { which, opening, spent, proof } => {
                w.put(&[3, *which]);
                put_opening(&mut w, opening);
                match *spent {
                    Spent::Spend => w.put(&[0]),
                    Spent::Exit { c } => {
                        w.put(&[1]);
                        w.put(&c.to_be_bytes());
                    }
                }
                w.put(&proof.bitmap);
                w.list(&proof.siblings);
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
                        let spent = match r.take()? {
                            [0] => Spent::Spend,
                            [1] => Spent::Exit { c: u32::from_be_bytes(r.take()?) },
                            _ => return Err(Reject::Encoding),
                        };
                        Why::Spent { which, opening, spent, proof: smt::Proof { bitmap: r.take()?, siblings: r.list()? } }
                    }
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
        let mut claim = Claim { positions: vec![0], sigs: vec![] };
        let e = claim.fingerprint(c, &deposit, b);
        claim.sigs = vec![alice.sign_raw(&signed_digest(&e), &[0; 32]).unwrap().to_bytes()];
        f(&mut claim);
        let e = claim.fingerprint(c, &deposit, b);
        let tree = root_from_path(leaf, 0, &empties());
        let nullifiers = smt::root(&[], smt::empties());
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
        Opening { note: w.note, path: empties() }
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
        assert_eq!(lichen_validity::exit::fingerprint(w.input.c, &w.deposit, 5, &[0]), r.e, "the exit record's E is the claim's");
        assert_eq!(Claim::from_bytes(&claim.to_bytes()[1..]), Err(Reject::Encoding));
    }

    #[test]
    fn a_claim_is_well_formed() {
        let sig = [0; 64];
        let c = |positions: Vec<u32>, n: usize| Claim { positions, sigs: vec![sig; n] };
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
        // unspent
        let proof = smt::proof(&[], &w.note.nullifier(), smt::empties());
        assert_eq!(check_why(&w, Why::Spent { which: 0, opening: opening(&w), spent: Spent::Spend, proof }), Err(Reject::NotSpent));
    }

    #[test]
    fn an_opening_must_be_at_its_position() {
        let w = world(7, |_| {});
        // another note than the one there
        let mut o = opening(&w);
        o.note.value = 700;
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
        let wit = witness(&Claim { positions: vec![], sigs: vec![] }.to_bytes(), &[0; 32], 5);
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

    #[test]
    fn a_spend_and_what_doesnt_count() {
        // the note spent at A*: its nullifier's leaf in the tree
        let mut w = world(5, |_| {});
        let nf = w.note.nullifier();
        let set = |w: &mut World, s: Spent| -> Why {
            let keys = [(nf, s.leaf())];
            let (root, proof) = (smt::root(&keys, smt::empties()), smt::proof(&keys, &nf, smt::empties()));
            // A*'s nullifier root, signed and anchored again
            let Ground::At { last, .. } = &mut w.input.ground else { unreachable!() };
            let st = &mut last.state;
            st.nullifiers = root;
            let r = state_root(3, &last.tree, &root);
            st.signature = key(1).sign_raw(&r, &[0; 32]).unwrap().to_bytes();
            st.anchor.root = r;
            Why::Spent { which: 0, opening: opening(w), spent: s, proof }
        };
        let why = set(&mut w, Spent::Spend);
        assert!(check_why(&w, why).is_ok());
        // this contract's exit record: not a spend; another's: a spend
        let why = set(&mut w, Spent::Exit { c: 1007 });
        assert_eq!(check_why(&w, why), Err(Reject::Own));
        let why = set(&mut w, Spent::Exit { c: 1008 });
        assert!(check_why(&w, why).is_ok());
    }

    #[test]
    fn the_input_round_trips() {
        let w = world(5, |_| {});
        let proof = smt::proof(&[], &[1; 32], smt::empties());
        let other = Claim { positions: vec![0, 3], sigs: vec![[5; 64]] };
        for ground in [
            Why::NotANote { which: 0, leaf: [1; 32], path: empties() },
            Why::NotHers { which: 0, opening: opening(&w) },
            Why::TooMuch { openings: vec![opening(&w), opening(&w)] },
            Why::Spent { which: 0, opening: opening(&w), spent: Spent::Exit { c: 9 }, proof },
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
        let mut other = Claim { positions: claim_of(&w).positions, sigs: vec![] };
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
        let mut elsewhere = Claim { positions: vec![4], sigs: vec![] };
        let e3 = elsewhere.fingerprint(1008, &other_deposit, 3);
        elsewhere.sigs = vec![w.alice.sign_raw(&signed_digest(&e3), &[0; 32]).unwrap().to_bytes()];
        assert_eq!(check_why(&w, g(1008, &elsewhere)), Err(Reject::NotSpent));
    }
}

//! The exit where only the hub proves (docs/HUB_PROVES_PLAN.md): Alice
//! claims definite notes and an amount `b`, and the hub proves, if it
//! can, that her claim is false. Its statement is fixed when the contract
//! opens; BABE checks it with the roles swapped (Alice garbles).
//!
//! **The claim** ([`Claim`]), posted in `request`'s witness: each note by
//! its position in the commitment tree and its opening, and one signature
//! per owner key on the claim's fingerprint
//!
//! ```text
//! E = SHA256("lichen/exit" ‖ c ‖ O_D ‖ b ‖ 0 ‖ P ‖ nf_1 ‖ … ‖ nf_n)
//! P = SHA256("lichen/hp/positions" ‖ i_1 ‖ … ‖ i_n)
//! ```
//!
//! `lichen_validity::exit`'s fingerprint with no state named (`h_S` 0)
//! and the positions' digest for `SR_S`, so that the hub's exit record on
//! the L2 retires the notes under today's chain statement. Alice signs
//! `b` and `E` with her one-time keys; the claim's bytes, which script
//! can't check, must hash to that `E`.
//!
//! The opening is posted, not just the position: shielded commitments
//! share the tree, and the hub couldn't show that a leaf isn't a
//! transparent note's without one.
//!
//! **The claim is true** if its notes are hers (each owner signed `E`),
//! worth at least `b` (in the contract's units), and live at `A*`, the
//! last anchor confirmed at least `margin` blocks before `request`'s
//! block: each in the tree at its position, its nullifier unspent (her
//! return of at least `b` to this contract, or this contract's exit
//! record, not counting as a spend). The margin keeps the operator from
//! slipping a held spend of hers into an anchor while her `request`
//! confirms.
//!
//! **The statement** ([`check`]) holds on any ground ([`Ground`]) that
//! the claim is false: malformed, not hers, too much, not live at `A*`,
//! or a second claim of a note through another contract. `A*` is shown
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

use crate::counter::Spent;
use crate::exit::{fingerprint, signed_digest, POSTED_ITEMS};
use crate::{contract_id, deployment_id, root_from_path, work_on, Anchored, Hash, Reject, Request, TREE_DEPTH};

/// At most this many notes in a claim: an exit record's most
/// (`lichen_validity::exit::MAX_NOTES`).
pub const MAX_NOTES: usize = lichen_validity::exit::MAX_NOTES;

/// The journal's length in bytes: `c ‖ D ‖ H(O_D ‖ margin)`.
pub const JOURNAL_LEN: usize = 68;

/// A claimed note: its position in the commitment tree, and its opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimNote {
    pub index: u32,
    pub note: TNote,
}

/// A claim as `request` posts it: its notes, positions increasing, and
/// one signature per owner key on [`signed_digest`] of its `E`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub notes: Vec<ClaimNote>,
    pub sigs: Vec<[u8; 64]>,
}

fn verifies(owner: &Hash, digest: &Hash, sig: &[u8; 64]) -> bool {
    let (Ok(key), Ok(sig)) = (VerifyingKey::from_bytes(owner), Signature::try_from(&sig[..])) else { return false };
    key.verify_raw(digest, &sig).is_ok()
}

impl Claim {
    /// `P`: the positions' digest.
    pub fn positions(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(b"lichen/hp/positions");
        for n in &self.notes {
            h.update(n.index.to_be_bytes());
        }
        h.finalize().into()
    }

    pub fn nullifiers(&self) -> Vec<Hash> {
        self.notes.iter().map(|n| n.note.nullifier()).collect()
    }

    /// `E` for contract `c` of deposit coin `deposit`, claiming `b`.
    pub fn fingerprint(&self, c: u32, deposit: &OutPoint, b: u32) -> Hash {
        fingerprint(c, deposit, b, 0, &self.positions(), &self.nullifiers())
    }

    /// Whether it is well formed: one to [`MAX_NOTES`] notes, positions
    /// increasing and in the tree's range, nullifiers distinct, one to as many signatures as
    /// notes.
    pub fn well_formed(&self) -> bool {
        let nfs = self.nullifiers();
        (1..=MAX_NOTES).contains(&self.notes.len())
            && self.notes.windows(2).all(|w| w[0].index < w[1].index)
            && self.notes.iter().all(|n| n.index >> TREE_DEPTH == 0)
            && nfs.iter().enumerate().all(|(i, a)| !nfs[..i].contains(a))
            && (1..=self.notes.len()).contains(&self.sigs.len())
    }

    /// The signature of `owner`'s on the claim `e`, if any.
    pub fn signed_by(&self, owner: &Hash, e: &Hash) -> Option<[u8; 64]> {
        let d = signed_digest(e);
        self.sigs.iter().find(|s| verifies(owner, &d, s)).copied()
    }

    /// The claim as an exit record carries it (`lichen_validity::exit`):
    /// no state, the positions' digest, each note with its owner's
    /// signature. None unless every owner signed `e`.
    pub fn record(&self, e: &Hash) -> Option<lichen_validity::exit::Posted> {
        let notes = self.notes.iter().map(|n| Some(lichen_validity::exit::PostedNote::Transparent { note: n.note, sig: self.signed_by(&n.note.owner, e)? })).collect::<Option<Vec<_>>>()?;
        Some(lichen_validity::exit::Posted { h_s: 0, sr_s: self.positions(), notes })
    }

    /// `[n] (index ‖ owner ‖ value ‖ memo ‖ rho)ⁿ [k] sigᵏ`, big-endian:
    /// 80 bytes a note, 64 a signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(2 + 80 * self.notes.len() + 64 * self.sigs.len());
        w.push(self.notes.len() as u8);
        for n in &self.notes {
            w.extend_from_slice(&n.index.to_be_bytes());
            w.extend_from_slice(&n.note.owner);
            w.extend_from_slice(&n.note.value.to_be_bytes());
            w.extend_from_slice(&n.note.memo.to_be_bytes());
            w.extend_from_slice(&n.note.rho);
        }
        w.push(self.sigs.len() as u8);
        for s in &self.sigs {
            w.extend_from_slice(s);
        }
        w
    }

    pub fn from_bytes(b: &[u8]) -> Result<Claim, Reject> {
        let mut r = crate::exit::R(b);
        let [n] = r.take()?;
        let mut notes = Vec::with_capacity((n as usize).min(MAX_NOTES));
        for _ in 0..n {
            let index = u32::from_be_bytes(r.take()?);
            let note = TNote { owner: r.take()?, value: u64::from_be_bytes(r.take()?), memo: u32::from_be_bytes(r.take()?), rho: r.take()? };
            notes.push(ClaimNote { index, note });
        }
        let [k] = r.take()?;
        let sigs = (0..k).map(|_| r.take()).collect::<Result<Vec<_>, _>>()?;
        if !r.0.is_empty() {
            return Err(Reject::Encoding);
        }
        Ok(Claim { notes, sigs })
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

/// How a claimed note isn't live at `A*`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum How {
    /// The leaf at its position isn't its commitment (an empty leaf past
    /// the tree's end, too): the leaf and its path.
    Mismatch { leaf: Hash, path: Vec<Hash> },
    /// Its nullifier is spent, so, by this path in `A*`'s nullifier tree.
    Spent { spent: Spent, proof: smt::Proof },
}

/// Why the claim is false.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Ground {
    /// The claim's bytes don't parse, aren't well formed, or don't hash to
    /// the `E` she signed.
    Malformed,
    /// The note `which`'s owner signed none of the claim's signatures.
    NotHers { which: u8 },
    /// The notes are worth less than `b` units.
    TooMuch,
    /// The note `which` isn't live at `A*`.
    NotLive { which: u8, last: Last, how: How },
    /// The note `which`'s owner signed a claim of it through another
    /// contract `c'` (of deposit coin `deposit'`, for `b'`).
    Second { which: u8, other_c: u32, other_deposit: OutPoint, other_b: u32, other: Claim },
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
    let note = |which: u8| claim.as_ref().and_then(|c| c.notes.get(which as usize)).ok_or(Reject::NotSpent);
    match &input.ground {
        Ground::Malformed => {
            if claim.is_some() {
                return Err(Reject::Holds);
            }
        }
        Ground::NotHers { which } => {
            if claim.as_ref().ok_or(Reject::Holds)?.signed_by(&note(*which)?.note.owner, &r.e).is_some() {
                return Err(Reject::Holds);
            }
        }
        Ground::TooMuch => {
            let total = claim.as_ref().ok_or(Reject::Holds)?.notes.iter().try_fold(0u64, |s, n| s.checked_add(n.note.value)).ok_or(Reject::TooLarge)?;
            if total / t.unit >= u64::from(r.b) {
                return Err(Reject::Holds);
            }
        }
        Ground::NotLive { which, last, how } => {
            let n = note(*which)?;
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
            match how {
                How::Mismatch { leaf, path } => {
                    if path.len() != TREE_DEPTH || root_from_path(*leaf, n.index, path) != last.tree || *leaf == n.note.commitment() {
                        return Err(Reject::NotSpent);
                    }
                }
                How::Spent { spent, proof } => {
                    match *spent {
                        Spent::Return { c, r: v } if c == input.c && v / t.unit >= u64::from(r.b) => return Err(Reject::Own),
                        Spent::Exit { c } if c == input.c => return Err(Reject::Own),
                        _ => {}
                    }
                    if !smt::holds(&s.nullifiers, &n.note.nullifier(), &spent.leaf(), proof, smt::empties()) {
                        return Err(Reject::NotSpent);
                    }
                }
            }
        }
        Ground::Second { which, other_c, other_deposit, other_b, other } => {
            let n = note(*which)?;
            if *other_c == input.c || !other.well_formed() || !other.nullifiers().contains(&n.note.nullifier()) {
                return Err(Reject::NotSpent);
            }
            if other.signed_by(&n.note.owner, &other.fingerprint(*other_c, other_deposit, *other_b)).is_none() {
                return Err(Reject::NotYours);
            }
        }
    }
    Ok(journal(input.c, &d, &input.deposit, input.margin))
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
        let mut w: Vec<Vec<u8>> = crate::exit::posted_items(posted).unwrap().into_iter().map(<[u8]>::to_vec).collect();
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
        input: HubInput,
        id: Hash,
    }

    const MARGIN: u32 = 2;

    /// Alice's claim of one note of 600 at position 0 for `b` units of 100,
    /// alone in A*'s tree (height 3); `A*` anchored in block [9; 32], ten
    /// headers on it; `request` in the third, the seal spent in the
    /// fourth; `f` to change the claim before it is posted.
    fn world(b: u32, mut f: impl FnMut(&mut Claim)) -> World {
        let (seq, hub, alice) = (key(1), key(2), key(3));
        let deposit = OutPoint { txid: [0xd0; 32], vout: 1 };
        let c = 1007;
        let note = TNote { owner: xonly(&alice), value: 600, memo: 0, rho: [7; 32] };
        let mut claim = Claim { notes: vec![ClaimNote { index: 0, note }], sigs: vec![] };
        let e = claim.fingerprint(c, &deposit, b);
        claim.sigs = vec![alice.sign_raw(&signed_digest(&e), &[0; 32]).unwrap().to_bytes()];
        f(&mut claim);
        let e = claim.fingerprint(c, &deposit, b);
        let path = lichen_validity::tree_empties()[..TREE_DEPTH].to_vec();
        let tree = root_from_path(note.commitment(), 0, &path);
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
        let input = HubInput {
            c,
            deposit,
            margin: MARGIN,
            terms,
            request,
            headers: headers[3..].to_vec(),
            ground: Ground::NotLive { which: 0, last, how: How::Mismatch { leaf: [0; 32], path: vec![] } },
        };
        World { alice, deposit, input, id: [0xc4; 32] }
    }

    /// Position 1's path in A*'s tree: the note at 0 beside it.
    fn past_end(empties: &[Hash]) -> Vec<Hash> {
        let note = TNote { owner: xonly(&key(3)), value: 600, memo: 0, rho: [7; 32] };
        let mut p = empties.to_vec();
        p[0] = note.commitment();
        p
    }

    fn last(w: &World) -> Last {
        match &w.input.ground {
            Ground::NotLive { last, .. } => last.clone(),
            _ => unreachable!(),
        }
    }

    fn check_ground(w: &World, ground: Ground) -> Result<[u8; JOURNAL_LEN], Reject> {
        let mut i = w.input.clone();
        i.ground = ground;
        check(&i, &w.id, &mut |_| true)
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
        let rec = claim.record(&r.e).unwrap();
        assert_eq!(rec.fingerprint(w.input.c, &w.deposit, 5), r.e, "the exit record's E is the claim's");
        assert_eq!(Claim::from_bytes(&claim.to_bytes()[1..]), Err(Reject::Encoding));
    }

    #[test]
    fn a_true_claim_has_no_ground() {
        let w = world(5, |_| {});
        let last = last(&w);
        assert_eq!(check_ground(&w, Ground::Malformed), Err(Reject::Holds));
        assert_eq!(check_ground(&w, Ground::NotHers { which: 0 }), Err(Reject::Holds));
        assert_eq!(check_ground(&w, Ground::TooMuch), Err(Reject::Holds));
        // the note's own leaf: no mismatch
        let path = lichen_validity::tree_empties()[..TREE_DEPTH].to_vec();
        let leaf = Claim::from_bytes(&requested(&w.input.request.spending(&w.deposit).unwrap()).unwrap().posted).unwrap().notes[0].note.commitment();
        assert_eq!(check_ground(&w, Ground::NotLive { which: 0, last: last.clone(), how: How::Mismatch { leaf, path } }), Err(Reject::NotSpent));
    }

    #[test]
    fn the_grounds_of_a_false_claim() {
        let path = lichen_validity::tree_empties()[..TREE_DEPTH].to_vec();
        // too much: 600 is 6 units, not 7
        let w = world(7, |_| {});
        let j = check_ground(&w, Ground::TooMuch).unwrap();
        assert_eq!(j, journal(w.input.c, &w.input.terms.d(), &w.deposit, MARGIN));
        // not hers: signed by another key
        let w = world(5, |c| c.sigs = vec![key(9).sign_raw(&[0; 32], &[0; 32]).unwrap().to_bytes()]);
        assert!(check_ground(&w, Ground::NotHers { which: 0 }).is_ok());
        // malformed: not hashing to the E signed (another b in E)
        let mut w = world(5, |_| {});
        let wit = witness(&Claim { notes: vec![], sigs: vec![] }.to_bytes(), &[0; 32], 5);
        let items: Vec<&[u8]> = wit.iter().map(Vec::as_slice).collect();
        let prev = Header(w.input.request.header).prev();
        let (rh, req) = request_on(&prev, &w.deposit, &items);
        w.input.request = req;
        w.input.headers = headers_on(&sha256d(&rh), 10);
        assert!(check_ground(&w, Ground::Malformed).is_ok());
        // not live: a note at a position past the tree's end
        let w = world(5, |c| c.notes[0].index = 1);
        let w = {
            // re-signed for its own E
            let e = Claim::from_bytes(&requested(&w.input.request.spending(&w.deposit).unwrap()).unwrap().posted).unwrap();
            assert!(e.well_formed());
            w
        };
        let leaf = lichen_validity::tree_empties()[0];
        let r = check_ground(&w, Ground::NotLive { which: 0, last: last(&w), how: How::Mismatch { leaf, path: past_end(&path) } });
        // (the signature was on position 0's E: not hers too; but the
        // mismatch holds whatever the signature)
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn not_live_needs_the_last_anchor() {
        let w = world(5, |c| c.notes[0].index = 1);
        let leaf = lichen_validity::tree_empties()[0];
        let path = past_end(&lichen_validity::tree_empties()[..TREE_DEPTH]);
        let how = How::Mismatch { leaf, path };
        let ok = |l: Last| check_ground(&w, Ground::NotLive { which: 0, last: l, how: how.clone() });
        assert!(ok(last(&w)).is_ok());
        // a margin request's block is too close to the anchor for
        let mut far = w.input.clone();
        far.margin = 4;
        far.ground = Ground::NotLive { which: 0, last: last(&w), how: how.clone() };
        assert_eq!(check(&far, &w.id, &mut |_| true), Err(Reject::Last));
        // a margin of one block: the spend, a block after request's, still
        // after the cutoff
        let mut l = last(&w);
        let mut near = w.input.clone();
        near.margin = 1;
        near.ground = Ground::NotLive { which: 0, last: l.clone(), how: how.clone() };
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
        i.ground = Ground::NotLive { which: 0, last: last(&w), how };
        assert_eq!(check(&i, &w.id, &mut |_| false), Err(Reject::Chain));
    }

    #[test]
    fn a_spend_and_what_doesnt_count() {
        // the note spent at A*: its nullifier's leaf in the tree
        let mut w = world(5, |_| {});
        let nf = Claim::from_bytes(&requested(&w.input.request.spending(&w.deposit).unwrap()).unwrap().posted).unwrap().nullifiers()[0];
        let spent_leaf = |s: Spent| {
            let keys = [(nf, s.leaf())];
            (smt::root(&keys, smt::empties()), smt::proof(&keys, &nf, smt::empties()))
        };
        let set = |w: &mut World, s: Spent| -> How {
            let (root, proof) = spent_leaf(s);
            // A*'s nullifier root, signed and anchored again
            let Ground::NotLive { last, .. } = &mut w.input.ground else { unreachable!() };
            let st = &mut last.state;
            st.nullifiers = root;
            let r = state_root(3, &last.tree, &root);
            st.signature = key(1).sign_raw(&r, &[0; 32]).unwrap().to_bytes();
            st.anchor.root = r;
            How::Spent { spent: s, proof }
        };
        let how = set(&mut w, Spent::Spend);
        assert!(check_ground(&w, Ground::NotLive { which: 0, last: last(&w), how }).is_ok());
        // her return of at least b to this contract: not a spend
        let how = set(&mut w, Spent::Return { c: 1007, r: 500 });
        assert_eq!(check_ground(&w, Ground::NotLive { which: 0, last: last(&w), how }), Err(Reject::Own));
        // of less than b, or to another contract: a spend
        let how = set(&mut w, Spent::Return { c: 1007, r: 499 });
        assert!(check_ground(&w, Ground::NotLive { which: 0, last: last(&w), how }).is_ok());
        let how = set(&mut w, Spent::Return { c: 1008, r: 500 });
        assert!(check_ground(&w, Ground::NotLive { which: 0, last: last(&w), how }).is_ok());
        // this contract's exit record: not a spend; another's: a spend
        let how = set(&mut w, Spent::Exit { c: 1007 });
        assert_eq!(check_ground(&w, Ground::NotLive { which: 0, last: last(&w), how }), Err(Reject::Own));
        let how = set(&mut w, Spent::Exit { c: 1008 });
        assert!(check_ground(&w, Ground::NotLive { which: 0, last: last(&w), how }).is_ok());
    }

    #[test]
    fn a_second_claim() {
        let w = world(5, |_| {});
        let claim = Claim::from_bytes(&requested(&w.input.request.spending(&w.deposit).unwrap()).unwrap().posted).unwrap();
        let other_deposit = OutPoint { txid: [0xd1; 32], vout: 0 };
        let mut other = Claim { notes: claim.notes.clone(), sigs: vec![] };
        let e2 = other.fingerprint(1008, &other_deposit, 3);
        other.sigs = vec![w.alice.sign_raw(&signed_digest(&e2), &[0; 32]).unwrap().to_bytes()];
        let g = |c: u32, o: &Claim| Ground::Second { which: 0, other_c: c, other_deposit, other_b: 3, other: o.clone() };
        assert!(check_ground(&w, g(1008, &other)).is_ok());
        // through this contract: not a second claim
        assert_eq!(check_ground(&w, g(1007, &other)), Err(Reject::NotSpent));
        // not signed by her
        let mut forged = other.clone();
        forged.sigs = vec![key(9).sign_raw(&signed_digest(&e2), &[0; 32]).unwrap().to_bytes()];
        assert_eq!(check_ground(&w, g(1008, &forged)), Err(Reject::NotYours));
    }
}

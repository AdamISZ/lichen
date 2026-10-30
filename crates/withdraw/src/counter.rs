//! The hub's counter to an exit claim (docs/EXIT_PLAN.md, "The counter"
//! and "Under BABE"): one of the claim's notes was spent at an anchored
//! state `S'` after its `S`, in a way that may be held against it. The
//! hub posts it in `respond` as `K`; Alice's statement checks it.
//!
//! The nullifier tree's leaf says how the note was spent
//! (`lichen_validity::smt`), and the rules follow it:
//!
//! - **an ordinary spend** counts if it was final before the claim:
//!   `S'`'s anchor confirmed no later than [`GRACE`] blocks after the
//!   block of `request`, the transaction spending the output 0 of the
//!   contract's funding (the transaction spending its deposit coin);
//! - **a return to the hub with memo `c`** of at least `b` never counts
//!   against contract `c`: the hub has its tokens, and the contract pays
//!   once. Any other return counts as an ordinary spend;
//! - **an exit record** counts whenever it was anchored (two claims of
//!   one note through two contracts escalate together, and each record
//!   lands after both requests), unless it is contract `c`'s own.
//!
//! `S'` is in `S`'s history: the history hash folded from `S`'s root
//! through every later root to the chain receipt's.
//!
//! Or a second ground, with no state at all: **an equivocation**. A note
//! of the claim is in another claim, through a contract `c' ≠ c`, that
//! its owner signed: the signed claim `request` posted ([`Posted`]),
//! wherever the hub found it. An honest owner claims a note through one
//! contract only, and nobody else can sign. The hub learns it when the
//! other `request` is posted, so before it must respond, whereas an exit
//! record waits on that claim's proof (docs/EXIT_PLAN.md, "Exit authority
//! on chain"). Only transparent notes can be cited, for now.
//!
//! Journal: `D ‖ E`, 64 bytes. An equivocation names no state, so its `D`
//! is the input's: the ground holds whatever the deployment.

use alloc::vec::Vec;
use k256::schnorr::{Signature, VerifyingKey};
use lichen_validity::btc::Header;
use lichen_validity::{hist_next, smt, OutPoint};

use crate::exit::{fingerprint, signed_digest, Posted, PostedNote};
use crate::{Anchored, Hash, Reject, Request};

/// The journal's length in bytes: `D ‖ E`.
pub const JOURNAL_LEN: usize = 64;

/// How many blocks after `request`'s an ordinary spend's anchor may
/// confirm and still count: the operator's cover for a spend it sequenced
/// before the claim appeared, whose anchor confirmed after it. Safe for
/// an honest Alice only once a counter must cite her acknowledgment of
/// the spend (docs/EXIT_PLAN.md, "Sender acknowledgment"); until then 0,
/// and that race is the operator's loss.
pub const GRACE: usize = 0;

/// How a nullifier was spent: its leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spent {
    Spend,
    Return { c: u32, r: u64 },
    Exit { c: u32 },
}

impl Spent {
    pub fn leaf(&self) -> Hash {
        match *self {
            Spent::Spend => smt::spent(),
            Spent::Return { c, r } => smt::returned(c, r),
            Spent::Exit { c } => smt::exited(c),
        }
    }
}

/// The counter's input: the claim (`E`'s preimage); the nullifier cited
/// (its place in the claim) and how it was spent; the anchored state `S'`
/// it is spent in, with its commitment tree's root and the nullifier's
/// path; `S` in `S'`'s history (`hist` before `S`, and the roots after it
/// to the chain receipt's height); and `request`, unless the spend is an
/// exit record, with `earlier`: the header of `S'`'s anchor block and its
/// parents, newest first, for a `request` before it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CounterInput {
    pub c: u32,
    pub deposit: OutPoint,
    pub b: u32,
    pub h_s: u64,
    pub sr_s: Hash,
    pub nullifiers: Vec<Hash>,
    pub which: u8,
    pub spent: Spent,
    pub state: Anchored,
    pub tree: Hash,
    pub proof: smt::Proof,
    pub before: Hash,
    pub roots: Vec<Hash>,
    pub request: Option<Request>,
    pub earlier: Vec<[u8; 80]>,
}

/// The counter: check `input` against a chain receipt of `chain_id`; on
/// success, the journal `D ‖ E`.
pub fn check(input: &CounterInput, chain_id: &Hash, verify_chain: &mut dyn FnMut(&[u8]) -> bool) -> Result<[u8; JOURNAL_LEN], Reject> {
    check_with(input, GRACE, chain_id, verify_chain)
}

fn check_with(input: &CounterInput, grace: usize, chain_id: &Hash, verify_chain: &mut dyn FnMut(&[u8]) -> bool) -> Result<[u8; JOURNAL_LEN], Reject> {
    let e = fingerprint(input.c, &input.deposit, input.b, input.h_s, &input.sr_s, &input.nullifiers);
    let nf = input.nullifiers.get(input.which as usize).ok_or(Reject::NotSpent)?;
    let needs_cutoff = match input.spent {
        Spent::Return { c, r } if c == input.c && r >= u64::from(input.b) => return Err(Reject::Own),
        Spent::Exit { c } if c == input.c => return Err(Reject::Own),
        Spent::Exit { .. } => false,
        Spent::Spend | Spent::Return { .. } => true,
    };
    if !smt::holds(&input.state.nullifiers, nf, &input.spent.leaf(), &input.proof, smt::empties()) {
        return Err(Reject::NotSpent);
    }
    let d = input.state.check(&input.tree, chain_id, verify_chain)?;
    // S, then each root after it, to the receipt's history
    if input.h_s == 0 || input.state.chain_height.checked_sub(input.h_s) != Some(input.roots.len() as u64) {
        return Err(Reject::History);
    }
    let hist = input.roots.iter().fold(hist_next(&input.before, &input.sr_s), |h, r| hist_next(&h, r));
    if hist != input.state.hist {
        return Err(Reject::History);
    }
    if needs_cutoff {
        let a = &input.state.anchor;
        let req = input.request.as_ref().ok_or(Reject::Cutoff)?;
        let header = Header(req.header);
        // the anchor's block and up to `grace` parents, or a block after it
        let mut back = a.block;
        let mut earlier = true;
        for h in &input.earlier {
            earlier &= Header(*h).hash() == back;
            back = Header(*h).prev();
        }
        let earlier = earlier && input.earlier.len() <= grace + 1;
        let in_range = input.state.deep(&header) || (earlier && input.earlier.iter().any(|h| Header(*h).hash() == header.hash()));
        if !in_range || req.spending(&input.deposit).is_none() {
            return Err(Reject::Cutoff);
        }
    }
    let mut journal = [0u8; JOURNAL_LEN];
    journal[..32].copy_from_slice(&d);
    journal[32..].copy_from_slice(&e);
    Ok(journal)
}

/// An equivocation's input: the claim (`E`'s preimage) and its `D`; the
/// other claim cited, through contract `c'`, of deposit coin `deposit'`, for
/// `b'`, as its `request` posted it; and the note cited (its place there).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquivocationInput {
    pub c: u32,
    pub deposit: OutPoint,
    pub b: u32,
    pub h_s: u64,
    pub sr_s: Hash,
    pub nullifiers: Vec<Hash>,
    pub d: Hash,
    pub other_c: u32,
    pub other_deposit: OutPoint,
    pub other_b: u32,
    pub other: Posted,
    pub which: u8,
}

/// The counter guest's input: either ground.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Counter {
    Spent(CounterInput),
    Equivocation(EquivocationInput),
}

/// The counter on either ground; on success, the journal `D ‖ E`.
pub fn check_counter(input: &Counter, chain_id: &Hash, verify_chain: &mut dyn FnMut(&[u8]) -> bool) -> Result<[u8; JOURNAL_LEN], Reject> {
    match input {
        Counter::Spent(i) => check(i, chain_id, verify_chain),
        Counter::Equivocation(i) => equivocation(i),
    }
}

/// The equivocation ground: the cited note is one of the claim's, and its
/// owner signed the other claim, through another contract.
pub fn equivocation(input: &EquivocationInput) -> Result<[u8; JOURNAL_LEN], Reject> {
    if input.other_c == input.c {
        return Err(Reject::Own);
    }
    let Some(PostedNote::Transparent { note, sig }) = input.other.notes.get(input.which as usize) else {
        return Err(Reject::NotYours);
    };
    if !input.nullifiers.contains(&note.nullifier()) {
        return Err(Reject::NotSpent);
    }
    let other = input.other.fingerprint(input.other_c, &input.other_deposit, input.other_b);
    let key = VerifyingKey::from_bytes(&note.owner).map_err(|_| Reject::NotYours)?;
    let sig = Signature::try_from(&sig[..]).map_err(|_| Reject::NotYours)?;
    key.verify_raw(&signed_digest(&other), &sig).map_err(|_| Reject::NotYours)?;
    let mut journal = [0u8; JOURNAL_LEN];
    journal[..32].copy_from_slice(&input.d);
    journal[32..].copy_from_slice(&fingerprint(input.c, &input.deposit, input.b, input.h_s, &input.sr_s, &input.nullifiers));
    Ok(journal)
}

// ----- the encoding -----

impl EquivocationInput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = crate::exit::W(Vec::new());
        w.put(&self.c.to_be_bytes());
        w.put(&self.deposit.to_bytes());
        w.put(&self.b.to_be_bytes());
        w.put(&self.h_s.to_be_bytes());
        w.put(&self.sr_s);
        w.list(&self.nullifiers);
        w.put(&self.d);
        w.put(&self.other_c.to_be_bytes());
        w.put(&self.other_deposit.to_bytes());
        w.put(&self.other_b.to_be_bytes());
        w.bytes(&self.other.to_bytes());
        w.put(&[self.which]);
        w.0
    }

    pub fn from_bytes(b: &[u8]) -> Result<EquivocationInput, Reject> {
        let mut r = crate::exit::R(b);
        let (c, deposit, b) = (u32::from_be_bytes(r.take()?), OutPoint::from_bytes(&r.take()?), u32::from_be_bytes(r.take()?));
        let (h_s, sr_s, nullifiers, d) = (u64::from_be_bytes(r.take()?), r.take()?, r.list()?, r.take()?);
        let (other_c, other_deposit, other_b) = (u32::from_be_bytes(r.take()?), OutPoint::from_bytes(&r.take()?), u32::from_be_bytes(r.take()?));
        let (other, [which]) = (Posted::from_bytes(&r.bytes()?).map_err(|_| Reject::Encoding)?, r.take()?);
        if !r.0.is_empty() {
            return Err(Reject::Encoding);
        }
        Ok(EquivocationInput { c, deposit, b, h_s, sr_s, nullifiers, d, other_c, other_deposit, other_b, other, which })
    }
}

impl Counter {
    pub fn to_bytes(&self) -> Vec<u8> {
        let (tag, body) = match self {
            Counter::Spent(i) => (0, i.to_bytes()),
            Counter::Equivocation(i) => (1, i.to_bytes()),
        };
        [&[tag][..], &body].concat()
    }

    pub fn from_bytes(b: &[u8]) -> Result<Counter, Reject> {
        match b.split_first() {
            Some((0, rest)) => Ok(Counter::Spent(CounterInput::from_bytes(rest)?)),
            Some((1, rest)) => Ok(Counter::Equivocation(EquivocationInput::from_bytes(rest)?)),
            _ => Err(Reject::Encoding),
        }
    }
}

impl CounterInput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = crate::exit::W(Vec::new());
        w.put(&self.c.to_be_bytes());
        w.put(&self.deposit.to_bytes());
        w.put(&self.b.to_be_bytes());
        w.put(&self.h_s.to_be_bytes());
        w.put(&self.sr_s);
        w.list(&self.nullifiers);
        w.put(&[self.which]);
        match self.spent {
            Spent::Spend => w.put(&[0]),
            Spent::Return { c, r } => {
                w.put(&[1]);
                w.put(&c.to_be_bytes());
                w.put(&r.to_be_bytes());
            }
            Spent::Exit { c } => {
                w.put(&[2]);
                w.put(&c.to_be_bytes());
            }
        }
        self.state.write(&mut w);
        w.put(&self.tree);
        w.put(&self.proof.bitmap);
        w.list(&self.proof.siblings);
        w.put(&self.before);
        w.list(&self.roots);
        match &self.request {
            None => w.put(&[0]),
            Some(r) => {
                w.put(&[1]);
                r.write(&mut w);
            }
        }
        w.list(&self.earlier);
        w.0
    }

    pub fn from_bytes(b: &[u8]) -> Result<CounterInput, Reject> {
        let mut r = crate::exit::R(b);
        let (c, deposit, b) = (u32::from_be_bytes(r.take()?), OutPoint::from_bytes(&r.take()?), u32::from_be_bytes(r.take()?));
        let (h_s, sr_s, nullifiers) = (u64::from_be_bytes(r.take()?), r.take()?, r.list()?);
        let [which] = r.take()?;
        let spent = match r.take()? {
            [0] => Spent::Spend,
            [1] => Spent::Return { c: u32::from_be_bytes(r.take()?), r: u64::from_be_bytes(r.take()?) },
            [2] => Spent::Exit { c: u32::from_be_bytes(r.take()?) },
            _ => return Err(Reject::Encoding),
        };
        let state = Anchored::read(&mut r)?;
        let (tree, proof) = (r.take()?, smt::Proof { bitmap: r.take()?, siblings: r.list()? });
        let (before, roots) = (r.take()?, r.list()?);
        let request = match r.take()? {
            [0] => None,
            [1] => Some(Request::read(&mut r)?),
            _ => return Err(Reject::Encoding),
        };
        let earlier = r.list()?;
        if !r.0.is_empty() {
            return Err(Reject::Encoding);
        }
        Ok(CounterInput { c, deposit, b, h_s, sr_s, nullifiers, which, spent, state, tree, proof, before, roots, request, earlier })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::tests::{block_with, header_with, headers_on, key, request_on, xonly};
    use lichen_validity::{btc, state_root, AnchorState};
    use std::vec;

    fn tx_spending(op: &OutPoint) -> (Vec<u8>, Hash) {
        crate::tests::tx_spending(op, &[&[1, 2, 3]])
    }

    /// `request` spending the funding of `deposit`, in a block on `prev`.
    fn request(prev: &Hash, deposit: &OutPoint) -> ([u8; 80], Request) {
        request_on(prev, deposit, &[&[1, 2, 3]])
    }

    const DEPOSIT: OutPoint = OutPoint { txid: [12; 32], vout: 2 };

    /// Contract 42's claim of 9 from `S` (height 3), two notes; the first
    /// spent (an ordinary spend) at `S'`, height 5, anchored; the chain
    /// receipt at 6. Twelve headers on the anchor's block, `request` in
    /// the third.
    fn input() -> (CounterInput, Hash) {
        let (seq, hub) = (key(1), key(2));
        let (nf, other) = ([0x31; 32], [0x40; 32]);
        let set = [(nf, smt::spent()), ([0x77; 32], smt::spent())];
        let n = smt::root(&set, smt::empties());
        let tree = [0x21; 32];
        let root = state_root(5, &tree, &n);
        let anchor_block = header_with(&[0x99; 32], &[0; 32]);
        let mut headers = headers_on(&Header(anchor_block).hash(), 2);
        let (req_block, request) = request(&Header(headers[1]).hash(), &DEPOSIT);
        headers.push(req_block);
        headers.extend(headers_on(&Header(req_block).hash(), 9));
        let anchor = AnchorState { genesis: OutPoint { txid: [3; 32], vout: 1 }, sequencer: xonly(&seq), seal: OutPoint { txid: [4; 32], vout: 0 }, height: 5, root, block: Header(anchor_block).hash() };
        let (sr_s, before) = ([0x33; 32], [0x30; 32]);
        let roots = vec![[0x34; 32], root, [0x36; 32]];
        let hist = roots.iter().fold(hist_next(&before, &sr_s), |h, r| hist_next(&h, r));
        let state = Anchored {
            height: 5,
            nullifiers: n,
            signature: seq.sign_raw(&root, &[0; 32]).unwrap().to_bytes(),
            sequencer: xonly(&seq),
            hub: xonly(&hub),
            chain_height: 6,
            chain_root: [0x36; 32],
            recent: [6; 32],
            hist,
            anchor,
            headers,
            work: 10 * btc::work(0x207fffff),
        };
        let proof = smt::proof(&set, &nf, smt::empties());
        let input = CounterInput { c: 42, deposit: DEPOSIT, b: 9, h_s: 3, sr_s, nullifiers: vec![nf, other], which: 0, spent: Spent::Spend, state, tree, proof, before, roots, request: Some(request), earlier: vec![] };
        (input, [8; 32])
    }

    /// `input` with the cited nullifier's leaf `spent` instead.
    fn spent_as(input: &CounterInput, spent: Spent) -> CounterInput {
        let mut i = input.clone();
        let set = [(i.nullifiers[0], spent.leaf()), ([0x77; 32], smt::spent())];
        i.state.nullifiers = smt::root(&set, smt::empties());
        let root = state_root(5, &i.tree, &i.state.nullifiers);
        i.state.anchor.root = root;
        i.state.signature = key(1).sign_raw(&root, &[0; 32]).unwrap().to_bytes();
        i.roots[1] = root;
        i.state.hist = i.roots.iter().fold(hist_next(&i.before, &i.sr_s), |h, r| hist_next(&h, r));
        i.proof = smt::proof(&set, &i.nullifiers[0], smt::empties());
        i.spent = spent;
        i
    }

    fn ok(input: &CounterInput, id: &Hash) -> impl FnMut(&[u8]) -> bool {
        let good = input.state.chain_journal(id).to_bytes();
        move |c: &[u8]| c == good
    }

    #[test]
    fn a_spend_before_the_request() {
        let (i, id) = input();
        let j = check(&i, &id, &mut ok(&i, &id)).unwrap();
        assert_eq!(&j[..32], &i.state.check(&i.tree, &id, &mut |_| true).unwrap());
        assert_eq!(&j[32..], &fingerprint(42, &DEPOSIT, 9, 3, &i.sr_s, &i.nullifiers));
        // the request in the anchor's own block: final at the same time
        let mut same = i.clone();
        let (anchor_block, req) = request(&[0x99; 32], &DEPOSIT);
        same.state.anchor.block = Header(anchor_block).hash();
        same.state.headers = headers_on(&same.state.anchor.block, 10);
        same.request = Some(req);
        let same = spent_as(&same, Spent::Spend);
        assert!(check(&same, &id, &mut ok(&same, &id)).is_ok());
        // the encoding round-trips, and refuses a byte more or less
        assert_eq!(CounterInput::from_bytes(&i.to_bytes()).unwrap(), i);
        assert_eq!(CounterInput::from_bytes(&i.to_bytes()[1..]), Err(Reject::Encoding));
        let c = Counter::Spent(i.clone());
        assert_eq!(Counter::from_bytes(&c.to_bytes()), Ok(c.clone()));
        assert_eq!(check_counter(&c, &id, &mut ok(&i, &id)), Ok(j));
        let mut long = i.to_bytes();
        long.push(0);
        assert_eq!(CounterInput::from_bytes(&long), Err(Reject::Encoding));
    }

    #[test]
    fn what_counts_by_how_it_was_spent() {
        let (i, id) = input();
        let counts = |i: &CounterInput| check(i, &id, &mut ok(i, &id)).map(|_| ());
        // contract 42's own return of at least b, or its own exit record:
        // never
        assert_eq!(counts(&spent_as(&i, Spent::Return { c: 42, r: 9 })), Err(Reject::Own));
        assert_eq!(counts(&spent_as(&i, Spent::Return { c: 42, r: 20 })), Err(Reject::Own));
        assert_eq!(counts(&spent_as(&i, Spent::Exit { c: 42 })), Err(Reject::Own));
        // a return of less than b, or to another contract: an ordinary
        // spend, so only with the request
        for s in [Spent::Return { c: 42, r: 8 }, Spent::Return { c: 43, r: 9 }] {
            let mut r = spent_as(&i, s);
            assert_eq!(counts(&r), Ok(()));
            r.request = None;
            assert_eq!(counts(&r), Err(Reject::Cutoff));
        }
        // another contract's exit record: whenever anchored, no request
        let mut x = spent_as(&i, Spent::Exit { c: 43 });
        x.request = None;
        assert_eq!(counts(&x), Ok(()));
        // the leaf must be the one named
        let mut lie = spent_as(&i, Spent::Return { c: 42, r: 9 });
        lie.spent = Spent::Spend;
        assert_eq!(counts(&lie), Err(Reject::NotSpent));
        let mut lie = i.clone();
        lie.spent = Spent::Exit { c: 43 };
        assert_eq!(counts(&lie), Err(Reject::NotSpent));
        // a nullifier the claim doesn't name, or one not spent at S'
        let mut w = i.clone();
        w.which = 2;
        assert_eq!(counts(&w), Err(Reject::NotSpent));
        let mut w = i.clone();
        w.which = 1;
        w.proof = smt::proof(&[(w.nullifiers[0], smt::spent()), ([0x77; 32], smt::spent())], &w.nullifiers[1], smt::empties());
        assert_eq!(counts(&w), Err(Reject::NotSpent));
    }

    /// Alice's claim through contract 42 (`exit`'s), and her signed claim
    /// of the same notes through 43, as its `request` posted it: an
    /// equivocation citing her transparent note.
    fn equivocation_input() -> EquivocationInput {
        let (claim, _) = crate::exit::tests::input();
        let mut other = claim.clone();
        (other.c, other.deposit) = (43, OutPoint { txid: [13; 32], vout: 0 });
        crate::exit::tests::sign(&mut other);
        let posted = crate::exit::posted(&other);
        let which = posted.notes.iter().position(|n| matches!(n, PostedNote::Transparent { .. })).unwrap() as u8;
        let p = crate::exit::posted(&claim);
        EquivocationInput {
            c: claim.c,
            deposit: claim.deposit,
            b: claim.b,
            h_s: p.h_s,
            sr_s: p.sr_s,
            nullifiers: p.nullifiers(),
            d: [0x0d; 32],
            other_c: other.c,
            other_deposit: other.deposit,
            other_b: other.b,
            other: posted,
            which,
        }
    }

    #[test]
    fn a_note_claimed_through_two_contracts() {
        let i = equivocation_input();
        let j = equivocation(&i).unwrap();
        assert_eq!(&j[..32], &[0x0d; 32], "D as given: no state");
        assert_eq!(&j[32..], &fingerprint(42, &i.deposit, i.b, i.h_s, &i.sr_s, &i.nullifiers));
        let c = Counter::Equivocation(i.clone());
        assert_eq!(check_counter(&c, &[8; 32], &mut |_| false), Ok(j));
        assert_eq!(Counter::from_bytes(&c.to_bytes()), Ok(c.clone()));
        assert_eq!(Counter::from_bytes(&c.to_bytes()[..c.to_bytes().len() - 1]), Err(Reject::Encoding));
        // the same contract: her own claim
        let mut x = i.clone();
        x.other_c = 42;
        assert_eq!(equivocation(&x), Err(Reject::Own));
        // a signature on another claim than the one cited (another b, so
        // another E')
        let mut x = i.clone();
        x.other_b -= 1;
        assert_eq!(equivocation(&x), Err(Reject::NotYours));
        // a shielded note: nothing signed to cite; no note at all
        let mut x = i.clone();
        x.which = x.other.notes.iter().position(|n| matches!(n, PostedNote::Shielded { .. })).unwrap() as u8;
        assert_eq!(equivocation(&x), Err(Reject::NotYours));
        let mut x = i.clone();
        x.which = 2;
        assert_eq!(equivocation(&x), Err(Reject::NotYours));
        // a note the claim doesn't name
        let mut x = i.clone();
        let PostedNote::Transparent { note, .. } = &x.other.notes[x.which as usize] else { unreachable!() };
        let nf = note.nullifier();
        x.nullifiers.retain(|n| *n != nf);
        assert_eq!(equivocation(&x), Err(Reject::NotSpent));
        // someone else's key over the note: not the owner's signature
        let mut x = i.clone();
        let other_e = x.other.fingerprint(x.other_c, &x.other_deposit, x.other_b);
        if let PostedNote::Transparent { sig, .. } = &mut x.other.notes[x.which as usize] {
            *sig = key(9).sign_raw(&signed_digest(&other_e), &[0; 32]).unwrap().to_bytes();
        }
        assert_eq!(equivocation(&x), Err(Reject::NotYours));
    }

    #[test]
    fn the_grace() {
        let (mut i, id) = input();
        // `request` two blocks before the anchor's: its block, a parent,
        // then the anchor's block
        let (req_block, request) = request(&[0x98; 32], &DEPOSIT);
        let parent = header_with(&Header(req_block).hash(), &[0; 32]);
        let anchor_block = header_with(&Header(parent).hash(), &[0; 32]);
        i.state.anchor.block = Header(anchor_block).hash();
        i.state.headers = headers_on(&i.state.anchor.block, 10);
        i.request = Some(request);
        i.earlier = vec![anchor_block, parent, req_block];
        let counts = |i: &CounterInput, grace| check_with(i, grace, &id, &mut ok(i, &id)).map(|_| ());
        assert_eq!(counts(&i, 2), Ok(()));
        assert_eq!(counts(&i, 1), Err(Reject::Cutoff), "beyond the grace");
        assert_eq!(check(&i, &id, &mut ok(&i, &id)), Err(Reject::Cutoff), "none yet");
        let mut r = i.clone();
        r.earlier.swap(1, 2);
        assert_eq!(counts(&r, 2), Err(Reject::Cutoff), "headers that don't link back");
        let mut r = i.clone();
        r.earlier.remove(0);
        assert_eq!(counts(&r, 2), Err(Reject::Cutoff), "not from the anchor's block");
        assert_eq!(CounterInput::from_bytes(&i.to_bytes()), Ok(i));
    }

    #[test]
    fn the_cutoff_and_the_history() {
        let (i, id) = input();
        let counts = |i: &CounterInput| check(i, &id, &mut ok(i, &id)).map(|_| ());
        // no request; a transaction not spending O; a block not on S''s
        // anchor (before it, say); not in the block named
        let mut r = i.clone();
        r.request = None;
        assert_eq!(counts(&r), Err(Reject::Cutoff));
        let mut r = i.clone();
        let (h, req) = block_with(&Header(i.state.headers[1]).hash(), tx_spending(&OutPoint { txid: [12; 32], vout: 3 }));
        r.state.headers[2] = h;
        r.request = Some(req);
        assert_eq!(counts(&r).unwrap_err(), Reject::Depth, "another block breaks the chain of headers");
        let mut r = i.clone();
        r.request.as_mut().unwrap().tx = tx_spending(&OutPoint { txid: [12; 32], vout: 3 }).0;
        assert_eq!(counts(&r), Err(Reject::Cutoff));
        let mut r = i.clone();
        r.request.as_mut().unwrap().reserved = [0; 32];
        assert_eq!(counts(&r), Err(Reject::Cutoff), "another witness reserved value");
        // request at the tip: in the headers, but without the work on it
        let mut r = i.clone();
        let tip = Header(*r.state.headers.last().unwrap()).hash();
        let (h, req) = request(&tip, &DEPOSIT);
        r.state.headers.push(h);
        r.request = Some(req);
        assert!(r.state.check(&r.tree, &id, &mut ok(&r, &id)).is_ok());
        assert_eq!(counts(&r), Err(Reject::Cutoff), "a block at the tip is cheap to forge");
        // a request spending the funding of another deposit
        let mut r = i.clone();
        let (h, req) = request(&Header(i.state.headers[1]).hash(), &OutPoint { txid: [12; 32], vout: 3 });
        r.state.headers[2] = h;
        r.state.headers.truncate(3);
        r.state.headers.extend(headers_on(&Header(h).hash(), 9));
        r.request = Some(req);
        assert!(r.state.check(&r.tree, &id, &mut ok(&r, &id)).is_ok());
        assert_eq!(counts(&r), Err(Reject::Cutoff), "another contract's request");
        let mut r = i.clone();
        let (h, req) = request(&[0x55; 32], &DEPOSIT);
        r.request = Some(Request { header: h, ..req });
        assert_eq!(counts(&r), Err(Reject::Cutoff), "a block that isn't on the anchor's");
        let mut r = i.clone();
        r.request.as_mut().unwrap().path = vec![[1; 32]];
        assert_eq!(counts(&r), Err(Reject::Cutoff), "a witness path but the coinbase's zero");
        let mut r = i.clone();
        r.request.as_mut().unwrap().coinbase_path.push([0; 32]);
        assert_eq!(counts(&r), Err(Reject::Cutoff), "a path that isn't the tree's depth");
        // S' not in S's history: another root, a root missing, another S
        let mut h = i.clone();
        h.roots[0] = [0; 32];
        assert_eq!(counts(&h), Err(Reject::History));
        let mut h = i.clone();
        h.roots.remove(0);
        assert_eq!(counts(&h), Err(Reject::History));
        let mut h = i.clone();
        h.sr_s = [0; 32];
        assert_eq!(counts(&h), Err(Reject::History));
        // S' as a withdrawal's state: no receipt, not anchored
        assert_eq!(check(&i, &id, &mut |_| false), Err(Reject::Chain));
        let mut a = i.clone();
        a.state.anchor.root = [0; 32];
        assert_eq!(counts(&a), Err(Reject::NotAnchored));
    }
}

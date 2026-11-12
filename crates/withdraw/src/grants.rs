//! The grants L2's statement (docs/GRANTS_PLAN.md, milestone 2): "the
//! claim posted in `request` is owed at most `b_corr`", the hub's
//! correction, one-time signed in `correct`. And the hashes and encodings
//! the notes, spends, grants and claims are made of: one implementation,
//! for the wallet, the hub (`lichen_notes`) and the guest.
//!
//! - **The claim** ([`Claim`]): settled notes of the contract's owner (the
//!   hub's BIP340 signature on each), fallbacks (the ids of spends in
//!   flight whose inputs are among the notes: if the hub shows one
//!   recorded, the claimant's change of it counts instead), `b` in the
//!   contract's units, the owner's signature on its fingerprint `E`.
//! - **Owed**: 0 for a malformed claim (not as posted under her one-time
//!   signatures, a note not settled or not hers, her signature, `b` above
//!   the notes); else the notes not killed, plus the change of the
//!   fallbacks revived, in units, at most `b`. A note is killed by a
//!   spend she signed (with its grant's commitment) whose unlock `t` the
//!   hub put on chain (`t·G = T`), or by another claim she signed naming
//!   it; a killing spend's change is revived if the claim names it a
//!   fallback.
//! - **The statement** holds iff `owed ≤ b_corr`. It reads `request` (the
//!   contract output's spend), `correct` (`request`'s), and the hub's
//!   child of `correct` (its `OP_RETURN`: the unlocks), each in a block of
//!   the headers given, which carry the contract's work on `request`'s
//!   block. Its journal is the hub-proves one, fixed at the opening.

use alloc::vec::Vec;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::schnorr::{Signature, VerifyingKey};
use lichen_validity::btc::{self, Header};
use lichen_validity::OutPoint;
use sha2::{Digest, Sha256};

use crate::codec::{R, W};
use crate::hp::{journal, requested, signed_message, checksum_digits, JOURNAL_LEN};
use crate::{contract_id, deployment_id, work_on, Hash, Reject, Request};

/// The most notes, fallbacks, cited spends and other claims a statement
/// takes.
pub const MAX_NOTES: usize = 8;
pub const MAX_FALLBACKS: usize = 4;
pub const MAX_CITED: usize = 4;
/// The unlocks the hub's child of `correct` carries: two, in an
/// `OP_RETURN` of 64 bytes (Core 29 relays 83).
pub const MAX_UNLOCKS: usize = 2;

// ----- the hashes -----

/// A domain-separated hash of length-prefixed parts.
pub fn tagged(tag: &str, parts: &[&[u8]]) -> Hash {
    let mut s = Sha256::new();
    s.update(tag.as_bytes());
    s.update([0u8]);
    for p in parts {
        s.update((p.len() as u32).to_be_bytes());
        s.update(p);
    }
    s.finalize().into()
}

/// A note: `(id, owner, value)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    pub id: Hash,
    pub owner: Hash,
    pub value: u64,
}

impl Note {
    /// What the hub signs to issue it.
    pub fn digest(&self) -> Hash {
        tagged("lichen/notes/note", &[&self.id, &self.owner, &self.value.to_be_bytes()])
    }
}

/// A spend's id, from its inputs and its outputs `(owner, value)`.
pub fn spend_id(inputs: &[Note], outputs: &[(Hash, u64)]) -> Hash {
    let mut parts: Vec<Vec<u8>> = alloc::vec![(inputs.len() as u32).to_be_bytes().to_vec()];
    parts.extend(inputs.iter().map(|n| n.digest().to_vec()));
    parts.push((outputs.len() as u32).to_be_bytes().to_vec());
    parts.extend(outputs.iter().map(|(o, v)| [o.to_vec(), v.to_be_bytes().to_vec()].concat()));
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    tagged("lichen/notes/spend", &refs)
}

/// The id of a spend's output `j`.
pub fn output_id(sid: &Hash, j: u32) -> Hash {
    tagged("lichen/notes/out", &[sid, &j.to_be_bytes()])
}

/// A grant's commitment: the spend, `T` (33 bytes), and each output's
/// pre-signature (`R'` x-only, `R`, `s'`: 97 bytes).
pub fn grant_commitment(sid: &Hash, t_point: &[u8; 33], presigs: &[[u8; 97]]) -> Hash {
    let mut parts: Vec<&[u8]> = alloc::vec![sid.as_slice(), t_point.as_slice()];
    parts.extend(presigs.iter().map(|p| p.as_slice()));
    tagged("lichen/notes/grant-commitment", &parts)
}

/// What each input's owner signs to make a spend.
pub fn auth_msg(sid: &Hash, commitment: &Hash) -> Hash {
    tagged("lichen/notes/auth", &[sid, commitment])
}

/// Whether `sig` is `pk`'s BIP340 signature on `msg`.
pub fn verify(pk: &Hash, msg: &Hash, sig: &[u8; 64]) -> bool {
    let (Ok(k), Ok(s)) = (VerifyingKey::from_bytes(pk), Signature::try_from(&sig[..])) else { return false };
    k.verify_raw(msg, &s).is_ok()
}

// ----- the claim -----

/// A settled note in a claim: its id, value and the hub's signature (its
/// owner is the claim's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item {
    pub id: Hash,
    pub value: u64,
    pub sig: [u8; 64],
}

/// A claim of `b` units of contract `cid` (its deposit coin `deposit`) by
/// `owner`: settled notes, fallbacks, her signature on `E`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub cid: u32,
    pub deposit: OutPoint,
    pub b: u32,
    pub owner: Hash,
    pub notes: Vec<Item>,
    pub fallbacks: Vec<Hash>,
    pub sig: [u8; 64],
}

impl Claim {
    pub fn note(&self, i: &Item) -> Note {
        Note { id: i.id, owner: self.owner, value: i.value }
    }
    /// `E`: what the owner signs, and an exit's one-time key signs.
    pub fn fingerprint(&self) -> Hash {
        let mut parts: Vec<Vec<u8>> = alloc::vec![self.cid.to_be_bytes().to_vec(), self.deposit.to_bytes().to_vec(), self.b.to_be_bytes().to_vec(), self.owner.to_vec()];
        parts.push((self.notes.len() as u32).to_be_bytes().to_vec());
        parts.extend(self.notes.iter().map(|i| self.note(i).digest().to_vec()));
        parts.push((self.fallbacks.len() as u32).to_be_bytes().to_vec());
        parts.extend(self.fallbacks.iter().map(|f| f.to_vec()));
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        tagged("lichen/notes/claim", &refs)
    }
    /// Its bytes, as an exit posts them.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(self.cid.to_be_bytes());
        v.extend(self.deposit.to_bytes());
        v.extend(self.b.to_be_bytes());
        v.extend(self.owner);
        v.push(self.notes.len() as u8);
        for i in &self.notes {
            v.extend(i.id);
            v.extend(i.value.to_be_bytes());
            v.extend(i.sig);
        }
        v.push(self.fallbacks.len() as u8);
        for f in &self.fallbacks {
            v.extend(f);
        }
        v.extend(self.sig);
        v
    }
    pub fn from_bytes(b: &[u8]) -> Option<Claim> {
        let mut r = R(b);
        let cid = u32::from_be_bytes(r.take().ok()?);
        let deposit = OutPoint::from_bytes(&r.take().ok()?);
        let bb = u32::from_be_bytes(r.take().ok()?);
        let owner: Hash = r.take().ok()?;
        let [n] = r.take().ok()?;
        if n as usize > MAX_NOTES {
            return None;
        }
        let mut notes = Vec::new();
        for _ in 0..n {
            notes.push(Item { id: r.take().ok()?, value: u64::from_be_bytes(r.take().ok()?), sig: r.take().ok()? });
        }
        let [f] = r.take().ok()?;
        if f as usize > MAX_FALLBACKS {
            return None;
        }
        let fallbacks = (0..f).map(|_| r.take().ok()).collect::<Option<Vec<Hash>>>()?;
        let sig = r.take().ok()?;
        r.0.is_empty().then_some(Claim { cid, deposit, b: bb, owner, notes, fallbacks, sig })
    }
    /// The claim shows itself whole: by `owner`, its notes distinct, each
    /// settled under `issuer`, its fallbacks distinct, her signature on
    /// `E`, `b` within the notes' value in units of `unit`. Their value.
    pub fn holds(&self, issuer: &Hash, owner: &Hash, unit: u64) -> Option<u64> {
        if self.owner != *owner || self.notes.is_empty() || unit == 0 {
            return None;
        }
        for (k, i) in self.notes.iter().enumerate() {
            if self.notes[..k].iter().any(|j| j.id == i.id) || !verify(issuer, &self.note(i).digest(), &i.sig) {
                return None;
            }
        }
        for (k, f) in self.fallbacks.iter().enumerate() {
            if self.fallbacks[..k].contains(f) {
                return None;
            }
        }
        if !verify(owner, &self.fingerprint(), &self.sig) {
            return None;
        }
        let total = self.notes.iter().try_fold(0u64, |a, i| a.checked_add(i.value))?;
        (u64::from(self.b) <= total / unit).then_some(total)
    }
}

// ----- the statement's input -----

/// A spend the hub cites: what she signed (the spend, its grant's `T` and
/// pre-signatures), her signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cited {
    pub inputs: Vec<Note>,
    pub outputs: Vec<(Hash, u64)>,
    pub t_point: [u8; 33],
    pub presigs: Vec<[u8; 97]>,
    pub sig: [u8; 64],
}

impl Cited {
    pub fn sid(&self) -> Hash {
        spend_id(&self.inputs, &self.outputs)
    }
    /// Signed by `owner` with its grant.
    fn signed_by(&self, owner: &Hash) -> bool {
        let sid = self.sid();
        verify(owner, &auth_msg(&sid, &grant_commitment(&sid, &self.t_point, &self.presigs)), &self.sig)
    }
}

/// A transaction (non-witness serialization) in a block: its index and
/// path, the block's coinbase and its path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InBlock {
    pub tx: Vec<u8>,
    pub header: [u8; 80],
    pub index: u32,
    pub path: Vec<Hash>,
    pub coinbase: Vec<u8>,
    pub coinbase_path: Vec<Hash>,
}

impl InBlock {
    fn holds(&self) -> bool {
        btc::in_block(&self.tx, &Header(self.header), self.index, &self.path, &self.coinbase, &self.coinbase_path)
    }
}

/// The contract as the statement needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GTerms {
    /// The hub's issuer key, which signs every note.
    pub issuer: Hash,
    /// The contract owner's L2 key.
    pub owner: Hash,
    pub work: u128,
    pub unit: u64,
}

impl GTerms {
    /// `D`: the deployment (the issuer's), no genesis seal, the work `W`,
    /// the unit.
    pub fn d(&self) -> Hash {
        contract_id(&deployment_id(&self.issuer, &self.issuer), &OutPoint { txid: [0; 32], vout: 0 }, self.work, self.unit)
    }
}

/// The hub's statement's input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantsInput {
    pub c: u32,
    pub deposit: OutPoint,
    pub margin: u32,
    pub terms: GTerms,
    /// `request` (its witness serialization) with the funding.
    pub request: Request,
    /// `correct` (witness serialization), spending `request`'s output, in
    /// a block of `headers`.
    pub correct: Request,
    /// The hub's child of `correct` (spending its anchor), in a block of
    /// `headers`: its `OP_RETURN` carries the unlocks. None: no unlocks.
    pub child: Option<InBlock>,
    /// From `request`'s block on, consecutive.
    pub headers: Vec<[u8; 80]>,
    pub cited: Vec<Cited>,
    /// Other claims she signed.
    pub others: Vec<Vec<u8>>,
}

/// A transaction's id from its witness serialization.
pub fn txid_of(witness_tx: &[u8]) -> Option<Hash> {
    // version, then (past the marker) inputs and outputs, then witnesses,
    // then the lock time: the id hashes all but the marker and witnesses
    let t = btc::parse_witness_tx(witness_tx)?;
    let mut v = Vec::with_capacity(witness_tx.len());
    v.extend(&witness_tx[..4]);
    let body_len = body_len(&witness_tx[6..], t.tx.inputs.len(), t.tx.outputs.len())?;
    v.extend(&witness_tx[6..6 + body_len]);
    v.extend(&witness_tx[witness_tx.len() - 4..]);
    Some(btc::sha256d(&v))
}

fn varint(b: &[u8], at: &mut usize) -> Option<usize> {
    let first = *b.get(*at)?;
    *at += 1;
    let (n, k) = match first {
        0xfd => (u16::from_le_bytes(b.get(*at..*at + 2)?.try_into().ok()?) as u64, 2),
        0xfe => (u32::from_le_bytes(b.get(*at..*at + 4)?.try_into().ok()?) as u64, 4),
        0xff => (u64::from_le_bytes(b.get(*at..*at + 8)?.try_into().ok()?), 8),
        n => (n as u64, 0),
    };
    *at += k;
    usize::try_from(n).ok()
}

/// The length of a transaction's body (its input and output counts and
/// lists).
fn body_len(b: &[u8], inputs: usize, outputs: usize) -> Option<usize> {
    let mut at = 0;
    if varint(b, &mut at)? != inputs {
        return None;
    }
    for _ in 0..inputs {
        at += 36;
        let s = varint(b, &mut at)?;
        at += s + 4;
    }
    if varint(b, &mut at)? != outputs {
        return None;
    }
    for _ in 0..outputs {
        at += 8;
        let s = varint(b, &mut at)?;
        at += s;
    }
    (at <= b.len()).then_some(at)
}

/// `correct`'s witness: the hub's one-time signature on `b_corr` (4
/// bytes), below the 2-of-2's signatures, the script and the control
/// block.
pub fn corrected(witness: &[&[u8]]) -> Option<u32> {
    let items = 2 * (8 + checksum_digits(4));
    if witness.len() != items + 4 {
        return None;
    }
    let b = signed_message(&witness[..items], 4)?;
    Some(u32::from_be_bytes(b.try_into().ok()?))
}

/// The unlocks an `OP_RETURN` script carries: 32 bytes each.
fn unlocks(script: &[u8]) -> Option<Vec<[u8; 32]>> {
    // OP_RETURN, then one push of 32·k bytes
    let (&op, rest) = script.split_first()?;
    if op != 0x6a {
        return None;
    }
    let (&len, data) = rest.split_first()?;
    let data = match len {
        1..=75 if data.len() == len as usize => data,
        0x4c if !data.is_empty() && data.len() == data[0] as usize + 1 => &data[1..],
        _ => return None,
    };
    (data.len() % 32 == 0 && data.len() / 32 <= MAX_UNLOCKS).then(|| data.chunks(32).map(|c| c.try_into().unwrap()).collect())
}

/// `t·G`, compressed.
fn point_of(t: &[u8; 32]) -> Option<[u8; 33]> {
    let s: k256::Scalar = Option::from(k256::Scalar::from_repr((*t).into()))?;
    let p = (k256::ProjectivePoint::GENERATOR * s).to_affine();
    p.to_encoded_point(true).as_bytes().try_into().ok()
}

/// What the claim is owed, in units, by the evidence: the cited spends
/// (each signed by her; counting if its `T`'s unlock is among `unlocks`)
/// and the other claims she signed.
pub fn owed(claim: Option<&Claim>, issuer: &Hash, owner: &Hash, unit: u64, cited: &[Cited], unlocks: &[[u8; 32]], others: &[Vec<u8>]) -> u32 {
    let Some(claim) = claim else { return 0 };
    if claim.holds(issuer, owner, unit).is_none() {
        return 0;
    }
    let e = claim.fingerprint();
    let mut dead: Vec<Hash> = Vec::new();
    let mut revived: u64 = 0;
    for c in cited {
        if !c.signed_by(owner) || !unlocks.iter().any(|t| point_of(t) == Some(c.t_point)) {
            continue;
        }
        let sid = c.sid();
        let killed: Vec<Hash> = c.inputs.iter().map(|n| n.id).filter(|id| claim.notes.iter().any(|i| i.id == *id)).collect();
        if killed.is_empty() {
            continue;
        }
        if claim.fallbacks.contains(&sid) {
            revived = revived.saturating_add(c.outputs.iter().filter(|(o, _)| o == owner).map(|(_, v)| *v).sum());
        }
        dead.extend(killed);
    }
    for o in others {
        let Some(other) = Claim::from_bytes(o) else { continue };
        if other.owner != *owner || other.fingerprint() == e || !verify(owner, &other.fingerprint(), &other.sig) {
            continue;
        }
        dead.extend(other.notes.iter().map(|i| i.id).filter(|id| claim.notes.iter().any(|i| i.id == *id)));
    }
    let live: u64 = claim.notes.iter().filter(|i| !dead.contains(&i.id)).map(|i| i.value).sum::<u64>().saturating_add(revived);
    claim.b.min(u32::try_from(live / unit).unwrap_or(u32::MAX))
}

/// The hub's statement: the claim `request` posts is owed at most the
/// `b_corr` `correct` signs. Its journal, or why not.
pub fn check(input: &GrantsInput) -> Result<[u8; JOURNAL_LEN], Reject> {
    let t = &input.terms;
    if t.unit == 0 || input.cited.len() > MAX_CITED || input.others.len() > MAX_CITED {
        return Err(Reject::Encoding);
    }
    // request: the contract output's spend, in a block with the work on it
    let witness = input.request.spending(&input.deposit).ok_or(Reject::Posted)?;
    let header = Header(input.request.header);
    if input.headers.first() != Some(&input.request.header) {
        return Err(Reject::Depth);
    }
    if work_on(&header.hash(), &input.headers[1..]).is_none_or(|w| w < t.work) {
        return Err(Reject::Depth);
    }
    let r = requested(&witness).ok_or(Reject::Posted)?;
    let claim = Claim::from_bytes(&r.posted).filter(|c| c.fingerprint() == r.e && c.b == r.b && c.cid == input.c && c.deposit == input.deposit);
    // correct: request's spend, in a block of the headers
    let request_id = txid_of(&input.request.tx).ok_or(Reject::Posted)?;
    let in_headers = |h: &[u8; 80]| input.headers.contains(h);
    let c = &input.correct;
    if !in_headers(&c.header) || !btc::witness_in_block(&c.tx, &Header(c.header), c.index, &c.path, &c.coinbase, &c.coinbase_path, &c.reserved) {
        return Err(Reject::Posted);
    }
    let ct = btc::parse_witness_tx(&c.tx).ok_or(Reject::Posted)?;
    let at = ct.tx.inputs.iter().position(|o| *o == OutPoint { txid: request_id, vout: 0 }).ok_or(Reject::Posted)?;
    let b_corr = corrected(&ct.witness[at]).ok_or(Reject::Posted)?;
    let correct_id = txid_of(&c.tx).ok_or(Reject::Posted)?;
    // the unlocks: the hub's child of correct, in a block of the headers
    let unlocks = match &input.child {
        None => Vec::new(),
        Some(ch) => {
            if !in_headers(&ch.header) || !ch.holds() {
                return Err(Reject::Posted);
            }
            let tx = btc::parse_tx(&ch.tx).ok_or(Reject::Posted)?;
            if !tx.inputs.contains(&OutPoint { txid: correct_id, vout: 1 }) {
                return Err(Reject::Posted);
            }
            tx.outputs.iter().find_map(|(_, s)| unlocks(s)).ok_or(Reject::Posted)?
        }
    };
    if owed(claim.as_ref(), &t.issuer, &t.owner, t.unit, &input.cited, &unlocks, &input.others) > b_corr {
        return Err(Reject::Holds);
    }
    Ok(journal(input.c, &t.d(), &input.deposit, input.margin))
}

// ----- encodings -----

impl GrantsInput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.put(&self.c.to_be_bytes());
        w.put(&self.deposit.to_bytes());
        w.put(&self.margin.to_be_bytes());
        w.put(&self.terms.issuer);
        w.put(&self.terms.owner);
        w.put(&self.terms.work.to_be_bytes());
        w.put(&self.terms.unit.to_be_bytes());
        self.request.write(&mut w);
        self.correct.write(&mut w);
        match &self.child {
            None => w.put(&[0]),
            Some(ch) => {
                w.put(&[1]);
                w.bytes(&ch.tx);
                w.put(&ch.header);
                w.put(&ch.index.to_be_bytes());
                w.list(&ch.path);
                w.bytes(&ch.coinbase);
                w.list(&ch.coinbase_path);
            }
        }
        w.list(&self.headers);
        w.put(&(self.cited.len() as u32).to_be_bytes());
        for c in &self.cited {
            w.put(&(c.inputs.len() as u32).to_be_bytes());
            for n in &c.inputs {
                w.put(&n.id);
                w.put(&n.owner);
                w.put(&n.value.to_be_bytes());
            }
            w.put(&(c.outputs.len() as u32).to_be_bytes());
            for (o, v) in &c.outputs {
                w.put(o);
                w.put(&v.to_be_bytes());
            }
            w.put(&c.t_point);
            w.list(&c.presigs);
            w.put(&c.sig);
        }
        w.put(&(self.others.len() as u32).to_be_bytes());
        for o in &self.others {
            w.bytes(o);
        }
        w.0
    }

    pub fn from_bytes(b: &[u8]) -> Result<GrantsInput, Reject> {
        let mut r = R(b);
        let c = u32::from_be_bytes(r.take()?);
        let deposit = OutPoint::from_bytes(&r.take()?);
        let margin = u32::from_be_bytes(r.take()?);
        let terms = GTerms { issuer: r.take()?, owner: r.take()?, work: u128::from_be_bytes(r.take()?), unit: u64::from_be_bytes(r.take()?) };
        let request = Request::read(&mut r)?;
        let correct = Request::read(&mut r)?;
        let child = match r.take()? {
            [0] => None,
            [1] => Some(InBlock { tx: r.bytes()?, header: r.take()?, index: u32::from_be_bytes(r.take()?), path: r.list()?, coinbase: r.bytes()?, coinbase_path: r.list()? }),
            _ => return Err(Reject::Encoding),
        };
        let headers = r.list()?;
        let n = u32::from_be_bytes(r.take()?) as usize;
        if n > MAX_CITED {
            return Err(Reject::Encoding);
        }
        let mut cited = Vec::new();
        for _ in 0..n {
            let ni = u32::from_be_bytes(r.take()?) as usize;
            if ni > 64 {
                return Err(Reject::Encoding);
            }
            let inputs = (0..ni).map(|_| Ok(Note { id: r.take()?, owner: r.take()?, value: u64::from_be_bytes(r.take()?) })).collect::<Result<Vec<_>, Reject>>()?;
            let no = u32::from_be_bytes(r.take()?) as usize;
            if no > 64 {
                return Err(Reject::Encoding);
            }
            let outputs = (0..no).map(|_| Ok((r.take()?, u64::from_be_bytes(r.take()?)))).collect::<Result<Vec<_>, Reject>>()?;
            cited.push(Cited { inputs, outputs, t_point: r.take()?, presigs: r.list()?, sig: r.take()? });
        }
        let n = u32::from_be_bytes(r.take()?) as usize;
        if n > MAX_CITED {
            return Err(Reject::Encoding);
        }
        let others = (0..n).map(|_| r.bytes()).collect::<Result<Vec<_>, _>>()?;
        if !r.0.is_empty() {
            return Err(Reject::Encoding);
        }
        Ok(GrantsInput { c, deposit, margin, terms, request, correct, child, headers, cited, others })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use k256::schnorr::SigningKey;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32]).unwrap()
    }
    fn pk(k: &SigningKey) -> Hash {
        k.verifying_key().to_bytes().into()
    }
    fn sign(k: &SigningKey, msg: &Hash) -> [u8; 64] {
        k.sign_raw(msg, &[0; 32]).unwrap().to_bytes()
    }
    fn item(issuer: &SigningKey, owner: &Hash, id: u8, value: u64) -> Item {
        let n = Note { id: [id; 32], owner: *owner, value };
        Item { id: n.id, value, sig: sign(issuer, &n.digest()) }
    }
    fn claim(owner: &SigningKey, b: u32, notes: Vec<Item>, fallbacks: Vec<Hash>) -> Claim {
        let mut c = Claim { cid: 7, deposit: OutPoint { txid: [9; 32], vout: 0 }, b, owner: pk(owner), notes, fallbacks, sig: [0; 64] };
        c.sig = sign(owner, &c.fingerprint());
        c
    }
    /// A spend of `inputs` by `owner`: `pay` to another, the rest back, its
    /// grant's T the point of `t`.
    fn spend(owner: &SigningKey, inputs: Vec<Note>, pay: u64, t: &[u8; 32]) -> Cited {
        let total: u64 = inputs.iter().map(|n| n.value).sum();
        let outputs = vec![([5; 32], pay), (pk(owner), total - pay)];
        let mut c = Cited { inputs, outputs, t_point: point_of(t).unwrap(), presigs: vec![[3; 97], [4; 97]], sig: [0; 64] };
        let sid = c.sid();
        c.sig = sign(owner, &auth_msg(&sid, &grant_commitment(&sid, &c.t_point, &c.presigs)));
        c
    }

    #[test]
    fn what_a_claim_is_owed() {
        let (hub, alice) = (key(1), key(2));
        let (issuer, owner) = (pk(&hub), pk(&alice));
        let unit = 100;
        let (n1, n2) = (item(&hub, &owner, 1, 70_000), item(&hub, &owner, 2, 30_000));
        let t = [11u8; 32];
        // her spend of n1 in flight: 50,000 to Bob, 20,000 back to her
        let s = spend(&alice, vec![Note { id: n1.id, owner, value: n1.value }], 50_000, &t);
        let with_fallback = claim(&alice, 1000, vec![n1, n2], vec![s.sid()]);
        let owed = |c: &Claim, cited: &[Cited], unlocks: &[[u8; 32]], others: &[Vec<u8>]| super::owed(Some(c), &issuer, &owner, unit, cited, unlocks, others);
        // nothing cited: all of it
        assert_eq!(owed(&with_fallback, &[], &[], &[]), 1000);
        // the spend recorded and its unlock on chain: n1 dead, her change revived
        assert_eq!(owed(&with_fallback, &[s.clone()], &[t], &[]), 500);
        // without its unlock on chain the spend doesn't count
        assert_eq!(owed(&with_fallback, &[s.clone()], &[[12; 32]], &[]), 1000);
        // not declared a fallback: no change revived
        let without = claim(&alice, 1000, vec![n1, n2], vec![]);
        assert_eq!(owed(&without, &[s.clone()], &[t], &[]), 300);
        // a spend not signed by her doesn't count
        let mut forged = s.clone();
        forged.sig = sign(&key(3), &[0; 32]);
        assert_eq!(owed(&with_fallback, &[forged], &[t], &[]), 1000);
        // another claim of hers naming n2 kills it; the same claim doesn't
        let other = Claim { cid: 8, ..claim(&alice, 300, vec![n2], vec![]) };
        let other = Claim { sig: sign(&alice, &other.fingerprint()), ..other };
        assert_eq!(owed(&without, &[], &[], &[other.to_bytes()]), 700);
        assert_eq!(owed(&without, &[], &[], &[without.to_bytes()]), 1000);
        // malformed: a note not settled, her signature, b above the notes
        let bad_note = claim(&alice, 100, vec![Item { sig: [0; 64], ..n1 }], vec![]);
        assert_eq!(owed(&bad_note, &[], &[], &[]), 0);
        let unsigned = Claim { sig: [0; 64], ..without.clone() };
        assert_eq!(owed(&unsigned, &[], &[], &[]), 0);
        let too_much = claim(&alice, 1001, vec![n1, n2], vec![]);
        assert_eq!(owed(&too_much, &[], &[], &[]), 0);
        assert_eq!(super::owed(None, &issuer, &owner, unit, &[], &[], &[]), 0);
        // the bytes round-trip
        assert_eq!(Claim::from_bytes(&with_fallback.to_bytes()), Some(with_fallback));
    }

    #[test]
    fn unlocks_read_from_op_return() {
        let mut s = vec![0x6a, 64];
        s.extend([1u8; 32]);
        s.extend([2u8; 32]);
        assert_eq!(unlocks(&s), Some(vec![[1; 32], [2; 32]]));
        assert_eq!(unlocks(&[0x6a, 32, 0]), None);
        assert!(unlocks(&[0x51]).is_none());
    }
}

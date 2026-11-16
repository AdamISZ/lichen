//! The grants L2's statement (agent notes: docs/GRANTS_PLAN.md, milestones
//! 2 and 4): "the claim posted in `request` is owed at most `b_corr`", the
//! hub's correction, one-time signed in `correct`. And the hashes and
//! encodings the notes, spends, grants and claims are made of: one
//! implementation, for the wallet, the hub (`lichen_notes`) and the guest.
//!
//! - **The claim** ([`Claim`]): settled notes of the contract's owner (the
//!   hub's BIP340 signature on each), fallbacks (the ids of spends in
//!   flight whose inputs are among the notes: if the hub shows one
//!   recorded, the claimant's change of it counts instead), `b` in the
//!   contract's units, the owner's signature on its fingerprint `E`: what
//!   a cooperative withdrawal hands the hub.
//! - **The posted claim** ([`Posted`]): what an exit posts, its
//!   [`POSTED_LEN`] bytes one-time signed in full in `request` (so no one
//!   can swap them): each note by the first 8 bytes of its id, its value
//!   and its signature's `R`, the signatures' `s` half-aggregated into
//!   one; each fallback by its first 8 bytes. The contract (`c`, its
//!   deposit, its owner) and `b` (signed apart) aren't in it.
//! - **Owed**: 0 for a malformed claim (its encoding, a note named twice,
//!   the hub's aggregate signature, `b` above the notes); else the notes
//!   not killed, plus the change of the fallbacks revived, in units, at
//!   most `b`. A note is killed by a spend she signed (with its grant's
//!   commitment) whose unlock `t` the hub revealed to her in `correct`:
//!   one of its [`SLOTS`] holds the hub's signature completing the
//!   grant's pre-signature on `correct` (its reveal), so `t = s − s'`. A
//!   killing spend's change is revived if the claim names it a fallback.
//! - **The statement** holds iff `owed ≤ b_corr`. It reads `request` (the
//!   contract output's spend) and `correct` (`request`'s: `b_corr` and the
//!   slots), each in a block of the headers given, which carry the
//!   contract's work on `request`'s block. Its journal is the hub-proves
//!   one, fixed at the opening; its `D` binds the issuer and the
//!   contract's owner, a key fresh for the contract.

use alloc::vec::Vec;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::DecompressPoint;
use k256::elliptic_curve::subtle::Choice;
use k256::elliptic_curve::PrimeField;
use k256::schnorr::{Signature, VerifyingKey};
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
use lichen_validity::btc::{self, Header};
use lichen_validity::OutPoint;
use sha2::{Digest, Sha256};

use crate::codec::{R, W};
use crate::hp::{journal, signed_message, checksum_digits, JOURNAL_LEN};
use crate::{contract_id, deployment_id, work_on, Hash, Reject, Request};

/// The most notes and fallbacks a claim takes (the posted claim fits
/// fewer of both: [`fits`]).
pub const MAX_NOTES: usize = 4;
pub const MAX_FALLBACKS: usize = 4;
/// `correct`'s slots: each a signature by the hub on `correct`, which
/// completes the reveal of one spend it cites. Enough for every spend a
/// claim's evidence needs: each kills a candidate, and a claim has at
/// most 4 notes and 4 fallbacks, each reviving one output of hers (a
/// spend pays an owner once).
pub const SLOTS: usize = 8;

/// The posted claim's length: its one-time signature (2 digits a byte, 2
/// witness items a digit), `b`'s, and the 2-of-2's fill `request`'s
/// stack to about 960 of Bitcoin's 1,000 elements: four notes and two
/// fallbacks, or three and four.
pub const POSTED_LEN: usize = 233;
/// A posted note: its id's first 8 bytes, its value (6 bytes), its
/// signature's `R`.
const SHORT_LEN: usize = 8 + 6 + 32;

/// Whether a claim of `notes` notes and `fallbacks` fallbacks fits the
/// posted claim.
pub fn fits(notes: usize, fallbacks: usize) -> bool {
    (1..=MAX_NOTES).contains(&notes) && fallbacks <= MAX_FALLBACKS && 1 + notes * SHORT_LEN + 32 + fallbacks * 8 <= POSTED_LEN
}

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

/// A note's short id: its id's first 8 bytes, what the hub's signature
/// and a posted claim name it by.
pub type Short8 = [u8; 8];
pub fn short(id: &Hash) -> Short8 {
    id[..8].try_into().unwrap()
}

/// What the hub signs to issue a note: its short id, owner and value.
pub fn note_digest(id: &Short8, owner: &Hash, value: u64) -> Hash {
    tagged("lichen/notes/note", &[id, owner, &value.to_be_bytes()])
}

/// A note: `(id, owner, value)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    pub id: Hash,
    pub owner: Hash,
    pub value: u64,
}

impl Note {
    /// What the hub signs to issue it ([`note_digest`]).
    pub fn digest(&self) -> Hash {
        note_digest(&short(&self.id), &self.owner, self.value)
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

/// A grant's commitment: the spend, `T` (33 bytes), each output's
/// pre-signature (`R` x-only, `R'`, `s'`: 97 bytes), and each reveal (an
/// input owner, its pre-signature on her contract's `correct`).
pub fn grant_commitment(sid: &Hash, t_point: &[u8; 33], presigs: &[[u8; 97]], reveals: &[(Hash, [u8; 97])]) -> Hash {
    let n = (presigs.len() as u32).to_be_bytes();
    let mut parts: Vec<&[u8]> = alloc::vec![sid.as_slice(), t_point.as_slice(), n.as_slice()];
    parts.extend(presigs.iter().map(|p| p.as_slice()));
    for (o, p) in reveals {
        parts.push(o);
        parts.push(p);
    }
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

// ----- half-aggregated signatures -----

/// BIP340's tagged hash.
fn bip340_hash(tag: &str, parts: &[&[u8]]) -> Hash {
    let t: Hash = Sha256::digest(tag.as_bytes()).into();
    let mut s = Sha256::new();
    s.update(t);
    s.update(t);
    for p in parts {
        s.update(p);
    }
    s.finalize().into()
}

fn reduce(h: &Hash) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&(*h).into())
}

/// The point with x-coordinate `x` and an even y (BIP340's `lift_x`).
fn lift_x(x: &[u8; 32]) -> Option<ProjectivePoint> {
    Option::<AffinePoint>::from(AffinePoint::decompress(&(*x).into(), Choice::from(0))).map(ProjectivePoint::from)
}

/// The aggregation's weights: 1 for the first signature, then a hash of
/// the key, each message and `R` so far (the half-aggregation of BIP340
/// signatures, Chalkias et al.; Nick and Ruffing's draft BIP).
fn weights(pk: &Hash, msgs: &[Hash], rs: &[[u8; 32]]) -> Vec<Scalar> {
    let mut parts: Vec<&[u8]> = alloc::vec![pk.as_slice()];
    let mut z = alloc::vec![Scalar::ONE];
    for i in 0..rs.len() {
        parts.push(&rs[i]);
        parts.push(&msgs[i]);
        if i > 0 {
            z.push(reduce(&tagged("lichen/notes/half-agg", &parts)));
        }
    }
    z
}

/// Half-aggregate `pk`'s BIP340 signatures `sigs` on `msgs`: each `R`,
/// and one `s`. None if a signature's `s` isn't a scalar.
pub fn aggregate(pk: &Hash, msgs: &[Hash], sigs: &[[u8; 64]]) -> Option<(Vec<[u8; 32]>, [u8; 32])> {
    let rs: Vec<[u8; 32]> = sigs.iter().map(|s| s[..32].try_into().unwrap()).collect();
    let z = weights(pk, msgs, &rs);
    let mut s = Scalar::ZERO;
    for (sig, z) in sigs.iter().zip(&z) {
        let si: Scalar = Option::from(Scalar::from_repr(<[u8; 32]>::try_from(&sig[32..]).unwrap().into()))?;
        s += si * z;
    }
    Some((rs, s.to_bytes().into()))
}

/// Whether `(rs, s)` aggregates `pk`'s signatures on `msgs`:
/// `s·G = Σ z_i (R_i + e_i P)`.
pub fn verify_aggregate(pk: &Hash, msgs: &[Hash], rs: &[[u8; 32]], s: &[u8; 32]) -> bool {
    if msgs.len() != rs.len() || rs.is_empty() {
        return false;
    }
    let (Some(p), Some(s)) = (lift_x(pk), Option::<Scalar>::from(Scalar::from_repr((*s).into()))) else { return false };
    let mut sum = ProjectivePoint::IDENTITY;
    for ((r, m), z) in rs.iter().zip(msgs).zip(weights(pk, msgs, rs)) {
        let Some(rp) = lift_x(r) else { return false };
        let e = reduce(&bip340_hash("BIP0340/challenge", &[r, pk, m]));
        sum += (rp + p * e) * z;
    }
    ProjectivePoint::GENERATOR * s == sum
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
    /// `E`: what the owner signs.
    pub fn fingerprint(&self) -> Hash {
        let mut parts: Vec<Vec<u8>> = alloc::vec![self.cid.to_be_bytes().to_vec(), self.deposit.to_bytes().to_vec(), self.b.to_be_bytes().to_vec(), self.owner.to_vec()];
        parts.push((self.notes.len() as u32).to_be_bytes().to_vec());
        parts.extend(self.notes.iter().map(|i| self.note(i).digest().to_vec()));
        parts.push((self.fallbacks.len() as u32).to_be_bytes().to_vec());
        parts.extend(self.fallbacks.iter().map(|f| f.to_vec()));
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        tagged("lichen/notes/claim", &refs)
    }
    /// Its bytes, as a cooperative withdrawal hands them over.
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
    /// The claim shows itself whole: by `owner`, its notes distinct (by
    /// short id), each settled under `issuer`, its fallbacks distinct,
    /// her signature on `E`, `b` within the notes' value in units of
    /// `unit`, and it fits the posted claim. Their value.
    pub fn holds(&self, issuer: &Hash, owner: &Hash, unit: u64) -> Option<u64> {
        if self.owner != *owner || !fits(self.notes.len(), self.fallbacks.len()) || unit == 0 {
            return None;
        }
        for (k, i) in self.notes.iter().enumerate() {
            if self.notes[..k].iter().any(|j| short(&j.id) == short(&i.id)) || i.value >> 48 != 0 || !verify(issuer, &self.note(i).digest(), &i.sig) {
                return None;
            }
        }
        for (k, f) in self.fallbacks.iter().enumerate() {
            if self.fallbacks[..k].iter().any(|g| short(g) == short(f)) {
                return None;
            }
        }
        if !verify(owner, &self.fingerprint(), &self.sig) {
            return None;
        }
        let total = self.notes.iter().try_fold(0u64, |a, i| a.checked_add(i.value))?;
        (u64::from(self.b) <= total / unit).then_some(total)
    }
    /// What an exit posts of it: its notes short, the hub's (`issuer`'s)
    /// signatures half-aggregated. None if it doesn't fit, or a signature
    /// isn't one.
    pub fn posted(&self, issuer: &Hash) -> Option<Posted> {
        if !fits(self.notes.len(), self.fallbacks.len()) || self.notes.iter().any(|i| i.value >> 48 != 0) {
            return None;
        }
        let msgs: Vec<Hash> = self.notes.iter().map(|i| self.note(i).digest()).collect();
        let sigs: Vec<[u8; 64]> = self.notes.iter().map(|i| i.sig).collect();
        let (rs, s) = aggregate(issuer, &msgs, &sigs)?;
        let notes = self.notes.iter().zip(rs).map(|(i, r)| ShortItem { id: short(&i.id), value: i.value, r }).collect();
        Some(Posted { notes, s, fallbacks: self.fallbacks.iter().map(short).collect() })
    }
}

/// A note as a claim posts it: its short id, its value, its signature's
/// `R`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortItem {
    pub id: Short8,
    pub value: u64,
    pub r: [u8; 32],
}

/// The claim an exit posts ([`POSTED_LEN`] bytes, one-time signed in
/// `request`): its notes, the hub's signatures' `s` aggregated, the
/// fallbacks' short ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Posted {
    pub notes: Vec<ShortItem>,
    pub s: [u8; 32],
    pub fallbacks: Vec<Short8>,
}

impl Posted {
    /// Its [`POSTED_LEN`] bytes: the counts (4 bits each), the notes, `s`,
    /// the fallbacks, zeros.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = alloc::vec![((self.notes.len() as u8) << 4) | self.fallbacks.len() as u8];
        for n in &self.notes {
            v.extend(n.id);
            v.extend(&n.value.to_be_bytes()[2..]);
            v.extend(n.r);
        }
        v.extend(self.s);
        for f in &self.fallbacks {
            v.extend(f);
        }
        v.resize(POSTED_LEN, 0);
        v
    }
    /// The posted claim, if its bytes are one: a fitting count, zeros
    /// after.
    pub fn from_bytes(b: &[u8]) -> Option<Posted> {
        let (n, f) = ((*b.first()? >> 4) as usize, (b[0] & 15) as usize);
        if b.len() != POSTED_LEN || !fits(n, f) {
            return None;
        }
        let mut r = R(&b[1..]);
        let mut notes = Vec::new();
        for _ in 0..n {
            let id: Short8 = r.take().ok()?;
            let v: [u8; 6] = r.take().ok()?;
            let mut value = [0u8; 8];
            value[2..].copy_from_slice(&v);
            notes.push(ShortItem { id, value: u64::from_be_bytes(value), r: r.take().ok()? });
        }
        let s = r.take().ok()?;
        let fallbacks = (0..f).map(|_| r.take().ok()).collect::<Option<Vec<Short8>>>()?;
        r.0.iter().all(|&z| z == 0).then_some(Posted { notes, s, fallbacks })
    }
    /// It shows itself whole: its notes distinct, settled under `issuer`
    /// to `owner` (the aggregate signature), its fallbacks distinct, `b`
    /// within the notes' value in units of `unit`.
    pub fn holds(&self, b: u32, issuer: &Hash, owner: &Hash, unit: u64) -> bool {
        for (k, n) in self.notes.iter().enumerate() {
            if self.notes[..k].iter().any(|m| m.id == n.id) {
                return false;
            }
        }
        for (k, f) in self.fallbacks.iter().enumerate() {
            if self.fallbacks[..k].contains(f) {
                return false;
            }
        }
        let msgs: Vec<Hash> = self.notes.iter().map(|n| note_digest(&n.id, owner, n.value)).collect();
        let rs: Vec<[u8; 32]> = self.notes.iter().map(|n| n.r).collect();
        let total: u64 = self.notes.iter().map(|n| n.value).sum();
        unit != 0 && u64::from(b) <= total / unit && verify_aggregate(issuer, &msgs, &rs, &self.s)
    }
}


// ----- the statement's input -----

/// A spend the hub cites: what she signed (the spend, its grant's `T`,
/// its output pre-signatures and its reveals), her signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cited {
    pub inputs: Vec<Note>,
    pub outputs: Vec<(Hash, u64)>,
    pub t_point: [u8; 33],
    pub presigs: Vec<[u8; 97]>,
    /// Each input owner's reveal: the hub's pre-signature under `T` on
    /// that owner's contract's `correct` (`R` x-only, `R'`, `s'`).
    pub reveals: Vec<(Hash, [u8; 97])>,
    pub sig: [u8; 64],
}

impl Cited {
    pub fn sid(&self) -> Hash {
        spend_id(&self.inputs, &self.outputs)
    }
    /// Signed by `owner` with its grant.
    fn signed_by(&self, owner: &Hash) -> bool {
        let sid = self.sid();
        verify(owner, &auth_msg(&sid, &grant_commitment(&sid, &self.t_point, &self.presigs, &self.reveals)), &self.sig)
    }
    /// Revealed to `owner` by one of `correct`'s `slots`: a signature
    /// there with the final nonce of her reveal. Bitcoin checked it, on the
    /// message she checked her pre-signature on, so `s − s'` is `t`.
    fn revealed(&self, owner: &Hash, slots: &[[u8; 32]]) -> bool {
        self.reveals.iter().any(|(o, p)| o == owner && slots.iter().any(|r| r[..] == p[..32]))
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
    /// `D`: the issuer and the contract's owner (the journal binds both:
    /// the statement reads her notes as the owner's), no genesis seal,
    /// the work `W`, the unit.
    pub fn d(&self) -> Hash {
        contract_id(&deployment_id(&self.issuer, &self.owner), &OutPoint { txid: [0; 32], vout: 0 }, self.work, self.unit)
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
    /// a block of `headers`: `b_corr`, and the slots' signatures.
    pub correct: Request,
    /// From `request`'s block on, consecutive.
    pub headers: Vec<[u8; 80]>,
    pub cited: Vec<Cited>,
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

/// `correct`'s witness (bottom first): the slots' signatures (64 bytes
/// each: `SIGHASH_DEFAULT`, the message every reveal pre-signs), the hub's
/// one-time signature on `b_corr` (4 bytes), below the 2-of-2's
/// signatures, the script and the control block. `b_corr`, and each
/// slot's final nonce `R`.
pub fn corrected(witness: &[&[u8]]) -> Option<(u32, Vec<[u8; 32]>)> {
    let items = 2 * (8 + checksum_digits(4));
    if witness.len() != SLOTS + items + 4 || witness[..SLOTS].iter().any(|s| s.len() != 64) {
        return None;
    }
    let slots = witness[..SLOTS].iter().map(|s| s[..32].try_into().unwrap()).collect();
    let b = signed_message(&witness[SLOTS..SLOTS + items], 4)?;
    Some((u32::from_be_bytes(b.try_into().ok()?), slots))
}

/// `request`'s witness (bottom first): Alice's one-time signature on the
/// posted claim ([`POSTED_LEN`] bytes), then on `b` (4), each a hash and
/// a digit a digit, below the 2-of-2's two signatures, the script and the
/// control block. `b` and the posted claim's bytes.
pub fn requested(witness: &[&[u8]]) -> Option<(u32, Vec<u8>)> {
    let c_items = 2 * (2 * POSTED_LEN + checksum_digits(POSTED_LEN));
    let b_items = 2 * (8 + checksum_digits(4));
    if witness.len() != c_items + b_items + 4 {
        return None;
    }
    let posted = signed_message(&witness[..c_items], POSTED_LEN)?;
    let b = signed_message(&witness[c_items..c_items + b_items], 4)?;
    Some((u32::from_be_bytes(b.try_into().ok()?), posted))
}

/// A posted claim of `b` units as the statement counts it: the
/// contract's owner, the hub's key `issuer`, the contract's `unit`.
#[derive(Clone, Copy, Debug)]
pub struct Counted<'a> {
    pub posted: Option<&'a Posted>,
    pub b: u32,
    pub issuer: &'a Hash,
    pub owner: &'a Hash,
    pub unit: u64,
}

/// What the claim is owed, in units, by the evidence: the cited spends,
/// each counting if she signed it and one of `correct`'s `slots`
/// revealed its `t` to her.
///
/// The candidates are the claim's notes (by short id and value); a cited
/// spend kills those among its inputs, and if the claim names it a
/// fallback, its output to her joins the candidates (a later spend of
/// hers may kill it in turn). Owed: the candidates not killed, in units,
/// at most `b`. (The contract's key is its own: no claim through another
/// contract names its notes.)
pub fn owed(c: &Counted, cited: &[Cited], slots: &[[u8; 32]]) -> u32 {
    let Some(claim) = c.posted else { return 0 };
    if !claim.holds(c.b, c.issuer, c.owner, c.unit) {
        return 0;
    }
    let owner = c.owner;
    let mut cands: Vec<(Short8, u64)> = claim.notes.iter().map(|n| (n.id, n.value)).collect();
    let mut dead: Vec<(Short8, u64)> = Vec::new();
    let usable: Vec<(Hash, &Cited)> = cited.iter().filter(|x| x.signed_by(owner) && x.revealed(owner, slots)).map(|x| (x.sid(), x)).collect();
    let mut revived: Vec<Hash> = Vec::new();
    loop {
        let mut more = false;
        for (sid, x) in &usable {
            let killed: Vec<(Short8, u64)> = x.inputs.iter().filter(|n| n.owner == *owner).map(|n| (short(&n.id), n.value)).filter(|k| cands.contains(k) && !dead.contains(k)).collect();
            if killed.is_empty() {
                continue;
            }
            more = true;
            dead.extend(killed);
            if claim.fallbacks.contains(&short(sid)) && !revived.contains(sid) {
                revived.push(*sid);
                cands.extend(x.outputs.iter().enumerate().filter(|(_, (o, _))| o == owner).map(|(j, (_, v))| (short(&output_id(sid, j as u32)), *v)));
            }
        }
        if !more {
            break;
        }
    }
    let live: u64 = cands.iter().filter(|k| !dead.contains(k)).fold(0u64, |a, (_, v)| a.saturating_add(*v));
    c.b.min(u32::try_from(live / c.unit).unwrap_or(u32::MAX))
}

/// The hub's statement: the claim `request` posts is owed at most the
/// `b_corr` `correct` signs. Its journal, or why not.
pub fn check(input: &GrantsInput) -> Result<[u8; JOURNAL_LEN], Reject> {
    let t = &input.terms;
    if t.unit == 0 || input.cited.len() > SLOTS {
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
    let (b, bytes) = requested(&witness).ok_or(Reject::Posted)?;
    let posted = Posted::from_bytes(&bytes);
    // correct: request's spend, in a block of the headers
    let request_id = txid_of(&input.request.tx).ok_or(Reject::Posted)?;
    let c = &input.correct;
    if !input.headers.contains(&c.header) || !btc::witness_in_block(&c.tx, &Header(c.header), c.index, &c.path, &c.coinbase, &c.coinbase_path, &c.reserved) {
        return Err(Reject::Posted);
    }
    let ct = btc::parse_witness_tx(&c.tx).ok_or(Reject::Posted)?;
    let at = ct.tx.inputs.iter().position(|o| *o == OutPoint { txid: request_id, vout: 0 }).ok_or(Reject::Posted)?;
    let (b_corr, slots) = corrected(&ct.witness[at]).ok_or(Reject::Posted)?;
    let counted = Counted { posted: posted.as_ref(), b, issuer: &t.issuer, owner: &t.owner, unit: t.unit };
    if owed(&counted, &input.cited, &slots) > b_corr {
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
            w.put(&(c.reveals.len() as u32).to_be_bytes());
            for (o, p) in &c.reveals {
                w.put(o);
                w.put(p);
            }
            w.put(&c.sig);
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
        let headers = r.list()?;
        let n = u32::from_be_bytes(r.take()?) as usize;
        if n > SLOTS {
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
            let (t_point, presigs) = (r.take()?, r.list()?);
            let nr = u32::from_be_bytes(r.take()?) as usize;
            if nr > 64 {
                return Err(Reject::Encoding);
            }
            let reveals = (0..nr).map(|_| Ok((r.take()?, r.take()?))).collect::<Result<Vec<_>, Reject>>()?;
            cited.push(Cited { inputs, outputs, t_point, presigs, reveals, sig: r.take()? });
        }
        if !r.0.is_empty() {
            return Err(Reject::Encoding);
        }
        Ok(GrantsInput { c, deposit, margin, terms, request, correct, headers, cited })
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
    /// `t·G`, compressed.
    fn point_of(t: &[u8; 32]) -> [u8; 33] {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let s: Scalar = Option::from(Scalar::from_repr((*t).into())).unwrap();
        (ProjectivePoint::GENERATOR * s).to_affine().to_encoded_point(true).as_bytes().try_into().unwrap()
    }
    /// A spend of `inputs` by `owner`: `pay` to another, the rest back, its
    /// grant's T the point of `t`, its reveal to her with final nonce `r`.
    fn spend(owner: &SigningKey, inputs: Vec<Note>, pay: u64, t: &[u8; 32], r: u8) -> Cited {
        let total: u64 = inputs.iter().map(|n| n.value).sum();
        let outputs = vec![([5; 32], pay), (pk(owner), total - pay)];
        let mut reveal = [7u8; 97];
        reveal[..32].copy_from_slice(&[r; 32]);
        let mut c = Cited { inputs, outputs, t_point: point_of(t), presigs: vec![[3; 97], [4; 97]], reveals: vec![(pk(owner), reveal)], sig: [0; 64] };
        let sid = c.sid();
        c.sig = sign(owner, &auth_msg(&sid, &grant_commitment(&sid, &c.t_point, &c.presigs, &c.reveals)));
        c
    }

    #[test]
    fn signatures_half_aggregate() {
        let hub = key(1);
        let msgs: Vec<Hash> = (0..4u8).map(|i| [i; 32]).collect();
        let sigs: Vec<[u8; 64]> = msgs.iter().map(|m| sign(&hub, m)).collect();
        let (rs, s) = aggregate(&pk(&hub), &msgs, &sigs).unwrap();
        assert!(verify_aggregate(&pk(&hub), &msgs, &rs, &s));
        // one message changed, the order changed, another key: no
        let mut other = msgs.clone();
        other[2] = [9; 32];
        assert!(!verify_aggregate(&pk(&hub), &other, &rs, &s));
        let (mut rs2, mut m2) = (rs.clone(), msgs.clone());
        rs2.swap(0, 1);
        m2.swap(0, 1);
        assert!(!verify_aggregate(&pk(&hub), &m2, &rs2, &s));
        assert!(!verify_aggregate(&pk(&key(2)), &msgs, &rs, &s));
        // a signature not the hub's spoils it
        let mut bad = sigs.clone();
        bad[3] = sign(&key(2), &msgs[3]);
        let (rs, s) = aggregate(&pk(&hub), &msgs, &bad).unwrap();
        assert!(!verify_aggregate(&pk(&hub), &msgs, &rs, &s));
    }

    #[test]
    fn what_a_claim_is_owed() {
        let (hub, alice) = (key(1), key(2));
        let (issuer, owner) = (pk(&hub), pk(&alice));
        let unit = 100;
        let (n1, n2) = (item(&hub, &owner, 1, 70_000), item(&hub, &owner, 2, 30_000));
        // her spend of n1 in flight: 50,000 to Bob, 20,000 back to her;
        // its reveal's final nonce [21; 32]
        let s = spend(&alice, vec![Note { id: n1.id, owner, value: n1.value }], 50_000, &[11; 32], 21);
        let with_fallback = claim(&alice, 1000, vec![n1, n2], vec![s.sid()]).posted(&issuer).unwrap();
        let owed = |p: &Posted, b: u32, cited: &[Cited], slots: &[[u8; 32]]| super::owed(&Counted { posted: Some(p), b, issuer: &issuer, owner: &owner, unit }, cited, slots);
        // nothing cited: all of it
        assert_eq!(owed(&with_fallback, 1000, &[], &[]), 1000);
        // the spend recorded and revealed in a slot: n1 dead, her change revived
        assert_eq!(owed(&with_fallback, 1000, core::slice::from_ref(&s), &[[9; 32], [21; 32]]), 500);
        // not revealed in correct's slots: the spend doesn't count
        assert_eq!(owed(&with_fallback, 1000, core::slice::from_ref(&s), &[[9; 32]]), 1000);
        // a reveal to another owner doesn't count
        let mut other = s.clone();
        other.reveals[0].0 = [8; 32];
        other.sig = sign(&alice, &auth_msg(&other.sid(), &grant_commitment(&other.sid(), &other.t_point, &other.presigs, &other.reveals)));
        assert_eq!(owed(&with_fallback, 1000, &[other], &[[21; 32]]), 1000);
        // not declared a fallback: no change revived
        let full = claim(&alice, 1000, vec![n1, n2], vec![]);
        let without = full.posted(&issuer).unwrap();
        assert_eq!(owed(&without, 1000, core::slice::from_ref(&s), &[[21; 32]]), 300);
        // a spend not signed by her, or its reveal altered: doesn't count
        let mut forged = s.clone();
        forged.sig = sign(&key(3), &[0; 32]);
        assert_eq!(owed(&with_fallback, 1000, &[forged], &[[21; 32]]), 1000);
        let mut swapped = s.clone();
        swapped.reveals[0].1[..32].copy_from_slice(&[9; 32]);
        assert_eq!(owed(&with_fallback, 1000, &[swapped], &[[9; 32]]), 1000);
        // her revived change spent on: dead too
        let change = Note { id: output_id(&s.sid(), 1), owner, value: 20_000 };
        let s2 = spend(&alice, vec![change], 20_000, &[13; 32], 22);
        assert_eq!(owed(&with_fallback, 1000, &[s.clone(), s2.clone()], &[[21; 32], [22; 32]]), 300);
        // malformed: a note not settled, b above the notes, a note twice
        let bad_note = Claim { notes: vec![Item { sig: sign(&key(3), &[0; 32]), ..n1 }], ..full.clone() }.posted(&issuer).unwrap();
        assert_eq!(owed(&bad_note, 100, &[], &[]), 0);
        assert_eq!(owed(&without, 1001, &[], &[]), 0);
        let twice = Posted { notes: vec![without.notes[0], without.notes[0]], ..without.clone() };
        assert_eq!(owed(&twice, 1, &[], &[]), 0);
        // another owner's claim, under the contract's owner: malformed
        let bobs = claim(&key(4), 100, vec![item(&hub, &pk(&key(4)), 3, 10_000)], vec![]).posted(&issuer).unwrap();
        assert_eq!(owed(&bobs, 100, &[], &[]), 0);
        assert_eq!(super::owed(&Counted { posted: None, b: 1, issuer: &issuer, owner: &owner, unit }, &[], &[]), 0);
        // the bytes round-trip
        assert_eq!(Claim::from_bytes(&full.to_bytes()), Some(full));
        let bytes = with_fallback.to_bytes();
        assert_eq!(bytes.len(), POSTED_LEN);
        assert_eq!(Posted::from_bytes(&bytes), Some(with_fallback));
        // trailing bytes not zero: not a posted claim
        let mut junk = bytes.clone();
        junk[POSTED_LEN - 1] = 1;
        assert_eq!(Posted::from_bytes(&junk), None);
    }

    #[test]
    fn the_posted_claim_fits() {
        assert!(fits(4, 2) && fits(3, 4) && fits(1, 0));
        assert!(!fits(4, 3) && !fits(0, 0) && !fits(5, 0) && !fits(1, 5));
        let (hub, alice) = (key(1), key(2));
        let notes: Vec<Item> = (0..4).map(|i| item(&hub, &pk(&alice), i, 1 << 40)).collect();
        let p = claim(&alice, 1, notes, vec![[1; 32]]).posted(&pk(&hub)).unwrap();
        assert_eq!(Posted::from_bytes(&p.to_bytes()), Some(p));
    }
}

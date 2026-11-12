//! The grants L2 (docs/GRANTS_PLAN.md): notes the hub issues, owned by
//! keys, any value; payments made atomic by grants; no global ordering.
//!
//! - **A note** is `(id, owner, value)`. It is *settled* when its holder
//!   has the hub's BIP340 signature on it ([`Settled`]): anyone can check
//!   it under the hub's issuer key.
//! - **A spend** ([`Spend`]) names input notes and asks for outputs of the
//!   same total. Its outputs' ids derive from the spend's id, so a spend
//!   fixes the notes it makes.
//! - **A grant** ([`Grant`]): before the payer signs, the hub returns a
//!   one-time point `T = tG` (signed, so the payer can't pick it) and an
//!   adaptor pre-signature under `T` on each output note. The payer checks
//!   them, then signs the spend together with the grant's commitment
//!   ([`auth_msg`]); the hub records the spend, marking its inputs spent,
//!   and publishes `t`, which completes every output's signature. Before
//!   `t` the outputs are unusable, after it they are ordinary settled
//!   notes: the payer's inputs and the payee's outputs are never both
//!   good. `t` derives from the hub's key and the spend ([`unlock`]).
//! - **A claim** ([`Claim`]): settled notes of the contract's owner, and an
//!   amount `b` in the contract's units, signed by the owner: what a
//!   cooperative withdrawal hands the hub, and what an exit posts.
//!
//! The hub keeps its [`book::Book`]: every note issued, which are spent and
//! by what, and each owner's mailbox of notes to collect.

pub mod book;

use anyhow::{ensure, Context, Result};
use bitcoin::key::{Keypair, XOnlyPublicKey};
use bitcoin::secp256k1::{schnorr, Message, PublicKey, SecretKey, SECP256K1};
use lngap_btc::adaptor::{adaptor_complete, adaptor_sign, adaptor_verify, AdaptorSig};
use serde::{Deserialize, Serialize};
use lichen_withdraw::grants as g;

pub use lichen_withdraw::grants::tagged;

pub type Hash = [u8; 32];

/// The most inputs, and outputs, a spend takes.
pub const MAX_INPUTS: usize = 16;
pub const MAX_OUTPUTS: usize = 16;
/// The most notes a claim takes (what fits in `request`'s posted bytes),
/// and the most fallbacks.
pub const MAX_CLAIM_NOTES: usize = g::MAX_NOTES;
pub const MAX_FALLBACKS: usize = g::MAX_FALLBACKS;

pub mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(h: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(h))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let v = hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|_| serde::de::Error::custom("not 32 bytes"))
    }
}

pub mod hex64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(h: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(h))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v = hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|_| serde::de::Error::custom("not 64 bytes"))
    }
}

/// A key's x-only public key, as bytes (a note's owner, the issuer).
pub fn xonly(kp: &Keypair) -> Hash {
    kp.x_only_public_key().0.serialize()
}

/// A BIP340 signature by `kp` on `msg` (deterministic).
pub fn sign(kp: &Keypair, msg: &Hash) -> [u8; 64] {
    *SECP256K1.sign_schnorr_no_aux_rand(&Message::from_digest(*msg), kp).as_ref()
}

/// Whether `sig` is `pk`'s BIP340 signature on `msg`.
pub fn verify(pk: &Hash, msg: &Hash, sig: &[u8; 64]) -> bool {
    let (Ok(pk), Ok(sig)) = (XOnlyPublicKey::from_slice(pk), schnorr::Signature::from_slice(sig)) else { return false };
    SECP256K1.verify_schnorr(&sig, &Message::from_digest(*msg), &pk).is_ok()
}

/// A note: issued by the hub to `owner`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Note {
    #[serde(with = "hex32")]
    pub id: Hash,
    #[serde(with = "hex32")]
    pub owner: Hash,
    pub value: u64,
}

impl Note {
    /// What the hub signs to issue it.
    pub fn digest(&self) -> Hash {
        self.g().digest()
    }
    pub fn g(&self) -> g::Note {
        g::Note { id: self.id, owner: self.owner, value: self.value }
    }
}

/// A note with the hub's signature: settled, as anyone can check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settled {
    pub note: Note,
    #[serde(with = "hex64")]
    pub sig: [u8; 64],
}

impl Settled {
    pub fn verify(&self, issuer: &Hash) -> bool {
        verify(issuer, &self.note.digest(), &self.sig)
    }
}

/// Issue `note`: the hub's signature on it.
pub fn issue(issuer: &Keypair, note: Note) -> Settled {
    Settled { note, sig: sign(issuer, &note.digest()) }
}

/// An output a spend asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    #[serde(with = "hex32")]
    pub owner: Hash,
    pub value: u64,
}

/// A spend: input notes, and the outputs asked for, of the same total.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spend {
    pub inputs: Vec<Note>,
    pub outputs: Vec<Output>,
}

impl Spend {
    pub fn id(&self) -> Hash {
        g::spend_id(&self.inputs.iter().map(Note::g).collect::<Vec<_>>(), &self.outputs.iter().map(|o| (o.owner, o.value)).collect::<Vec<_>>())
    }
    /// The notes it makes, in its outputs' order.
    pub fn notes(&self) -> Vec<Note> {
        let sid = self.id();
        self.outputs.iter().enumerate().map(|(j, o)| Note { id: g::output_id(&sid, j as u32), owner: o.owner, value: o.value }).collect()
    }
    /// Well formed: inputs and outputs within bounds, distinct inputs, no
    /// empty output, the totals equal.
    pub fn check(&self) -> Result<()> {
        ensure!(!self.inputs.is_empty() && self.inputs.len() <= MAX_INPUTS, "a spend of {} inputs (1 to {MAX_INPUTS})", self.inputs.len());
        ensure!(!self.outputs.is_empty() && self.outputs.len() <= MAX_OUTPUTS, "a spend of {} outputs (1 to {MAX_OUTPUTS})", self.outputs.len());
        let mut ids: Vec<&Hash> = self.inputs.iter().map(|n| &n.id).collect();
        ids.sort();
        ids.dedup();
        ensure!(ids.len() == self.inputs.len(), "a spend names an input twice");
        ensure!(self.outputs.iter().all(|o| o.value > 0), "an output of nothing");
        fn total(mut v: impl Iterator<Item = u64>) -> Result<u64> {
            v.try_fold(0u64, |a, x| a.checked_add(x)).context("a sum that overflows")
        }
        let (i, o) = (total(self.inputs.iter().map(|n| n.value))?, total(self.outputs.iter().map(|o| o.value))?);
        ensure!(i == o, "the outputs total {o}, the inputs {i}");
        Ok(())
    }
}

/// An adaptor pre-signature on the wire ([`AdaptorSig`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presig {
    pub r_final: XOnlyPublicKey,
    pub r: PublicKey,
    pub s_prime: SecretKey,
}

impl From<&AdaptorSig> for Presig {
    fn from(a: &AdaptorSig) -> Presig {
        Presig { r_final: a.r_final, r: a.r, s_prime: a.s_prime }
    }
}

impl From<&Presig> for AdaptorSig {
    fn from(p: &Presig) -> AdaptorSig {
        AdaptorSig { r_final: p.r_final, r: p.r, s_prime: p.s_prime }
    }
}

/// The hub's unlock for spend `sid`: from its key and the spend, so a
/// spend asked again gets the same grant.
pub fn unlock(issuer: &Keypair, sid: &Hash) -> SecretKey {
    let mut ctr = 0u32;
    loop {
        if let Ok(t) = SecretKey::from_slice(&tagged("lichen/notes/unlock", &[&issuer.secret_bytes(), sid, &ctr.to_be_bytes()])) {
            return t;
        }
        ctr += 1;
    }
}

/// The hub's grant on a spend: `T`, its signature on `(sid, T)`, and an
/// adaptor pre-signature under `T` on each output note.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    #[serde(with = "hex32")]
    pub sid: Hash,
    pub t_point: PublicKey,
    #[serde(with = "hex64")]
    pub t_sig: [u8; 64],
    pub presigs: Vec<Presig>,
}

impl Grant {
    fn t_digest(sid: &Hash, t_point: &PublicKey) -> Hash {
        tagged("lichen/notes/grant", &[sid, &t_point.serialize()])
    }
    /// The hub's grant on `spend`, unlocked by `t`.
    pub fn make(issuer: &Keypair, spend: &Spend, t: &SecretKey) -> Grant {
        let sid = spend.id();
        let t_point = PublicKey::from_secret_key(SECP256K1, t);
        let presigs = spend.notes().iter().map(|n| Presig::from(&adaptor_sign(issuer, &Message::from_digest(n.digest()), &t_point))).collect();
        Grant { sid, t_point, t_sig: sign(issuer, &Grant::t_digest(&sid, &t_point)), presigs }
    }
    /// What the payer signs with the spend: the grant as she checked it.
    pub fn commitment(&self) -> Hash {
        g::grant_commitment(&self.sid, &self.t_point.serialize(), &self.presig_bytes())
    }
    /// Each pre-signature as the commitment takes it: `R'` x-only, `R`,
    /// `s'` (97 bytes).
    pub fn presig_bytes(&self) -> Vec<[u8; 97]> {
        self.presigs.iter().map(|p| [p.r_final.serialize().as_slice(), &p.r.serialize(), &p.s_prime.secret_bytes()].concat().try_into().expect("97 bytes")).collect()
    }
    /// The grant is the hub's, on `spend`: `T` signed, and each output's
    /// pre-signature good under `T`.
    pub fn verify(&self, issuer: &Hash, spend: &Spend) -> Result<()> {
        ensure!(self.sid == spend.id(), "a grant on another spend");
        ensure!(verify(issuer, &Grant::t_digest(&self.sid, &self.t_point), &self.t_sig), "the grant's T isn't signed by the hub");
        let notes = spend.notes();
        ensure!(self.presigs.len() == notes.len(), "the grant pre-signs {} outputs of {}", self.presigs.len(), notes.len());
        let pk = XOnlyPublicKey::from_slice(issuer).context("the issuer key")?;
        for (j, (n, p)) in notes.iter().zip(&self.presigs).enumerate() {
            ensure!(adaptor_verify(&pk, &Message::from_digest(n.digest()), &self.t_point, &AdaptorSig::from(p)), "the grant's pre-signature on output {j}");
        }
        Ok(())
    }
    /// The outputs settled, with `t`.
    pub fn open(&self, issuer: &Hash, spend: &Spend, t: &SecretKey) -> Result<Vec<Settled>> {
        ensure!(PublicKey::from_secret_key(SECP256K1, t) == self.t_point, "not the grant's unlock");
        let out: Vec<Settled> = spend.notes().into_iter().zip(&self.presigs).map(|(note, p)| Settled { note, sig: *adaptor_complete(&AdaptorSig::from(p), t).as_ref() }).collect();
        ensure!(out.iter().all(|s| s.verify(issuer)), "an output's completed signature doesn't verify");
        Ok(out)
    }
}

/// What each input's owner signs to make a spend: the spend, and the
/// grant she checked.
pub fn auth_msg(sid: &Hash, commitment: &Hash) -> Hash {
    g::auth_msg(sid, commitment)
}

/// The owners' signatures on a spend and its grant, one per input.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Authorized {
    #[serde(with = "hex32")]
    pub sid: Hash,
    pub sigs: Vec<String>,
}

/// A note for an owner to collect, from the spend (or issuance) that made it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
    pub settled: Settled,
    #[serde(with = "hex32")]
    pub from: Hash,
}

/// A claim: settled notes of the contract's owner, fallbacks (the ids of
/// spends of hers in flight whose inputs are among the notes: if the hub
/// shows one recorded, its change to her counts instead), and `b` units
/// of the contract, signed by the owner. Its hash and bytes are the
/// statement's ([`lichen_withdraw::grants::Claim`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub cid: u32,
    pub deposit: bitcoin::OutPoint,
    pub b: u32,
    #[serde(with = "hex32")]
    pub owner: Hash,
    pub notes: Vec<Settled>,
    #[serde(default)]
    pub fallbacks: Vec<String>,
    #[serde(with = "hex64")]
    pub sig: [u8; 64],
}

/// The statement's outpoint for a Bitcoin one.
pub fn outpoint(o: &bitcoin::OutPoint) -> lichen_ledger::OutPoint {
    use bitcoin::hashes::Hash as _;
    lichen_ledger::OutPoint { txid: o.txid.to_byte_array(), vout: o.vout }
}

impl Claim {
    pub fn g(&self) -> g::Claim {
        g::Claim {
            cid: self.cid,
            deposit: outpoint(&self.deposit),
            b: self.b,
            owner: self.owner,
            notes: self.notes.iter().map(|s| g::Item { id: s.note.id, value: s.note.value, sig: s.sig }).collect(),
            fallbacks: self.fallbacks.iter().map(|f| hex::decode(f).ok().and_then(|v| v.try_into().ok()).unwrap_or([0; 32])).collect(),
            sig: self.sig,
        }
    }
    /// A claim by `owner` of `b` units of contract `cid`: `notes`, and
    /// the spends in flight `fallbacks` (their ids).
    pub fn new(owner: &Keypair, cid: u32, deposit: bitcoin::OutPoint, b: u32, notes: Vec<Settled>, fallbacks: &[Hash]) -> Claim {
        let mut c = Claim { cid, deposit, b, owner: xonly(owner), notes, fallbacks: fallbacks.iter().map(hex::encode).collect(), sig: [0; 64] };
        c.sig = sign(owner, &c.e());
        c
    }
    /// `E`: what the owner signs, and an exit's one-time key signs.
    pub fn e(&self) -> Hash {
        self.g().fingerprint()
    }
    /// The fallbacks' ids.
    pub fn fallback_ids(&self) -> Vec<Hash> {
        self.g().fallbacks
    }
    /// The claim holds as far as it shows itself: of contract `cid` and
    /// `deposit`, by `owner`; its notes distinct, settled under `issuer`,
    /// each `owner`'s; signed; worth at least `b` units of `unit`. Their
    /// total.
    pub fn check(&self, issuer: &Hash, cid: u32, deposit: &bitcoin::OutPoint, owner: &Hash, unit: u64) -> Result<u64> {
        ensure!(self.cid == cid && self.deposit == *deposit, "a claim on another contract");
        ensure!(self.notes.len() <= MAX_CLAIM_NOTES && self.fallbacks.len() <= MAX_FALLBACKS, "a claim of {} notes and {} fallbacks (at most {MAX_CLAIM_NOTES} and {MAX_FALLBACKS})", self.notes.len(), self.fallbacks.len());
        ensure!(self.notes.iter().all(|s| s.note.owner == self.owner), "a note of the claim isn't the owner's");
        self.g().holds(issuer, owner, unit).with_context(|| format!("the claim doesn't hold: by another owner, a note not settled or named twice, its signature, or worth less than {} units of {unit}", self.b))
    }
    /// Its bytes, as an exit posts them.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.g().to_bytes()
    }
    pub fn from_bytes(b: &[u8]) -> Result<Claim> {
        use bitcoin::hashes::Hash as _;
        let c = g::Claim::from_bytes(b).context("not a claim's bytes")?;
        let notes = c.notes.iter().map(|i| Settled { note: Note { id: i.id, owner: c.owner, value: i.value }, sig: i.sig }).collect();
        let deposit = bitcoin::OutPoint { txid: bitcoin::Txid::from_byte_array(c.deposit.txid), vout: c.deposit.vout };
        Ok(Claim { cid: c.cid, deposit, b: c.b, owner: c.owner, notes, fallbacks: c.fallbacks.iter().map(hex::encode).collect(), sig: c.sig })
    }
}

/// A keypair from 32 secret bytes (the hub's issuer key, a wallet's).
pub fn keypair(secret: &[u8; 32]) -> Result<Keypair> {
    Ok(Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(secret).context("a secret key")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(b: u8) -> Keypair {
        keypair(&[b; 32]).unwrap()
    }

    #[test]
    fn a_granted_spend_opens_only_with_its_unlock() {
        let (hub, alice, bob) = (kp(1), kp(2), kp(3));
        let issuer = xonly(&hub);
        let n = issue(&hub, Note { id: [9; 32], owner: xonly(&alice), value: 1000 });
        assert!(n.verify(&issuer));
        let spend = Spend { inputs: vec![n.note], outputs: vec![Output { owner: xonly(&bob), value: 600 }, Output { owner: xonly(&alice), value: 400 }] };
        spend.check().unwrap();
        let t = unlock(&hub, &spend.id());
        let g = Grant::make(&hub, &spend, &t);
        g.verify(&issuer, &spend).unwrap();
        // another t opens nothing
        assert!(g.open(&issuer, &spend, &kp(4).secret_key()).is_err());
        let out = g.open(&issuer, &spend, &t).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|s| s.verify(&issuer)));
        assert_eq!((out[0].note.owner, out[0].note.value), (xonly(&bob), 600));
        // a grant isn't good for another spend
        let other = Spend { inputs: vec![n.note], outputs: vec![Output { owner: xonly(&bob), value: 1000 }] };
        assert!(g.verify(&issuer, &other).is_err());
    }

    #[test]
    fn a_spend_balances() {
        let n = Note { id: [1; 32], owner: [2; 32], value: 10 };
        assert!(Spend { inputs: vec![n], outputs: vec![Output { owner: [3; 32], value: 11 }] }.check().is_err());
        assert!(Spend { inputs: vec![n, n], outputs: vec![Output { owner: [3; 32], value: 20 }] }.check().is_err());
        assert!(Spend { inputs: vec![n], outputs: vec![Output { owner: [3; 32], value: 10 }, Output { owner: [3; 32], value: 0 }] }.check().is_err());
    }

    #[test]
    fn a_claim_round_trips_and_checks() {
        let (hub, alice) = (kp(1), kp(2));
        let issuer = xonly(&hub);
        let notes = vec![issue(&hub, Note { id: [5; 32], owner: xonly(&alice), value: 7000 }), issue(&hub, Note { id: [6; 32], owner: xonly(&alice), value: 3000 })];
        let dep = bitcoin::OutPoint { txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([8; 32])), vout: 1 };
        let c = Claim::new(&alice, 1000, dep, 9, notes, &[[3; 32]]);
        assert_eq!(Claim::from_bytes(&c.to_bytes()).unwrap(), c);
        assert_eq!(c.check(&issuer, 1000, &dep, &xonly(&alice), 1000).unwrap(), 10_000);
        // more units than the notes hold
        assert!(c.check(&issuer, 1000, &dep, &xonly(&alice), 1200).is_err());
        // the most notes fit in what an exit posts (15 items of 80 bytes)
        let many: Vec<Settled> = (0..MAX_CLAIM_NOTES as u8).map(|i| issue(&hub, Note { id: [i; 32], owner: xonly(&alice), value: 1 })).collect();
        assert!(Claim::new(&alice, 1, dep, 0, many, &[[1; 32], [2; 32], [3; 32], [4; 32]]).to_bytes().len() <= 15 * 80);
    }
}

//! The hub's book: per account its live note, the last spend it took part
//! in (what a claim of an earlier note is answered with), a payment
//! pending, and whether a claim closed it; and the payments, by id. Its
//! storage is O(1) per account: a payment is dropped once neither of its
//! accounts has it as its last spend. Kept whole in one file, written
//! atomically after each change (a prototype's ledger).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{bail, ensure, Context, Result};
use bitcoin::key::Keypair;
use serde::{Deserialize, Serialize};

use crate::proto::{cancel_msg, sides_to, Account, Payment, State};
use crate::{core, hex32, issue, verify, xonly, Grant, Half, Hash, Note, Seed, Settled, Sides};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Acct {
    live: Note,
    /// The last spend recorded on it.
    #[serde(default)]
    last: Option<String>,
    #[serde(default)]
    busy: Option<String>,
    #[serde(default)]
    closed: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Pay {
    id: String,
    #[serde(with = "hex32")]
    from: Hash,
    #[serde(with = "hex32")]
    to: Hash,
    amount: u64,
    state: State,
    /// The payer's half, then the payee's.
    halves: [Option<Half>; 2],
    #[serde(default)]
    grant: Option<Grant>,
    /// Signatures by owner (hex).
    #[serde(default)]
    psi: BTreeMap<String, String>,
    #[serde(default, with = "opt16")]
    seed: Option<Seed>,
    /// Whether the seed was released.
    #[serde(default)]
    released: bool,
    #[serde(default)]
    reissued: Vec<Settled>,
}

mod opt16 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(h: &Option<[u8; 16]>, s: S) -> Result<S::Ok, S::Error> {
        match h {
            Some(h) => s.serialize_some(&hex::encode(h)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 16]>, D::Error> {
        let v: Option<String> = Option::deserialize(d)?;
        v.map(|s| hex::decode(s).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| serde::de::Error::custom("not 16 bytes"))).transpose()
    }
}

impl Pay {
    fn sides(&self) -> Option<Sides> {
        let (a, b) = (self.halves[0]?, self.halves[1]?);
        core::ordered((a.owner, a.digest()), (b.owner, b.digest()))
    }
    /// Both signatures, in owner order.
    fn psi(&self) -> Option<[[u8; 64]; 2]> {
        let sides = self.sides()?;
        let get = |o: &Hash| self.psi.get(&hex::encode(o)).and_then(|s| hex::decode(s).ok()).and_then(|v| v.try_into().ok());
        Some([get(&sides[0].0)?, get(&sides[1].0)?])
    }
    fn half_of(&self, owner: &Hash) -> Option<Half> {
        self.halves.iter().flatten().find(|h| h.owner == *owner).copied()
    }
}

/// What the book holds against a claim: the spend it cites, the seed.
#[derive(Clone, Debug)]
pub struct Evidence {
    pub cited: core::Cited,
    pub seed: Seed,
}

#[derive(Default, Serialize, Deserialize)]
struct St {
    accounts: BTreeMap<String, Acct>,
    payments: BTreeMap<String, Pay>,
}

pub struct Book {
    path: PathBuf,
    issuer: Keypair,
    s: Mutex<St>,
}

/// A payment's id: the payer's account, the note it takes, and its half's
/// digest (a payment cancelled unsigned leaves the note live, and the next
/// from it is another payment).
pub fn payment_id(half: &Half) -> String {
    format!("{}-{}-{}", hex::encode(half.owner), half.k_in, hex::encode(&half.digest()[..8]))
}

impl Book {
    /// The book at `path` (a new one if there's none), of the issuer `issuer`.
    pub fn open(path: PathBuf, issuer: Keypair) -> Result<Book> {
        let s = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("the book at {}", path.display()))?,
            Err(_) => St::default(),
        };
        Ok(Book { path, issuer, s: Mutex::new(s) })
    }

    pub fn issuer(&self) -> Hash {
        xonly(&self.issuer)
    }

    fn save(&self, s: &St) -> Result<()> {
        lichen_ledger::files::write_atomic(&self.path, &serde_json::to_vec(s)?)?;
        Ok(())
    }

    fn acct<'a>(s: &'a St, owner: &Hash) -> Option<&'a Acct> {
        s.accounts.get(&hex::encode(owner))
    }

    /// An account's live note, from its first (the empty note) if the book
    /// has none.
    fn live_of(s: &St, owner: &Hash) -> Note {
        Book::acct(s, owner).map_or(Note::first(*owner, 0), |a| a.live)
    }

    /// Whether `owner`'s account has any history: a contract's key must be
    /// fresh, its note 0 its mint.
    pub fn knows(&self, owner: &Hash) -> bool {
        let s = self.s.lock().unwrap();
        Book::acct(&s, owner).is_some() || s.payments.values().any(|p| p.to == *owner)
    }

    /// A contract key's account, opened at its mint `(owner, 0, v0)` (once
    /// the contract's funding is out). Asked again, the same.
    pub fn open_account(&self, owner: Hash, v0: u64) -> Result<()> {
        let mut s = self.s.lock().unwrap();
        if let Some(a) = Book::acct(&s, &owner) {
            ensure!(a.live == Note::first(owner, v0) || a.last.is_some() || a.live.k > 0, "account {} exists already, otherwise", hex::encode(owner));
            return Ok(());
        }
        s.accounts.insert(hex::encode(owner), Acct { live: Note::first(owner, v0), last: None, busy: None, closed: None });
        self.save(&s)
    }

    /// `owner`'s account: its live note, settled.
    pub fn account(&self, owner: &Hash) -> Account {
        let s = self.s.lock().unwrap();
        let a = Book::acct(&s, owner);
        Account { live: issue(&self.issuer, Book::live_of(&s, owner)), busy: a.and_then(|a| a.busy.clone()), closed: a.is_some_and(|a| a.closed.is_some()) }
    }

    /// Credit `v` sats to `owner` outright: its account one step on, the
    /// issuer's alone (it only adds). The new note.
    pub fn credit(&self, owner: &Hash, v: u64) -> Result<Settled> {
        let mut s = self.s.lock().unwrap();
        let mut a = Book::acct(&s, owner).cloned().unwrap_or(Acct { live: Note::first(*owner, 0), last: None, busy: None, closed: None });
        ensure!(a.closed.is_none(), "a closed account");
        ensure!(a.busy.is_none(), "a payment is pending on the account: retry");
        a.live = Note { owner: *owner, k: a.live.k.checked_add(1).context("the account's number")?, v: a.live.v.checked_add(v).filter(|v| *v < core::VALUE_LIMIT).context("a value too large")? };
        let live = a.live;
        s.accounts.insert(hex::encode(owner), a);
        self.save(&s)?;
        Ok(issue(&self.issuer, live))
    }

    fn view(&self, p: &Pay) -> Payment {
        Payment {
            id: p.id.clone(),
            from: p.from,
            to: p.to,
            amount: p.amount,
            state: p.state,
            sides: p.sides().map(|s| sides_to(&s)),
            grant: p.grant.clone(),
            signed: p.psi.keys().cloned().collect(),
            seed: p.seed.filter(|_| p.released).map(hex::encode),
            reissued: p.reissued.clone(),
        }
    }

    /// Whether an account may take part in a payment now: open, not busy.
    fn free(s: &St, owner: &Hash) -> Result<()> {
        if let Some(a) = Book::acct(s, owner) {
            ensure!(a.closed.is_none(), "account {} is closed", hex::encode(owner));
            if let Some(b) = &a.busy {
                bail!("busy, retry: account {} has payment {b} pending", hex::encode(owner));
            }
        }
        Ok(())
    }

    /// A payer's half (`POST /pay`): it takes her live note and pays
    /// `amount` to `to`. The payment, proposed.
    pub fn pay(&self, half: Half, to: Hash, amount: u64) -> Result<Payment> {
        let mut s = self.s.lock().unwrap();
        ensure!(amount > 0, "a payment of nothing");
        ensure!(to != half.owner, "a payment to oneself");
        let live = Book::live_of(&s, &half.owner);
        ensure!(half.input() == live, "the half takes note {} of {}, not the live one ({})", half.k_in, half.v_in, live.k);
        ensure!(half.v_out.checked_add(amount) == Some(half.v_in), "the half leaves {} of {}, not {} less", half.v_out, half.v_in, amount);
        Book::free(&s, &half.owner)?;
        let id = crate::book::payment_id(&half);
        if let Some(p) = s.payments.get(&id) {
            ensure!(p.halves[0] == Some(half) && p.to == to && p.state != State::Cancelled, "payment {id} is another, or cancelled");
            return Ok(self.view(p));
        }
        let p = Pay { id: id.clone(), from: half.owner, to, amount, state: State::Proposed, halves: [Some(half), None], grant: None, psi: BTreeMap::new(), seed: None, released: false, reissued: vec![] };
        s.accounts.entry(hex::encode(half.owner)).or_insert(Acct { live, last: None, busy: None, closed: None }).busy = Some(id.clone());
        let v = self.view(&p);
        s.payments.insert(id, p);
        self.save(&s)?;
        Ok(v)
    }

    /// Payments to `owner` awaiting its half.
    pub fn incoming(&self, owner: &Hash) -> Vec<Payment> {
        let s = self.s.lock().unwrap();
        s.payments.values().filter(|p| p.to == *owner && p.state == State::Proposed).map(|p| self.view(p)).collect()
    }

    pub fn payment(&self, id: &str) -> Option<Payment> {
        let s = self.s.lock().unwrap();
        s.payments.get(id).map(|p| self.view(p))
    }

    /// The payee's half (`POST /half`): it takes its live note and gains
    /// the amount. The payment, granted.
    pub fn half(&self, id: &str, half: Half) -> Result<Payment> {
        let mut s = self.s.lock().unwrap();
        let p = s.payments.get(id).cloned().with_context(|| format!("no payment {id}"))?;
        if p.state == State::Granted && p.halves[1] == Some(half) {
            return Ok(self.view(&p));
        }
        ensure!(p.state == State::Proposed, "payment {id} isn't awaiting a half");
        ensure!(half.owner == p.to, "payment {id} isn't to that owner");
        let live = Book::live_of(&s, &half.owner);
        ensure!(half.input() == live, "the half takes note {} of {}, not the live one ({})", half.k_in, half.v_in, live.k);
        ensure!(half.v_in.checked_add(p.amount) == Some(half.v_out) && half.v_out < core::VALUE_LIMIT, "the half leaves {} of {}, not {} more", half.v_out, half.v_in, p.amount);
        Book::free(&s, &half.owner)?;
        let mut p = p;
        p.halves[1] = Some(half);
        let sides = p.sides().context("a payment to oneself")?;
        let payer = p.halves[0].context("the payer's half")?;
        let of = |o: &Hash| if *o == payer.owner { payer.next() } else { half.next() };
        let next = [of(&sides[0].0)?, of(&sides[1].0)?];
        let z = core::seed(&self.issuer.secret_bytes(), &core::spend_digest(&sides));
        p.grant = Some(Grant::make(&self.issuer, &next, &z));
        p.seed = Some(z);
        p.state = State::Granted;
        s.accounts.entry(hex::encode(half.owner)).or_insert(Acct { live, last: None, busy: None, closed: None }).busy = Some(id.to_string());
        let v = self.view(&p);
        s.payments.insert(id.to_string(), p);
        self.save(&s)?;
        Ok(v)
    }

    /// A party's signature on `α` (`POST /sign`). With both, the spend is
    /// recorded: both accounts one step on; the seed released if
    /// `release` (a test's hub withholds it).
    pub fn sign(&self, id: &str, owner: &Hash, psi: &[u8; 64], release: bool) -> Result<Payment> {
        let mut s = self.s.lock().unwrap();
        let mut p = s.payments.get(id).cloned().with_context(|| format!("no payment {id}"))?;
        ensure!(matches!(p.state, State::Granted | State::Recorded), "payment {id} isn't granted");
        let sides = p.sides().context("the sides")?;
        ensure!(sides.iter().any(|(o, _)| o == owner), "not a party to payment {id}");
        let alpha = p.grant.as_ref().context("the grant")?.alpha(&sides);
        ensure!(verify(owner, &alpha, psi), "the signature isn't the owner's on the payment");
        p.psi.insert(hex::encode(owner), hex::encode(psi));
        if p.state == State::Granted && p.psi().is_some() {
            // both signed: record, both accounts one step on
            for h in p.halves.iter().flatten() {
                let a = s.accounts.get_mut(&hex::encode(h.owner)).context("the account")?;
                ensure!(a.live == h.input(), "account {} moved", hex::encode(h.owner));
                a.live = h.next()?;
                a.busy = None;
                let old = a.last.replace(id.to_string());
                if let Some(old) = old {
                    Book::drop_if_unused(&mut s, &old, id);
                }
            }
            p.state = State::Recorded;
            p.released = release;
        }
        let v = self.view(&p);
        s.payments.insert(id.to_string(), p);
        self.save(&s)?;
        Ok(v)
    }

    /// Drop payment `old` once no account has it as its last spend.
    fn drop_if_unused(s: &mut St, old: &str, new: &str) {
        if old != new && !s.accounts.values().any(|a| a.last.as_deref() == Some(old)) {
            s.payments.remove(old);
        }
    }

    /// Release a recorded payment's seed (a withholding hub, made honest).
    pub fn release(&self, id: &str) -> Result<Payment> {
        let mut s = self.s.lock().unwrap();
        let p = s.payments.get_mut(id).with_context(|| format!("no payment {id}"))?;
        ensure!(p.state == State::Recorded, "payment {id} isn't recorded");
        p.released = true;
        let v = self.view(p);
        self.save(&s)?;
        Ok(v)
    }

    /// A party's cancel (`POST /cancel`), signed. Recorded: the seed (if
    /// `release`). Otherwise refused from now on, and each party that
    /// signed reissued its note one step on.
    pub fn cancel(&self, id: &str, owner: &Hash, sig: &[u8; 64], release: bool) -> Result<Payment> {
        let mut s = self.s.lock().unwrap();
        let mut p = s.payments.get(id).cloned().with_context(|| format!("no payment {id}"))?;
        ensure!(p.from == *owner || p.to == *owner, "not a party to payment {id}");
        ensure!(verify(owner, &cancel_msg(id), sig), "the cancel isn't signed by the owner");
        match p.state {
            State::Recorded => {
                ensure!(release || p.released, "payment {id} is recorded: its seed is withheld (a test's hub)");
                p.released = true;
            }
            State::Cancelled => {}
            State::Proposed | State::Granted => {
                for h in p.halves.iter().flatten() {
                    let a = s.accounts.get_mut(&hex::encode(h.owner)).context("the account")?;
                    if a.busy.as_deref() == Some(id) {
                        a.busy = None;
                    }
                    if p.psi.contains_key(&hex::encode(h.owner)) && a.live == h.input() {
                        a.live = Note { owner: h.owner, k: h.k_in + 1, v: h.v_in };
                        p.reissued.push(issue(&self.issuer, a.live));
                    }
                }
                p.state = State::Cancelled;
            }
        }
        let v = self.view(&p);
        s.payments.insert(id.to_string(), p);
        self.save(&s)?;
        Ok(v)
    }

    /// Take a claim on contract `cid` of `owner`'s note `claim` (an exit's,
    /// or a withdrawal's): the account closed. The evidence against it: the
    /// last spend recorded on the account, if it takes the claimed note or
    /// a later one. Taken again, the same.
    pub fn take_claim(&self, cid: u32, owner: &Hash, claim: &core::Claim) -> Result<Option<Evidence>> {
        let mut s = self.s.lock().unwrap();
        let a = s.accounts.get_mut(&hex::encode(owner)).with_context(|| format!("no account {}", hex::encode(owner)))?;
        if let Some(c) = a.closed {
            ensure!(c == cid, "account {} closed by contract {c}", hex::encode(owner));
        }
        a.closed = Some(cid);
        a.busy = None;
        let last = a.last.clone();
        let ev = last.and_then(|id| s.payments.get(&id)).and_then(|p| {
            let half = p.half_of(owner)?;
            (half.k_in >= claim.k).then_some(())?;
            let sides = p.sides()?;
            Some(Evidence { cited: p.grant.as_ref()?.cited(&half, &sides, &p.psi()?), seed: p.seed? })
        });
        self.save(&s)?;
        Ok(ev)
    }

    /// What the book holds against a claim of `owner`'s note `k`, without
    /// taking it.
    pub fn evidence(&self, owner: &Hash, k: u32) -> Option<Evidence> {
        let s = self.s.lock().unwrap();
        let p = s.payments.get(Book::acct(&s, owner)?.last.as_ref()?)?;
        let half = p.half_of(owner)?;
        (half.k_in >= k).then_some(())?;
        Some(Evidence { cited: p.grant.as_ref()?.cited(&half, &p.sides()?, &p.psi()?), seed: p.seed? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{keypair, sign};

    fn kp(b: u8) -> Keypair {
        keypair(&[b; 32]).unwrap()
    }

    /// A payment of `amount` from `a` to `b` through the book, both signing.
    fn pay(book: &Book, a: &Keypair, b: &Keypair, amount: u64, release: bool) -> Payment {
        let la = book.account(&xonly(a)).live.note;
        let p = book.pay(Half::of(&la, la.v - amount), xonly(b), amount).unwrap();
        let lb = book.account(&xonly(b)).live.note;
        let hb = Half::of(&lb, lb.v + amount);
        let p = book.half(&p.id, hb).unwrap();
        let sides = crate::proto::sides_from(&p.sides.unwrap());
        let alpha = p.grant.as_ref().unwrap().alpha(&sides);
        book.sign(&p.id, &xonly(a), &sign(a, &alpha), release).unwrap();
        book.sign(&p.id, &xonly(b), &sign(b, &alpha), release).unwrap()
    }

    #[test]
    fn payments_through_the_book() {
        let dir = std::env::temp_dir().join(format!("lichen-notes-book-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (hub, alice, bob) = (kp(1), kp(2), kp(3));
        let book = Book::open(dir.join("book.json"), hub).unwrap();
        let issuer = book.issuer();
        book.open_account(xonly(&alice), 1000).unwrap();
        let p = pay(&book, &alice, &bob, 300, true);
        assert_eq!(p.state, State::Recorded);
        let z = crate::seed_hex(p.seed.as_ref().unwrap()).unwrap();
        // both new notes open with the seed
        let g = p.grant.unwrap();
        let sides = crate::proto::sides_from(&p.sides.unwrap());
        for (i, (o, _)) in sides.iter().enumerate() {
            let n = book.account(o).live.note;
            assert!(g.complete(&issuer, i, &n, &z).unwrap().verify(&issuer));
        }
        assert_eq!(book.account(&xonly(&alice)).live.note, Note { owner: xonly(&alice), k: 1, v: 700 });
        assert_eq!(book.account(&xonly(&bob)).live.note, Note { owner: xonly(&bob), k: 1, v: 300 });
        // a half of a note no longer live is refused
        assert!(book.pay(Half::of(&Note { owner: xonly(&alice), k: 0, v: 1000 }, 900), xonly(&bob), 100).is_err());
        // busy, retry: one pending payment per account
        let la = book.account(&xonly(&alice)).live.note;
        let q = book.pay(Half::of(&la, la.v - 10), xonly(&bob), 10).unwrap();
        let lb = book.account(&xonly(&bob)).live.note;
        assert!(book.pay(Half::of(&lb, lb.v - 5), xonly(&alice), 5).is_ok());
        // bob is busy paying alice: his half for q waits
        assert!(book.half(&q.id, Half::of(&lb, lb.v + 10)).is_err());
        // cancel q (unsigned): no reissue
        let c = book.cancel(&q.id, &xonly(&alice), &sign(&alice, &cancel_msg(&q.id)), true).unwrap();
        assert_eq!((c.state, c.reissued.len()), (State::Cancelled, 0));
        // a claim of alice's note 0 (stale): the payment that took it cited
        let ev = book.evidence(&xonly(&alice), 0).unwrap();
        assert_eq!(ev.cited.half.v_out, 700);
        assert!(book.evidence(&xonly(&alice), 1).is_none());
        // reopened from its file: the same
        drop(book);
        let book = Book::open(dir.join("book.json"), keypair(&[1; 32]).unwrap()).unwrap();
        assert_eq!(book.account(&xonly(&alice)).live.note.v, 700);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cancel_after_signing_reissues() {
        let dir = std::env::temp_dir().join(format!("lichen-notes-cancel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (hub, alice, bob) = (kp(1), kp(2), kp(3));
        let book = Book::open(dir.join("book.json"), hub).unwrap();
        book.open_account(xonly(&alice), 1000).unwrap();
        let la = book.account(&xonly(&alice)).live.note;
        let p = book.pay(Half::of(&la, 600), xonly(&bob), 400).unwrap();
        let lb = book.account(&xonly(&bob)).live.note;
        let p = book.half(&p.id, Half::of(&lb, 400)).unwrap();
        let alpha = p.grant.as_ref().unwrap().alpha(&crate::proto::sides_from(&p.sides.unwrap()));
        book.sign(&p.id, &xonly(&alice), &sign(&alice, &alpha), true).unwrap();
        let c = book.cancel(&p.id, &xonly(&alice), &sign(&alice, &cancel_msg(&p.id)), true).unwrap();
        assert_eq!(c.reissued.len(), 1);
        assert_eq!(c.reissued[0].note, Note { owner: xonly(&alice), k: 1, v: 1000 });
        // bob's late signature records nothing
        assert!(book.sign(&p.id, &xonly(&bob), &sign(&bob, &alpha), true).is_err());
        // a withholding hub records and keeps the seed
        let la = book.account(&xonly(&alice)).live.note;
        let p = pay(&book, &alice, &bob, 100, false);
        assert_eq!((p.state, p.seed.is_none()), (State::Recorded, true));
        // her claim of the note the payment took: cited, with the seed
        let ev = book.take_claim(9, &xonly(&alice), &issue(&keypair(&[1; 32]).unwrap(), la).claim()).unwrap().unwrap();
        assert!(crate::Grant::opens(p.grant.as_ref().unwrap(), &ev.seed));
        assert!(book.account(&xonly(&alice)).closed);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

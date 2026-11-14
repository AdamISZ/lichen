//! The wallet's accounts on the grants L2 (papers/lichen-grants-v0.5.6):
//! one note per key, numbered in sequence, and payments made by joint
//! spends that both parties sign (`lichen_notes`).
//!
//! The wallet holds, per key, its live note ([`Acct`]) and at most one
//! payment pending ([`Pending`]): Rule 2, one pending signature per
//! account. It signs only a step from the note it holds (Rule 3): its half
//! names its live note and the value it expects. A payment's steps:
//!
//! - the payer: [`Wallet::pay`] (`POST /pay`, its half);
//! - the payee: [`Wallet::receive`] (`GET /incoming`, `POST /half`);
//! - both: [`Wallet::progress`], once the hub has granted it: check the
//!   grant (its pre-signature on our new note; the other side's owner the
//!   one we deal with), sign `α`; once recorded, complete the new note with
//!   the seed.
//!
//! A party in flight (signed, no seed) keeps its old note: an exit claims
//! it, and if the hub cites the spend it must publish the seed
//! ([`Wallet::complete`]). [`Wallet::cancel`] asks the hub to give up the
//! payment: the seed if it was recorded, else a reissue of the note one
//! step on.
//!
//! Each contract has an L2 key of its own, fresh at its opening: its
//! account starts at its mint, note 0. The wallet's address is its open
//! contract's key.

use anyhow::{bail, ensure, Context, Result};
use lichen_notes::proto::{cancel_msg, sides_from, Account, CancelRequest, HalfRequest, PayRequest, Payment, Side, SignRequest, State};
use lichen_notes::{sign, Grant, Half, Hash, Note, Seed, Settled};
use serde::{Deserialize, Serialize};

use crate::exit::ExitPlan;
use crate::{hub_call, Wallet};

/// A payment pending on one of our accounts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pending {
    pub id: String,
    /// Our half, and whether we pay (else we're paid).
    pub half: Half,
    pub payer: bool,
    /// The other party, and the amount.
    #[serde(with = "lichen_notes::hex32")]
    pub peer: Hash,
    pub amount: u64,
    /// Once granted and signed: the sides and the grant, as we signed them.
    #[serde(default)]
    pub sides: Option<[Side; 2]>,
    #[serde(default)]
    pub grant: Option<Grant>,
    #[serde(default)]
    pub signed: bool,
}

impl Pending {
    /// Our index among the sides.
    fn index(&self) -> Option<usize> {
        self.sides.map(|s| usize::from(s[0].owner != self.half.owner))
    }
}

/// One of our accounts: its live note, a payment pending.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Acct {
    pub live: Settled,
    #[serde(default)]
    pub pending: Option<Pending>,
    /// Claimed (a withdrawal, an exit): the hub closed it; what it held is
    /// on chain, or credited elsewhere.
    #[serde(default)]
    pub closed: bool,
}

/// What a step of a payment came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Signed; the seed awaited.
    Signed(String),
    /// Done: our new note settled.
    Done(String, Settled),
    /// Cancelled: our note as it stands now.
    Cancelled(String, Settled),
}

impl Wallet {
    /// The hub's issuer key: every note's signer.
    pub fn issuer(&self) -> Hash {
        self.deployment.hub
    }
    /// What our accounts hold.
    pub fn balance(&self) -> u64 {
        self.accounts.values().filter(|a| !a.closed).map(|a| a.live.note.v).sum()
    }
    /// Our account under `owner`: its live note, the empty note if none.
    pub fn account(&self, owner: &Hash) -> Acct {
        self.accounts.get(&hex::encode(owner)).cloned().unwrap_or(Acct { live: Settled::first(*owner, 0), pending: None, closed: false })
    }
    fn set_account(&mut self, a: Acct) {
        self.accounts.insert(hex::encode(a.live.note.owner), a);
    }
    /// The live note of our open contract's account.
    pub fn live(&self) -> Settled {
        self.account(&self.address()).live
    }

    /// Our accounts as the hub has them: a later note of the hub's that is
    /// no less than ours (a credit, a reissue, a step we missed the end of)
    /// taken; then each pending payment moved on. How many changed.
    pub fn sync(&mut self) -> Result<usize> {
        let mut n = 0;
        for owner in self.owners() {
            let a: Account = hub_call(&format!("{}/account/{}", self.hub, hex::encode(owner)), None, true)?;
            let mut mine = self.account(&owner);
            if a.live.note.owner == owner && a.live.note.k > mine.live.note.k && a.live.note.v >= mine.live.note.v && a.live.verify(&self.issuer()) && mine.pending.is_none() {
                mine.live = a.live;
                self.set_account(mine);
                n += 1;
            }
        }
        n += self.progress()?.len();
        self.save()?;
        Ok(n)
    }

    /// Pay `amount` sats to `to` from our open contract's account (`POST
    /// /pay`): the payment's id. The payee must be online to take it.
    pub fn pay(&mut self, to: Hash, amount: u64) -> Result<String> {
        let me = self.address();
        let mut a = self.account(&me);
        ensure!(a.pending.is_none(), "a payment is pending on our account: finish or cancel it first");
        ensure!(amount > 0 && amount <= a.live.note.v, "a payment of {amount} sats from {}", a.live.note.v);
        ensure!(to != me, "a payment to ourselves");
        let half = Half::of(&a.live.note, a.live.note.v - amount);
        // kept before it goes: a lost answer leaves it proposed at the hub
        a.pending = Some(Pending { id: lichen_notes::book::payment_id(&half), half, payer: true, peer: to, amount, sides: None, grant: None, signed: false });
        self.set_account(a.clone());
        self.save()?;
        let p: Payment = hub_call(&format!("{}/pay", self.hub), Some(serde_json::to_string(&PayRequest { half, to, amount })?), true)?;
        ensure!(p.id == a.pending.as_ref().unwrap().id, "the hub named the payment {}", p.id);
        Ok(p.id)
    }

    /// Take the first payment to our open contract's account (`GET
    /// /incoming`, `POST /half`), if we have none pending: its id.
    pub fn receive(&mut self) -> Result<Option<String>> {
        let me = self.address();
        let mut a = self.account(&me);
        if a.pending.is_some() {
            return Ok(None);
        }
        let incoming: Vec<Payment> = hub_call(&format!("{}/incoming/{}", self.hub, hex::encode(me)), None, true)?;
        let Some(p) = incoming.into_iter().find(|p| p.to == me && p.amount > 0) else { return Ok(None) };
        let v_out = a.live.note.v.checked_add(p.amount).filter(|v| *v < lichen_notes::VALUE_LIMIT).context("a payment too large")?;
        let half = Half::of(&a.live.note, v_out);
        a.pending = Some(Pending { id: p.id.clone(), half, payer: false, peer: p.from, amount: p.amount, sides: None, grant: None, signed: false });
        self.set_account(a);
        self.save()?;
        let _: Payment = hub_call(&format!("{}/half", self.hub), Some(serde_json::to_string(&HalfRequest { id: p.id.clone(), half })?), true)?;
        self.say(format!("taking a payment of {} sats from {}", p.amount, &hex::encode(p.from)[..12]));
        Ok(Some(p.id))
    }

    /// Move each pending payment on, as the hub shows it: sign it once
    /// granted (the grant checked), complete it once recorded, apply a
    /// cancel. The steps taken.
    pub fn progress(&mut self) -> Result<Vec<Step>> {
        let mut steps = vec![];
        let pending: Vec<Hash> = self.accounts.values().filter(|a| a.pending.is_some()).map(|a| a.live.note.owner).collect();
        for owner in pending {
            let a = self.account(&owner);
            let pend = a.pending.clone().expect("pending");
            let p: Payment = match hub_call(&format!("{}/payment/{}", self.hub, pend.id), None, true) {
                Ok(p) => p,
                Err(e) => {
                    self.say(format!("payment {}: {e:#}", pend.id));
                    continue;
                }
            };
            match p.state {
                State::Proposed => {}
                State::Granted if !pend.signed => steps.push(self.sign_payment(&owner, &p)?),
                State::Granted => {}
                State::Recorded => {
                    if !pend.signed {
                        steps.push(self.sign_payment(&owner, &p)?);
                    }
                    if let Some(z) = &p.seed {
                        let z = lichen_notes::seed_hex(z)?;
                        steps.push(self.complete(&owner, &z)?);
                    }
                }
                State::Cancelled => steps.push(self.cancelled(&owner, &p)?),
            }
        }
        self.save()?;
        Ok(steps)
    }

    /// Sign payment `p` on our account `owner`, its grant checked: the
    /// sides hold our half and the other party's owner; the pre-signature
    /// on our new note verifies.
    fn sign_payment(&mut self, owner: &Hash, p: &Payment) -> Result<Step> {
        let mut a = self.account(owner);
        let mut pend = a.pending.clone().context("nothing pending")?;
        ensure!(p.id == pend.id && p.amount == pend.amount, "payment {} isn't the one pending", p.id);
        let sides = p.sides.context("the payment's sides")?;
        let grant = p.grant.clone().context("the payment's grant")?;
        let i = usize::from(sides[0].owner != pend.half.owner);
        ensure!(sides[i].owner == pend.half.owner && sides[i].h == pend.half.digest(), "the spend doesn't hold our half");
        ensure!(sides[1 - i].owner == pend.peer, "the spend's other side isn't the party we deal with");
        let next = pend.half.next()?;
        grant.verify(&self.issuer(), i, &next)?;
        let alpha = grant.alpha(&sides_from(&sides));
        let psi = sign(&self.kp_of(owner)?, &alpha);
        pend.sides = Some(sides);
        pend.grant = Some(grant);
        pend.signed = true;
        a.pending = Some(pend.clone());
        self.set_account(a);
        // kept before it goes: from here we're in flight
        self.save()?;
        let _: Payment = hub_call(&format!("{}/sign", self.hub), Some(serde_json::to_string(&SignRequest { id: pend.id.clone(), owner: *owner, psi })?), true)?;
        Ok(Step::Signed(pend.id))
    }

    /// Complete our pending payment on account `owner` with seed `z` (from
    /// the hub, the other party, or `correct`): our new note settled and
    /// live.
    pub fn complete(&mut self, owner: &Hash, z: &Seed) -> Result<Step> {
        let mut a = self.account(owner);
        let pend = a.pending.clone().context("nothing pending")?;
        let (grant, i) = (pend.grant.clone().context("not signed")?, pend.index().context("not signed")?);
        let next = pend.half.next()?;
        let s = grant.complete(&self.issuer(), i, &next, z)?;
        a.live = s;
        a.pending = None;
        self.set_account(a);
        self.save()?;
        self.say(format!("payment {}: {} {} sats, note {} of {} sats", pend.id, if pend.payer { "paid" } else { "received" }, pend.amount, s.note.k, s.note.v));
        Ok(Step::Done(pend.id, s))
    }

    /// Whether `z` opens the grant of our pending payment on `owner`.
    pub fn opens(&self, owner: &Hash, z: &Seed) -> bool {
        self.account(owner).pending.and_then(|p| p.grant).is_some_and(|g| g.opens(z))
    }

    fn cancelled(&mut self, owner: &Hash, p: &Payment) -> Result<Step> {
        let mut a = self.account(owner);
        if let Some(r) = p.reissued.iter().find(|r| r.note.owner == *owner) {
            ensure!(r.verify(&self.issuer()) && r.note.k == a.live.note.k + 1 && r.note.v == a.live.note.v, "a reissue not of our note");
            a.live = *r;
        }
        a.pending = None;
        let live = a.live;
        self.set_account(a);
        self.save()?;
        Ok(Step::Cancelled(p.id.clone(), live))
    }

    /// Ask the hub to cancel the payment pending on our open contract's
    /// account (`POST /cancel`): recorded, its seed completes it; otherwise
    /// it is refused from now on, and our note reissued if we signed.
    pub fn cancel(&mut self) -> Result<Step> {
        let me = self.address();
        let pend = self.account(&me).pending.context("no payment pending")?;
        let sig = sign(&self.kp_of(&me)?, &cancel_msg(&pend.id));
        let p: Payment = hub_call(&format!("{}/cancel", self.hub), Some(serde_json::to_string(&CancelRequest { id: pend.id.clone(), owner: me, sig })?), true)?;
        match (p.state, &p.seed) {
            (State::Recorded, Some(z)) => self.complete(&me, &lichen_notes::seed_hex(z)?),
            (State::Cancelled, _) => self.cancelled(&me, &p),
            _ => bail!("payment {} not cancelled: {:?}", p.id, p.state),
        }
    }

    /// The exit claim of contract `cid`'s account, `units` of its unit:
    /// its live note (in flight, the note the spend takes: the step, if the
    /// hub cites it, counts by itself).
    pub(crate) fn claim_for(&mut self, cid: u32, units: u32) -> Result<ExitPlan> {
        let record = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?.record.clone();
        let live = self.account(&record.l2_address).live;
        let v = if live.note.k == 0 { record.hp().v0 } else { live.note.v };
        ensure!(u64::from(units) * record.terms.unit.to_sat() <= v, "the account holds {v} sats, short of {units} units");
        let q = hex::encode(live.claim().to_bytes());
        Ok(ExitPlan { b: units, claim: q.clone(), posted: q })
    }

    /// Contract `cid`'s account, claimed: closed.
    pub(crate) fn close_account(&mut self, cid: u32) -> Result<()> {
        let owner = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?.record.l2_address;
        let mut a = self.account(&owner);
        a.closed = true;
        self.set_account(a);
        self.save()
    }

    /// A note of ours, as the hub signed it (tests, front ends).
    pub fn note_of(&self, owner: &Hash) -> Note {
        self.account(owner).live.note
    }
}

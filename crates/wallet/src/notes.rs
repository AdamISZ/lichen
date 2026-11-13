//! The wallet's notes on the grants L2 (`lichen_notes`): collected from
//! the hub's mailbox, paid by grants, merged so that it holds few.
//!
//! A payment spends all our notes at once: the payment and our change come
//! out, so after it we hold one note. Notes received since are merged into
//! one by a payment to ourselves once there are more than
//! [`KEEP_NOTES`]: an exit claims every note it needs in one `request`,
//! and a hub that won't merge them is a hub to leave
//! ([`ALARM_NOTES`]).
//!
//! Each contract has an L2 key of its own, fresh at its opening: its
//! claims take the notes paid to it, and a spend of them is cited against
//! them only by completing the grant's reveal on its `correct` (checked
//! here before we sign). The wallet's address is its contract's key; the
//! notes of its other keys (its own, a closed contract's) are moved to it.
//!
//! A spend is kept before it goes ([`InFlight`]): until the hub answers
//! with `t`, its inputs may be spent or not. Finishing it again asks the
//! same (the hub's grant and record are idempotent). A hub that says it
//! has no grant on it is taken at its word for spending the inputs again,
//! but not for claiming them: the spend stays a fallback of any claim of
//! its inputs until a spend of ours that we hold `t` for consumes them (a
//! hub that recorded it and said otherwise could cite it against us).

use anyhow::{ensure, Context, Result};
use bitcoin::secp256k1::SecretKey;
use lichen_notes::{auth_msg, sign, Authorized, Claim, Delivery, Grant, Hash, Note, Output, Settled, Spend, MAX_CLAIM_NOTES, MAX_INPUTS};
use serde::{Deserialize, Serialize};

use crate::exit::ExitPlan;
use crate::{hub_call, Wallet};

/// The notes the wallet keeps before merging them into one.
pub const KEEP_NOTES: usize = 2;
/// Notes left unmerged past which the hub is refusing merges, or worse:
/// stop taking payments, and exit while every note fits in a claim.
pub const ALARM_NOTES: usize = 4;

/// A spend we signed, not yet answered with its unlock.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InFlight {
    pub spend: Spend,
    pub grant: Grant,
    pub sigs: Vec<String>,
    /// The hub said it has no grant on it: not asked again.
    #[serde(default)]
    pub abandoned: bool,
}

impl Wallet {
    /// The hub's issuer key: every note's signer.
    pub fn issuer(&self) -> Hash {
        self.deployment.hub
    }
    /// What our notes hold.
    pub fn balance(&self) -> u64 {
        self.notes.iter().map(|s| s.note.value).sum()
    }
    /// A note for us, kept if new: settled by the hub, ours, not one we
    /// spent.
    fn add_note(&mut self, s: Settled) -> Result<bool> {
        ensure!(s.verify(&self.issuer()), "a note not signed by the hub: {}", hex::encode(s.note.id));
        ensure!(self.owners().contains(&s.note.owner), "a note of someone else's: {}", hex::encode(s.note.id));
        if self.notes.iter().any(|x| x.note.id == s.note.id) || self.spent.contains(&s.note.id) {
            return Ok(false);
        }
        self.notes.push(s);
        Ok(true)
    }
    /// Collect what the hub's mailbox holds for us, after finishing our
    /// spends in flight. How many notes are new.
    pub fn sync(&mut self) -> Result<usize> {
        self.settle_inflight()?;
        let mut new = 0;
        for owner in self.owners() {
            let k = hex::encode(owner);
            let from = self.mailboxes.get(&k).copied().unwrap_or(0);
            let ds: Vec<Delivery> = hub_call(&format!("{}/mailbox/{k}?from={from}", self.hub), None, true)?;
            for d in &ds {
                if self.add_note(d.settled.clone())? {
                    new += 1;
                }
            }
            if !ds.is_empty() {
                self.mailboxes.insert(k, from + ds.len());
            }
        }
        self.save()?;
        Ok(new)
    }
    /// Our notes as the hub's book has them, unspent (a wallet restored
    /// from its file, or from its key): each checked, the mailbox read
    /// past what they include.
    pub fn restore_notes(&mut self) -> Result<usize> {
        self.settle_inflight()?;
        self.notes.clear();
        for owner in self.owners() {
            let k = hex::encode(owner);
            let theirs: Vec<Settled> = hub_call(&format!("{}/notes/{k}", self.hub), None, true)?;
            let all: Vec<Delivery> = hub_call(&format!("{}/mailbox/{k}?from=0", self.hub), None, true)?;
            for s in theirs {
                self.spent.retain(|id| *id != s.note.id);
                self.add_note(s)?;
            }
            self.mailboxes.insert(k, all.len());
        }
        self.save()?;
        Ok(self.notes.len())
    }
    /// Pay `amount` to `to`: all our notes in, the payment and our change
    /// out. The spend's id.
    pub fn send(&mut self, to: Hash, amount: u64) -> Result<Hash> {
        ensure!(amount > 0, "nothing to send");
        self.sync()?;
        let total = self.balance();
        ensure!(total >= amount, "the balance is {total} sats, short of {amount}");
        ensure!(to != self.address(), "a payment to ourselves: merge instead");
        let mut outputs = vec![Output { owner: to, value: amount }];
        if total > amount {
            outputs.push(Output { owner: self.address(), value: total - amount });
        }
        self.pay(outputs)
    }
    /// Merge our notes into one under our address, by a payment to
    /// ourselves, if we hold more than [`KEEP_NOTES`] or any under another
    /// key of ours. Its id if it did.
    pub fn merge(&mut self) -> Result<Option<Hash>> {
        let me = self.address();
        if self.notes.len() <= KEEP_NOTES && self.notes.iter().all(|s| s.note.owner == me) {
            return Ok(None);
        }
        let total = self.balance();
        self.pay(vec![Output { owner: self.address(), value: total }]).map(Some)
    }
    /// Spend all our notes (at most [`MAX_INPUTS`]) to `outputs`: the
    /// hub's grant checked, signed with the spend, kept, then recorded.
    fn pay(&mut self, outputs: Vec<Output>) -> Result<Hash> {
        ensure!(!self.notes.is_empty(), "no notes to spend");
        ensure!(self.notes.len() <= MAX_INPUTS, "{} notes, more than a spend takes ({MAX_INPUTS})", self.notes.len());
        let spend = Spend { inputs: self.notes.iter().map(|s| s.note).collect(), outputs };
        spend.check()?;
        let grant: Grant = hub_call(&format!("{}/grant", self.hub), Some(serde_json::to_string(&spend)?), true)?;
        grant.verify(&self.issuer(), &spend).context("the hub's grant")?;
        // for each of our contracts open whose notes it spends: the reveal
        // through its correct, so that the hub can't cite the spend against
        // our claim without giving us t
        for h in self.contracts.iter().filter(|h| h.closed.is_none() && h.payout.is_none() && spend.inputs.iter().any(|n| n.owner == h.record.l2_address)) {
            let Some(m) = h.correct_msg.as_deref().and_then(|m| hex::decode(m).ok()).and_then(|v| <[u8; 32]>::try_from(v).ok()) else { continue };
            grant.verify_reveal(&h.record.l2_address, &h.record.pubs[1].payment, &bitcoin::secp256k1::Message::from_digest(m)).context("the hub's grant")?;
        }
        let msg = auth_msg(&grant.sid, &grant.commitment());
        let sigs = spend.inputs.iter().map(|n| Ok(hex::encode(sign(&self.kp_of(&n.owner)?, &msg)))).collect::<Result<Vec<String>>>()?;
        // kept before it goes: until the hub answers, the inputs may be
        // spent, and the grant opens our change once it does
        self.inflight.push(InFlight { spend, grant, sigs, abandoned: false });
        self.save()?;
        self.finish(self.inflight.len() - 1)
    }
    /// Finish spend in flight `i`: recorded at the hub, its `t` opening the
    /// outputs; its inputs gone, our outputs kept.
    fn finish(&mut self, i: usize) -> Result<Hash> {
        let f = self.inflight[i].clone();
        let r: serde_json::Value = hub_call(&format!("{}/spend", self.hub), Some(serde_json::to_string(&Authorized { sid: f.grant.sid, sigs: f.sigs.clone() })?), true)?;
        let t: [u8; 32] = r.get("t").and_then(|t| t.as_str()).and_then(|t| hex::decode(t).ok()).and_then(|v| v.try_into().ok()).context("the hub's answer has no unlock")?;
        let t = SecretKey::from_slice(&t).context("the unlock")?;
        let outs = f.grant.open(&self.issuer(), &f.spend, &t).context("the unlock doesn't open the grant")?;
        let gone: Vec<Hash> = f.spend.inputs.iter().map(|n| n.id).collect();
        self.notes.retain(|s| !gone.contains(&s.note.id));
        self.spent.extend(gone.iter().copied());
        let mine = self.owners();
        for o in outs.into_iter().filter(|o| mine.contains(&o.note.owner)) {
            self.add_note(o)?;
        }
        self.inflight.remove(i);
        // a spend abandoned whose inputs this one consumed can't have been
        // recorded: done with
        self.inflight.retain(|x| !(x.abandoned && x.spend.inputs.iter().any(|n| gone.contains(&n.id))));
        self.save()?;
        Ok(f.grant.sid)
    }
    /// Each spend in flight finished, or dropped if the hub has no grant on
    /// it (never recorded: its inputs are still ours).
    fn settle_inflight(&mut self) -> Result<()> {
        while let Some(i) = self.inflight.iter().position(|f| !f.abandoned) {
            match self.finish(i) {
                Ok(_) => {}
                Err(e) if format!("{e:#}").contains("no grant on that spend") => {
                    self.inflight[i].abandoned = true;
                    self.save()?;
                }
                Err(e) => return Err(e.context("a spend in flight")),
            }
        }
        Ok(())
    }
    /// A claim of `units` of contract `cid`'s unit: the notes of its key
    /// (our other keys' moved to it first, and merged if too many for one
    /// claim; if still too many with their spends in flight, the largest
    /// that fit what an exit posts), signed with its key. Its notes leave the wallet with it: the hub
    /// spends them when it takes the claim, and returns what they hold
    /// beyond `units` as change.
    pub(crate) fn claim_for(&mut self, cid: u32, units: u32) -> Result<ExitPlan> {
        let record = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?.record.clone();
        // a hub that won't answer (a spend in flight, the mailbox) mustn't
        // hold off the claim: what's unknown is a fallback
        if let Err(e) = self.sync() {
            self.step(format!("claiming without a sync: {e:#}"));
        }
        let owner = record.l2_address;
        if self.address() == owner && (self.notes.len() > MAX_CLAIM_NOTES || self.notes.iter().any(|s| s.note.owner != owner)) {
            if let Err(e) = self.merge() {
                self.step(format!("merging before the claim: {e:#}"));
            }
        }
        let want = u64::from(units) * record.terms.unit.to_sat();
        let held: u64 = self.notes.iter().filter(|s| s.note.owner == owner).map(|s| s.note.value).sum();
        ensure!(held >= want, "the contract's key holds {held} sats, short of {want}");
        // every spend of ours not known recorded whose inputs the claim
        // takes: a fallback
        let fallbacks_of = |notes: &[Settled]| -> Vec<Hash> {
            let ids: Vec<Hash> = notes.iter().map(|s| s.note.id).collect();
            self.inflight.iter().filter(|f| f.spend.inputs.iter().any(|n| ids.contains(&n.id))).map(|f| f.grant.sid).collect()
        };
        let mut chosen: Vec<Settled> = self.notes.iter().filter(|s| s.note.owner == owner).cloned().collect();
        chosen.sort_by_key(|s| std::cmp::Reverse(s.note.value));
        while chosen.len() > 1 && !lichen_withdraw::grants::fits(chosen.len(), fallbacks_of(&chosen).len()) {
            chosen.pop();
        }
        let fallbacks = fallbacks_of(&chosen);
        ensure!(lichen_withdraw::grants::fits(chosen.len(), fallbacks.len()), "{} spends of a note in flight, more than a claim posts", fallbacks.len());
        let total: u64 = chosen.iter().map(|s| s.note.value).sum();
        ensure!(total >= want, "the notes an exit can post hold {total} sats, short of {want}");
        let claim = Claim::new(&self.kp_of(&owner)?, cid, record.hp().deposit, units, chosen.clone(), &fallbacks);
        let posted = claim.g().posted(&self.issuer()).context("the claim's notes aren't the hub's")?;
        let gone: Vec<Hash> = chosen.iter().map(|s| s.note.id).collect();
        self.notes.retain(|s| !gone.contains(&s.note.id));
        self.spent.extend(gone);
        self.save()?;
        Ok(ExitPlan { b: units, claim: hex::encode(claim.to_bytes()), posted: hex::encode(posted.to_bytes()) })
    }
    /// The notes a claim kept with contract `cid` takes.
    pub fn claimed_notes(&self, cid: u32) -> Vec<Note> {
        self.contracts.iter().find(|h| h.record.cid() == cid).and_then(|h| h.exit.as_ref()).and_then(|p| p.claim().ok()).map(|c| c.notes.into_iter().map(|s| s.note).collect()).unwrap_or_default()
    }
}

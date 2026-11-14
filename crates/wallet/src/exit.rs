//! The wallet's exit: a claim of its account's note posted through the
//! contract's dispute ([`crate::engine`] plays it), for when the hub won't
//! fold or has gone. The claim is the note with the hub's signature (`Q`),
//! so it needs nothing from the hub. After a cooperative withdrawal the hub
//! didn't fold, the exit posts that withdrawal's claim.

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};

use crate::dispute::{Outcome, Swept};
use crate::Wallet;

/// An exit's claim, prepared before `request` and kept with the contract
/// until its dispute ends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitPlan {
    /// The amount claimed, in the contract's units.
    pub b: u32,
    /// The claim, `Q`'s bytes, hex: what a cooperative withdrawal hands
    /// the hub.
    pub claim: String,
    /// What `request` posts (one-time signed there): the same bytes, hex.
    pub posted: String,
}

impl ExitPlan {
    /// The claim, `Q`.
    pub fn claim(&self) -> Result<lichen_notes::core::Claim> {
        lichen_notes::core::Claim::from_bytes(&hex::decode(&self.claim)?).context("not a claim's bytes")
    }
    pub fn posted(&self) -> Result<Vec<u8>> {
        Ok(hex::decode(&self.posted)?)
    }
}

impl Wallet {
    /// Exit through contract `cid`: its claim (the one kept: a cooperative
    /// withdrawal's the hub didn't fold; else a claim of its account's note
    /// now), and its dispute played.
    pub fn exit(&mut self, chain: &lichen_chain::Chain, statement: &lichen_proto::Statement, cid: u32) -> Result<(Outcome, Swept)> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let plan = match self.contracts[k].exit.clone() {
            Some(p) => p,
            None => self.keep_exit_claim(chain, cid)?,
        };
        let out = self.play(chain, statement, cid, plan.b)?;
        // the hub took the claim at request: the account is closed
        self.close_account(cid)?;
        Ok(out)
    }

    /// Contract `cid`'s exit claim prepared now and kept with it, not
    /// posted ([`Wallet::exit`] posts the claim kept): its account's live
    /// note (in flight, the note the spend takes), as many whole units as
    /// it holds, up to the cap.
    pub fn keep_exit_claim(&mut self, _chain: &lichen_chain::Chain, cid: u32) -> Result<ExitPlan> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let (t, owner, v0) = (self.contracts[k].record.terms, self.contracts[k].record.l2_address, self.contracts[k].record.hp().v0);
        let unit = t.unit.to_sat();
        // a hub that won't answer mustn't hold off the claim
        if let Err(e) = self.sync() {
            self.say(format!("claiming without a sync: {e:#}"));
        }
        let live = self.account(&owner).live;
        let held = if live.note.k == 0 { v0 } else { live.note.v };
        let units = (held.min(t.v_max().to_sat()) / unit) as u32;
        ensure!(units > 0, "nothing to claim: {held} sats in the contract's account, a unit of {unit}");
        let p = self.claim_for(cid, units)?;
        self.contracts[k].exit = Some(p.clone());
        self.save()?;
        Ok(p)
    }

    /// The seed `correct` published in contract `cid`'s dispute, if any:
    /// the counterparty of the spend it completes needs it.
    pub fn unlock_of(&self, chain: &lichen_chain::Chain, statement: &lichen_proto::Statement, cid: u32) -> Result<Option<lichen_notes::Seed>> {
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let d = lichen_proto::hp::HpDisputed::new(&h.record, statement)?;
        let Some(correct) = chain.get_tx(&d.txid("correct")) else { return Ok(None) };
        let (_, u) = lichen_proto::hp::HpDisputed::corrected(&correct)?;
        Ok((u != [0; lichen_notes::U_LEN]).then_some(u))
    }

    /// Complete the payment pending on our open contract's account with a
    /// seed handed to us (by the other party, or read from its exit's
    /// `correct`).
    pub fn complete_with(&mut self, z: &lichen_notes::Seed) -> Result<crate::notes::Step> {
        let me = self.address();
        ensure!(self.opens(&me, z), "the seed doesn't open our payment pending");
        self.complete(&me, z)
    }
}

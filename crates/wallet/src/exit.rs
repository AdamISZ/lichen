//! The wallet's exit: a claim of its notes posted through the contract's
//! dispute ([`crate::engine`] plays it), for when the hub won't fold or has
//! gone. The claim is the notes themselves, each with the hub's signature
//! ([`lichen_notes::Claim`]), so it needs nothing from the hub. After a
//! cooperative withdrawal the hub didn't fold, the exit posts that
//! withdrawal's claim.
//!
//! Milestone 1 of the grants L2 (docs/GRANTS_PLAN.md): the hub doesn't
//! contest a claim yet, so `request_timeout` pays it; milestone 2 adds the
//! statement "she is owed at most `b_corr`".

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
    /// The claim ([`lichen_notes::Claim`]'s bytes, signed with our key):
    /// what a cooperative withdrawal hands the hub, hex.
    pub claim: String,
    /// What `request` posts of it (`lichen_withdraw::grants::Posted`'s
    /// bytes, one-time signed there), hex.
    pub posted: String,
}

impl ExitPlan {
    pub fn claim(&self) -> Result<lichen_notes::Claim> {
        lichen_notes::Claim::from_bytes(&hex::decode(&self.claim)?)
    }
    pub fn posted(&self) -> Result<Vec<u8>> {
        Ok(hex::decode(&self.posted)?)
    }
}

impl Wallet {
    /// Exit through contract `cid`: its claim (the one kept: a cooperative
    /// withdrawal's the hub didn't fold; else a claim of our notes now),
    /// and its dispute played.
    pub fn exit(&mut self, chain: &lichen_chain::Chain, statement: &lichen_proto::Statement, cid: u32) -> Result<(Outcome, Swept)> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let plan = match self.contracts[k].exit.clone() {
            Some(p) => p,
            None => self.keep_exit_claim(chain, cid)?,
        };
        self.play(chain, statement, cid, plan.b)
    }

    /// Contract `cid`'s exit claim prepared now and kept with it, not
    /// posted ([`Wallet::exit`] posts the claim kept): the notes of its
    /// key (our others' moved to it first, if the hub will), as many whole
    /// units as they hold, up to the cap.
    pub fn keep_exit_claim(&mut self, _chain: &lichen_chain::Chain, cid: u32) -> Result<ExitPlan> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let (t, owner) = (self.contracts[k].record.terms, self.contracts[k].record.l2_address);
        let unit = t.unit.to_sat();
        let _ = self.sync();
        if self.address() == owner {
            let _ = self.merge();
        }
        let held: u64 = self.notes.iter().filter(|s| s.note.owner == owner).map(|s| s.note.value).sum();
        let units = (held.min(t.v_max().to_sat()) / unit) as u32;
        ensure!(units > 0, "nothing to claim: {held} sats of notes under the contract's key, a unit of {unit}");
        let p = self.claim_for(cid, units)?;
        self.contracts[k].exit = Some(p.clone());
        self.save()?;
        Ok(p)
    }

    /// The unlocks `correct` revealed to us (contract `cid`'s dispute, once
    /// the hub corrected the claim): each spend of ours in flight that the
    /// hub cited, completed in a slot of `correct`, finished with its `t`.
    /// Their outputs (the payees' notes too, to hand them), the spends done
    /// with. Our own outputs stay with the claim (the statement counted
    /// them as revived change).
    pub fn revealed(&mut self, chain: &lichen_chain::Chain, statement: &lichen_proto::Statement, cid: u32) -> Result<Vec<lichen_notes::Settled>> {
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).cloned().with_context(|| format!("no contract {cid}"))?;
        let d = lichen_proto::hp::HpDisputed::new(&h.record, statement)?;
        let Some(correct) = chain.get_tx(&d.txid("correct")) else { return Ok(vec![]) };
        let (_, slots) = lichen_babe::hp::HubProves::read_correct(&lichen_proto::setup::link_args(&correct))?;
        let owner = h.record.l2_address;
        let mut outs = vec![];
        let mut done = vec![];
        for (i, f) in self.inflight.iter().enumerate() {
            if let Some(t) = f.grant.revealed(&owner, &slots) {
                outs.extend(f.grant.open(&self.issuer(), &f.spend, &t)?);
                done.push(i);
            }
        }
        for i in done.into_iter().rev() {
            self.inflight.remove(i);
        }
        self.save()?;
        Ok(outs)
    }
}

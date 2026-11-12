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
    /// `E`, hex.
    pub e: String,
    /// What `request` posts ([`lichen_notes::Claim`]'s bytes), hex.
    pub posted: String,
}

impl ExitPlan {
    pub fn e(&self) -> Result<[u8; 32]> {
        hex::decode(&self.e)?.try_into().map_err(|_| anyhow::anyhow!("E of other than 32 bytes"))
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
    /// posted ([`Wallet::exit`] posts the claim kept): our notes, as many
    /// whole units as they hold, up to the cap.
    pub fn keep_exit_claim(&mut self, _chain: &lichen_chain::Chain, cid: u32) -> Result<ExitPlan> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let t = self.contracts[k].record.terms;
        let unit = t.unit.to_sat();
        let _ = self.sync();
        let units = (self.balance().min(t.v_max().to_sat()) / unit) as u32;
        ensure!(units > 0, "nothing to claim: {} sats of notes, a unit of {unit}", self.balance());
        let p = self.claim_for(cid, units)?;
        self.contracts[k].exit = Some(p.clone());
        self.save()?;
        Ok(p)
    }
}

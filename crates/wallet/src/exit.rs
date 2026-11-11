//! The wallet's exit (docs/HUB_PROVES_PLAN.md): a claim of its notes,
//! definite notes by position, through the contract's dispute
//! ([`crate::hp`] makes it; [`crate::engine`] plays it), for when the
//! operator won't fold or has gone. The hub proves the claim false, if it
//! can; she proves nothing. After a cooperative withdrawal the hub didn't
//! fold, the exit posts that withdrawal's claim: the hub's own exit
//! record of it doesn't count against it.
//!
//! So that an exit needs neither the sequencer nor the hub, the wallet
//! keeps an [`ExitSet`] as it reads the sequencer's state: its notes, by
//! position, in the last anchored state. [`Wallet::exit`] prepares the
//! claim ([`ExitPlan`]), keeps it with the contract, and plays the
//! dispute.
//!
//! Transparent notes only, for now (docs/HUB_PROVES_PLAN.md, "Shielded
//! notes").

use anyhow::{ensure, Context, Result};
use lichen_l2::State;
use lichen_ledger::{nullifier, Hash, Note, SignedRoot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::dispute::{Outcome, Swept};
use crate::Wallet;

/// An exit's claim, prepared before `request` and kept with the contract
/// until its dispute ends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitPlan {
    /// The amount claimed.
    pub b: u32,
    /// `E`, hex.
    pub e: String,
    /// What `request` posts (`lichen_withdraw::hp::Claim`'s bytes), hex.
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

/// How often [`Wallet::state`] looks to keep the exit set.
pub const EXIT_SET_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// One note of an [`ExitSet`]: its position and opening.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetNote {
    pub index: u32,
    pub note: Note,
}

/// Our notes in an anchored state: the anchor (and the height `from` that
/// recorded it), the root signed at its height, and each of our notes in
/// its tree a claim may take, transparent and shielded. With the
/// sequencer gone, a claim is made from it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitSet {
    pub anchored: lichen_ledger::Anchored,
    pub sealed: SignedRoot,
    pub notes: Vec<SetNote>,
    #[serde(default)]
    pub shielded: Vec<crate::shielded::SOwned>,
}

impl ExitSet {
    /// The anchored L2 height.
    pub fn height(&self) -> u64 {
        self.anchored.anchor.height
    }
    fn indices(&self) -> BTreeSet<u32> {
        self.notes.iter().map(|n| n.index).chain(self.shielded.iter().map(|n| n.index)).collect()
    }
    /// Its notes, as a claim takes them.
    pub(crate) fn held(&self) -> Vec<(u32, crate::hp::Cand)> {
        self.notes.iter().map(|n| (n.index, crate::hp::Cand::T(n.note))).chain(self.shielded.iter().map(|o| (o.index, crate::hp::Cand::S(*o)))).collect()
    }
}

impl Wallet {
    /// Whether the wallet holds an open contract, so that an exit set is
    /// worth keeping.
    fn may_exit(&self) -> bool {
        self.contracts.iter().any(|h| h.closed.is_none())
    }

    /// The exit sets kept, oldest first.
    pub fn exit_sets(&self) -> Vec<ExitSet> {
        self.exit_sets.lock().unwrap().clone()
    }

    /// Record a spend about to be signed off ([`crate::Signed`]), dropping
    /// records no longer needed: a spend once no kept set holds its notes.
    pub(crate) fn record_signed(&mut self, s: crate::Signed) -> Result<()> {
        let held: BTreeSet<Hash> = self.exit_sets.lock().unwrap().iter().flat_map(|x| x.notes.iter().map(|n| nullifier(&n.note))).collect();
        // kept while unsettled, or while its acknowledgment may be needed by
        // a claim of its outputs, or its notes are in a kept set
        self.signed.retain(|x| !x.done || x.ack.is_some() || x.nullifiers.iter().any(|n| held.contains(n)));
        self.signed.push(s);
        self.save()
    }

    /// [`Wallet::keep_exit_set`], at most every [`EXIT_SET_EVERY`] and only
    /// while an open contract may exit; what it does said, an error too
    /// (it is a best effort: the next look tries again).
    pub(crate) fn keep_exit_set_soon(&self, state: &State) {
        if !self.may_exit() {
            return;
        }
        {
            let mut t = self.exit_looked.lock().unwrap();
            if t.is_some_and(|t| t.elapsed() < EXIT_SET_EVERY) {
                return;
            }
            *t = Some(std::time::Instant::now());
        }
        match self.keep_exit_set(state) {
            Ok(Some(m)) => self.say(m),
            Ok(None) => {}
            Err(e) => self.say(format!("the exit set not kept yet: {e:#}")),
        }
    }

    /// Keep the exit set up to date with the sequencer's `state`: at the
    /// last anchored height, a new set if our notes there aren't the newest
    /// set's; only the newest is kept. What was kept, in words, if
    /// anything.
    pub fn keep_exit_set(&self, state: &State) -> Result<Option<String>> {
        let Some(a) = state.anchors.last().copied() else { return Ok(None) };
        let hs = a.anchor.height;
        let s = state.sealed.iter().find(|s| s.height == hs).with_context(|| format!("the anchored height {hs} isn't sealed"))?;
        ensure!(s.root() == a.anchor.root, "the anchor isn't of the root signed at height {hs}");
        // what a claim may take: our locked notes too whose acknowledgment
        // we hold, and a note our own unacknowledged spend took
        let mine: Vec<(u32, crate::hp::Cand)> = self.claimable(state).into_iter().filter(|(i, _)| *i < s.size).collect();
        let want: BTreeSet<u32> = mine.iter().map(|(i, _)| *i).collect();
        if want.is_empty() || self.exit_sets.lock().unwrap().last().is_some_and(|n| n.indices() == want || n.height() >= hs) {
            return Ok(None);
        }
        let notes = mine.iter().filter_map(|(index, c)| if let crate::hp::Cand::T(note) = c { Some(SetNote { index: *index, note: *note }) } else { None }).collect();
        let shielded = mine.iter().filter_map(|(_, c)| if let crate::hp::Cand::S(o) = c { Some(*o) } else { None }).collect();
        *self.exit_sets.lock().unwrap() = vec![ExitSet { anchored: a, sealed: s.clone(), notes, shielded }];
        self.save()?;
        Ok(Some(format!("the exit set kept at L2 height {hs}: {} notes", mine.len())))
    }

    /// Exit through contract `cid`: its claim prepared (or the one kept: a
    /// cooperative withdrawal's the hub didn't fold, once its notes are in
    /// the tree of the last anchor the margin deep), and its dispute
    /// played.
    pub fn exit(&mut self, chain: &lichen_chain::Chain, statement: &lichen_proto::Statement, cid: u32) -> Result<(Outcome, Swept)> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let plan = match self.contracts[k].exit.clone() {
            Some(p) => {
                if chain.get_tx(&lichen_proto::hp::HpDisputed::new(&self.contracts[k].record, statement)?.txid("request")).is_none() {
                    let claim = lichen_withdraw::hp::Claim::from_bytes(&p.posted()?).map_err(|e| anyhow::anyhow!("the claim kept: {e:?}"))?;
                    self.hp_wait_anchored(chain, cid, &claim.positions)?;
                }
                p
            }
            None => self.keep_exit_claim(chain, cid)?,
        };
        self.play(chain, statement, cid, plan.b)
    }

    /// Contract `cid`'s exit claim prepared now and kept with it, not
    /// posted: [`Wallet::exit`] posts the claim kept. For trials, a stale
    /// claim: kept, then its notes spent.
    pub fn keep_exit_claim(&mut self, chain: &lichen_chain::Chain, cid: u32) -> Result<ExitPlan> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let p = self.hp_exit_plan(chain, cid)?;
        self.contracts[k].exit = Some(p.clone());
        self.save()?;
        Ok(p)
    }
}

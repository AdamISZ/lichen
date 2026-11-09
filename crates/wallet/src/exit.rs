//! The wallet's exit (docs/HUB_PROVES_PLAN.md): a claim of its notes,
//! definite notes by position and opening, through a hub-proves
//! contract's dispute ([`crate::hp`] makes it; [`crate::engine`] plays
//! it), for when the operator won't fold a return or has gone. The hub
//! proves the claim false, if it can; she proves nothing.
//!
//! So that an exit needs neither the sequencer nor the hub, the wallet
//! keeps an [`ExitSet`] as it reads the sequencer's state: its notes, by
//! position, in the last anchored state. [`Wallet::exit`] prepares the
//! claim ([`ExitPlan`]), keeps it with the contract, and plays the
//! dispute. [`Wallet::fallback`] says what to do when a cooperative
//! withdrawal fails.
//!
//! Transparent notes only, for now (docs/HUB_PROVES_PLAN.md, "Shielded
//! notes").

use anyhow::{ensure, Context, Result};
use lichen_l2::State;
use lichen_ledger::{nullifier, Hash, Note, SignedRoot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::dispute::{Outcome, Swept};
use crate::{Owned as Mine, Wallet};

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
/// recorded it), the root signed at its height, and each of our
/// transparent notes in its tree. With the sequencer gone, a claim is
/// made from it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitSet {
    pub anchored: lichen_ledger::Anchored,
    pub sealed: SignedRoot,
    pub notes: Vec<SetNote>,
}

impl ExitSet {
    /// The anchored L2 height.
    pub fn height(&self) -> u64 {
        self.anchored.anchor.height
    }
    fn indices(&self) -> BTreeSet<u32> {
        self.notes.iter().map(|n| n.index).collect()
    }
    fn holds_any(&self, nfs: &BTreeSet<Hash>) -> bool {
        self.notes.iter().any(|n| nfs.contains(&nullifier(&n.note)))
    }
}

/// What to do when a cooperative withdrawal fails ([`Wallet::fallback`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fallback {
    /// Dispute the return, `b` sats (a BABE contract).
    Dispute { b: u64 },
    /// Exit (a hub-proves contract).
    Exit,
}

impl Wallet {
    /// Whether the wallet holds an open hub-proves contract, so that an
    /// exit set is worth keeping.
    fn may_exit(&self) -> bool {
        self.contracts.iter().any(|h| h.closed.is_none() && h.record.hp().is_ok())
    }

    /// The nullifiers of the notes that open contracts' returns spent.
    fn returns_spent(&self) -> BTreeSet<Hash> {
        let open = |c: u32| self.contracts.iter().any(|h| h.record.cid() == c && h.closed.is_none());
        self.signed.iter().filter(|s| s.ret.is_some_and(|(c, _)| open(c))).flat_map(|s| s.nullifiers.iter().copied()).collect()
    }

    /// The exit sets kept, oldest first.
    pub fn exit_sets(&self) -> Vec<ExitSet> {
        self.exit_sets.lock().unwrap().clone()
    }

    /// Record a spend about to be signed off ([`crate::Signed`]), dropping
    /// records no longer needed: a plain spend once no kept set holds its
    /// notes, a return once its contract is closed.
    pub(crate) fn record_signed(&mut self, s: crate::Signed) -> Result<()> {
        let held: BTreeSet<Hash> = self.exit_sets.lock().unwrap().iter().flat_map(|x| x.notes.iter().map(|n| nullifier(&n.note))).collect();
        let open: BTreeSet<u32> = self.contracts.iter().filter(|h| h.closed.is_none()).map(|h| h.record.cid()).collect();
        self.signed.retain(|x| match x.ret {
            Some((c, _)) => open.contains(&c),
            None => x.nullifiers.iter().any(|n| held.contains(n)),
        });
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
    /// set's. Kept: the newest set, and any holding notes an open
    /// contract's return spent (an exit after that return claims them).
    /// What was kept, in words, if anything.
    pub fn keep_exit_set(&self, state: &State) -> Result<Option<String>> {
        let Some(a) = state.anchors.last().copied() else { return Ok(None) };
        let hs = a.anchor.height;
        let s = state.sealed.iter().find(|s| s.height == hs).with_context(|| format!("the anchored height {hs} isn't sealed"))?;
        ensure!(s.root() == a.anchor.root, "the anchor isn't of the root signed at height {hs}");
        let mine: Vec<Mine> = self.notes(state).into_iter().filter(|o| o.index < s.size).collect();
        let want: BTreeSet<u32> = mine.iter().map(|o| o.index).collect();
        if want.is_empty() || self.exit_sets.lock().unwrap().last().is_some_and(|n| n.indices() == want || n.height() >= hs) {
            return Ok(None);
        }
        let notes = mine.iter().map(|o| SetNote { index: o.index, note: o.note }).collect();
        self.exit_sets.lock().unwrap().push(ExitSet { anchored: a, sealed: s.clone(), notes });
        let pinned = self.returns_spent();
        {
            let mut sets = self.exit_sets.lock().unwrap();
            let n = sets.len();
            let keep: Vec<bool> = sets.iter().enumerate().map(|(i, s)| i + 1 == n || s.holds_any(&pinned)).collect();
            let mut k = keep.iter();
            sets.retain(|_| *k.next().unwrap());
        }
        self.save()?;
        Ok(Some(format!("the exit set kept at L2 height {hs}: {} notes", mine.len())))
    }

    /// What to do when contract `cid`'s cooperative withdrawal fails: a
    /// BABE contract disputes its return; a hub-proves contract exits.
    pub fn fallback(&mut self, cid: u32) -> Result<Fallback> {
        let held = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        ensure!(held.closed.is_none(), "contract {cid} is closed");
        if held.record.hp().is_ok() {
            return Ok(Fallback::Exit);
        }
        let idx = self.returned(cid).with_context(|| format!("contract {cid}: nothing returned to dispute"))?;
        let _ = self.withdraw_input(cid);
        let value = self.kept(idx).and_then(|k| k.input.as_ref()).map(|i| i.note.value).or_else(|| self.signed.iter().rev().find_map(|s| s.ret.filter(|r| r.0 == cid)).map(|r| r.1));
        Ok(Fallback::Dispute { b: value.with_context(|| format!("contract {cid}: the return's value isn't known (the sequencer doesn't answer)"))? })
    }

    /// Exit through contract `cid`, a hub-proves contract: its claim
    /// prepared (or the one kept), and its dispute played.
    pub fn exit(&mut self, chain: &lichen_chain::Chain, statement: &lichen_proto::Statement, dir: &std::path::Path, cid: u32) -> Result<(Outcome, Swept)> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        ensure!(self.contracts[k].record.hp().is_ok(), "contract {cid} isn't a hub-proves contract: dispute its return (lichen dispute)");
        let plan = match self.contracts[k].exit.clone() {
            Some(p) => p,
            None => {
                let p = self.hp_exit_plan(chain, cid)?;
                self.contracts[k].exit = Some(p.clone());
                self.save()?;
                p
            }
        };
        self.dispute(chain, statement, dir, cid, plan.b, &[])
    }
}

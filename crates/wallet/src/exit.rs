//! The wallet's exit (docs/EXIT_PLAN.md): a claim of its notes at an
//! anchored state, through a BABE contract's dispute, for when the
//! operator won't fold a return. The wallet keeps an [`ExitSet`] as it
//! reads the sequencer's state: its notes at an anchored height, each
//! with its kit, and that height's chain receipt, so that an exit needs
//! neither the sequencer nor the hub. [`Wallet::exit`] prepares the claim
//! from it ([`ExitPlan`]: `E`; the owner's signature on `E` per note; what
//! `request` posts), keeps it with the contract, and plays the dispute
//! ([`crate::engine`]): `request` posts the claim, and once the hub
//! responds the engine proves the statement's branch the response leaves
//! (`fixed::check_exit`). [`Wallet::fallback`] chooses between an exit
//! and a return's dispute when a cooperative withdrawal fails.
//!
//! Transparent notes only, for now: a shielded note's claim has no
//! signature to post until the shielded address holds an owner key.

use anyhow::{bail, ensure, Context, Result};
use lichen_ledger::lichen_validity::{smt, TNote};
use lichen_ledger::{nullifier, Hash, Kit, Note, SignedRoot};
use lichen_l2::State;
use std::collections::BTreeSet;
use lichen_withdraw::exit::{fingerprint, posted, signed_digest, Claimed, ExitInput, Owned, MAX_NOTES};
use lichen_withdraw::{Anchored, Request};
use serde::{Deserialize, Serialize};

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
    /// What `request` posts (`lichen_withdraw::exit::Posted`'s bytes), hex.
    pub posted: String,
    /// The claim's input but for `request` and the headers (`ExitInput`'s
    /// bytes), hex.
    pub claim: String,
}

impl ExitPlan {
    pub fn e(&self) -> Result<[u8; 32]> {
        hex::decode(&self.e)?.try_into().map_err(|_| anyhow::anyhow!("E of other than 32 bytes"))
    }
    pub fn posted(&self) -> Result<Vec<u8>> {
        Ok(hex::decode(&self.posted)?)
    }
    /// The claim's input, with `request` in its block and the headers from
    /// the anchor's block on.
    pub fn input(&self, request: Request, headers: Vec<[u8; 80]>) -> Result<ExitInput> {
        let mut i = ExitInput::from_bytes(&hex::decode(&self.claim)?).map_err(|r| anyhow::anyhow!("the kept claim: {r:?}"))?;
        i.request = request;
        i.state.headers = headers;
        Ok(i)
    }
}

/// How often [`Wallet::state`] looks to keep the exit set.
pub const EXIT_SET_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// One note's part of an [`ExitSet`]: the note and its kit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetNote {
    pub index: u32,
    pub note: Note,
    pub kit: Kit,
}

/// What an exit needs from the L2 at one anchored height `h_S`, kept so
/// that an exit needs neither the sequencer nor the hub, only Bitcoin
/// (docs/EXIT_PLAN.md, "The exit set"): the anchor with the height `from`
/// that recorded it, the root signed at `h_S`, the chain fields at `from`,
/// each of our transparent notes there with its kit, and the chain receipt
/// at `from` once proved. A claim names one `h_S`, so its notes' kits are
/// all at it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitSet {
    pub anchored: lichen_ledger::Anchored,
    pub sealed: SignedRoot,
    pub chain_root: Hash,
    pub recent: Hash,
    pub hist: Hash,
    pub notes: Vec<SetNote>,
    /// The chain receipt at `from`, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
}

impl ExitSet {
    /// `h_S`.
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
    /// Dispute the return, `b` sats: it is provable with what's kept.
    Dispute { b: u64 },
    /// Exit: claim from the exit set kept.
    Exit,
}

impl Wallet {
    /// Whether the wallet holds an open contract with the exit, so that an
    /// exit set is worth keeping.
    fn may_exit(&self) -> bool {
        self.contracts.iter().any(|h| h.closed.is_none() && (h.record.babe().is_ok_and(|b| b.exit.is_some()) || h.record.hp().is_ok()))
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
    /// while an open contract has the exit; what it does said, an error too
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

    /// Keep the exit set up to date with the sequencer's `state`
    /// (docs/EXIT_PLAN.md, "The exit set"): at the last height anchored and
    /// recorded, a new set if our notes there aren't the newest set's, each
    /// note's kit fetched and checked against the signed root; and the
    /// chain receipt at `from` for the newest set, once the sequencer has
    /// proved it. Kept: the newest set, the newest with its receipt, and any
    /// holding notes an open contract's return spent (an exit after that
    /// return claims them). What was kept, in words, if anything.
    pub fn keep_exit_set(&self, state: &State) -> Result<Option<String>> {
        let Some(a) = state.anchors.last().copied() else { return Ok(None) };
        let hs = a.anchor.height;
        let s = state.sealed.iter().find(|s| s.height == hs).with_context(|| format!("the anchored height {hs} isn't sealed"))?;
        ensure!(s.root() == a.anchor.root, "the anchor isn't of the root signed at height {hs}");
        let mine: Vec<Mine> = self.notes(state).into_iter().filter(|o| o.index < s.size).collect();
        let want: BTreeSet<u32> = mine.iter().map(|o| o.index).collect();
        let newest = self.exit_sets.lock().unwrap().last().cloned();
        let msg = match newest {
            // the newest set already holds these notes (or is at this
            // height): at most its receipt to fetch
            Some(n) if n.indices() == want || n.height() >= hs => {
                if n.receipt.is_some() {
                    return Ok(None);
                }
                let Some(r) = self.receipt_if_proved(n.anchored.from)? else { return Ok(None) };
                if let Some(last) = self.exit_sets.lock().unwrap().last_mut().filter(|l| l.height() == n.height()) {
                    last.receipt = Some(hex::encode(r));
                }
                format!("the exit set at L2 height {}: its chain receipt kept", n.height())
            }
            _ if want.is_empty() => return Ok(None),
            _ => {
                let mut notes = vec![];
                for o in &mine {
                    let nf = nullifier(&o.note);
                    let k = self.sequencer.kit(o.index, &nf, hs)?;
                    ensure!(k.check(s, &o.note.commitment(), &nf), "the sequencer's kit for note {} doesn't check against height {hs}'s signed root", o.index);
                    notes.push(SetNote { index: o.index, note: o.note, kit: k });
                }
                let (chain_root, recent, hist) = state.chain_at(a.from)?;
                let receipt = self.receipt_if_proved(a.from)?.map(hex::encode);
                let proved = if receipt.is_some() { ", with its chain receipt" } else { ", its chain receipt to come" };
                let set = ExitSet { anchored: a, sealed: s.clone(), chain_root, recent, hist, notes, receipt };
                self.exit_sets.lock().unwrap().push(set);
                format!("the exit set kept at L2 height {hs}: {} notes{proved}", mine.len())
            }
        };
        let pinned = self.returns_spent();
        {
            let mut sets = self.exit_sets.lock().unwrap();
            let n = sets.len();
            let with_receipt = sets.iter().rposition(|s| s.receipt.is_some());
            let keep: Vec<bool> = sets.iter().enumerate().map(|(i, s)| i + 1 == n || Some(i) == with_receipt || s.holds_any(&pinned)).collect();
            let mut k = keep.iter();
            sets.retain(|_| *k.next().unwrap());
        }
        self.save()?;
        Ok(Some(msg))
    }

    /// The sequencer's chain receipt at `h`, if it has proved that far.
    fn receipt_if_proved(&self, h: u64) -> Result<Option<Vec<u8>>> {
        match self.sequencer.proved_height()? {
            Some(p) if p < h => Ok(None),
            _ => self.sequencer.chain_receipt(h),
        }
    }

    /// Contract `cid`'s exit claim, from the exit set kept
    /// (docs/EXIT_PLAN.md, "The exit set"), refreshed first if the
    /// sequencer answers. Notes spent since are left out: by the
    /// sequencer's state, else by the spends this wallet signed. The
    /// largest first, only as many as cover the cap, at most [`MAX_NOTES`],
    /// `b` their total up to it. After a return to `cid`, the notes it
    /// spent first and `b` at most its value ("An exit after a return": the
    /// counter excludes the contract's own return of at least `b`).
    pub fn exit_plan(&self, cid: u32) -> Result<ExitPlan> {
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let record = &h.record;
        let x = record.babe()?.exit.as_ref().with_context(|| format!("contract {cid} has no exit"))?;
        let checkpoint = record.checkpoint.as_ref().context("an exit is from an anchored state: the contract has no checkpoint")?;
        let live = match self.sequencer.state() {
            Ok(s) => {
                let s = self.observe(s)?;
                if let Err(e) = self.keep_exit_set(&s) {
                    self.say(format!("the exit set not refreshed: {e:#}"));
                }
                Some(s)
            }
            Err(e) => {
                self.say(format!("the sequencer doesn't answer ({e:#}): claiming from the exit set kept"));
                None
            }
        };
        let returns: Vec<&crate::Signed> = self.signed.iter().filter(|s| s.ret.is_some_and(|(c, _)| c == cid)).collect();
        ensure!(
            self.returned(cid).is_none() || !returns.is_empty(),
            "contract {cid}'s return isn't one this wallet kept the spends of (shielded notes, or made before lichen v0.4.6): dispute it once it is sealed and anchored (lichen dispute)"
        );
        let own: BTreeSet<Hash> = returns.iter().flat_map(|s| s.nullifiers.iter().copied()).collect();
        let returned = returns.last().and_then(|s| s.ret).map(|(_, v)| v);
        let spent = |nf: &Hash| !own.contains(nf) && (self.signed.iter().any(|s| s.nullifiers.contains(nf)) || live.as_ref().is_some_and(|s| s.nullifiers.contains(nf)));
        let sets = self.exit_sets();
        let usable = |s: &ExitSet| s.notes.iter().any(|n| !spent(&nullifier(&n.note)));
        // the newest with its receipt, else the newest
        let best = |f: &dyn Fn(&ExitSet) -> bool| sets.iter().filter(|s| f(s) && usable(s)).max_by_key(|s| (s.receipt.is_some(), s.height())).cloned();
        let set = match best(&|s| s.holds_any(&own)) {
            Some(s) => s,
            None => {
                if !own.is_empty() {
                    self.say(format!("no exit set kept holds the notes contract {cid}'s return spent: claiming others, up to the return's value"));
                }
                best(&|_| true).with_context(|| "no exit set kept with notes of ours: an exit claims from a height anchored on Bitcoin, recorded and proved by the sequencer, and the wallet keeps one as it reads the sequencer's state")?
            }
        };
        let hs = set.height();
        let unit = record.terms.unit.to_sat();
        let v_max = record.terms.v_max().to_sat();
        let cap = returned.map_or(v_max, |r| (r / unit * unit).min(v_max));
        let mut notes: Vec<&SetNote> = set.notes.iter().filter(|n| !spent(&nullifier(&n.note))).collect();
        notes.sort_by_key(|n| (!own.contains(&nullifier(&n.note)), std::cmp::Reverse(n.note.value)));
        let (mut chosen, mut total) = (vec![], 0u64);
        for n in notes {
            if total >= cap || chosen.len() == MAX_NOTES {
                break;
            }
            total += n.note.value;
            chosen.push(n);
        }
        ensure!(!chosen.is_empty(), "no notes of ours unspent at the kept height {hs}");
        chosen.sort_by_key(|n| nullifier(&n.note));
        // b in the contract's units: the notes' total, up to the cap
        let b = u32::try_from(total.min(cap) / unit).context("b fits in a u32")?;
        ensure!(b > 0, "the notes claimable at height {hs} come to less than the contract's unit, {unit} sats");
        let deposit = lichen_proto::babe::statement_outpoint(&x.hub.deposit);
        let nfs: Vec<Hash> = chosen.iter().map(|n| nullifier(&n.note)).collect();
        let s = &set.sealed;
        let e = fingerprint(cid, &deposit, b, hs, &s.root(), &nfs);
        let sig = self.key.sign_raw(&signed_digest(&e), &[0; 32]).map_err(|e| anyhow::anyhow!("signing the claim: {e}"))?.to_bytes();
        let claimed = chosen
            .iter()
            .map(|c| {
                let n = &c.note;
                Claimed {
                    owned: Owned::Transparent { note: TNote { owner: n.owner, value: n.value, memo: n.memo, rho: n.rho }, sig },
                    index: c.index,
                    path: c.kit.path.clone(),
                    unspent: smt::Proof { bitmap: c.kit.bitmap, siblings: c.kit.siblings.clone() },
                }
            })
            .collect();
        let d = self.sequencer.deployment;
        let st = Anchored {
            height: hs,
            nullifiers: s.nullifiers,
            signature: s.signature.as_slice().try_into().context("a signature of 64 bytes")?,
            sequencer: d.sequencer,
            hub: d.hub,
            chain_height: set.anchored.from,
            chain_root: set.chain_root,
            recent: set.recent,
            hist: set.hist,
            anchor: set.anchored.anchor,
            headers: vec![],
            work: checkpoint.work(),
            unit,
        };
        let input = ExitInput { state: st, tree: s.tree, c: cid, deposit, b, notes: claimed, request: no_request() };
        Ok(ExitPlan { b, e: hex::encode(e), posted: hex::encode(posted(&input).to_bytes()), claim: hex::encode(input.to_bytes()) })
    }

    /// What to do when contract `cid`'s cooperative withdrawal fails
    /// (docs/EXIT_PLAN.md, "Always request in exit mode"): dispute a
    /// return that is provable with what's kept (its input, and on the real
    /// statement its chain receipt: fetched first if the sequencer has
    /// them), or with no exit any return; else exit.
    pub fn fallback(&mut self, statement: &lichen_proto::Statement, cid: u32) -> Result<Fallback> {
        let held = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        ensure!(held.closed.is_none(), "contract {cid} is closed");
        let exit = held.record.babe().is_ok_and(|b| b.exit.is_some());
        let Some(idx) = self.returned(cid) else {
            ensure!(exit, "contract {cid}: nothing returned, and it has no exit");
            return Ok(Fallback::Exit);
        };
        // what the sequencer has of the return, kept now
        let _ = self.withdraw_input(cid);
        if statement.is_real() {
            let _ = self.chain_receipt(cid);
        }
        let k = self.kept(idx);
        let value = k.and_then(|k| k.input.as_ref()).map(|i| i.note.value).or_else(|| self.signed.iter().rev().find_map(|s| s.ret.filter(|r| r.0 == cid)).map(|r| r.1));
        let provable = k.is_some_and(|k| k.input.is_some() && (!statement.is_real() || k.chain.is_some()));
        match (provable || !exit, value) {
            (true, Some(b)) => Ok(Fallback::Dispute { b }),
            (true, None) => bail!("contract {cid}: the return's value isn't known (the sequencer doesn't answer)"),
            (false, _) => Ok(Fallback::Exit),
        }
    }

    /// Exit through contract `cid`: its claim prepared (or the one kept),
    /// and its dispute played; `input` the proof, on the real statement,
    /// once due (empty before: the dispute stops at
    /// [`Outcome::ProofDue`] with the statement's input written).
    pub fn exit(&mut self, chain: &lichen_chain::Chain, statement: &lichen_proto::Statement, dir: &std::path::Path, cid: u32, input: &[u8]) -> Result<(Outcome, Swept)> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let plan = match self.contracts[k].exit.clone() {
            Some(p) => p,
            None => {
                // the hub proves: a claim by position, nothing to prove
                let p = if self.contracts[k].record.hp().is_ok() { self.hp_exit_plan(chain, cid)? } else { self.exit_plan(cid)? };
                self.contracts[k].exit = Some(p.clone());
                self.save()?;
                p
            }
        };
        let r = self.dispute(chain, statement, dir, cid, plan.b, input)?;
        if let (Outcome::ProofDue(_), true) = (&r.0, input.is_empty()) {
            // the claim's proof takes the chain receipt its state is under:
            // the set's, kept, else the sequencer's
            let h = plan.input(no_request(), vec![])?.state.chain_height;
            let to = crate::engine::babe::data_dir(dir, cid).join("exit-chain.receipt");
            let kept = self.exit_sets().into_iter().find(|s| s.anchored.from == h).and_then(|s| s.receipt);
            match kept.map(|r| Ok(hex::decode(r)?)).unwrap_or_else(|| crate::chain_receipt(&self.sequencer, h)) {
                Ok(r) => std::fs::write(&to, r)?,
                Err(e) => self.step(format!("the chain receipt at height {h}, for the claim's proof: {e:#}")),
            }
        }
        Ok(r)
    }
}

/// `request` not yet known: filled in once it is on chain
/// ([`ExitPlan::input`]).
fn no_request() -> Request {
    Request { funding: vec![], tx: vec![], header: [0; 80], index: 0, path: vec![], coinbase: vec![], coinbase_path: vec![], reserved: [0; 32] }
}

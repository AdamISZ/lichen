//! The wallet's exit (docs/EXIT_PLAN.md): a claim of its notes at an
//! anchored state, through a BABE contract's dispute, for when the
//! operator won't fold a return. [`Wallet::exit`] prepares the claim
//! ([`ExitPlan`]: its notes at the latest anchored state, each with its
//! kit from the sequencer, checked against the signed root; `E`; the
//! owner's signature on `E` per note; what `request` posts), keeps it with
//! the contract, and plays the dispute ([`crate::engine`]): `request`
//! posts the claim, and once the hub responds the engine proves the
//! statement's branch the response leaves (`fixed::check_exit`).
//!
//! Transparent notes only, for now: a shielded note's claim has no
//! signature to post until the shielded address holds an owner key.

use anyhow::{ensure, Context, Result};
use lichen_l2::State;
use lichen_ledger::lichen_validity::{hist_next, recent_hash, smt, TNote, RECENT};
use lichen_ledger::{nullifier, Hash};
use lichen_withdraw::exit::{fingerprint, posted, signed_digest, Claimed, ExitInput, Owned, MAX_NOTES};
use lichen_withdraw::{Anchored, Request};
use serde::{Deserialize, Serialize};

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

/// The chain journal's fields at height `h` of `state` (what the chain
/// receipt there shows): its root, the recent roots' hash, the history
/// hash.
fn chain_at(state: &State, h: u64) -> Result<(Hash, Hash, Hash)> {
    let upto: Vec<_> = state.sealed.iter().take_while(|s| s.height <= h).collect();
    ensure!(upto.last().is_some_and(|s| s.height == h), "no height {h} sealed");
    let hist = upto.iter().fold([0u8; 32], |acc, s| hist_next(&acc, &s.root()));
    let recent: Vec<Hash> = upto.iter().rev().take(RECENT).rev().map(|s| s.tree).collect();
    Ok((upto.last().unwrap().root(), recent_hash(&recent), hist))
}

impl Wallet {
    /// Contract `cid`'s exit claim: our transparent notes in the latest
    /// anchored state (unspent now, so then), the largest first, at most
    /// [`MAX_NOTES`], `b` their total up to the cap; each note's kit at
    /// that state, checked against its signed root.
    pub fn exit_plan(&self, cid: u32) -> Result<ExitPlan> {
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let record = &h.record;
        let x = record.babe()?.exit.as_ref().with_context(|| format!("contract {cid} has no exit"))?;
        let checkpoint = record.checkpoint.as_ref().context("an exit is from an anchored state: the contract has no checkpoint")?;
        let state = self.state()?;
        let a = state.anchors.last().context("nothing is anchored yet")?;
        let hs = a.anchor.height;
        let s = state.sealed.iter().find(|s| s.height == hs).context("the anchored height isn't sealed")?;
        ensure!(s.root() == a.anchor.root, "the anchor isn't of the root signed at height {hs}");
        let mut notes = self.notes(&state).into_iter().filter(|o| o.index < s.size).collect::<Vec<_>>();
        notes.sort_by_key(|o| std::cmp::Reverse(o.note.value));
        notes.truncate(MAX_NOTES);
        ensure!(!notes.is_empty(), "no notes of ours at the anchored height {hs}");
        notes.sort_by_key(|o| nullifier(&o.note));
        let cap = (1u64 << record.terms.bits) - 1;
        let b = u32::try_from(notes.iter().map(|o| o.note.value).sum::<u64>().min(cap)).context("b fits in a u32")?;
        let deposit = lichen_proto::babe::statement_outpoint(&x.hub.deposit);
        let nfs: Vec<Hash> = notes.iter().map(|o| nullifier(&o.note)).collect();
        let e = fingerprint(cid, &deposit, b, hs, &s.root(), &nfs);
        let sig = self.key.sign_raw(&signed_digest(&e), &[0; 32]).map_err(|e| anyhow::anyhow!("signing the claim: {e}"))?.to_bytes();
        let mut claimed = vec![];
        for (o, nf) in notes.iter().zip(&nfs) {
            let k = self.sequencer.kit(o.index, nf, hs)?;
            ensure!(k.check(s, &o.note.commitment(), nf), "the sequencer's kit for note {} doesn't check against height {hs}'s signed root", o.index);
            let n = &o.note;
            claimed.push(Claimed {
                owned: Owned::Transparent { note: TNote { owner: n.owner, value: n.value, memo: n.memo, rho: n.rho }, sig },
                index: o.index,
                path: k.path,
                unspent: smt::Proof { bitmap: k.bitmap, siblings: k.siblings },
            });
        }
        let (chain_root, recent, hist) = chain_at(&state, a.from)?;
        let d = self.sequencer.deployment;
        let st = Anchored {
            height: hs,
            nullifiers: s.nullifiers,
            signature: s.signature.as_slice().try_into().context("a signature of 64 bytes")?,
            sequencer: d.sequencer,
            hub: d.hub,
            chain_height: a.from,
            chain_root,
            recent,
            hist,
            anchor: a.anchor,
            headers: vec![],
            work: checkpoint.work(),
        };
        let empty = Request { funding: vec![], tx: vec![], header: [0; 80], index: 0, path: vec![], coinbase: vec![], coinbase_path: vec![], reserved: [0; 32] };
        let input = ExitInput { state: st, tree: s.tree, c: cid, deposit, b, notes: claimed, request: empty };
        Ok(ExitPlan { b, e: hex::encode(e), posted: hex::encode(posted(&input).to_bytes()), claim: hex::encode(input.to_bytes()) })
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
                let p = self.exit_plan(cid)?;
                self.contracts[k].exit = Some(p.clone());
                self.save()?;
                p
            }
        };
        let r = self.dispute(chain, statement, dir, cid, plan.b, input)?;
        if let (Outcome::ProofDue(_), true) = (&r.0, input.is_empty()) {
            // the claim's proof takes the chain receipt its state is under
            let h = plan.input(Request { funding: vec![], tx: vec![], header: [0; 80], index: 0, path: vec![], coinbase: vec![], coinbase_path: vec![], reserved: [0; 32] }, vec![])?.state.chain_height;
            let to = crate::engine::babe::data_dir(dir, cid).join("exit-chain.receipt");
            match crate::chain_receipt(&self.sequencer, h) {
                Ok(r) => std::fs::write(&to, r)?,
                Err(e) => self.step(format!("the chain receipt at height {h}, for the claim's proof: {e:#}")),
            }
        }
        Ok(r)
    }
}

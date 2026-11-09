//! The wallet's part of a hub-proves contract (docs/HUB_PROVES_PLAN.md,
//! `lichen_proto::hp`): its opening, in which she garbles for the hub's
//! statement, commits to her instances and uploads the ones the hub keeps;
//! and her exit's claim, definite notes by position and opening, signed
//! once.

use anyhow::{ensure, Context, Result};
use lichen_babe::hp::HubProves;
use lichen_babe::setup::{instance, par, VALUES};
use lichen_proto::babe::{dealing_to_hex, min_soundness, shares_to_hex, soundness, statement_outpoint, Opened};
use lichen_proto::hp::{check_setup, HpCommit, HpKept, HpKeys, HpOffer, HpRequest, HpSetup, HpSetupRequest};
use lichen_proto::{DisputeKeys, Net, Statement};
use lichen_withdraw::hp::{Claim, MAX_NOTES};
use lngap_sessions::contract::Presign;
use std::collections::BTreeSet;

use crate::engine::hp::{dealing, instance_seed};
use crate::engine::ContractSecrets;
use crate::exit::ExitPlan;
use crate::{hub_call, Wallet};

/// What her opening request carries, and what it rests on.
pub(crate) struct HpOpening {
    pub request: HpRequest,
    pub setup: HpSetup,
    pub kept: Vec<u32>,
    /// The kept instances' hashlocks, in `kept`'s order.
    pub hmsg: Vec<[u8; 32]>,
}

impl Wallet {
    /// The setup of contract `cid`, with the deposit coin `deposit`: the
    /// hub's statement and keys checked; her instances built for it, the
    /// input secrets dealt, committed to; the ones the hub keeps uploaded,
    /// the others opened in her request.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn hp_opening(&self, hub: &str, statement: &Statement, cid: u32, deposit: bitcoin::OutPoint, unit: u64, s: &ContractSecrets, net: Net) -> Result<HpOpening> {
        let setup: HpSetup = hub_call(&format!("{hub}/hp/setup"), Some(serde_json::to_string(&HpSetupRequest { cid, deposit, unit })?), false)?;
        ensure!(setup.cid == cid && setup.unit == unit && setup.deposit == deposit, "the setup is for another contract, unit or deposit");
        check_setup(&setup)?;
        ensure!(setup.margin == lichen_proto::hp::margin(net), "the hub's margin, {} blocks, isn't the network's", setup.margin);
        let (n, m) = (setup.n, setup.m);
        ensure!(soundness(n, m) >= min_soundness(net), "keeping {m} of {n} instances: a cheating garbler escapes with odds of 1 in 2^{}, not 2^{}", soundness(n, m), min_soundness(net));
        let checkpoint = setup.checkpoint.context("the setup has no checkpoint")?;
        let d = lichen_proto::contract_word(&self.sequencer.deployment, Some(&checkpoint), bitcoin::Amount::from_sat(unit))?;
        let journal = lichen_proto::hp::journal(cid, &d, &deposit, setup.margin);
        let kind = statement.hp_kind()?;
        let (vk, public) = (kind.verifying_key(), kind.public_inputs(&journal));
        let (dealer, dealt) = dealing(s, n, m);
        self.say(format!("garbling {n} instances of the hub's statement (the hub keeps {m})"));
        let start = std::time::Instant::now();
        let commitments: Vec<String> = par(n as usize, |k| {
            let i = k as u32 + 1;
            hex::encode(instance(&instance_seed(s, i), &dealer.shares(u64::from(i)), &vk, &public).0.commitment())
        });
        self.say(format!("garbled in {:.1?}", start.elapsed()));
        let commit = HpCommit { cid, b_key: s.babe_b().public(), e_key: s.babe_e().public(), commitments, dealing: dealing_to_hex(&dealt) };
        let kept: HpKept = hub_call(&format!("{hub}/hp/commit"), Some(serde_json::to_string(&commit)?), false)?;
        let mut k = kept.kept.clone();
        k.sort_unstable();
        k.dedup();
        ensure!(k.len() == m as usize && k == kept.kept && k.iter().all(|i| (1..=n).contains(i)), "the hub keeps {:?}, not {m} distinct of {n}", kept.kept);
        let mut hmsg = vec![];
        for (j, i) in k.iter().enumerate() {
            let (inst, _) = instance(&instance_seed(s, *i), &dealer.shares(u64::from(*i)), &vk, &public);
            let bytes = inst.to_bytes();
            self.say(format!("uploading the instance the hub keeps, {} of {m} ({} MB)", j + 1, bytes.len() >> 20));
            lichen_l2::http::slow().post(&format!("{hub}/hp/instance/{cid}/{i}")).send_bytes(&bytes).with_context(|| format!("uploading kept instance {i}"))?;
            hmsg.push(inst.hmsg);
        }
        let opened = (1..=n).filter(|i| !k.contains(i)).map(|i| Opened { i, seed: hex::encode(instance_seed(s, i)), shares: shares_to_hex(&dealer.shares(u64::from(i))) }).collect();
        Ok(HpOpening { request: HpRequest { hp_opened: opened }, setup, kept: k, hmsg })
    }

    /// The contract's keys from her opening and the hub's offer: its
    /// windows the network's, its pre-signatures on `challenge_assert` (in
    /// `set`) under its adaptor keys, adapted to her dealing's points.
    pub(crate) fn hp_record_keys(net: Net, t_close: u32, s: &ContractSecrets, o: &HpOpening, offer: &HpOffer, set: &[Presign]) -> Result<DisputeKeys> {
        ensure!(offer.hp_windows == lichen_proto::hp::windows(net, t_close), "the hub's windows {:?}, not the network's", offer.hp_windows);
        let (_, dealt) = dealing(s, o.setup.n, o.setup.m);
        let msg = HubProves::challenge_sighash(set)?;
        let presigs: Vec<[lngap_btc::adaptor::AdaptorSig; VALUES]> = offer.hp_presigs.iter().map(|p| p.each_ref().map(lngap_btc::adaptor::AdaptorSig::from)).collect();
        ensure!(lichen_babe::reveal::check_presigs(&o.setup.adaptor, &msg, &lichen_babe::reveal::points(&dealt), &presigs), "the hub's adaptor pre-signatures on challenge_assert");
        Ok(DisputeKeys::HubProves(Box::new(Wallet::hp_keys(s, o, offer.hp_windows, offer.hp_presigs.clone()))))
    }

    /// The record's keys, the pre-signatures as given.
    pub(crate) fn hp_keys(s: &ContractSecrets, o: &HpOpening, windows: lichen_babe::graph::Windows, presigs: Vec<[lichen_proto::Presig; VALUES]>) -> HpKeys {
        HpKeys {
            b_key: s.babe_b().public(),
            e_key: s.babe_e().public(),
            hub_lamport: o.setup.lamport.clone(),
            hub_adaptor: o.setup.adaptor.clone(),
            n: o.setup.n,
            kept: o.kept.clone(),
            hmsg: o.hmsg.clone(),
            hp_windows: windows,
            margin: o.setup.margin,
            deposit: o.setup.deposit,
            hub_presigs: presigs,
        }
    }

    /// Contract `cid`'s exit claim where the hub proves: her notes by
    /// position and opening, signed once. From the sequencer's state, or
    /// with it gone the exit set kept; notes spent left out (by the state,
    /// else by the spends this wallet signed). The largest first, as many as
    /// cover the cap, at most [`MAX_NOTES`], `b` their total up to it.
    /// After a return to `cid`, the notes it spent first and `b` at most
    /// its value (her own return isn't a spend against this contract).
    ///
    /// A note counts only if it is in `A*`'s tree, the last anchor at
    /// least the margin below her request's block: so the claim waits,
    /// once her notes are anchored, until that anchor is the margin deep.
    pub fn hp_exit_plan(&self, chain: &lichen_chain::Chain, cid: u32) -> Result<ExitPlan> {
        let mut stall = lichen_chain::Stall::new(chain.height()?, chain.network);
        let mut said = false;
        loop {
            if let Some(p) = self.hp_plan_now(chain, cid)? {
                return Ok(p);
            }
            if !said {
                self.say(format!("waiting for our notes' anchor to be {} blocks deep: the claim is judged at the last anchor that deep", self.contracts.iter().find(|h| h.record.cid() == cid).and_then(|h| h.record.hp().ok()).map_or(0, |k| k.margin)));
                said = true;
            }
            ensure!(!stall.stalled(chain.height()?), "the chain stalled before our notes' anchor was deep enough to claim");
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
    }

    /// The tree's size at the last anchor whose block is at least `margin`
    /// below the tip (`A*` of a request confirmed next), by the state's
    /// anchors, or with no state by the exit sets kept.
    fn hp_safe_size(&self, chain: &lichen_chain::Chain, margin: u32, state: Option<&lichen_l2::State>) -> Result<Option<u32>> {
        use bitcoin::hashes::Hash as _;
        let tip = chain.height()?;
        let deep = |block: &[u8; 32]| -> Result<bool> { Ok(chain.block_height(&bitcoin::BlockHash::from_byte_array(*block))?.is_some_and(|h| h + margin <= tip)) };
        match state {
            Some(s) => {
                let mut size = None;
                for a in &s.anchors {
                    if deep(&a.anchor.block)? {
                        size = s.sealed.iter().find(|x| x.height == a.anchor.height).map(|x| x.size);
                    }
                }
                Ok(size)
            }
            None => {
                let mut size = None;
                for x in self.exit_sets() {
                    if deep(&x.anchored.anchor.block)? {
                        size = size.max(Some(x.sealed.size));
                    }
                }
                Ok(size)
            }
        }
    }

    /// [`Wallet::hp_exit_plan`], or none while a note of ours is newer
    /// than the anchor the margin deep.
    fn hp_plan_now(&self, chain: &lichen_chain::Chain, cid: u32) -> Result<Option<ExitPlan>> {
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let record = &h.record;
        let k = record.hp()?;
        let live = match self.sequencer.state() {
            Ok(s) => Some(self.observe(s)?),
            Err(e) => {
                self.say(format!("the sequencer doesn't answer ({e:#}): claiming from the notes kept"));
                None
            }
        };
        let returns: Vec<&crate::Signed> = self.signed.iter().filter(|s| s.ret.is_some_and(|(c, _)| c == cid)).collect();
        let own: BTreeSet<_> = returns.iter().flat_map(|s| s.nullifiers.iter().copied()).collect();
        let returned = returns.last().and_then(|s| s.ret).map(|(_, v)| v);
        let spent = |nf: &[u8; 32]| !own.contains(nf) && (self.signed.iter().any(|s| s.nullifiers.contains(nf)) || live.as_ref().is_some_and(|s| s.nullifiers.contains(nf)));
        // her notes: in the state (and spent ones, her return's), else in
        // the newest exit set kept
        let mut mine: Vec<(u32, lichen_ledger::Note)> = match &live {
            Some(s) => {
                let mut v: Vec<(u32, lichen_ledger::Note)> = self.notes(s).into_iter().map(|o| (o.index, o.note)).collect();
                for (i, n) in s.transparent() {
                    if own.contains(&lichen_ledger::nullifier(n)) && !v.iter().any(|(j, _)| *j == i) {
                        v.push((i, *n));
                    }
                }
                v
            }
            None => self.exit_sets().into_iter().flat_map(|x| x.notes.into_iter().map(|n| (n.index, n.note))).collect(),
        };
        mine.sort_by_key(|(i, _)| *i);
        mine.dedup_by_key(|(i, _)| *i);
        let unit = record.terms.unit.to_sat();
        let v_max = record.terms.v_max().to_sat();
        let cap = returned.map_or(v_max, |r| (r / unit * unit).min(v_max));
        let mut notes: Vec<(u32, lichen_ledger::Note)> = mine.into_iter().filter(|(_, n)| !spent(&lichen_ledger::nullifier(n))).collect();
        let safe = self.hp_safe_size(chain, k.margin, live.as_ref())?;
        if notes.iter().any(|(i, _)| safe.is_none_or(|s| *i >= s)) {
            return Ok(None);
        }
        notes.sort_by_key(|(_, n)| (!own.contains(&lichen_ledger::nullifier(n)), std::cmp::Reverse(n.value)));
        let (mut chosen, mut total) = (vec![], 0u64);
        for (i, n) in notes {
            if total >= cap || chosen.len() == MAX_NOTES {
                break;
            }
            total += n.value;
            chosen.push(i);
        }
        ensure!(!chosen.is_empty(), "no notes of ours to claim");
        chosen.sort();
        let b = u32::try_from(total.min(cap) / unit).context("b fits in a u32")?;
        ensure!(b > 0, "the notes claimable come to less than the contract's unit, {unit} sats");
        let mut claim = Claim { positions: chosen, sigs: vec![] };
        let e = claim.fingerprint(cid, &statement_outpoint(&k.deposit), b);
        claim.sigs = vec![self.key.sign_raw(&lichen_withdraw::hp::signed_digest(&e), &[0; 32]).map_err(|e| anyhow::anyhow!("signing the claim: {e}"))?.to_bytes()];
        ensure!(claim.well_formed(), "the claim isn't well formed");
        Ok(Some(ExitPlan { b, e: hex::encode(e), posted: hex::encode(claim.to_bytes()) }))
    }
}

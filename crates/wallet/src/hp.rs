//! The wallet's part of a hub-proves contract (docs/HUB_PROVES_PLAN.md,
//! `lichen_proto::hp`): its opening, in which she garbles for the hub's
//! statement, commits to her instances and uploads the ones the hub keeps;
//! and her claims, definite notes by position, signed once: an exit's,
//! and a cooperative withdrawal's ([`Wallet::claim_of`]).

use anyhow::{ensure, Context, Result};
use lichen_babe::hp::HubProves;
use lichen_babe::setup::{instance, par, VALUES};
use lichen_proto::setup::{dealing_to_hex, min_soundness, shares_to_hex, soundness, statement_outpoint, Opened};
use lichen_proto::hp::{check_setup, HpCommit, HpKept, HpKeys, HpOffer, HpRequest, HpSetup, HpSetupRequest};
use lichen_proto::{Net, Record, Statement};
use lichen_withdraw::hp::{Claim, MAX_NOTES};
use lngap_sessions::contract::Presign;

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
        let commit = HpCommit { cid, b_key: s.hp_b().public(), e_key: s.hp_e().public(), commitments, dealing: dealing_to_hex(&dealt) };
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

    /// The hub's offer checked against her opening: its windows the
    /// network's, its pre-signatures on `challenge_assert` (in `set`)
    /// under its adaptor keys, adapted to her dealing's points.
    pub(crate) fn hp_check_offer(net: Net, t_close: u32, s: &ContractSecrets, o: &HpOpening, offer: &HpOffer, set: &[Presign]) -> Result<()> {
        ensure!(offer.hp_windows == lichen_proto::hp::windows(net, t_close), "the hub's windows {:?}, not the network's", offer.hp_windows);
        let (_, dealt) = dealing(s, o.setup.n, o.setup.m);
        let msg = HubProves::challenge_sighash(set)?;
        let presigs: Vec<[lngap_btc::adaptor::AdaptorSig; VALUES]> = offer.hp_presigs.iter().map(|p| p.each_ref().map(lngap_btc::adaptor::AdaptorSig::from)).collect();
        ensure!(lichen_babe::reveal::check_presigs(&o.setup.adaptor, &msg, &lichen_babe::reveal::points(&dealt), &presigs), "the hub's adaptor pre-signatures on challenge_assert");
        Ok(())
    }

    /// The record's keys, the pre-signatures as given.
    pub(crate) fn hp_keys(s: &ContractSecrets, o: &HpOpening, windows: lichen_babe::hp::Windows, presigs: Vec<[lichen_proto::Presig; VALUES]>) -> HpKeys {
        HpKeys {
            b_key: s.hp_b().public(),
            e_key: s.hp_e().public(),
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
    /// position, signed once. From the sequencer's state, or with it gone
    /// the exit set kept; notes spent left out (by the state, else by the
    /// spends this wallet signed). The largest first, as many as cover the
    /// cap, at most [`MAX_NOTES`], `b` their total up to it.
    ///
    /// A note counts only if it is in `A*`'s tree, the last anchor at
    /// least the margin below her request's block: so the claim waits,
    /// once her notes are anchored, until that anchor is the margin deep.
    pub fn hp_exit_plan(&self, chain: &lichen_chain::Chain, cid: u32) -> Result<ExitPlan> {
        let start = chain.height()?;
        let mut stall = lichen_chain::Stall::new(start, chain.network);
        let margin = self.contracts.iter().find(|h| h.record.cid() == cid).map_or(0, |h| h.record.hp().margin);
        // how long to wait for a note newer than the anchor the margin deep:
        // past it, anchoring seems stopped, and the claim leaves such notes
        // out rather than wait for ever
        let patience = 3 * margin.max(1);
        let mut said = false;
        loop {
            let patient = chain.height()? < start + patience;
            if let Some(p) = self.hp_plan_now(chain, cid, patient)? {
                return Ok(p);
            }
            if !said {
                self.say(format!("waiting for our notes' anchor to be {} blocks deep: the claim is judged at the last anchor that deep", self.contracts.iter().find(|h| h.record.cid() == cid).map_or(0, |h| h.record.hp().margin)));
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

    /// Wait until the notes at `positions` are in the tree of the last
    /// anchor the margin deep (`A*` of a request confirmed next): a claim
    /// made before, a cooperative withdrawal's, before its exit.
    pub(crate) fn hp_wait_anchored(&self, chain: &lichen_chain::Chain, cid: u32, positions: &[u32]) -> Result<()> {
        let margin = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?.record.hp().margin;
        let last = positions.iter().max().copied().unwrap_or(0);
        let mut stall = lichen_chain::Stall::new(chain.height()?, chain.network);
        let mut said = false;
        loop {
            let live = self.sequencer.state().ok().map(|s| self.observe(s)).transpose()?;
            if self.hp_safe_size(chain, margin, live.as_ref())?.is_some_and(|s| last < s) {
                return Ok(());
            }
            if !said {
                self.say(format!("waiting for the claim's notes' anchor to be {margin} blocks deep: the claim is judged at the last anchor that deep"));
                said = true;
            }
            ensure!(!stall.stalled(chain.height()?), "the chain stalled before the claim's notes' anchor was deep enough to claim");
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
    }

    /// [`Wallet::hp_exit_plan`], or, while `patient`, none while a note of
    /// ours is newer than the anchor the margin deep; not `patient`, the
    /// plan without such notes.
    fn hp_plan_now(&self, chain: &lichen_chain::Chain, cid: u32, patient: bool) -> Result<Option<ExitPlan>> {
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let record = &h.record;
        let live = match self.sequencer.state() {
            Ok(s) => Some(self.observe(s)?),
            Err(e) => {
                self.say(format!("the sequencer doesn't answer ({e:#}): claiming from the notes kept"));
                None
            }
        };
        use lichen_ledger::lichen_validity::ack;
        // a note is spent for her if she acknowledged a spend of it, or the
        // state shows it spent otherwise than by a spend of hers she never
        // acknowledged (which doesn't count against her)
        let unacked = |nf: &[u8; 32]| self.signed.iter().any(|s| s.nullifiers.contains(nf) && s.ack.is_none());
        let spent = |nf: &[u8; 32]| {
            self.signed.iter().any(|s| s.nullifiers.contains(nf) && s.ack.is_some())
                || live.as_ref().is_some_and(|s| {
                    let t = s.leaf(nf);
                    t != [0; 32] && !(unacked(nf) && !s.spent(&ack::acked_key(&t)))
                })
        };
        // her acknowledgments, by spend: a locked output of one is hers to
        // claim, carrying it ([`Wallet::acks_for`])
        let acks: Vec<lichen_ledger::Ack> = self.signed.iter().filter_map(|s| s.ack.clone()).collect();
        // her notes: in the state, else in the newest exit set kept
        let mut mine: Vec<(u32, lichen_ledger::Note)> = match &live {
            Some(s) => s
                .transparent()
                .filter(|(_, n)| n.owner == self.address() && !spent(&lichen_ledger::nullifier(n)))
                .map(|(index, n)| crate::Owned { note: *n, index })
                .filter(|o| {
                    if !s.locked(o.index) {
                        return true;
                    }
                    let t = s.leaf(&ack::lock_key(o.index));
                    acks.iter().any(|a| a.txid == t)
                })
                .map(|o| (o.index, o.note))
                .collect(),
            None => self.exit_sets().into_iter().flat_map(|x| x.notes.into_iter().map(|n| (n.index, n.note))).collect(),
        };
        mine.sort_by_key(|(i, _)| *i);
        mine.dedup_by_key(|(i, _)| *i);
        let unit = record.terms.unit.to_sat();
        let cap = record.terms.v_max().to_sat();
        let mut notes: Vec<(u32, lichen_ledger::Note)> = mine.into_iter().filter(|(_, n)| !spent(&lichen_ledger::nullifier(n))).collect();
        let safe = self.hp_safe_size(chain, record.hp().margin, live.as_ref())?;
        let newer = |i: &u32| safe.is_none_or(|s| *i >= s);
        if notes.iter().any(|(i, _)| newer(i)) {
            if patient {
                return Ok(None);
            }
            let left = notes.iter().filter(|(i, _)| newer(i)).count();
            self.say(format!("no anchor the margin deep holds {left} of our notes yet, and anchoring seems stopped: claiming without them"));
            notes.retain(|(i, _)| !newer(i));
        }
        notes.sort_by_key(|(_, n)| std::cmp::Reverse(n.value));
        let (mut chosen, mut total) = (vec![], 0u64);
        for (i, n) in notes {
            if total >= cap || chosen.len() == MAX_NOTES {
                break;
            }
            total += n.value;
            chosen.push(i);
        }
        ensure!(!chosen.is_empty(), "no notes of ours to claim");
        let b = u32::try_from(total.min(cap) / unit).context("b fits in a u32")?;
        ensure!(b > 0, "the notes claimable come to less than the contract's unit, {unit} sats");
        let acks = match &live {
            Some(s) => self.acks_for(s, &chosen)?,
            None => vec![],
        };
        self.claim_of(record, b, chosen, acks).map(Some)
    }

    /// Our acknowledgments of the spends whose outputs are at `positions`:
    /// a claim carries them, so that a note locked at `A*` is shown
    /// acknowledged (docs/HUB_PROVES_PLAN.md, "Data availability").
    pub(crate) fn acks_for(&self, state: &lichen_l2::State, positions: &[u32]) -> Result<Vec<lichen_ledger::lichen_validity::ack::Ack>> {
        use lichen_ledger::lichen_validity::ack;
        let mut out: Vec<ack::Ack> = vec![];
        for i in positions {
            let t = state.leaf(&ack::lock_key(*i));
            if t == [0; 32] || out.iter().any(|a| a.txid == t) {
                continue;
            }
            if let Some(a) = self.signed.iter().filter_map(|s| s.ack.as_ref()).find(|a| a.txid == t) {
                out.push(a.v()?);
            }
        }
        Ok(out)
    }

    /// A claim of `b` units from contract `record` of the notes at
    /// `positions`, signed: an exit's, or a cooperative withdrawal's.
    pub(crate) fn claim_of(&self, record: &Record, b: u32, mut positions: Vec<u32>, acks: Vec<lichen_ledger::lichen_validity::ack::Ack>) -> Result<ExitPlan> {
        positions.sort_unstable();
        let mut claim = Claim { positions, acks, sigs: vec![] };
        let e = claim.fingerprint(record.cid(), &statement_outpoint(&record.hp().deposit), b);
        claim.sigs = vec![self.key.sign_raw(&lichen_withdraw::hp::signed_digest(&e), &[0; 32]).map_err(|e| anyhow::anyhow!("signing the claim: {e}"))?.to_bytes()];
        ensure!(claim.well_formed(), "the claim isn't well formed");
        Ok(ExitPlan { b, e: hex::encode(e), posted: hex::encode(claim.to_bytes()) })
    }
}


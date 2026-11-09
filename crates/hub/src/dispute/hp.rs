//! The hub's side of a hub-proves contract (docs/HUB_PROVES_PLAN.md,
//! `lichen_proto::hp`): its setup, in which Alice garbles and the hub
//! keeps her instances, and its dispute ([`super`] drives it).
//!
//! When `request` confirms, the hub looks for a ground that her claim is
//! false (`lichen_withdraw::hp::Ground`), natively, from the L2's state
//! and the chain: once `request`'s block has the contract's work on it,
//! and `A*` is shown the last anchor before the cutoff. With one, it
//! builds the statement's input, checks it natively, and asserts its
//! proof (on the mock, the mock's) before `w_H`; she may challenge it,
//! revealing π1's input secrets, and the hub answers with a kept
//! instance's `msg`. Without one, it holds the claimed notes, records the
//! exit on the L2, and lets `request_timeout` pay her; until `w_H` nears
//! it keeps looking for a second claim of her notes through another
//! contract.
//!
//! Its keys as the prover (a Lamport key for π1, adaptor keys) derive from
//! its seed. Of the setup it keeps `hp/<cid>.json` (the setup, her
//! commitment, the instances kept and their hashlocks, the opened ones'
//! shares) and the kept instances, `hp/<cid>/instance-<i>.bin`.

use anyhow::{ensure, Context, Result};
use bitcoin::hashes::Hash as _;
use bitcoin::OutPoint;
use lichen_babe::garble::evaluate;
use lichen_babe::hp::HubProves;
use lichen_babe::reveal::{extract, AdaptorKeys, LamportKey};
use lichen_babe::setup::{check_opened, choose, digits, par, Hash, Instance, Secret, DIGITS, VALUES};
use lichen_babe::vsss::interpolate;
use lichen_babe::we::decrypt;
use lichen_chain::NodeWallet;
use lichen_proto::setup::{dealing_from_hex, link_args, shares_from_hex, statement_outpoint, Opened};
use lichen_proto::hp::{check_commit, HpCommit, HpDisputed, HpKept, HpKeys, HpOffer, HpRequest, HpSetup, HpSetupRequest};
use lichen_proto::{Checkpoint, Presig, Record};
use lichen_ledger::lichen_validity::TNote;
use lichen_ledger::lichen_validity::ack::{self, Ack};
use lichen_withdraw::hp::{Bad, ChainSet, Claim, Counts, Ground, HubInput, Last, Opening, SealSpend, Terms, Why};
use lngap_btc::adaptor::AdaptorSig;
use lngap_btc::keys::Seed;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};

use super::{confirmed_at, State as Outer};
use crate::Inner;

fn contract_seed(seed: &str, cid: u32) -> Seed {
    Seed::from_label(&format!("{seed}/contract/{cid}/hp"))
}

/// The hub's Lamport key for π1 in contract `cid`.
fn hub_lamport(seed: &str, cid: u32) -> LamportKey {
    LamportKey::new(&contract_seed(seed, cid), DIGITS)
}

/// The hub's adaptor keys in contract `cid`.
fn hub_adaptor(seed: &str, cid: u32) -> AdaptorKeys {
    AdaptorKeys::new(&contract_seed(seed, cid), DIGITS)
}

/// What the hub keeps of a setup.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Prepared {
    setup: HpSetup,
    #[serde(default)]
    commit: Option<HpCommit>,
    #[serde(default)]
    kept: Vec<u32>,
    /// Each kept instance uploaded, its hashlock.
    #[serde(default)]
    uploaded: std::collections::BTreeMap<u32, Hash>,
    /// The instances not kept, opened (at the opening).
    #[serde(default)]
    opened: Vec<Opened>,
}

impl Inner {
    fn hp_dir(&self, cid: u32) -> std::path::PathBuf {
        self.cfg.dir.join("hp").join(cid.to_string())
    }
    fn hp_prepared_path(&self, cid: u32) -> std::path::PathBuf {
        self.cfg.dir.join("hp").join(format!("{cid}.json"))
    }
    fn hp_prepared(&self, cid: u32) -> Result<Prepared> {
        Ok(serde_json::from_slice(&std::fs::read(self.hp_prepared_path(cid)).with_context(|| format!("no setup for contract {cid}"))?)?)
    }
    fn hp_save(&self, cid: u32, p: &Prepared) -> Result<()> {
        std::fs::create_dir_all(self.cfg.dir.join("hp"))?;
        Ok(lichen_ledger::files::write_atomic(&self.hp_prepared_path(cid), &serde_json::to_vec(p)?)?)
    }
    /// The journal of the contract of `setup`.
    fn hp_journal_of(&self, setup: &HpSetup) -> Result<[u8; lichen_withdraw::hp::JOURNAL_LEN]> {
        let d = lichen_proto::contract_word(&self.seq.deployment, setup.checkpoint.as_ref(), bitcoin::Amount::from_sat(setup.unit))?;
        Ok(lichen_proto::hp::journal(setup.cid, &d, &setup.deposit, setup.margin))
    }

    /// The setup for contract `cid` (`POST /hp/setup`): the statement fixed
    /// (its checkpoint now, the deposit coin paid and confirmed, the
    /// margin), and the hub's keys as the prover. Asked again, the same.
    pub(crate) fn hp_setup(&self, req: HpSetupRequest) -> Result<HpSetup> {
        let cid = req.cid;
        ensure!(self.deposits.lock().unwrap().contains_key(&cid), "no deposit asked for contract {cid}");
        ensure!(req.unit >= 1, "a unit of 0");
        if let Ok(p) = self.hp_prepared(cid) {
            ensure!(p.setup.deposit == req.deposit && p.setup.unit == req.unit, "contract {cid}'s setup is for another deposit or unit");
            return Ok(p.setup);
        }
        ensure!(self.seq.deployment.seal.is_some(), "the exit where the hub proves needs an anchored deployment");
        self.check_deposit(cid, &req.deposit)?;
        let (n, m) = cut_and_choose(self.cfg.network);
        let setup = HpSetup {
            cid,
            n,
            m,
            margin: lichen_proto::hp::margin(self.cfg.network),
            checkpoint: Some(Checkpoint::tip(&self.chain)?),
            unit: req.unit,
            deposit: req.deposit,
            lamport: hub_lamport(&self.cfg.seed, cid).public(),
            adaptor: hub_adaptor(&self.cfg.seed, cid).public(),
        };
        self.hp_save(cid, &Prepared { setup: setup.clone(), commit: None, kept: vec![], uploaded: Default::default(), opened: vec![] })?;
        Ok(setup)
    }

    /// Alice's commitment to her instances (`POST /hp/commit`): the hub
    /// chooses the ones it keeps. Asked again with the same, the same.
    pub(crate) fn hp_commit(&self, c: HpCommit) -> Result<HpKept> {
        let cid = c.cid;
        let mut p = self.hp_prepared(cid)?;
        check_commit(&c, p.setup.n)?;
        dealing_from_hex(&c.dealing, (p.setup.n - p.setup.m) as usize)?;
        if let Some(old) = &p.commit {
            ensure!(old.commitments == c.commitments && old.dealing == c.dealing, "contract {cid}'s instances are committed already");
            return Ok(HpKept { cid, kept: p.kept });
        }
        let rng = &mut ChaCha20Rng::from_seed(lichen_ledger::fresh_rho());
        p.kept = choose(p.setup.n as usize, p.setup.m as usize, rng).into_iter().map(|k| k as u32 + 1).collect();
        p.commit = Some(c);
        self.hp_save(cid, &p)?;
        Ok(HpKept { cid, kept: p.kept })
    }

    /// A kept instance, uploaded (`POST /hp/instance/<cid>/<i>`, bytes):
    /// checked against Alice's commitment, and kept.
    pub(crate) fn hp_upload(&self, url: &str, bytes: &[u8]) -> Result<String> {
        let (cid, i) = url["/hp/instance/".len()..].split_once('/').context("/hp/instance/<cid>/<i>")?;
        let (cid, i): (u32, u32) = (cid.parse()?, i.parse()?);
        let mut p = self.hp_prepared(cid)?;
        let commit = p.commit.as_ref().context("no instances committed")?;
        ensure!(p.kept.contains(&i), "instance {i} is not kept");
        let inst = Instance::from_bytes(bytes).with_context(|| format!("instance {i} is no instance"))?;
        ensure!(hex::encode(inst.commitment()) == commit.commitments[i as usize - 1], "instance {i} is not the one committed");
        std::fs::create_dir_all(self.hp_dir(cid))?;
        std::fs::write(self.hp_dir(cid).join(format!("instance-{i}.bin")), bytes)?;
        p.uploaded.insert(i, inst.hmsg);
        self.hp_save(cid, &p)?;
        Ok(serde_json::json!({ "kept": i }).to_string())
    }

    /// The contract's keys from Alice's opening request: every kept
    /// instance uploaded, the others opened, their shares on her dealing
    /// and each rebuilt to its commitment. The record's and the offer's
    /// (the pre-signatures to come, [`Inner::hp_presign`]).
    pub(crate) fn hp_open_keys(&self, cid: u32, req: &HpRequest, deposit: &OutPoint, t_close: u32, unit: bitcoin::Amount) -> Result<(HpKeys, HpOffer, Option<Checkpoint>)> {
        let mut p = self.hp_prepared(cid)?;
        let s = p.setup.clone();
        ensure!(s.unit == unit.to_sat() && s.deposit == *deposit, "the setup is for another unit or deposit than the opening's");
        let commit = p.commit.clone().context("no instances committed")?;
        ensure!(p.kept.iter().all(|i| p.uploaded.contains_key(i)), "not every kept instance uploaded");
        let want: Vec<u32> = (1..=s.n).filter(|i| !p.kept.contains(i)).collect();
        ensure!(req.hp_opened.iter().map(|o| o.i).collect::<Vec<_>>() == want, "other instances opened than those not kept");
        let dealing = dealing_from_hex(&commit.dealing, (s.n - s.m) as usize)?;
        let shares: Vec<(u64, Vec<[Secret; VALUES]>)> = req.hp_opened.iter().map(|o| Ok((u64::from(o.i), shares_from_hex(&o.shares)?))).collect::<Result<_>>()?;
        ensure!(dealing.verify(&shares, &mut ChaCha20Rng::from_seed(lichen_ledger::fresh_rho())), "an opened instance's shares are off the dealing's polynomials");
        let kind = self.cfg.statement.hp_kind()?;
        let journal = self.hp_journal_of(&s)?;
        let (vk, public) = (kind.verifying_key(), kind.public_inputs(&journal));
        let seeds: Vec<[u8; 32]> = req.hp_opened.iter().map(|o| hex::decode(&o.seed)?.try_into().map_err(|_| anyhow::anyhow!("a seed of other than 32 bytes"))).collect::<Result<_>>()?;
        let commits: Vec<[u8; 32]> = req.hp_opened.iter().map(|o| hex::decode(&commit.commitments[o.i as usize - 1])?.try_into().map_err(|_| anyhow::anyhow!("a commitment of other than 32 bytes"))).collect::<Result<_>>()?;
        let start = std::time::Instant::now();
        let ok = par(seeds.len(), |k| check_opened(&commits[k], &seeds[k], &shares[k].1, &vk, &public));
        if let Some(k) = ok.iter().position(|o| !o) {
            anyhow::bail!("opened instance {} is not the one committed", req.hp_opened[k].i);
        }
        self.note(format!("contract {cid}: the user's {} opened instances checked in {:.1?}", seeds.len(), start.elapsed()));
        p.opened = req.hp_opened.clone();
        self.hp_save(cid, &p)?;
        let windows = lichen_proto::hp::windows(self.cfg.network, t_close);
        let keys = HpKeys {
            b_key: commit.b_key,
            e_key: commit.e_key,
            hub_lamport: s.lamport,
            hub_adaptor: s.adaptor,
            n: s.n,
            kept: p.kept.clone(),
            hmsg: p.kept.iter().map(|i| p.uploaded[i]).collect(),
            hp_windows: windows,
            margin: s.margin,
            deposit: s.deposit,
            hub_presigs: vec![],
        };
        Ok((keys, HpOffer { hp_windows: windows, hp_presigs: vec![] }, s.checkpoint))
    }

    /// The hub's adaptor pre-signatures on `challenge_assert`, adapted to
    /// Alice's dealing's points, into the record and the offer.
    pub(crate) fn hp_presign(&self, record: &mut Record, offer: &mut HpOffer, set: &[lngap_sessions::contract::Presign]) -> Result<()> {
        let cid = record.cid();
        let p = self.hp_prepared(cid)?;
        let commit = p.commit.as_ref().context("no instances committed")?;
        let dealing = dealing_from_hex(&commit.dealing, (p.setup.n - p.setup.m) as usize)?;
        let msg = HubProves::challenge_sighash(set)?;
        let presigs: Vec<[Presig; VALUES]> = hub_adaptor(&self.cfg.seed, cid).presign(&msg, &lichen_babe::reveal::points(&dealing)).into_iter().map(|p| p.map(Presig::from)).collect();
        record.dispute.hub_presigs = presigs.clone();
        offer.hp_presigs = presigs;
        Ok(())
    }

    /// Alice's signatures on what the hub keeps its own of from her
    /// (`wrongly_challenged`): its answer needs them.
    pub(crate) fn hp_accept(&self, record: &Record) -> Result<()> {
        let built = self.built(record)?;
        for p in built.presign(record.funding)?.iter().filter(|p| built.withheld(&p.name)) {
            let s = record.alice_sigs.get(&p.name).with_context(|| format!("the user didn't sign {}", p.name))?;
            p.verify_input(&record.pubs[0].payment, 0, s).with_context(|| format!("the user's signature on {}", p.name))?;
        }
        Ok(())
    }
}

/// The cut-and-choose on a network: `N` instances, `M` kept. BABE's
/// smallest point with secret sharing, (78, 10); regtest's tests keep 2
/// of 4.
pub fn cut_and_choose(net: lichen_proto::Net) -> (u32, u32) {
    match net {
        lichen_proto::Net::Regtest => (4, 2),
        _ => (78, 10),
    }
}

/// The hub's decision on a claim.
enum Decision {
    /// A ground, its input, and why (for the log).
    Assert(Box<HubInput>, String),
    /// None holds.
    Holds,
    /// Not yet decidable: why.
    Wait(String),
}

/// A dispute's state at the hub, in play.
pub(crate) enum State {
    /// `request` confirmed at `at`; `recorded` once the claim was found to
    /// hold and its exit recorded.
    Requested(Box<HpDisputed>, u32, bool),
    /// `assert` confirmed at `at`: her challenge is due within `Δ2`.
    Asserted(Box<HpDisputed>, u32),
    /// Challenged: the hub's answer is due within `Δ1` of `at`; `tried`
    /// once its kept instances were evaluated and none opened.
    Challenged(Box<HpDisputed>, u32, bool),
}

fn bb(s: State) -> Option<Outer> {
    Some(Outer::Hp(s))
}

impl Inner {
    fn hp_terminal(&self, d: &HpDisputed, name: &str, wire: Vec<Vec<u8>>) -> Result<bitcoin::Txid> {
        let tx = d.finish(name, wire)?;
        self.chain.post_terminal(&tx, &d.set[name].prevout, lichen_proto::terminal_fee(&tx, self.cfg.network), &NodeWallet)
    }

    /// Whether the contract was disputed (`request` posted).
    pub(super) fn hp_requested(&self, record: &Record) -> Result<bool> {
        let d = HpDisputed::new(record, &self.cfg.statement)?;
        Ok(self.chain.get_tx(&d.txid("request")).is_some())
    }

    /// Alice's `b` and her signature on it, from `request`.
    pub(super) fn hp_claimed_b(&self, record: &Record) -> Result<(u32, Vec<Vec<u8>>)> {
        let d = HpDisputed::new(record, &self.cfg.statement)?;
        let req = self.chain.get_tx(&d.txid("request")).context("the request")?;
        let (b, _, _) = HubProves::read_request(&link_args(&req))?;
        let v = u32::from_be_bytes(b.message().try_into().map_err(|_| anyhow::anyhow!("b's signature signs 4 bytes"))?);
        Ok((v, HubProves::b_wire(&b)))
    }

    /// If Alice has requested, the dispute from where the chain shows it.
    pub(super) fn hp_start(&self, record: &Record) -> Result<Option<Outer>> {
        let d = HpDisputed::new(record, &self.cfg.statement)?;
        let req_id = d.txid("request");
        let Some(at) = confirmed_at(self, &req_id)? else { return Ok(None) };
        if let Some(a) = confirmed_at(self, &d.txid("assert"))? {
            return Ok(bb(State::Asserted(Box::new(d), a)));
        }
        Ok(bb(State::Requested(Box::new(d), at, false)))
    }

    /// One step of a dispute in play.
    pub(super) fn hp_tick(&self, record: &Record, s: State) -> Result<Option<Outer>> {
        let cid = record.cid();
        match s {
            State::Requested(d, at, recorded) => {
                if let Some(a) = confirmed_at(self, &d.txid("assert"))? {
                    return Ok(bb(State::Asserted(d, a)));
                }
                let r_op = OutPoint { txid: d.txid("request"), vout: 0 };
                if !self.chain.unspent(&r_op)? && self.chain.get_tx(&d.txid("assert")).is_none() {
                    self.note(format!("contract {cid}: the user's request timed out; she is paid her claim"));
                    return Ok(Some(Outer::Collect { link: r_op.txid, since: self.chain.height()? }));
                }
                let w = d.graph.spec.windows;
                // the assertion must confirm before her timeout
                let last_chance = at + u32::from(w.w_h) - (u32::from(w.w_h) / 4).max(2);
                if self.chain.height()? >= last_chance {
                    self.note_once(format!("contract {cid}: too late to assert; request_timeout will pay the user"));
                    return Ok(bb(State::Requested(d, at, recorded)));
                }
                if !recorded {
                    self.hp_hold(&d)?;
                }
                match self.hp_decide(&d, at, recorded)? {
                    Decision::Wait(why) => {
                        self.note_once(format!("contract {cid}: {why}"));
                        Ok(bb(State::Requested(d, at, recorded)))
                    }
                    // for tests: a lying hub asserts against a claim that holds
                    Decision::Holds if self.forge_assertions.load(std::sync::atomic::Ordering::Relaxed) => {
                        self.hp_assert(&d, None, "")?;
                        Ok(bb(State::Requested(d, at, recorded)))
                    }
                    Decision::Holds => {
                        if !recorded {
                            self.hp_record(&d)?;
                        }
                        Ok(bb(State::Requested(d, at, true)))
                    }
                    Decision::Assert(input, why) => {
                        self.hp_assert(&d, Some(&input), &why)?;
                        Ok(bb(State::Requested(d, at, recorded)))
                    }
                }
            }
            State::Asserted(d, at) => {
                if let Some(c) = confirmed_at(self, &d.txid("challenge_assert"))? {
                    return Ok(bb(State::Challenged(d, c, false)));
                }
                let a_op = OutPoint { txid: d.txid("assert"), vout: 0 };
                if !self.chain.unspent(&a_op)? && self.chain.get_tx(&d.txid("challenge_assert")).is_none() {
                    self.close_settled(cid, d.txid("success"))?;
                    return Ok(Some(Outer::Done));
                }
                if self.chain.height()? >= at + u32::from(d.graph.spec.windows.delta2) {
                    let txid = self.hp_terminal(&d, "success", vec![])?;
                    self.note(format!("contract {cid}: no challenge to the assertion; success {txid}: the contract is the hub's"));
                    self.close(cid, txid)?;
                    return Ok(Some(Outer::Done));
                }
                Ok(bb(State::Asserted(d, at)))
            }
            State::Challenged(d, at, tried) => {
                let c_op = OutPoint { txid: d.txid("challenge_assert"), vout: 0 };
                if !self.chain.unspent(&c_op)? {
                    if self.chain.get_tx(&d.txid("failure")).is_some() {
                        self.note(format!("contract {cid}: no answer to the user's challenge: failure paid her"));
                        return Ok(Some(Outer::Collect { link: c_op.txid, since: self.chain.height()? }));
                    }
                    self.close_settled(cid, c_op.txid)?;
                    return Ok(Some(Outer::Done));
                }
                if tried || self.chain.height()? >= at + u32::from(d.graph.spec.windows.delta1) {
                    return Ok(bb(State::Challenged(d, at, tried)));
                }
                if let Some(txid) = self.hp_answer(&d)? {
                    self.note(format!("contract {cid}: answered the challenge with a kept instance's msg: {txid}; the contract is the hub's"));
                    self.close(cid, txid)?;
                    return Ok(Some(Outer::Done));
                }
                self.note(format!("contract {cid}: no kept instance opens on the hub's proof: failure will pay the user"));
                Ok(bb(State::Challenged(d, at, true)))
            }
        }
    }

    /// Hold the notes a request claims, once, as soon as it is seen: the
    /// sequencer refuses their spends, and the acknowledgment of a spend of
    /// them (the earlier of an exit and a spend wins).
    fn hp_hold(&self, d: &HpDisputed) -> Result<()> {
        let cid = d.record.cid();
        let once = format!("contract {cid}: holding the notes the request claims");
        if self.log.lock().unwrap().contains(&once) {
            return Ok(());
        }
        let req = self.chain.get_tx(&d.txid("request")).context("the request")?;
        let (_, _, posted) = HpDisputed::requested(&req)?;
        let Ok(claim) = Claim::from_bytes(&posted) else { return Ok(()) };
        let state = self.seq.state()?;
        let nfs: Vec<Hash> = claim.positions.iter().filter_map(|i| state.note(*i)).map(lichen_ledger::nullifier).collect();
        if !nfs.is_empty() {
            self.seq.hold(&self.cfg.l2_key, &nfs)?;
        }
        self.note(once);
        Ok(())
    }

    /// The claim holds: hold its notes, and record its exit on the L2,
    /// retiring them.
    fn hp_record(&self, d: &HpDisputed) -> Result<()> {
        let cid = d.record.cid();
        let req = self.chain.get_tx(&d.txid("request")).context("the request")?;
        let (b, e, posted) = HpDisputed::requested(&req)?;
        let claim = Claim::from_bytes(&posted).map_err(|r| anyhow::anyhow!("the claim: {r:?}"))?;
        self.note(format!("contract {cid}: the user's exit claim of {b} units holds: no assertion; request_timeout will pay her"));
        let state = self.seq.state()?;
        let notes: Vec<TNote> = claim.positions.iter().map(|i| state.notes.get(*i as usize).and_then(|l| l.note()).map(tnote).context("a claimed note isn't transparent")).collect::<Result<_>>()?;
        if let Err(e) = self.seq.hold(&self.cfg.l2_key, &notes.iter().map(TNote::nullifier).collect::<Vec<_>>()) {
            self.note(format!("contract {cid}: holding the claimed notes: {e:#}"));
        }
        let deposit = statement_outpoint(&d.record.hp().deposit);
        let Some((notes, sigs)) = claim.record(&notes, &e) else { return Ok(()) };
        let notes = notes.into_iter().map(|(n, index)| lichen_ledger::Spend { note: lichen_ledger::Note { owner: n.owner, value: n.value, memo: n.memo, rho: n.rho }, index }).collect();
        let acks = claim.acks.iter().map(lichen_ledger::Ack::of).collect();
        let tx = lichen_ledger::Tx::Exit(lichen_ledger::Exit::new(&self.cfg.l2_key, &self.seq.deployment, cid, deposit, b, notes, acks, sigs));
        match self.seq.submit(&tx) {
            Ok(_) => self.note(format!("contract {cid}: the exit claim recorded on the L2: its notes are retired")),
            Err(e) => self.note(format!("contract {cid}: the exit record: {e:#}")),
        }
        Ok(())
    }

    /// Whether the claim of `d`'s request (confirmed at `at`) is false: its
    /// ground and the statement's input, once decidable.
    fn hp_decide(&self, d: &HpDisputed, at: u32, recorded: bool) -> Result<Decision> {
        let record = &d.record;
        let cid = record.cid();
        let k = record.hp();
        let deposit = statement_outpoint(&k.deposit);
        let req_id = d.txid("request");
        let req = self.chain.get_tx(&req_id).context("the request")?;
        let (b, e, posted) = HpDisputed::requested(&req)?;
        let checkpoint = record.checkpoint.as_ref().context("a hub-proves contract's checkpoint")?;
        let dep = self.seq.deployment;
        let terms = Terms { sequencer: dep.sequencer, hub: dep.hub, genesis: dep.seal.context("an anchored deployment")?, work: checkpoint.work(), unit: record.terms.unit.to_sat() };
        // request in its block, with the contract's work on it
        let funding = self.chain.get_tx(&record.funding.txid).context("the funding")?;
        let request = lichen_proto::exit::request_proof(&self.chain, &funding, &req_id)?;
        let req_block = lichen_ledger::lichen_validity::btc::Header(request.header).hash();
        let headers = match lichen_proto::headers_for(&self.chain, &req_block, terms.work) {
            Ok(h) => h,
            Err(e) => return Ok(Decision::Wait(format!("deciding the claim: {e:#}"))),
        };
        let input = |ground: Ground| Box::new(HubInput { c: cid, deposit, margin: k.margin, terms, request: request.clone(), headers: headers.clone(), ground });
        let claim = match Claim::from_bytes(&posted) {
            Ok(c) if c.well_formed() && c.fingerprint(cid, &deposit, b) == e => c,
            _ => return Ok(Decision::Assert(input(Ground::Malformed), "the claim is malformed".into())),
        };
        let state = self.seq.state()?;
        let cutoff = at.saturating_sub(k.margin);
        // A*: the last anchor recorded whose block is at most the cutoff
        let mut star = None;
        for (i, a) in state.anchors.iter().enumerate() {
            if self.chain.block_height(&bitcoin::BlockHash::from_byte_array(a.anchor.block))?.is_some_and(|h| h <= cutoff) {
                star = Some(i);
            }
        }
        let Some(i) = star else { return Ok(Decision::Wait("no anchor before the claim's cutoff".into())) };
        let a = state.anchors[i];
        let Some(next) = state.anchors.get(i + 1) else {
            self.hp_nudge(cid)?;
            return Ok(Decision::Wait("waiting for an anchor after the cutoff, to show A* the last before it".into()));
        };
        let succ = bitcoin::Txid::from_byte_array(next.anchor.seal.txid);
        let spend = lichen_proto::exit::in_block(&self.chain, &succ)?;
        let a_block = bitcoin::BlockHash::from_byte_array(a.anchor.block);
        let a_height = self.chain.block_height(&a_block)?.context("A*'s block isn't on the chain")?;
        let s_height = self.chain.block_height(&spend.block)?.context("the seal's spend isn't on the chain")?;
        ensure!(s_height > cutoff, "the anchor after A* is before the cutoff (not recorded yet?)");
        let star_headers = self.chain.headers_after(&a_block, (self.chain.height()? - a_height) as usize)?;
        let h2 = a.anchor.height;
        let s2 = state.sealed.iter().find(|s| s.height == h2).context("A* isn't sealed")?;
        let (chain_root, recent, hist) = state.chain_at(a.from)?;
        let last = Last {
            state: lichen_withdraw::Anchored {
                height: h2,
                nullifiers: s2.nullifiers,
                signature: s2.signature.as_slice().try_into().context("a signature of 64 bytes")?,
                sequencer: dep.sequencer,
                hub: dep.hub,
                chain_height: a.from,
                chain_root,
                recent,
                hist,
                anchor: a.anchor,
                headers: star_headers,
                work: terms.work,
                unit: terms.unit,
            },
            tree: s2.tree,
            seal: SealSpend { tx: spend.tx, at: s_height - a_height - 1, index: spend.index, path: spend.path, coinbase: spend.coinbase, coinbase_path: spend.coinbase_path },
        };
        let at_star = |why: Why| input(Ground::At { last: last.clone(), why });
        // each position at A*: a transparent note, opened
        let tree = state.tree();
        let mut openings = vec![];
        for (w, &index) in claim.positions.iter().enumerate() {
            let path = tree.path_at(index, s2.size);
            let leaf = state.notes.get(index as usize).filter(|_| index < s2.size);
            match leaf.and_then(|l| l.note()) {
                Some(n) => openings.push(Opening { note: tnote(n), path }),
                None => {
                    let leaf = leaf.map_or(lichen_ledger::lichen_validity::tree_empties()[0], |l| l.leaf());
                    return Ok(Decision::Assert(at_star(Why::NotANote { which: w as u8, leaf, path }), format!("position {index} isn't a transparent note at A* (height {h2})")));
                }
            }
        }
        for (w, o) in openings.iter().enumerate() {
            if claim.signed_by(&o.note.owner, &e).is_none() {
                return Ok(Decision::Assert(at_star(Why::NotHers { which: w as u8, opening: o.clone() }), format!("note {} isn't the user's", claim.positions[w])));
            }
        }
        let total: u64 = openings.iter().map(|o| o.note.value).sum();
        if total / terms.unit < u64::from(b) {
            return Ok(Decision::Assert(at_star(Why::TooMuch { openings }), format!("its notes are worth {total} sats, less than {b} units")));
        }
        if let Some((why, said)) = self.hp_second(cid, &claim, &openings)? {
            return Ok(Decision::Assert(at_star(why), said));
        }
        // once found to hold, only a second claim can still appear
        if recorded {
            return Ok(Decision::Holds);
        }
        // its locks at A*: each claimed output of a spend void then, or
        // pending without an acknowledgment that holds
        let c_h = a.from;
        let s_ch = state.sealed.iter().find(|s| s.height == c_h).context("A*'s chain receipt's height isn't sealed")?;
        let chain = ChainSet { tree: s_ch.tree, set: s_ch.nullifiers };
        let open = |k: &Hash, h: u64| self.seq.opening(k, h);
        for (w, &index) in claim.positions.iter().enumerate() {
            let lock = open(&ack::lock_key(index), h2)?;
            let t = lock.leaf;
            if t == [0; 32] {
                continue;
            }
            let void = open(&ack::void_key(&t), h2)?;
            if void.leaf != [0; 32] {
                return Ok(Decision::Assert(at_star(Why::Voided { which: w as u8, lock, void }), format!("note {index} is an output of a spend void at A* (height {h2})")));
            }
            let acked = open(&ack::acked_key(&t), h2)?;
            if acked.leaf != [0; 32] {
                continue;
            }
            let bad = match claim.acks.iter().find(|a| a.txid == t) {
                None => Some(None),
                Some(a) if !a.signed() => Some(Some(Bad::Signature)),
                Some(a) => {
                    let p = open(&ack::tx_key(&t), h2)?;
                    if p.leaf != ack::pending(&a.ak, a.h) {
                        Some(Some(Bad::Pending(p)))
                    } else {
                        let an = open(&ack::anchor_key(a.a), c_h)?;
                        (an.leaf != a.hist_a).then_some(Some(Bad::Anchor(an, chain)))
                    }
                }
            };
            if let Some(bad) = bad {
                return Ok(Decision::Assert(at_star(Why::Locked { which: w as u8, lock, acked, bad }), format!("note {index} is locked at A* (height {h2}): its spend unacknowledged")));
            }
        }
        // its spends at A*: each that counts against her
        let known = self.hp_known_acks(cid)?;
        for (w, o) in openings.iter().enumerate() {
            let nf = o.note.nullifier();
            let leaf = open(&nf, h2)?;
            let t = leaf.leaf;
            if t == [0; 32] {
                continue;
            }
            let counts = if let Some(c) = self.hp_exited(&t) {
                if c == cid {
                    continue;
                }
                Counts::Exit { c }
            } else {
                let acked = open(&ack::acked_key(&t), h2)?;
                if acked.leaf != [0; 32] {
                    Counts::Acked { acked }
                } else {
                    // pending at A*: it counts if an acknowledgment of it
                    // exists (sequenced since, or in another claim) whose
                    // anchor is applied by A*'s own record
                    let found = match self.seq.ack(&t)? {
                        Some(a) => Some(a.v()?),
                        None => known.iter().find(|a| a.txid == t).copied(),
                    };
                    let Some(a) = found else { continue };
                    let (pending, void, anchor) = (open(&ack::tx_key(&t), h2)?, open(&ack::void_key(&t), h2)?, open(&ack::anchor_key(a.a), c_h)?);
                    if !a.signed() || pending.leaf != ack::pending(&a.ak, a.h) || void.leaf != [0; 32] || anchor.leaf != a.hist_a {
                        continue;
                    }
                    Counts::Shown { ack: a, pending, void, anchor, chain }
                }
            };
            let why = Why::Spent { which: w as u8, opening: o.clone(), leaf, counts };
            return Ok(Decision::Assert(at_star(why), format!("note {} was spent by A* (height {h2})", claim.positions[w])));
        }
        Ok(Decision::Holds)
    }

    /// The contract whose exit record a spent set leaf is, if it is one.
    fn hp_exited(&self, leaf: &Hash) -> Option<u32> {
        let cids: Vec<u32> = self.open.lock().unwrap().keys().copied().collect();
        cids.into_iter().find(|c| lichen_ledger::lichen_validity::smt::exited(*c) == *leaf)
    }

    /// The acknowledgments other contracts' requests on chain carry: a
    /// user who claims a spend's outputs through one contract shows it
    /// counts, against a claim of its inputs through another.
    fn hp_known_acks(&self, cid: u32) -> Result<Vec<Ack>> {
        let records: Vec<Record> = self.open.lock().unwrap().values().map(|o| o.record.clone()).filter(|r| r.cid() != cid).collect();
        let mut acks = vec![];
        for r in records {
            let Ok(d) = HpDisputed::new(&r, &self.cfg.statement) else { continue };
            let Some(req) = self.chain.get_tx(&d.txid("request")) else { continue };
            let Ok((_, _, posted)) = HpDisputed::requested(&req) else { continue };
            if let Ok(other) = Claim::from_bytes(&posted) {
                acks.extend(other.acks);
            }
        }
        Ok(acks)
    }

    /// A second claim of a note of `claim` (`openings`, its notes)
    /// through another hub-proves contract, its request on chain and
    /// signed by the note's owner.
    fn hp_second(&self, cid: u32, claim: &Claim, openings: &[Opening]) -> Result<Option<(Why, String)>> {
        let records: Vec<Record> = self.open.lock().unwrap().values().map(|o| o.record.clone()).filter(|r| r.cid() != cid).collect();
        for r in records {
            let Ok(d) = HpDisputed::new(&r, &self.cfg.statement) else { continue };
            let Some(req) = self.chain.get_tx(&d.txid("request")) else { continue };
            let Ok((b2, _, posted)) = HpDisputed::requested(&req) else { continue };
            let Ok(other) = Claim::from_bytes(&posted) else { continue };
            let d2 = statement_outpoint(&r.hp().deposit);
            let e2 = other.fingerprint(r.cid(), &d2, b2);
            for (w, (index, o)) in claim.positions.iter().zip(openings).enumerate() {
                if other.positions.contains(index) && other.signed_by(&o.note.owner, &e2).is_some() {
                    let why = Why::Second { which: w as u8, opening: o.clone(), other_c: r.cid(), other_deposit: d2, other_b: b2, other: other.clone() };
                    return Ok(Some((why, format!("note {index} was claimed through contract {} too", r.cid()))));
                }
            }
        }
        Ok(None)
    }

    /// No anchor after `A*` yet: change the L2's state (a mint of one sat
    /// to the hub itself, once a contract), so that the sequencer seals and
    /// anchors, spending `A*`'s seal.
    fn hp_nudge(&self, cid: u32) -> Result<()> {
        let once = format!("contract {cid}: minting a sat to the hub, for an anchor after the cutoff");
        if self.log.lock().unwrap().contains(&once) {
            return Ok(());
        }
        self.note(once);
        let owner = lichen_ledger::xonly(&self.cfg.l2_key);
        self.seq.submit(&lichen_ledger::Tx::Mint(lichen_ledger::Mint::new(&self.cfg.l2_key, &self.seq.deployment, vec![lichen_ledger::note(owner, 1, 0)])))?;
        Ok(())
    }

    /// The statement's input `input` checked natively, then its proof
    /// asserted: on the mock, the mock's. With no input (a test's lying
    /// hub), a proof of another contract's statement.
    fn hp_assert(&self, d: &HpDisputed, input: Option<&HubInput>, why: &str) -> Result<()> {
        let record = &d.record;
        let cid = record.cid();
        let kind = self.cfg.statement.hp_kind()?;
        let journal = record.hp_journal();
        let proof = if let Some(input) = input {
            match lichen_withdraw::hp::check(input, &[0; 32], &mut |_| true) {
                Ok(j) if j == journal => {}
                Ok(_) => anyhow::bail!("the statement's journal isn't the contract's"),
                Err(r) => anyhow::bail!("the ground ({why}) doesn't check natively: {r:?}"),
            }
            self.note(format!("contract {cid}: the user's exit claim is false: {why}: asserting"));
            match kind {
                lichen_babe::statement::Kind::Mock => lichen_babe::statement::mock_prove(&journal),
            }
        } else {
            self.note(format!("contract {cid}: asserting a forged proof against the claim"));
            lichen_babe::statement::mock_prove(&lichen_proto::hp::journal(cid + 1, &record.deployment, &record.hp().deposit, record.hp().margin))
        };
        let bits = lichen_babe::gadget::input(&proof.a);
        let (pi2, pi3) = lichen_babe::statement::pi23_to_bytes(&proof);
        let wire = HubProves::assert_wire(&hub_lamport(&self.cfg.seed, cid).sign(&digits(&bits)), &pi2, &pi3);
        let tx = d.finish("assert", wire)?;
        self.post(cid, &tx)?;
        self.note(format!("contract {cid}: asserted ({} vB)", tx.vsize()));
        Ok(())
    }

    /// The answer to her challenge: π1's secrets from it (her completions
    /// of the hub's pre-signatures), each kept instance's from them and the
    /// opened shares, its circuit evaluated on the asserted π1, and the
    /// `msg` that opens its hashlock, posted in `wrongly_challenged`. None
    /// if no kept instance opens.
    fn hp_answer(&self, d: &HpDisputed) -> Result<Option<bitcoin::Txid>> {
        let cid = d.record.cid();
        let keys = d.record.hp();
        let asserted = d.asserted(&self.chain.get_tx(&d.txid("assert")).context("the assertion")?)?;
        let proof = asserted.proof.clone().context("the assertion's points aren't points")?;
        let tx = self.chain.get_tx(&d.txid("challenge_assert")).context("the challenge")?;
        let presigs: Vec<[AdaptorSig; VALUES]> = keys.hub_presigs.iter().map(|s| s.each_ref().map(AdaptorSig::from)).collect();
        let (posted, revealed) = extract(&keys.hub_lamport, &presigs, &link_args(&tx)).context("the challenge's secrets")?;
        ensure!(posted == asserted.digits, "the challenge reveals other digits than asserted");
        let p = self.hp_prepared(cid)?;
        let of_digits: Vec<(u64, Vec<Secret>)> = p.opened.iter().map(|o| Ok((u64::from(o.i), shares_from_hex(&o.shares)?.iter().zip(&posted).map(|(s, v)| s[*v as usize]).collect()))).collect::<Result<_>>()?;
        for (k, i) in keys.kept.iter().enumerate() {
            let inst = Instance::from_bytes(&std::fs::read(self.hp_dir(cid).join(format!("instance-{i}.bin"))).with_context(|| format!("kept instance {i}"))?).with_context(|| format!("kept instance {i} is unreadable"))?;
            let Some(secrets) = interpolate(u64::from(*i), &of_digits, &revealed) else { continue };
            let r_pi1 = evaluate(&inst.gc, &asserted.bits, &inst.labels(&asserted.bits, &secrets));
            let msg = decrypt(&inst.ct, &r_pi1, &proof);
            if inst.is_msg(&msg) {
                return self.hp_terminal(d, &format!("wrongly_challenged_{k}"), vec![msg.to_vec()]).map(Some);
            }
        }
        Ok(None)
    }
}

impl State {
    pub(crate) fn describe(&self) -> String {
        match self {
            State::Requested(_, _, false) => "requested: the hub decides the claim".into(),
            State::Requested(_, _, true) => "requested: the claim holds, request_timeout pays the user".into(),
            State::Asserted(..) => "asserted: the user's challenge is due".into(),
            State::Challenged(..) => "challenged: the hub's answer is due".into(),
        }
    }
}

/// A ledger note as the statements read it.
fn tnote(n: &lichen_ledger::Note) -> TNote {
    TNote { owner: n.owner, value: n.value, memo: n.memo, rho: n.rho }
}

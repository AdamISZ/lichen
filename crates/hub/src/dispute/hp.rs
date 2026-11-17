//! The hub's side of a contract (papers/lichen-grants-v0.5.6, §5–6;
//! `lichen_proto::hp`): its setup, in which Alice garbles and the hub keeps
//! her instances, and its dispute ([`super`] drives it).
//!
//! The dispute: when `request` confirms, the hub takes the claim into its
//! book (the account closed) and weighs it by Algorithm 1, citing the last
//! spend of the account if it takes the claimed note or a later one. Owed
//! in full: nothing, `request_timeout` pays her. Otherwise `correct`, its
//! one-time signatures on `b_corr` and `U` (the cited spend's seed). She
//! accepts (after `w_A`, `accept` pays `b_corr`) or countersigns in `ack`;
//! then the hub proves the statement from her four signatures and asserts.
//!
//! Its keys as the prover (a Lamport key for π1, adaptor keys) and its
//! one-time keys for `b_corr` and `U` derive from its seed. Of the setup it
//! keeps `hp/<cid>.json` and the kept instances, `hp/<cid>/instance-<i>.bin`.

use anyhow::{ensure, Context, Result};
use bitcoin::OutPoint;
use lichen_babe::countersigned::{Countersigned, U_LEN};
use lichen_babe::garble::evaluate;
use lichen_babe::reveal::{extract, AdaptorKeys, LamportKey};
use lichen_babe::setup::{check_opened, choose, digits, par, Hash, Instance, Secret, DIGITS, VALUES};
use lichen_babe::vsss::interpolate;
use lichen_babe::we::decrypt;
use lichen_chain::NodeWallet;
use lichen_notes::core as acc;
use lichen_proto::hp::{check_commit, HpCommit, HpDisputed, HpKept, HpKeys, HpOffer, HpRequest, HpSetup, HpSetupRequest};
use lichen_proto::setup::{dealing_from_hex, link_args, shares_from_hex, Opened};
use lichen_proto::{Presig, Record};
use lichen_btc::adaptor::AdaptorSig;
use lichen_btc::keys::Seed;
use lichen_wots::{WotsParams, WotsSecret};
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

/// The hub's one-time key for `b_corr` in contract `cid` (`correct`).
pub(crate) fn hub_corr(seed: &str, cid: u32) -> WotsSecret {
    WotsSecret::from_entropy(WotsParams::for_bytes(4), contract_seed(seed, cid).derive_bytes("hp/bc"))
}

/// The hub's one-time key for `U` in contract `cid` (`correct`).
pub(crate) fn hub_u(seed: &str, cid: u32) -> WotsSecret {
    WotsSecret::from_entropy(WotsParams::for_bytes(U_LEN as u32), contract_seed(seed, cid).derive_bytes("hp/u"))
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
    #[serde(default, with = "lichen_babe::hexbytes::btree_fixed")]
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

    /// Whether `owner` may open a contract: a key fresh for it, no
    /// contract's before and no account's. Its note 0 is its mint.
    pub(crate) fn check_owner(&self, owner: &lichen_ledger::Hash) -> Result<()> {
        if let Some(o) = self.open.lock().unwrap().values().find(|o| o.record.l2_address == *owner) {
            anyhow::bail!("this owner key has contract {} already: a fresh key for each contract", o.record.cid());
        }
        ensure!(!self.book.knows(owner), "this owner key has an account already: a fresh key for each contract");
        Ok(())
    }

    /// The setup for contract `cid` (`POST /hp/setup`): the statement's
    /// terms fixed (the deposit coin paid and confirmed), and the hub's keys
    /// as the prover. Asked again, the same.
    pub(crate) fn hp_setup(&self, req: HpSetupRequest) -> Result<HpSetup> {
        let cid = req.cid;
        ensure!(self.deposits.lock().unwrap().contains_key(&cid), "no deposit asked for contract {cid}");
        ensure!(req.unit >= 1, "a unit of 0");
        ensure!(req.v0 < acc::VALUE_LIMIT, "a mint too large");
        if let Ok(p) = self.hp_prepared(cid) {
            ensure!(p.setup.deposit == req.deposit && p.setup.unit == req.unit && p.setup.owner == req.owner && p.setup.v0 == req.v0, "contract {cid}'s setup is for another deposit, unit, owner or mint");
            return Ok(p.setup);
        }
        self.check_deposit(cid, &req.deposit)?;
        self.check_owner(&req.owner)?;
        let (n, m) = cut_and_choose(self.cfg.network);
        let setup = HpSetup {
            cid,
            n,
            m,
            unit: req.unit,
            deposit: req.deposit,
            owner: req.owner,
            v0: req.v0,
            issuer: self.book.issuer(),
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
            ensure!(old.commitments == c.commitments && old.dealing == c.dealing && old.keys == c.keys, "contract {cid}'s instances are committed already");
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
    pub(crate) fn hp_open_keys(&self, cid: u32, req: &HpRequest, deposit: &OutPoint, owner: &lichen_ledger::Hash, v0: u64, unit: bitcoin::Amount) -> Result<(HpKeys, HpOffer)> {
        let mut p = self.hp_prepared(cid)?;
        let s = p.setup.clone();
        ensure!(s.unit == unit.to_sat() && s.deposit == *deposit && s.owner == *owner && s.v0 == v0, "the setup is for another unit, deposit, owner or mint than the opening's");
        self.check_owner(owner)?;
        let commit = p.commit.clone().context("no instances committed")?;
        ensure!(p.kept.iter().all(|i| p.uploaded.contains_key(i)), "not every kept instance uploaded");
        let want: Vec<u32> = (1..=s.n).filter(|i| !p.kept.contains(i)).collect();
        ensure!(req.hp_opened.iter().map(|o| o.i).collect::<Vec<_>>() == want, "other instances opened than those not kept");
        let dealing = dealing_from_hex(&commit.dealing, (s.n - s.m) as usize)?;
        let shares: Vec<(u64, Vec<[Secret; VALUES]>)> = req.hp_opened.iter().map(|o| Ok((u64::from(o.i), shares_from_hex(&o.shares)?))).collect::<Result<_>>()?;
        ensure!(dealing.verify(&shares, &mut ChaCha20Rng::from_seed(lichen_ledger::fresh_rho())), "an opened instance's shares are off the dealing's polynomials");
        let kind = self.cfg.statement.hp_kind()?;
        let journal = lichen_proto::hp::contract(cid, &s.issuer, &s.owner, s.unit, s.v0, &commit.keys).journal();
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
        let windows = lichen_proto::hp::windows(self.cfg.network);
        let (corr_key, u_key) = (hub_corr(&self.cfg.seed, cid).public(), hub_u(&self.cfg.seed, cid).public());
        let keys = HpKeys {
            alice_keys: commit.keys,
            corr_key: corr_key.clone(),
            u_key: u_key.clone(),
            hub_lamport: s.lamport,
            hub_adaptor: s.adaptor,
            n: s.n,
            kept: p.kept.clone(),
            hmsg: p.kept.iter().map(|i| p.uploaded[i]).collect(),
            hp_windows: windows,
            deposit: s.deposit,
            issuer: s.issuer,
            v0: s.v0,
            hub_presigs: vec![],
        };
        Ok((keys, HpOffer { hp_windows: windows, corr_key, u_key, hp_presigs: vec![] }))
    }

    /// The hub's adaptor pre-signatures on `challenge_assert`, adapted to
    /// Alice's dealing's points, into the record and the offer.
    pub(crate) fn hp_presign(&self, record: &mut Record, offer: &mut HpOffer, set: &[lichen_contract::Presign]) -> Result<()> {
        let cid = record.cid();
        let p = self.hp_prepared(cid)?;
        let commit = p.commit.as_ref().context("no instances committed")?;
        let dealing = dealing_from_hex(&commit.dealing, (p.setup.n - p.setup.m) as usize)?;
        let msg = Countersigned::link_sighash(set, "challenge_assert")?;
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

/// A dispute's state at the hub, in play.
pub(crate) enum State {
    /// `request` confirmed at `at`; `done` once weighed (owed in full, or
    /// too late to correct).
    Requested(Box<HpDisputed>, u32, bool),
    /// `correct` confirmed at `at`: her `ack` is due within `w_A`, or
    /// `accept` pays `b_corr`.
    Corrected(Box<HpDisputed>, u32),
    /// `ack` confirmed at `at`: the statement is proved and asserted within
    /// `w_H`; `done` once asserted, or given up.
    Acked(Box<HpDisputed>, u32, bool),
    /// `assert` confirmed at `at`: her challenge is due within `Δ2`.
    Asserted(Box<HpDisputed>, u32),
    /// Challenged: the hub's answer is due within `Δ1` of `at`; `tried`
    /// once its kept instances were evaluated and none opened.
    Challenged(Box<HpDisputed>, u32, bool),
}

fn bb(s: State) -> Option<Outer> {
    Some(Outer::Hp(s))
}

/// What the hub holds against a claim: what it's owed, the cited spend,
/// the unlock.
pub(crate) struct Assessed {
    pub owed: u32,
    pub cited: Option<acc::Cited>,
    pub u: acc::Seed,
}

impl Inner {
    fn hp_terminal(&self, d: &HpDisputed, name: &str, wire: Vec<Vec<u8>>) -> Result<bitcoin::Txid> {
        let tx = d.finish(name, wire)?;
        self.chain.post_terminal(&tx, &d.set[name].prevout, lichen_proto::terminal_fee(&tx, self.cfg.network), &NodeWallet)
    }

    /// Alice's `b` and her signature on it, from `request`.
    pub(super) fn hp_claimed_b(&self, record: &Record) -> Result<(u32, Vec<Vec<u8>>)> {
        let d = HpDisputed::new(record, &self.cfg.statement)?;
        let req = self.chain.get_tx(&d.txid("request")).context("the request")?;
        let (b, _) = Countersigned::read_request(&link_args(&req))?;
        let v = u32::from_be_bytes(b.message().try_into().map_err(|_| anyhow::anyhow!("b's signature signs 4 bytes"))?);
        Ok((v, Countersigned::word_wire(&b)))
    }

    /// If Alice has requested, the dispute from where the chain shows it.
    pub(super) fn hp_start(&self, record: &Record) -> Result<Option<Outer>> {
        let d = HpDisputed::new(record, &self.cfg.statement)?;
        let Some(at) = confirmed_at(self, &d.txid("request"))? else { return Ok(None) };
        if let Some(a) = confirmed_at(self, &d.txid("assert"))? {
            return Ok(bb(State::Asserted(Box::new(d), a)));
        }
        if let Some(a) = confirmed_at(self, &d.txid("ack"))? {
            return Ok(bb(State::Acked(Box::new(d), a, false)));
        }
        if let Some(c) = confirmed_at(self, &d.txid("correct"))? {
            return Ok(bb(State::Corrected(Box::new(d), c)));
        }
        Ok(bb(State::Requested(Box::new(d), at, false)))
    }

    /// The link `name`'s output spent by other than `next`: a terminal (its
    /// payout) is out.
    fn ended(&self, d: &HpDisputed, name: &str, next: &str) -> Result<bool> {
        let op = OutPoint { txid: d.txid(name), vout: 0 };
        Ok(!self.chain.unspent(&op)? && self.chain.get_tx(&d.txid(next)).is_none())
    }

    /// One step of a dispute in play.
    pub(super) fn hp_tick(&self, record: &Record, s: State) -> Result<Option<Outer>> {
        let cid = record.cid();
        let collect = |link: bitcoin::Txid, corrected: bool| -> Result<Option<Outer>> { Ok(Some(Outer::Collect { link, since: self.chain.height()?, corrected })) };
        match s {
            State::Requested(d, at, done) => {
                if let Some(c) = confirmed_at(self, &d.txid("correct"))? {
                    return Ok(bb(State::Corrected(d, c)));
                }
                if self.ended(&d, "request", "correct")? {
                    self.note(format!("contract {cid}: request_timeout paid the user her claim"));
                    return collect(d.txid("request"), false);
                }
                if done {
                    return Ok(bb(State::Requested(d, at, true)));
                }
                let w = d.graph.spec.windows;
                let last_chance = at + u32::from(w.w_h) - (u32::from(w.w_h) / 4).max(2);
                if self.chain.height()? >= last_chance {
                    self.note_once(format!("contract {cid}: too late to correct the claim; request_timeout will pay the user"));
                    return Ok(bb(State::Requested(d, at, true)));
                }
                match self.grants_correct(&d)? {
                    None => Ok(bb(State::Requested(d, at, true))),
                    Some(c) => Ok(bb(State::Corrected(d, c))),
                }
            }
            State::Corrected(d, at) => {
                if let Some(a) = confirmed_at(self, &d.txid("ack"))? {
                    self.note(format!("contract {cid}: the user countersigned the correction (ack): the statement is due"));
                    return Ok(bb(State::Acked(d, a, false)));
                }
                if self.ended(&d, "correct", "ack")? {
                    self.note(format!("contract {cid}: accept paid the user b_corr"));
                    return collect(d.txid("correct"), true);
                }
                if self.chain.height()? >= at + u32::from(d.graph.spec.windows.w_a) {
                    let txid = self.hp_terminal(&d, "accept", vec![])?;
                    self.note(format!("contract {cid}: the user accepted the correction: accept {txid} pays her b_corr"));
                    return collect(d.txid("correct"), true);
                }
                Ok(bb(State::Corrected(d, at)))
            }
            State::Acked(d, at, done) => {
                if let Some(a) = confirmed_at(self, &d.txid("assert"))? {
                    return Ok(bb(State::Asserted(d, a)));
                }
                if self.ended(&d, "ack", "assert")? {
                    self.note(format!("contract {cid}: the hub never proved: ack_timeout paid the user her claim"));
                    return collect(d.txid("ack"), false);
                }
                if done {
                    return Ok(bb(State::Acked(d, at, true)));
                }
                let w = d.graph.spec.windows;
                let last_chance = at + u32::from(w.w_h) - (u32::from(w.w_h) / 4).max(2);
                if self.chain.height()? >= last_chance {
                    self.note_once(format!("contract {cid}: too late to assert; ack_timeout will pay the user"));
                    return Ok(bb(State::Acked(d, at, true)));
                }
                if self.abandon_corrections.load(std::sync::atomic::Ordering::Relaxed) {
                    self.note_once(format!("contract {cid}: abandoning the correction (tests): ack_timeout will pay the user"));
                    return Ok(bb(State::Acked(d, at, true)));
                }
                let done = self.grants_assert(&d)?;
                Ok(bb(State::Acked(d, at, done)))
            }
            State::Asserted(d, at) => {
                if let Some(c) = confirmed_at(self, &d.txid("challenge_assert"))? {
                    return Ok(bb(State::Challenged(d, c, false)));
                }
                if self.ended(&d, "assert", "challenge_assert")? {
                    return collect(d.txid("assert"), true);
                }
                if self.chain.height()? >= at + u32::from(d.graph.spec.windows.delta2) {
                    let txid = self.hp_terminal(&d, "success", vec![])?;
                    self.note(format!("contract {cid}: no challenge to the assertion; success {txid} pays the user b_corr"));
                    return collect(d.txid("assert"), true);
                }
                Ok(bb(State::Asserted(d, at)))
            }
            State::Challenged(d, at, tried) => {
                let c_op = OutPoint { txid: d.txid("challenge_assert"), vout: 0 };
                if !self.chain.unspent(&c_op)? {
                    if self.chain.get_tx(&d.txid("failure")).is_some() {
                        self.note(format!("contract {cid}: no answer to the user's challenge: failure paid her"));
                        return collect(c_op.txid, false);
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

    /// What the hub holds against a claim `q` of `b` units on contract
    /// `record` (by the statement's own count), from the evidence the book
    /// gives: the cited spend and its seed.
    pub(crate) fn assess(&self, record: &Record, b: u32, q: Option<&acc::Claim>, ev: Option<lichen_notes::book::Evidence>) -> Assessed {
        let k = record.hp();
        let (cited, u) = match ev {
            Some(e) => (Some(e.cited), e.seed),
            None => (None, [0; acc::U_LEN]),
        };
        let owed = acc::owed(q, b, &record.l2_address, &k.issuer, record.terms.unit.to_sat(), k.v0, cited.as_ref(), &u);
        // a citation that doesn't lower the claim isn't posted
        let plain = acc::owed(q, b, &record.l2_address, &k.issuer, record.terms.unit.to_sat(), k.v0, None, &[0; acc::U_LEN]);
        if owed < plain {
            Assessed { owed, cited, u }
        } else {
            Assessed { owed: plain, cited: None, u: [0; acc::U_LEN] }
        }
    }

    /// The hub's answer to a request: the claim taken into the book (the
    /// account closed) and weighed; owed in full, nothing (`request_timeout`
    /// pays her, None); otherwise `correct`, signing `b_corr` and `U`.
    /// `correct`'s confirmation height.
    fn grants_correct(&self, d: &HpDisputed) -> Result<Option<u32>> {
        let record = &d.record;
        let cid = record.cid();
        let req = self.chain.get_tx(&d.txid("request")).context("the request")?;
        let (b, q, _, _) = HpDisputed::requested(&req)?;
        let q = acc::Claim::from_bytes(&q);
        let ev = match &q {
            Some(c) => self.book.take_claim(cid, &record.l2_address, c)?,
            None => None,
        };
        let a = self.assess(record, b, q.as_ref(), ev);
        // a lying hub (tests) corrects a claim to nothing
        let forge = self.forge_assertions.load(std::sync::atomic::Ordering::Relaxed);
        let (b_corr, u) = if forge { (0, [0; acc::U_LEN]) } else { (a.owed, a.u) };
        self.note(format!("contract {cid}: the user's exit claim of {b} units taken into the book"));
        if b_corr == b {
            self.note(format!("contract {cid}: the claim is owed in full: request_timeout pays her"));
            return Ok(None);
        }
        self.note(format!("contract {cid}: the claim of {b} units is owed {b_corr}{}: correcting it", match (&q, &a.cited) {
            (None, _) => " (malformed)",
            (_, Some(_)) => " (her last step cited, its seed in U)",
            _ => "",
        }));
        let wire = Countersigned::correct_wire(&hub_corr(&self.cfg.seed, cid).sign(&b_corr.to_be_bytes())?, &hub_u(&self.cfg.seed, cid).sign(&u)?)?;
        let tx = d.finish("correct", wire)?;
        let at = self.post(cid, &tx)?;
        self.note(format!("contract {cid}: corrected to {b_corr} units ({} vB)", tx.vsize()));
        Ok(Some(at))
    }

    /// The statement's input for an acked dispute: the contract, her four
    /// signatures from `request` and `ack`, the spend `correct` cited.
    fn grants_input(&self, d: &HpDisputed) -> Result<acc::Input> {
        let record = &d.record;
        let req = self.chain.get_tx(&d.txid("request")).context("the request")?;
        let (_, q, q_sig, b_sig) = HpDisputed::requested(&req)?;
        let ack = self.chain.get_tx(&d.txid("ack")).context("the ack")?;
        let (c_sig, u_sig) = HpDisputed::acked(&ack)?;
        let correct = self.chain.get_tx(&d.txid("correct")).context("correct")?;
        let (_, u) = HpDisputed::corrected(&correct)?;
        let cited = match acc::Claim::from_bytes(&q) {
            Some(c) if u != [0; acc::U_LEN] => self.book.evidence(&record.l2_address, c.k).filter(|e| e.seed == u).map(|e| e.cited),
            _ => None,
        };
        Ok(acc::Input { contract: record.hp_contract(), sigs: [q_sig, b_sig, c_sig, u_sig], cited })
    }

    /// Prove the statement for an acked dispute and assert it: checked
    /// natively, then proved. A lying hub (tests) asserts a forged proof.
    /// Whether done.
    fn grants_assert(&self, d: &HpDisputed) -> Result<bool> {
        let record = &d.record;
        let cid = record.cid();
        let proof = if self.forge_assertions.load(std::sync::atomic::Ordering::Relaxed) {
            self.note(format!("contract {cid}: asserting a forged proof against the claim"));
            let mut other = record.hp_journal();
            other[0] ^= 1;
            lichen_babe::statement::mock_prove(&other)
        } else {
            let input = self.grants_input(d)?;
            let journal = match acc::check(&input) {
                Ok(j) => j,
                Err(e) => {
                    self.note(format!("contract {cid}: the statement doesn't hold ({e:?}): no assertion; ack_timeout will pay the user"));
                    return Ok(true);
                }
            };
            ensure!(journal == record.hp_journal(), "the statement's journal isn't the contract's");
            match self.cfg.statement.hp_kind()? {
                lichen_babe::statement::Kind::Mock => {
                    // for the guest's tests: the statement's input, as the prover takes it
                    if let Ok(dir) = std::env::var("LICHEN_DUMP_HP") {
                        let _ = std::fs::write(std::path::Path::new(&dir).join(format!("grants-{cid}.bin")), input.to_bytes());
                    }
                    lichen_babe::statement::mock_prove(&journal)
                }
                lichen_babe::statement::Kind::Risc0 => match self.hp_proof(cid, &input, &journal)? {
                    Some(p) => p,
                    None => return Ok(false),
                },
            }
        };
        let bits = lichen_babe::gadget::input(&proof.a);
        let (pi2, pi3) = lichen_babe::statement::pi23_to_bytes(&proof);
        let wire = Countersigned::assert_wire(&hub_lamport(&self.cfg.seed, cid).sign(&digits(&bits)), &pi2, &pi3);
        let tx = d.finish("assert", wire)?;
        self.post(cid, &tx)?;
        self.note(format!("contract {cid}: asserted ({} vB)", tx.vsize()));
        Ok(true)
    }

    /// The proof of the hub's statement for contract `cid` (RISC Zero's,
    /// wrapped in Groth16), once proved, from `input`: the prover runs in
    /// the background (`r0/hp-prover.sh hp-proof`; LICHEN_HP_PROVER names
    /// another), one a contract, its files in `hp/<cid>/`. None while it
    /// proves; a failed prover is run again.
    fn hp_proof(&self, cid: u32, input: &acc::Input, journal: &[u8]) -> Result<Option<ark_groth16::Proof<ark_bn254::Bn254>>> {
        let dir = self.hp_dir(cid);
        let seal = dir.join("proof.seal");
        if seal.exists() {
            let p = lichen_babe::risc0::proof_from_seal(&std::fs::read(&seal)?).context("the prover's seal")?;
            ensure!(lichen_babe::statement::Kind::Risc0.verify(journal, &p), "the prover's proof doesn't verify for this contract");
            self.note_once(format!("contract {cid}: the correction proved; asserting"));
            return Ok(Some(p));
        }
        if !self.proving.lock().unwrap().insert(cid) {
            return Ok(None);
        }
        std::fs::create_dir_all(&dir)?;
        let in_path = dir.join("input.bin");
        std::fs::write(&in_path, input.to_bytes())?;
        let prover = std::env::var("LICHEN_HP_PROVER").unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../r0/hp-prover.sh").to_string());
        let log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("prover.log"))?;
        let tmp = dir.join("proof.seal.tmp");
        let mut cmd = std::process::Command::new(&prover);
        cmd.arg("hp-proof").arg(&in_path).arg(&tmp).stdout(log.try_clone()?).stderr(log);
        self.note(format!("contract {cid}: proving the correction ({prover}, hp/{cid}/prover.log)"));
        let proving = self.proving.clone();
        std::thread::spawn(move || {
            let ok = cmd.status().is_ok_and(|s| s.success()) && std::fs::rename(&tmp, &seal).is_ok();
            if !ok {
                eprintln!("hub: contract {cid}: the prover failed (hp/{cid}/prover.log); trying again");
            }
            proving.lock().unwrap().remove(&cid);
        });
        Ok(None)
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
                return self.hp_terminal(d, &format!("wrongly_challenged_{k}"), Countersigned::wrongly_wire(&msg)).map(Some);
            }
        }
        Ok(None)
    }
}

impl State {
    pub(crate) fn describe(&self) -> String {
        match self {
            State::Requested(_, _, false) => "requested: the hub weighs the claim".into(),
            State::Requested(_, _, true) => "requested: owed in full, request_timeout pays the user".into(),
            State::Corrected(..) => "corrected: the user accepts or countersigns".into(),
            State::Acked(_, _, false) => "acked: the hub's statement is due".into(),
            State::Acked(_, _, true) => "acked: asserted, or left to ack_timeout".into(),
            State::Asserted(..) => "asserted: the user's challenge is due".into(),
            State::Challenged(..) => "challenged: the hub's answer is due".into(),
        }
    }
}

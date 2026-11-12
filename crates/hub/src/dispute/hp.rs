//! The hub's side of a hub-proves contract (docs/HUB_PROVES_PLAN.md,
//! `lichen_proto::hp`): its setup, in which Alice garbles and the hub
//! keeps her instances, and its dispute ([`super`] drives it).
//!
//! On the grants L2 (milestone 1, docs/GRANTS_PLAN.md): when `request`
//! confirms, the hub takes the claim it posts into its book (its notes
//! spent, the change beyond `b` issued back to the owner) and lets
//! `request_timeout` pay her. It doesn't contest a claim yet: the
//! statement "she is owed at most `b_corr`" comes in milestone 2. A test's
//! lying hub still asserts a forged proof, and answers a challenge with a
//! kept instance if one opens.
//!
//! Its keys as the prover (a Lamport key for π1, adaptor keys) derive from
//! its seed. Of the setup it keeps `hp/<cid>.json` (the setup, her
//! commitment, the instances kept and their hashlocks, the opened ones'
//! shares) and the kept instances, `hp/<cid>/instance-<i>.bin`.

use anyhow::{ensure, Context, Result};
use bitcoin::OutPoint;
use lichen_babe::garble::evaluate;
use lichen_babe::hp::HubProves;
use lichen_babe::reveal::{extract, AdaptorKeys, LamportKey};
use lichen_babe::setup::{check_opened, choose, digits, par, Hash, Instance, Secret, DIGITS, VALUES};
use lichen_babe::vsss::interpolate;
use lichen_babe::we::decrypt;
use lichen_chain::NodeWallet;
use lichen_proto::setup::{dealing_from_hex, link_args, shares_from_hex, Opened};
use lichen_proto::hp::{check_commit, HpCommit, HpDisputed, HpKept, HpKeys, HpOffer, HpRequest, HpSetup, HpSetupRequest};
use lichen_proto::{Checkpoint, Presig, Record};
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

/// The hub's one-time key for `b_corr` in contract `cid` (`correct`).
pub(crate) fn hub_bc(seed: &str, cid: u32) -> lngap_lamport::winternitz::WotsSecret {
    lngap_lamport::winternitz::WotsSecret::from_entropy(lngap_lamport::winternitz::WotsParams::for_bytes(4), contract_seed(seed, cid).derive_bytes("hp/bc"))
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
        let d = lichen_proto::contract_word(&self.deployment, setup.checkpoint.as_ref(), bitcoin::Amount::from_sat(setup.unit))?;
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
        self.check_deposit(cid, &req.deposit)?;
        let (n, m) = cut_and_choose(self.cfg.network);
        let setup = HpSetup {
            cid,
            n,
            m,
            margin: lichen_proto::hp::margin(self.cfg.network),
            // the work the statement asks on request's block: ten blocks'
            // at this difficulty
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
            bc_key: hub_bc(&self.cfg.seed, cid).public(),
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
        Ok((keys, HpOffer { hp_windows: windows, hp_presigs: vec![], bc_key: hub_bc(&self.cfg.seed, cid).public() }, s.checkpoint))
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
                if !recorded {
                    self.grants_take_exit(&d)?;
                }
                let w = d.graph.spec.windows;
                // the assertion must confirm before her timeout
                let last_chance = at + u32::from(w.w_h) - (u32::from(w.w_h) / 4).max(2);
                if self.chain.height()? >= last_chance {
                    self.note_once(format!("contract {cid}: too late to assert; request_timeout will pay the user"));
                    return Ok(bb(State::Requested(d, at, true)));
                }
                // for tests: a lying hub asserts against a claim that holds
                if self.forge_assertions.load(std::sync::atomic::Ordering::Relaxed) {
                    self.hp_assert(&d)?;
                }
                Ok(bb(State::Requested(d, at, true)))
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

    /// The claim `request` posts, taken into the book: checked against the
    /// contract and the `b` and `E` she signed, its notes spent, the change
    /// beyond `b` issued back to her. A claim that doesn't hold is noted,
    /// not contested (milestone 2's statement will): `request_timeout`
    /// pays her `b` all the same.
    fn grants_take_exit(&self, d: &HpDisputed) -> Result<()> {
        let record = &d.record;
        let cid = record.cid();
        let req = self.chain.get_tx(&d.txid("request")).context("the request")?;
        let (b, e, posted) = HubProves::read_request(&link_args(&req))?;
        let b = u32::from_be_bytes(b.message().try_into().map_err(|_| anyhow::anyhow!("b's signature signs 4 bytes"))?);
        let e: [u8; 32] = e.message().try_into().map_err(|_| anyhow::anyhow!("E's signature signs 32 bytes"))?;
        let taken = (|| -> Result<u64> {
            let claim = lichen_notes::Claim::from_bytes(&posted)?;
            ensure!(claim.e() == e && claim.b == b, "the claim posted isn't the one signed (its E or b)");
            let unit = record.terms.unit.to_sat();
            let total = claim.check(&self.book.issuer(), cid, &record.hp().deposit, &record.l2_address, unit)?;
            self.book.take_claim(&claim, total, u64::from(b) * unit)?;
            Ok(total)
        })();
        match taken {
            Ok(total) => self.note(format!("contract {cid}: the user's exit claims {b} units ({total} sats of notes): taken into the book; request_timeout pays her")),
            Err(e) => self.note(format!("contract {cid}: the user's exit claim doesn't hold ({e:#}); not contested in milestone 1: request_timeout pays her")),
        }
        Ok(())
    }

    /// For tests, a lying hub: a forged proof asserted against the claim
    /// (a proof of another contract's statement).
    fn hp_assert(&self, d: &HpDisputed) -> Result<()> {
        let record = &d.record;
        let cid = record.cid();
        self.note(format!("contract {cid}: asserting a forged proof against the claim"));
        let proof = lichen_babe::statement::mock_prove(&lichen_proto::hp::journal(cid + 1, &record.deployment, &record.hp().deposit, record.hp().margin));
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
                return self.hp_terminal(d, &format!("wrongly_challenged_{k}"), HubProves::wrongly_wire(&msg)).map(Some);
            }
        }
        Ok(None)
    }
}

impl State {
    pub(crate) fn describe(&self) -> String {
        match self {
            State::Requested(_, _, false) => "requested: the hub takes the claim".into(),
            State::Requested(_, _, true) => "requested: the claim taken, request_timeout pays the user".into(),
            State::Asserted(..) => "asserted: the user's challenge is due".into(),
            State::Challenged(..) => "challenged: the hub's answer is due".into(),
        }
    }
}

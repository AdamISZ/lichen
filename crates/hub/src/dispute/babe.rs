//! The hub's side of a BABE contract: its setup (the dealing and the
//! instances Alice cuts and chooses from), and its dispute ([`super`]
//! drives it, one step per tick).
//!
//! Everything the hub needs of a contract derives from its seed: the
//! dealing, each instance's seed, its key for `b`. So it keeps only what
//! the setup committed to (`babe/<cid>.json`: the checkpoint, the
//! instances' hashes and hashlocks), and after a restart reads a dispute
//! again from the chain.
//!
//! When `request` confirms, the hub signs Alice's `b` in `respond` (an
//! honest hub always does: its signature is what the proof needs). When
//! `assert` confirms, it rebuilds her proof from the chain (π1 from the
//! digits she signed, π2 and π3 beside them) and checks it: a valid one it
//! lets stand (`success` pays her after `Δ2`); otherwise it challenges,
//! revealing π1's secrets by completing her pre-signatures, and takes
//! `failure` after `Δ1` unless she answers with a kept instance's `msg`.
//! If she never asserts, `respond_timeout` from `T_A` is its.

use anyhow::{ensure, Context, Result};
use bitcoin::OutPoint;
use lichen_babe::reveal::{complete, reveal_args};
use lichen_babe::setup::{instance, par, Hash, Instance, DIGITS};
use lichen_babe::vsss::{deal, Dealer, Dealing};
use lichen_chain::NodeWallet;
use lichen_proto::babe::{babe_journal, check_request, dealing_to_hex, shares_to_hex, BabeOffer, BabeRequest, Disputed, Opened, Setup, SetupRequest};
use lichen_proto::{BabeKeys, Checkpoint, DisputeKeys, OfferKeys, Record};
use lngap_btc::adaptor::AdaptorSig;
use lngap_btc::keys::Seed;
use lngap_lamport::winternitz::{Wots256Secret, WotsParams};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};

use super::{confirmed_at, State as Outer};
use crate::Inner;

/// The cut-and-choose on a network: `N` instances, `M` kept. BABE's
/// smallest point with secret sharing, (78, 10); regtest's tests keep 2
/// of 4.
pub fn cut_and_choose(net: lichen_proto::Net) -> (u32, u32) {
    match net {
        lichen_proto::Net::Regtest => (4, 2),
        _ => (78, 10),
    }
}

fn contract_seed(seed: &str, cid: u32) -> Seed {
    Seed::from_label(&format!("{seed}/contract/{cid}/babe"))
}

/// The hub's one-time key for `b` in contract `cid` (`pk_H`).
pub fn hub_b(seed: &str, cid: u32) -> Wots256Secret {
    Wots256Secret::from_entropy(WotsParams::for_bytes(4), contract_seed(seed, cid).derive_bytes("b"))
}

/// The dealing of contract `cid`'s input secrets, of degree `N - M`.
fn dealing(seed: &str, cid: u32, n: u32, m: u32) -> (Dealer, Dealing) {
    deal(DIGITS, (n - m) as usize, &mut ChaCha20Rng::from_seed(contract_seed(seed, cid).derive_bytes("dealing")))
}

/// Instance `i`'s seed (from 1).
fn instance_seed(seed: &str, cid: u32, i: u32) -> [u8; 32] {
    contract_seed(seed, cid).derive_bytes(&format!("instance/{i}"))
}

/// What the hub keeps of a setup until the contract opens on it, and
/// after.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Prepared {
    pub(crate) setup: Setup,
    /// Every instance's hashlock.
    pub(crate) hmsg: Vec<Hash>,
}

impl Inner {
    fn babe_kind(&self) -> Result<lichen_babe::statement::Kind> {
        self.cfg.statement.babe_kind().context("the hub's statement isn't BABE's")
    }
    fn prepared_path(&self, cid: u32) -> std::path::PathBuf {
        self.cfg.dir.join("babe").join(format!("{cid}.json"))
    }
    /// Contract `cid`'s setup, made before.
    pub(crate) fn prepared(&self, cid: u32) -> Result<Prepared> {
        if let Some(p) = self.babe.lock().unwrap().get(&cid) {
            return Ok(p.clone());
        }
        let p: Prepared = serde_json::from_slice(&std::fs::read(self.prepared_path(cid)).with_context(|| format!("no setup for contract {cid}"))?)?;
        self.babe.lock().unwrap().insert(cid, p.clone());
        Ok(p)
    }
    /// The journal of contract `cid` under `checkpoint`.
    fn journal_of(&self, cid: u32, checkpoint: Option<&Checkpoint>) -> Result<[u8; lichen_withdraw::fixed::JOURNAL_LEN]> {
        let d = lichen_proto::contract_word(&self.seq.deployment, checkpoint)?;
        Ok(babe_journal(cid, &d, &hub_b(&self.cfg.seed, cid).public()))
    }
    /// Instance `i` of contract `cid` (from 1), built again from its seed.
    fn build_instance(&self, setup: &Setup, dealer: &Dealer, i: u32) -> Result<Instance> {
        let kind = self.babe_kind()?;
        let journal = self.journal_of(setup.cid, setup.checkpoint.as_ref())?;
        Ok(instance(&instance_seed(&self.cfg.seed, setup.cid, i), &dealer.shares(u64::from(i)), &kind.verifying_key(), &kind.public_inputs(&journal)).0)
    }

    /// The setup for contract `cid` (`POST /babe/setup`): the statement
    /// fixed (its checkpoint now, in an anchored deployment), the input
    /// secrets dealt, `N` instances built and committed. Asked again, the
    /// same.
    pub(crate) fn babe_setup(&self, req: SetupRequest) -> Result<Setup> {
        let cid = req.cid;
        ensure!(self.deposits.lock().unwrap().contains_key(&cid), "no deposit asked for contract {cid}");
        if let Ok(p) = self.prepared(cid) {
            return Ok(p.setup);
        }
        let (n, m) = cut_and_choose(self.cfg.network);
        let checkpoint = match self.seq.deployment.seal {
            Some(_) => Some(Checkpoint::tip(&self.chain)?),
            None => None,
        };
        let (dealer, dealing) = dealing(&self.cfg.seed, cid, n, m);
        let kind = self.babe_kind()?;
        let journal = self.journal_of(cid, checkpoint.as_ref())?;
        let (vk, public) = (kind.verifying_key(), kind.public_inputs(&journal));
        let start = std::time::Instant::now();
        let made = par(n as usize, |k| {
            let i = k as u32 + 1;
            let (inst, _) = instance(&instance_seed(&self.cfg.seed, cid, i), &dealer.shares(u64::from(i)), &vk, &public);
            (inst.commitment(), inst.hmsg)
        });
        self.note(format!("contract {cid}: BABE's setup: {n} instances built in {:.1?}", start.elapsed()));
        let setup = Setup { cid, n, m, checkpoint, hub_b: hub_b(&self.cfg.seed, cid).public(), commitments: made.iter().map(|c| hex::encode(c.0)).collect(), dealing: dealing_to_hex(&dealing) };
        let p = Prepared { setup: setup.clone(), hmsg: made.iter().map(|c| c.1).collect() };
        std::fs::create_dir_all(self.cfg.dir.join("babe"))?;
        lichen_ledger::files::write_atomic(&self.prepared_path(cid), &serde_json::to_vec(&p)?)?;
        self.babe.lock().unwrap().insert(cid, p);
        Ok(setup)
    }

    /// Instance `i` of contract `cid`'s setup, as bytes (`GET
    /// /babe/instance/<cid>/<i>`).
    pub(crate) fn babe_instance(&self, cid: u32, i: u32) -> Result<Vec<u8>> {
        let p = self.prepared(cid)?;
        ensure!((1..=p.setup.n).contains(&i), "no instance {i} of {}", p.setup.n);
        let (dealer, _) = dealing(&self.cfg.seed, cid, p.setup.n, p.setup.m);
        Ok(self.build_instance(&p.setup, &dealer, i)?.to_bytes())
    }

        /// The instance a URL `/babe/instance/<cid>/<i>` names.
    pub(crate) fn babe_instance_at(&self, url: &str) -> Result<Vec<u8>> {
        let (cid, i) = url["/babe/instance/".len()..].split_once('/').context("/babe/instance/<cid>/<i>")?;
        self.babe_instance(cid.parse()?, i.parse()?)
    }

    /// A BABE contract's keys, from Alice's request (checked against the
    /// setup) and the hub's own: the record's, and the offer's, with the
    /// instances she doesn't keep opened.
    pub(crate) fn babe_open_keys(&self, cid: u32, req: &BabeRequest, t_close: u32) -> Result<(DisputeKeys, OfferKeys, Option<Checkpoint>)> {
        let p = self.prepared(cid)?;
        let Setup { n, m, .. } = p.setup;
        check_request(req, n, m)?;
        let windows = lichen_proto::babe::windows(self.cfg.network, t_close);
        let hmsg: Vec<Hash> = req.kept.iter().map(|i| p.hmsg[*i as usize - 1]).collect();
        let (dealer, _) = dealing(&self.cfg.seed, cid, n, m);
        let opened = (1..=n).filter(|i| !req.kept.contains(i)).map(|i| Opened { i, seed: hex::encode(instance_seed(&self.cfg.seed, cid, i)), shares: shares_to_hex(&dealer.shares(u64::from(i))) }).collect();
        let keys = BabeKeys { b_key: req.b_key.clone(), hub_b: p.setup.hub_b.clone(), lamport: req.lamport.clone(), adaptor: req.adaptor.clone(), n, kept: req.kept.clone(), hmsg: hmsg.clone(), windows, presigs: vec![] };
        Ok((DisputeKeys::Babe(Box::new(keys)), OfferKeys::Babe(Box::new(BabeOffer { windows, hmsg, opened })), p.setup.checkpoint))
    }

    /// Alice's adaptor pre-signatures on `challenge_assert`, checked
    /// against the dealing's points, into the record.
    pub(crate) fn babe_accept(&self, record: &mut Record, presigs: &[[lichen_proto::Presig; 4]]) -> Result<()> {
        let built = self.built(record)?;
        let set = built.presign(record.funding)?;
        let msg = lichen_babe::graph::Babe::challenge_sighash(&set)?;
        let p = self.prepared(record.cid())?;
        let (_, dealing) = dealing(&self.cfg.seed, record.cid(), p.setup.n, p.setup.m);
        let ads: Vec<[AdaptorSig; 4]> = presigs.iter().map(|s| s.each_ref().map(AdaptorSig::from)).collect();
        let keys = record.babe()?;
        ensure!(lichen_babe::reveal::check_presigs(&keys.adaptor, &msg, &lichen_babe::reveal::points(&dealing), &ads), "Alice's adaptor pre-signatures on challenge_assert");
        let DisputeKeys::Babe(k) = &mut record.dispute else { unreachable!("checked") };
        k.presigs = presigs.to_vec();
        Ok(())
    }
}

/// A BABE dispute's state at the hub, in play.
pub(crate) enum State {
    /// `respond` posted: Alice's `assert` is due before `T_A`.
    Responded(Box<Disputed>),
    /// Her proof is valid: `success` pays her after `Δ2`.
    Conceded(Box<Disputed>),
    /// Challenged (confirmed at `at`): her answer is due within `Δ1`.
    Challenged(Box<Disputed>, u32),
}

fn bb(s: State) -> Option<Outer> {
    Some(Outer::Babe(s))
}

impl Inner {
    /// Post the pre-signed terminal `name`, its fee paid by a coin of the
    /// hub's wallet.
    fn babe_terminal(&self, d: &Disputed, name: &str) -> Result<bitcoin::Txid> {
        let tx = d.finish(name, vec![])?;
        self.chain.post_terminal(&tx, &d.set[name].prevout, lichen_proto::terminal_fee(&tx, self.cfg.network), &NodeWallet)
    }

    /// Whether the contract was disputed (`request` posted).
    pub(super) fn babe_requested(&self, record: &Record) -> Result<bool> {
        let d = Disputed::new(record, &self.cfg.statement)?;
        Ok(self.chain.get_tx(&d.txid("request")).is_some())
    }

    /// Alice's `b` and her signature on it, from `request`.
    pub(super) fn babe_claimed_b(&self, record: &Record) -> Result<(u32, Vec<Vec<u8>>)> {
        let d = Disputed::new(record, &self.cfg.statement)?;
        let req = self.chain.get_tx(&d.txid("request")).context("the request")?;
        let sig = Disputed::alice_b(&req)?;
        let b = u32::from_be_bytes(sig.message().try_into().map_err(|_| anyhow::anyhow!("b's signature signs 4 bytes"))?);
        Ok((b, lngap_ladder::script::wots_wire(&sig)))
    }

    /// If Alice has requested, respond: sign her `b`.
    pub(super) fn babe_start(&self, record: &Record) -> Result<Option<Outer>> {
        let cid = record.cid();
        let d = Disputed::new(record, &self.cfg.statement)?;
        let req_id = d.txid("request");
        if confirmed_at(self, &req_id)?.is_none() {
            return Ok(None);
        }
        let r_op = OutPoint { txid: req_id, vout: 0 };
        if self.chain.get_tx(&d.txid("respond")).is_none() && !self.chain.unspent(&r_op)? {
            self.note(format!("contract {cid}: the user's request timed out; she is paid her claim"));
            return Ok(Some(Outer::Collect { link: req_id, since: self.chain.height()? }));
        }
        let req = self.chain.get_tx(&req_id).context("the request")?;
        let alice_b = Disputed::alice_b(&req)?;
        let b = u32::from_be_bytes(alice_b.message().try_into().map_err(|_| anyhow::anyhow!("b's signature signs 4 bytes"))?);
        let ours = hub_b(&self.cfg.seed, cid).sign(&b.to_be_bytes())?;
        // (once: a dispute read again from the chain finds it posted)
        if self.chain.get_tx(&d.txid("respond")).is_none() {
            self.note(format!("contract {cid}: the user requests {b} sats: responding"));
        }
        self.post(cid, &d.finish("respond", lichen_babe::graph::Babe::respond_wire(&ours, &alice_b))?)?;
        Ok(bb(State::Responded(Box::new(d))))
    }

    /// One step of a BABE dispute in play.
    pub(super) fn babe_tick(&self, record: &Record, s: State) -> Result<Option<Outer>> {
        let cid = record.cid();
        match s {
            State::Responded(d) => {
                let s_op = OutPoint { txid: d.txid("respond"), vout: 0 };
                let assert_id = d.txid("assert");
                if confirmed_at(self, &assert_id)?.is_some() {
                    return self.babe_judge(cid, *d);
                }
                if !self.chain.unspent(&s_op)? && self.chain.get_tx(&assert_id).is_none() {
                    self.note(format!("contract {cid}: already settled by respond_timeout"));
                    self.close_settled(cid, s_op.txid)?;
                    return Ok(Some(Outer::Done));
                }
                if self.chain.height()? >= d.babe.spec.windows.t_a && self.chain.get_tx(&assert_id).is_none() {
                    let txid = self.babe_terminal(&d, "respond_timeout")?;
                    self.note(format!("contract {cid}: the user never asserted by T_A; respond_timeout {txid}"));
                    self.close(cid, txid)?;
                    return Ok(Some(Outer::Done));
                }
                Ok(bb(State::Responded(d)))
            }
            State::Conceded(d) => {
                let a_op = OutPoint { txid: d.txid("assert"), vout: 0 };
                if !self.chain.unspent(&a_op)? {
                    self.note(format!("contract {cid}: settled: success paid the user"));
                    return Ok(Some(Outer::Collect { link: a_op.txid, since: self.chain.height()? }));
                }
                Ok(bb(State::Conceded(d)))
            }
            State::Challenged(d, at) => {
                let c_op = OutPoint { txid: d.txid("challenge_assert"), vout: 0 };
                if !self.chain.unspent(&c_op)? {
                    if self.chain.get_tx(&d.txid("failure")).is_some() {
                        self.close_settled(cid, d.txid("failure"))?;
                        return Ok(Some(Outer::Done));
                    }
                    self.note(format!("contract {cid}: the user answered the challenge with a kept instance's msg: she is paid"));
                    return Ok(Some(Outer::Collect { link: c_op.txid, since: self.chain.height()? }));
                }
                if self.chain.height()? >= at + u32::from(d.babe.spec.windows.delta1) {
                    let txid = self.babe_terminal(&d, "failure")?;
                    self.note(format!("contract {cid}: no answer to the challenge; failure {txid}"));
                    self.close(cid, txid)?;
                    return Ok(Some(Outer::Done));
                }
                Ok(bb(State::Challenged(d, at)))
            }
        }
    }

    /// `assert` confirmed: check her proof from the chain; challenge a
    /// false one (or, misbehaving, a true one).
    fn babe_judge(&self, cid: u32, d: Disputed) -> Result<Option<Outer>> {
        let challenge_id = d.txid("challenge_assert");
        if let Some(at) = confirmed_at(self, &challenge_id)? {
            return Ok(bb(State::Challenged(Box::new(d), at)));
        }
        let a_op = OutPoint { txid: d.txid("assert"), vout: 0 };
        if !self.chain.unspent(&a_op)? {
            self.note(format!("contract {cid}: settled: success paid the user"));
            return Ok(Some(Outer::Collect { link: a_op.txid, since: self.chain.height()? }));
        }
        let asserted = d.asserted(&self.chain.get_tx(&a_op.txid).context("the assertion")?)?;
        let journal = d.record.babe_journal()?;
        let valid = asserted.proof.as_ref().is_some_and(|p| self.babe_kind().is_ok_and(|k| k.verify(&journal, p)));
        let dispute_true = self.dispute_true_claims.load(std::sync::atomic::Ordering::Relaxed);
        if valid && !dispute_true {
            self.note(format!("contract {cid}: the user's proof is valid; success will pay her"));
            return Ok(bb(State::Conceded(Box::new(d))));
        }
        self.note(format!("contract {cid}: {}: challenging", if valid { "the user's proof is valid, but the hub disputes true claims" } else { "the user's proof is not valid" }));
        let p = self.prepared(cid)?;
        let (dealer, _) = dealing(&self.cfg.seed, cid, p.setup.n, p.setup.m);
        let secrets: Vec<_> = asserted.digits.iter().enumerate().map(|(j, v)| dealer.reveal(j, *v)).collect();
        let presigs: Vec<[AdaptorSig; 4]> = d.record.babe()?.presigs.iter().map(|s| s.each_ref().map(AdaptorSig::from)).collect();
        let sigs = complete(&presigs, &asserted.digits, &secrets);
        let tx = d.finish("challenge_assert", lichen_babe::graph::Babe::challenge_wire(reveal_args(&asserted.preimages, &sigs)))?;
        let at = self.post(cid, &tx)?;
        self.note(format!("contract {cid}: challenged ({} vB)", tx.vsize()));
        Ok(bb(State::Challenged(Box::new(d), at)))
    }
}

impl State {
    pub(crate) fn describe(&self) -> String {
        match self {
            State::Responded(_) => "responded: the user's assertion is due".into(),
            State::Conceded(_) => "the user's proof is valid: success pays her".into(),
            State::Challenged(..) => "challenged: the user's answer is due".into(),
        }
    }
}

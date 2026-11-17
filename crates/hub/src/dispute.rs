//! The hub's side of a dispute, run by its watcher, one step per tick: the
//! L2's front ([`HubL2::front_tick`]), then BABE's tail. When the front is
//! done the hub proves its statement (the L2 gives the input; the prover
//! is the L2's, or the mock) and asserts before the front's last window
//! ends; she may challenge it, revealing π1's input secrets, and the hub
//! answers with a kept instance's `msg`. Whichever terminal pays out, the
//! hub collects its bit outputs of the payout ([`HubL2::collect`]) and
//! closes.
//!
//! Nothing of a dispute is kept but the contract: after a restart the hub
//! reads it again from the chain.

use anyhow::{ensure, Context, Result};
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxOut, Txid};
use lichen_babe::garble::evaluate;
use lichen_babe::graph::Graph;
use lichen_babe::reveal::extract;
use lichen_babe::setup::{digits, Instance, Secret};
use lichen_babe::vsss::interpolate;
use lichen_babe::we::decrypt;
use lichen_btc::adaptor::AdaptorSig;
use lichen_btc::sighash::sign_tapscript;
use lichen_btc::taptree::TapTree;
use lichen_btc::witness::tapscript_witness;
use lichen_chain::{Chain, NodeWallet};
use lichen_contract::PartyKeys;
use lichen_proto::hp::Disputed;
use lichen_proto::setup::{link_args, shares_from_hex};
use lichen_proto::{anchor_vout, sign_anchor, Built, Record};

use crate::l2::{Bits, Ctx, FrontStep, ProverInput};
use crate::setup::hub_lamport;
use crate::{contract_keys, Config, HubL2, Inner};

/// A dispute's state at the hub.
pub(crate) enum State<F> {
    /// In the L2's front.
    Front(Box<Disputed>, F),
    /// The front done at `at`: the hub proves and asserts before its last
    /// window ends; `done` once asserted, or given up.
    Proving(Box<Disputed>, u32, bool),
    /// `assert` confirmed at `at`: her challenge is due within `Δ2`.
    Asserted(Box<Disputed>, u32),
    /// Challenged: the hub's answer is due within `Δ1` of `at`; `tried`
    /// once its kept instances were evaluated and none opened.
    Challenged(Box<Disputed>, u32, bool),
    /// A payout is posted (`terminal`), spending link `link`'s output
    /// (first seen spent at `since`): the hub collects its bit outputs,
    /// then closes.
    Collect { d: Box<Disputed>, link: Txid, terminal: String, since: u32 },
    Done,
}

/// The height `txid` confirmed at, if it has.
pub(crate) fn confirmed_at(chain: &Chain, txid: &Txid) -> Result<Option<u32>> {
    let c = chain.confirmations(txid)?;
    (c > 0).then(|| chain.height().map(|h| h + 1 - c)).transpose()
}

impl<L: HubL2> Inner<L> {
    /// Advance every dispute by what the chain shows now.
    pub(crate) fn disputes_tick(&self) -> Result<()> {
        self.check_closings()?;
        let open: Vec<_> = self.open.lock().unwrap().values().filter(|o| o.closed.is_none()).map(|o| o.record.clone()).collect();
        for record in open {
            let cid = record.cid();
            let state = self.disputes.lock().unwrap().remove(&cid);
            let next = match state {
                None => self.hp_start(&record),
                Some(s) => self.hp_tick(&record, s),
            };
            // one contract's error never stops the others: its dispute is
            // read again from the chain at the next tick
            match next {
                Ok(Some(s)) => {
                    self.disputes.lock().unwrap().insert(cid, s);
                }
                Ok(None) => {}
                Err(e) => self.note_once(format!("contract {cid}: {e:#}")),
            }
        }
        Ok(())
    }

    /// The contract's graph.
    pub(crate) fn built(&self, record: &Record) -> Result<Built> {
        record.build(&self.cfg.statement, &self.l2)
    }

    fn front_state(&self, d: Box<Disputed>, step: FrontStep<L::Front>) -> Result<Option<State<L::Front>>> {
        Ok(Some(match step {
            FrontStep::Wait(f) => State::Front(d, f),
            FrontStep::Prove { at } => State::Proving(d, at, false),
            FrontStep::Paid { link, terminal } => {
                self.note(format!("contract {}: {terminal} paid out", d.record.cid()));
                let since = self.chain.height()?;
                State::Collect { d, link, terminal, since }
            }
        }))
    }

    /// If the user has requested, the dispute from where the chain shows
    /// it.
    fn hp_start(&self, record: &Record) -> Result<Option<State<L::Front>>> {
        let d = Disputed::new(record, &self.cfg.statement, &self.l2)?;
        let first = d.graph.front_names()?[0];
        let Some(at) = confirmed_at(&self.chain, &d.txid(first))? else { return Ok(None) };
        if let Some(a) = confirmed_at(&self.chain, &d.txid("assert"))? {
            return Ok(Some(State::Asserted(Box::new(d), a)));
        }
        let step = self.l2.front_start(self, &d, at)?;
        self.front_state(Box::new(d), step)
    }

    /// The link `name`'s output spent by other than `next`: a terminal (its
    /// payout) is out.
    fn ended(&self, d: &Disputed, name: &str, next: &str) -> Result<bool> {
        let op = OutPoint { txid: d.txid(name), vout: 0 };
        Ok(!self.chain.unspent(&op)? && self.chain.get_tx(&d.txid(next)).is_none())
    }

    /// One step of a dispute.
    fn hp_tick(&self, record: &Record, s: State<L::Front>) -> Result<Option<State<L::Front>>> {
        let cid = record.cid();
        let collect = |d: Box<Disputed>, link: &str, terminal: &str| -> Result<Option<State<L::Front>>> {
            let link = d.txid(link);
            Ok(Some(State::Collect { d, link, terminal: terminal.to_string(), since: self.chain.height()? }))
        };
        match s {
            State::Front(d, f) => {
                if let Some(a) = confirmed_at(&self.chain, &d.txid("assert"))? {
                    return Ok(Some(State::Asserted(d, a)));
                }
                let step = self.l2.front_tick(self, &d, f)?;
                self.front_state(d, step)
            }
            State::Proving(d, at, done) => {
                if let Some(a) = confirmed_at(&self.chain, &d.txid("assert"))? {
                    return Ok(Some(State::Asserted(d, a)));
                }
                let last = d.last_front()?;
                let terminal = d.graph.terminal_of(last)?;
                if self.ended(&d, last, "assert")? {
                    self.note(format!("contract {cid}: the hub never asserted: {terminal} paid the user her claim"));
                    return collect(d, last, &terminal);
                }
                if done {
                    return Ok(Some(State::Proving(d, at, true)));
                }
                let window = d.graph.front.links()?.pop().context("an empty front")?.window;
                let last_chance = at + u32::from(window) - (u32::from(window) / 4).max(2);
                if self.chain.height()? >= last_chance {
                    self.note_once(format!("contract {cid}: too late to assert; {terminal} will pay the user"));
                    return Ok(Some(State::Proving(d, at, true)));
                }
                if self.abandon_corrections.load(std::sync::atomic::Ordering::Relaxed) {
                    self.note_once(format!("contract {cid}: abandoning the proof (tests): {terminal} will pay the user"));
                    return Ok(Some(State::Proving(d, at, true)));
                }
                let done = self.hp_assert(&d)?;
                Ok(Some(State::Proving(d, at, done)))
            }
            State::Asserted(d, at) => {
                if let Some(c) = confirmed_at(&self.chain, &d.txid("challenge_assert"))? {
                    return Ok(Some(State::Challenged(d, c, false)));
                }
                if self.ended(&d, "assert", "challenge_assert")? {
                    return collect(d, "assert", "success");
                }
                if self.chain.height()? >= at + u32::from(d.graph.tail.windows.delta2) {
                    let txid = self.hp_terminal(&d, "success", vec![])?;
                    self.note(format!("contract {cid}: no challenge to the assertion; success {txid} pays out"));
                    return collect(d, "assert", "success");
                }
                Ok(Some(State::Asserted(d, at)))
            }
            State::Challenged(d, at, tried) => {
                let c_op = OutPoint { txid: d.txid("challenge_assert"), vout: 0 };
                if !self.chain.unspent(&c_op)? {
                    if self.chain.get_tx(&d.txid("failure")).is_some() {
                        self.note(format!("contract {cid}: no answer to the user's challenge: failure paid her"));
                        return collect(d, "challenge_assert", "failure");
                    }
                    self.close_settled(cid, c_op.txid)?;
                    return Ok(Some(State::Done));
                }
                if tried || self.chain.height()? >= at + u32::from(d.graph.tail.windows.delta1) {
                    return Ok(Some(State::Challenged(d, at, tried)));
                }
                if let Some(txid) = self.hp_answer(&d)? {
                    self.note(format!("contract {cid}: answered the challenge with a kept instance's msg: {txid}; the contract is the hub's"));
                    self.close(cid, txid)?;
                    return Ok(Some(State::Done));
                }
                self.note(format!("contract {cid}: no kept instance opens on the hub's proof: failure will pay the user"));
                Ok(Some(State::Challenged(d, at, true)))
            }
            State::Collect { d, link, terminal, since } => {
                let swept = self.l2.collect(self, &d, link, &terminal)?;
                let delta = u32::from(d.graph.core().params.delta);
                match swept {
                    Bits::None => self.note(format!("contract {cid}: no bit outputs of the hub's in the payout")),
                    Bits::Swept(txid, n, value) => self.note(format!("contract {cid}: collected the hub's {n} bit outputs, {} sats: {txid}", value.to_sat())),
                    Bits::NotYet if self.chain.height()? < since + delta + 4 * self.cfg.network.patience_blocks() => return Ok(Some(State::Collect { d, link, terminal, since })),
                    Bits::NotYet => self.note(format!("contract {cid}: no bit outputs of the hub's appeared; closed without collecting")),
                }
                self.close(cid, link)?;
                Ok(Some(State::Done))
            }
            State::Done => Ok(Some(State::Done)),
        }
    }

    pub(crate) fn hp_terminal(&self, d: &Disputed, name: &str, wire: Vec<Vec<u8>>) -> Result<Txid> {
        let tx = d.finish(name, wire)?;
        self.chain.post_terminal(&tx, &d.set[name].prevout, lichen_proto::terminal_fee(&tx, self.cfg.network), &NodeWallet)
    }

    /// Prove the statement for a dispute whose front is done and assert
    /// it: the L2's input checked natively, then proved. A lying hub
    /// (tests) asserts a forged proof. Whether done.
    fn hp_assert(&self, d: &Disputed) -> Result<bool> {
        let record = &d.record;
        let cid = record.cid();
        let journal = self.l2.journal(record)?;
        let proof = if self.forge_assertions.load(std::sync::atomic::Ordering::Relaxed) {
            self.note(format!("contract {cid}: asserting a forged proof against the claim"));
            let mut other = journal.clone();
            other[0] ^= 1;
            lichen_babe::statement::mock_prove(&other)
        } else {
            let input = match self.l2.prover_input(self, d)? {
                ProverInput::Holds(i) => i,
                ProverInput::NotYet(why) => {
                    self.note_once(format!("contract {cid}: {why}"));
                    return Ok(false);
                }
                ProverInput::Fails(why) => {
                    let t = d.graph.terminal_of(d.last_front()?)?;
                    self.note(format!("contract {cid}: the statement doesn't hold ({why}): no assertion; {t} will pay the user"));
                    return Ok(true);
                }
            };
            match self.cfg.statement.hp_kind()? {
                lichen_babe::statement::Kind::Mock => {
                    // for the guest's tests: the statement's input, as the prover takes it
                    if let Ok(dir) = std::env::var("LICHEN_DUMP_HP") {
                        let _ = std::fs::write(std::path::Path::new(&dir).join(format!("hp-{cid}.bin")), &input);
                    }
                    lichen_babe::statement::mock_prove(&journal)
                }
                lichen_babe::statement::Kind::Risc0(_) => match self.hp_proof(cid, &input, &journal)? {
                    Some(p) => p,
                    None => return Ok(false),
                },
            }
        };
        let bits = lichen_babe::gadget::input(&proof.a);
        let (pi2, pi3) = lichen_babe::statement::pi23_to_bytes(&proof);
        let wire = Graph::assert_wire(&hub_lamport(&self.cfg.seed, cid).sign(&digits(&bits)), &pi2, &pi3);
        let tx = d.finish("assert", wire)?;
        self.post(cid, &tx)?;
        self.note(format!("contract {cid}: asserted ({} vB)", tx.vsize()));
        Ok(true)
    }

    /// The proof of the hub's statement for contract `cid` (RISC Zero's,
    /// wrapped in Groth16), once proved, from `input`: the prover
    /// ([`Config::prover`]; LICHEN_HP_PROVER names another) runs in the
    /// background, one a contract, its files in `hp/<cid>/`. None while it
    /// proves; a failed prover is run again.
    fn hp_proof(&self, cid: u32, input: &[u8], journal: &[u8]) -> Result<Option<ark_groth16::Proof<ark_bn254::Bn254>>> {
        let dir = self.hp_dir(cid);
        let seal = dir.join("proof.seal");
        if seal.exists() {
            let p = lichen_babe::risc0::proof_from_seal(&std::fs::read(&seal)?).context("the prover's seal")?;
            ensure!(self.cfg.statement.hp_kind()?.verify(journal, &p), "the prover's proof doesn't verify for this contract");
            self.note_once(format!("contract {cid}: the statement proved; asserting"));
            return Ok(Some(p));
        }
        if !self.proving.lock().unwrap().insert(cid) {
            return Ok(None);
        }
        std::fs::create_dir_all(&dir)?;
        let in_path = dir.join("input.bin");
        std::fs::write(&in_path, input)?;
        let prover = match std::env::var("LICHEN_HP_PROVER") {
            Ok(p) => std::path::PathBuf::from(p),
            Err(_) => self.cfg.prover.clone().context("no prover for the hub's statement (Config::prover, or LICHEN_HP_PROVER)")?,
        };
        let log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("prover.log"))?;
        let tmp = dir.join("proof.seal.tmp");
        let mut cmd = std::process::Command::new(&prover);
        cmd.arg("hp-proof").arg(&in_path).arg(&tmp).stdout(log.try_clone()?).stderr(log);
        self.note(format!("contract {cid}: proving the statement ({}, hp/{cid}/prover.log)", prover.display()));
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
    fn hp_answer(&self, d: &Disputed) -> Result<Option<Txid>> {
        let cid = d.record.cid();
        let keys = d.record.hp();
        let asserted = d.asserted(&self.chain.get_tx(&d.txid("assert")).context("the assertion")?)?;
        let proof = asserted.proof.clone().context("the assertion's points aren't points")?;
        let tx = self.chain.get_tx(&d.txid("challenge_assert")).context("the challenge")?;
        let presigs: Vec<[AdaptorSig; lichen_babe::setup::VALUES]> = keys.hub_presigs.iter().map(|s| s.each_ref().map(AdaptorSig::from)).collect();
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
                return self.hp_terminal(d, &format!("wrongly_challenged_{k}"), Graph::wrongly_wire(&msg)).map(Some);
            }
        }
        Ok(None)
    }

    /// Sweep to the hub's wallet the outputs of `trees` on chain, each by
    /// its named leaf: `wire`, then the hub's signature.
    fn sweep_trees(&self, record: &Record, trees: Vec<(bitcoin::ScriptBuf, TapTree, String)>, wire: &[Vec<u8>], sequence: Sequence) -> Result<Bits> {
        let cid = record.cid();
        if trees.is_empty() {
            return Ok(Bits::None);
        }
        let spks: Vec<_> = trees.iter().map(|t| t.0.clone()).collect();
        let coins = self.chain.scan_utxos(&spks)?;
        if coins.is_empty() {
            return Ok(Bits::NotYet);
        }
        let ins: Vec<_> = coins.iter().map(|(op, out, _)| (*op, out.clone(), trees.iter().find(|t| t.0 == out.script_pubkey).expect("a scanned script"))).collect();
        let kp = contract_keys(&self.cfg.seed, cid).payment;
        let to = self.chain.new_spk()?;
        let total: Amount = ins.iter().map(|i| i.1.value).sum();
        let prevouts: Vec<TxOut> = ins.iter().map(|i| i.1.clone()).collect();
        let seqs: Vec<(OutPoint, Sequence)> = ins.iter().map(|i| (i.0, sequence)).collect();
        let build = |fee: Amount| -> Result<Transaction> {
            let out = TxOut { value: total.checked_sub(fee).context("the bit outputs can't pay the sweep's fee")?, script_pubkey: to.clone() };
            let mut sweep = lichen_btc::tx::build_tx(&seqs, vec![out], bitcoin::absolute::LockTime::ZERO);
            sweep.version = bitcoin::transaction::Version::TWO;
            for (n, (_, _, (_, tree, name))) in ins.iter().enumerate() {
                let leaf = tree.leaf(name)?;
                let mut w = wire.to_vec();
                w.push(sign_tapscript(&kp, &sweep, n, &prevouts, &leaf.script)?.as_ref().to_vec());
                sweep.input[n].witness = tapscript_witness(&w, &leaf.script, &tree.control_block(name)?);
            }
            Ok(sweep)
        };
        // sized once at no fee, then paid
        let vsize = build(Amount::ZERO)?.vsize() as u64;
        let fee = Amount::from_sat((vsize + 2) * lichen_proto::feerate(self.cfg.network));
        let txid = self.chain.broadcast(&build(fee)?).context("sweeping the hub's bit outputs")?;
        Ok(Bits::Swept(txid, ins.len(), total - fee))
    }

    /// An error once the hub is being dropped, for a wait on the chain to
    /// give up on (its dispute is read again from the chain on restart).
    pub(crate) fn stopping(&self) -> Result<()> {
        anyhow::ensure!(!self.stop.load(std::sync::atomic::Ordering::Relaxed), "the hub is stopping");
        Ok(())
    }

    /// Post one of the hub's links (unless it is already there: replayed,
    /// checked to be the same), its child paying from the hub's anchor;
    /// its confirmation height.
    pub(crate) fn post(&self, cid: u32, tx: &Transaction) -> Result<u32> {
        self.post_with(cid, tx, &[]).map(|(h, _)| h)
    }

    /// [`Inner::post`], its fee child carrying `extra` outputs (posted
    /// whatever the feerate): its confirmation height and the child.
    pub(crate) fn post_with(&self, cid: u32, tx: &Transaction, extra: &[TxOut]) -> Result<(u32, Option<Txid>)> {
        let txid = tx.compute_txid();
        let child = match self.chain.get_tx(&txid) {
            None => {
                let kp = contract_keys(&self.cfg.seed, cid).payment;
                let anchor = anchor_vout(tx, &kp.x_only_public_key().0)?;
                self.chain.post_link_with(tx, anchor, lichen_proto::feerate(self.cfg.network), &|c, p| sign_anchor(&kp, c, p), &NodeWallet, extra)?
            }
            Some(posted) => {
                anyhow::ensure!(posted.input.iter().zip(&tx.input).all(|(a, b)| a.witness == b.witness), "{txid} on chain is not the link replayed");
                None
            }
        };
        let patience = lichen_proto::Patience::new(self.chain.height()?, self.cfg.network);
        loop {
            if let Some(h) = confirmed_at(&self.chain, &txid)? {
                return Ok((h, child));
            }
            anyhow::ensure!(!patience.expired(self.chain.height()?), "{txid} never confirmed");
            self.stopping()?;
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

impl<L: HubL2> Ctx for Inner<L> {
    fn chain(&self) -> &Chain {
        &self.chain
    }
    fn cfg(&self) -> &Config {
        &self.cfg
    }
    fn note(&self, msg: String) {
        Inner::note(self, msg)
    }
    fn note_once(&self, msg: String) {
        Inner::note_once(self, msg)
    }
    fn contract_keys(&self, cid: u32) -> PartyKeys {
        contract_keys(&self.cfg.seed, cid)
    }
    fn contract_secret(&self, cid: u32, label: &str) -> [u8; 32] {
        crate::setup::contract_seed(&self.cfg.seed, cid).derive_bytes(label)
    }
    fn contracts(&self) -> Vec<(Record, bool)> {
        self.open.lock().unwrap().values().map(|o| (o.record.clone(), o.closed.is_some())).collect()
    }
    fn hp_dir(&self, cid: u32) -> std::path::PathBuf {
        Inner::hp_dir(self, cid)
    }
    fn confirmed_at(&self, txid: &Txid) -> Result<Option<u32>> {
        confirmed_at(&self.chain, txid)
    }
    fn post(&self, cid: u32, tx: &Transaction) -> Result<u32> {
        Inner::post(self, cid, tx)
    }
    fn post_with(&self, cid: u32, tx: &Transaction, extra: &[TxOut]) -> Result<(u32, Option<Txid>)> {
        Inner::post_with(self, cid, tx, extra)
    }
    fn post_terminal(&self, d: &Disputed, name: &str, wire: Vec<Vec<u8>>) -> Result<Txid> {
        self.hp_terminal(d, name, wire)
    }
    fn sweep(&self, record: &Record, trees: Vec<(bitcoin::ScriptBuf, TapTree, String)>, wire: &[Vec<u8>], sequence: Sequence) -> Result<Bits> {
        self.sweep_trees(record, trees, wire, sequence)
    }
    fn forging(&self) -> bool {
        self.forge_assertions.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn stopping(&self) -> Result<()> {
        Inner::stopping(self)
    }
}

impl<F> State<F> {
    pub(crate) fn describe<L: HubL2<Front = F>>(&self, l2: &L) -> String {
        match self {
            State::Front(_, f) => l2.describe(f),
            State::Proving(_, _, false) => "the front done: the hub's statement is due".into(),
            State::Proving(_, _, true) => "asserted, or left to the front's timeout".into(),
            State::Asserted(..) => "asserted: the user's challenge is due".into(),
            State::Challenged(..) => "challenged: the hub's answer is due".into(),
            State::Collect { .. } => "paid out: collecting the hub's bit outputs".into(),
            State::Done => "settled".into(),
        }
    }
}

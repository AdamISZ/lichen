//! The hub's side of a BitVMX dispute ([`super`] drives it, one step per
//! tick).
//!
//! When a contract's escalation appears on chain, the hub reads Alice's
//! claim (move 1 with the claim block) and her input words, and runs the
//! verifier on them. If her claim is true, an honest hub does not dispute
//! it: it lets her timeout pay her. Otherwise it plays BitVMX's search,
//! posting its choice after each of her rounds; at the end it reads her
//! final move and does what BitVMX's verifier says: disproves it with the
//! rule that applies or, under a jump list, posts a path through its own
//! history that proves her step wrong (a read or a long jump) and, unless
//! she shows a hop of it false, takes the output with the path's verdict.
//! If she stops answering, its timeout pays it.
//!
//! After a restart the hub rebuilds its verifier from the claim on chain
//! and replays the moves already made (each of its own checked against
//! what it would play now), then carries on.
//!
//! Also the hub's BitVMX keys for a contract it opens ([`open_keys`]).

use anyhow::{ensure, Context, Result};
use bitcoin::{OutPoint, Transaction};
use emulator::decision::challenge::ForceCondition;
use lichen_chain::NodeWallet;
use lichen_proto::bitvmx::{all_moves, check_request_keys, input_from_words, link_name, sign_fields, sign_move, tail_keys, Disputed, Site, Windows};
use lichen_proto::{BitVmxKeys, BitVmxOffer, BitVmxRequest, DisputeKeys, OfferKeys, Record};
use lngap_btc::keys::Seed;
use lngap_ladder::ladder::TailOut;
use lngap_ladder::tail::{chunk_fields, Path};
use lngap_lamport::winternitz::{WotsParams, WotsSecret};
use lngap_sessions::contract::Program;
use lngap_sessions::play::{read_move, read_words, word_wires, PathKind, Verdict, Verifier};

use super::{confirmed_at, State as Outer};
use crate::Inner;

/// The hub's move keys for depth `d` of contract `cid`, one per field.
pub fn move_secrets(seed: &str, cid: u32, program: &Program, d: u32) -> Vec<WotsSecret> {
    let at = |f: usize, n: u32| WotsSecret::from_entropy(WotsParams::for_bytes(n), Seed::from_label(&format!("{seed}/contract/{cid}/move/{d}/{f}")).derive_bytes("wots"));
    program.field_bytes(d).into_iter().enumerate().map(|(f, n)| at(f, n)).collect()
}

/// The hub's keys for its path under a jump list, by chunk and field
/// (empty without one).
pub fn path_secrets(seed: &str, cid: u32, program: &Program) -> Vec<Vec<WotsSecret>> {
    if program.schedule.jump.is_none() {
        return vec![];
    }
    let at = |c: usize, f: usize, n: usize| WotsSecret::from_entropy(WotsParams::for_bytes(n as u32), Seed::from_label(&format!("{seed}/contract/{cid}/path/{c}/{f}")).derive_bytes("wots"));
    (0..lngap_ladder::tail::CHUNKS).map(|c| lngap_ladder::tail::chunk_fields(c).into_iter().enumerate().map(|(f, n)| at(c, f, n)).collect()).collect()
}

/// A BitVMX contract's keys, from Alice's request (checked) and the hub's
/// own: the record's, and the offer's.
pub(crate) fn open_keys(seed: &str, cid: u32, program: &Program, req: &BitVmxRequest, windows: Windows) -> Result<(DisputeKeys, OfferKeys)> {
    let m = program.depths();
    ensure!(req.moves.len() as u32 == m.div_ceil(2), "{} move keys for the odd depths of {m}", req.moves.len());
    check_request_keys(program, req)?;
    let pub_of = |ks: Vec<WotsSecret>| ks.iter().map(|k| k.public()).collect::<Vec<_>>();
    let hub_moves: Vec<_> = (1..=m).filter(|d| d % 2 == 0).map(|d| pub_of(move_secrets(seed, cid, program, d))).collect();
    let path: Vec<_> = path_secrets(seed, cid, program).into_iter().map(pub_of).collect();
    let keys = BitVmxKeys { moves: all_moves(&req.moves, &hub_moves), inputs: req.inputs.clone(), tail: tail_keys(program, &path, &req.hops)?, windows: Some(windows) };
    Ok((DisputeKeys::BitVmx(keys), OfferKeys::BitVmx(BitVmxOffer { moves: hub_moves, path, windows: Some(windows) })))
}

fn bx(s: State) -> Option<Outer> {
    Some(Outer::BitVmx(s))
}

/// A BitVMX dispute's state at the hub, in play.
pub(crate) enum State {
    /// The claim is true: the hub lets Alice's timeout pay her.
    Conceded,
    /// Playing: Alice's move `awaiting` is due; the hub's last link
    /// confirmed at `last`.
    Playing { d: Box<Disputed>, v: Box<Verifier>, awaiting: u32, last: u32 },
    /// Her last move (`last`) is valid: she proves it.
    Proved { last: u32 },
    /// No rule applies, yet her step doesn't prove: the hub's timeout,
    /// after her final move (confirmed at `at`). Or, `proved`, her step is
    /// valid and the hub disputes true claims: its timeout races her
    /// proof.
    Waiting { d: Box<Disputed>, at: u32, proved: bool },
    /// Under a jump list: the hub's path is posted (its combine of `k`
    /// chunks confirmed at `at`); Alice may challenge a hop, else the
    /// verdict `name` (its witness `pre_y`) takes the output.
    Path(Box<Posted>),
}

/// A posted path, and what answering it takes.
pub(crate) struct Posted {
    d: Disputed,
    v: Verifier,
    path: Path,
    pre_y: Vec<u8>,
    name: String,
    k: usize,
    at: u32,
}

impl Inner {
    /// One step of a BitVMX dispute in play.
    pub(super) fn bitvmx_tick(&self, record: &Record, s: State) -> Result<Option<Outer>> {
        let cid = record.cid();
        match s {
            State::Playing { d, v, awaiting, last } => self.play(cid, *d, *v, awaiting, last),
            State::Conceded => self.settled_by_user(record, None),
            State::Proved { last } => self.settled_by_user(record, Some(last)),
            State::Waiting { d, at, proved } => self.wait_timeout(cid, *d, at, proved),
            State::Path(p) => self.path_tick(cid, *p),
        }
    }

    /// Whether the contract was escalated.
    pub(super) fn bitvmx_escalated(&self, record: &Record) -> Result<bool> {
        let d = Disputed::new(record, &self.cfg.statement, &self.cfg.dir)?;
        Ok(self.chain.get_tx(&d.txid("escalate")).is_some())
    }

    /// Alice's `b` and her signature on it, read from the escalation.
    pub(super) fn bitvmx_claimed_b(&self, record: &Record) -> Result<(u32, Vec<Vec<u8>>)> {
        let d = Disputed::new(record, &self.cfg.statement, &self.cfg.dir)?;
        let esc = self.chain.get_tx(&d.txid("escalate")).context("the escalation")?;
        let claim = d.contract.claim_words();
        let keys: Vec<_> = claim.iter().map(|&j| d.contract.spec.inputs[j].clone()).collect();
        let at = claim.iter().position(|&j| j == d.contract.spec.b_word).context("b is not in the claim")?;
        let b = read_words(&esc, &keys, Some(d.key(1)))?[at];
        let b_wire = word_wires(&esc, &keys, Some(d.key(1)))?.swap_remove(at);
        Ok((b, b_wire))
    }

    /// A posted link by name (the txid the pre-signed set fixed).
    fn link(&self, d: &Disputed, name: &str) -> Result<Transaction> {
        self.chain.get_tx(&d.txid(name)).with_context(|| format!("{name} is not on chain"))
    }

    /// Post the pre-signed terminal `name` (a timeout), its fee paid by a
    /// coin of the hub's wallet.
    fn terminal(&self, d: &Disputed, name: &str) -> Result<bitcoin::Txid> {
        let tx = d.finish(name, vec![])?;
        self.chain.post_terminal(&tx, &d.set[name].prevout, lichen_proto::terminal_fee(&tx, self.cfg.network), &NodeWallet)
    }

    /// If the contract has been escalated (and its input published), read
    /// the claim and decide.
    pub(super) fn bitvmx_start(&self, record: &Record) -> Result<Option<Outer>> {
        let cid = record.cid();
        let d = Disputed::new(record, &self.cfg.statement, &self.cfg.dir)?;
        let esc_id = d.txid("escalate");
        if confirmed_at(self, &esc_id)?.is_none() {
            return Ok(None);
        }
        let esc = self.chain.get_tx(&esc_id).context("the escalation")?;
        let n = d.contract.spec.inputs.len();
        let mut words = vec![0u32; n];
        let claim = d.contract.claim_words();
        let keys = |js: &[usize]| js.iter().map(|&j| d.contract.spec.inputs[j].clone()).collect::<Vec<_>>();
        for (j, w) in claim.iter().zip(read_words(&esc, &keys(&claim), Some(d.key(1)))?) {
            words[*j] = w;
        }
        // each word's signature, from the link that published it
        let mut wires: std::collections::HashMap<usize, Vec<Vec<u8>>> = claim.iter().copied().zip(word_wires(&esc, &keys(&claim), Some(d.key(1)))?).collect();
        if d.set.contains_key("inputs") {
            let id = d.txid("inputs");
            if confirmed_at(self, &id)?.is_none() {
                // the rest of the input is due within the window, or the hub's timeout
                let at = confirmed_at(self, &esc_id)?.context("the escalation, no longer confirmed")?;
                if self.chain.height()? >= at + u32::from(d.contract.lock(Site::Claimed)) {
                    let txid = self.terminal(&d, "timeout_inputs")?;
                    self.note(format!("contract {cid}: the input never came; timeout {txid}"));
                    self.close(cid, txid)?;
                    return Ok(Some(Outer::Done));
                }
                return Ok(None);
            }
            let rest = d.contract.rest_words();
            let inputs = self.chain.get_tx(&id).context("the inputs")?;
            for (j, w) in rest.iter().zip(read_words(&inputs, &keys(&rest), None)?) {
                words[*j] = w;
            }
            wires.extend(rest.iter().copied().zip(word_wires(&inputs, &keys(&rest), None)?));
        }
        // a claim whose words break the contract's checks (another
        // contract's memo or deployment, another program's image id) takes
        // no search: the check's leaf is on the ladder output after move 1,
        // whichever link published the word
        for c in &d.contract.spec.checks {
            if words[c.word] != c.value {
                let wire = wires.get(&c.word).context("a checked word no link published")?.clone();
                return self.take_by_check(&d, cid, &c.name, wire);
            }
        }
        let move1 = read_move(&esc, d.key(1))?;
        let dispute_true = self.dispute_true_claims.load(std::sync::atomic::Ordering::Relaxed);
        // an honest hub disputes only an input the program rejects: when the
        // statement can say so natively, a true claim is conceded at once,
        // without emulating
        if !dispute_true && self.cfg.statement.accepts(&input_from_words(&words)) == Some(true) {
            self.note(format!("contract {cid}: the claim is true (checked natively); conceding"));
            return Ok(bx(State::Conceded));
        }
        let force = if dispute_true { ForceCondition::ValidInputStepAndHash } else { ForceCondition::No };
        let dir = self.cfg.dir.join("disputes").join(cid.to_string());
        let Some(mut v) = Verifier::start(&d.program, &input_from_words(&words), &dir, &move1, force)? else {
            self.note(format!("contract {cid}: the claim is true; conceding"));
            return Ok(bx(State::Conceded));
        };
        self.note(format!("contract {cid}: disputing the claim"));
        // replay what is already on chain, then carry on
        let m = d.contract.m();
        let mut alice: Option<Vec<u8>> = None;
        let mut j = 2;
        loop {
            let choice = v.choose(alice.as_deref())?;
            let last = self.post_move(&d, cid, j, &choice)?;
            let next = link_name(j + 1);
            match confirmed_at(self, &d.txid(&next))? {
                Some(_) if j + 1 < m => {
                    alice = Some(read_move(&self.link(&d, &next)?, d.key(j + 1))?);
                    j += 2;
                }
                _ => return Ok(bx(State::Playing { d: Box::new(d), v: Box::new(v), awaiting: j + 1, last })),
            }
        }
    }

    /// A dispute the user settles: conceded (her timeout pays her, from the
    /// ladder output after move 1) or proved (her proof, from the output
    /// after her last move, `proved`). Once that output is spent, the hub
    /// collects its bit outputs from the payout, then closes.
    fn settled_by_user(&self, record: &Record, proved: Option<u32>) -> Result<Option<Outer>> {
        let cid = record.cid();
        let d = Disputed::new(record, &self.cfg.statement, &self.cfg.dir)?;
        let link = match proved {
            Some(m) => link_name(m),
            None if d.set.contains_key("inputs") => "inputs".to_string(),
            None => "escalate".to_string(),
        };
        let op = OutPoint { txid: d.txid(&link), vout: 0 };
        if self.chain.get_tx(&op.txid).is_some() && !self.chain.unspent(&op)? {
            let how = if proved.is_some() { "the user proved the last step" } else { "the user's timeout paid the claim" };
            self.note(format!("contract {cid}: settled: {how}"));
            return Ok(Some(Outer::Collect { link: op.txid, since: self.chain.height()? }));
        }
        Ok(bx(match proved {
            Some(last) => State::Proved { last },
            None => State::Conceded,
        }))
    }

    /// Take the contract with the check `name` on the ladder output after
    /// move 1, re-revealing Alice's signature on the word (`wire`).
    fn take_by_check(&self, d: &Disputed, cid: u32, name: &str, wire: Vec<Vec<u8>>) -> Result<Option<Outer>> {
        let link = if d.set.contains_key("inputs") { "inputs" } else { "escalate" };
        let id = d.txid(link);
        if confirmed_at(self, &id)?.is_none() {
            return Ok(None);
        }
        let out = self.chain.get_tx(&id).context("the link")?.output[0].clone();
        let spend = self.spend_leaf(cid, &d.contract.ladder(1)?, name, OutPoint { txid: id, vout: 0 }, &out, wire)?;
        let txid = self.chain.broadcast(&spend).with_context(|| format!("the {name} check"))?;
        self.note(format!("contract {cid}: the claim breaks the {name} check; taken ({} vB)", spend.vsize()));
        self.close(cid, txid)?;
        Ok(Some(Outer::Done))
    }

    /// Post the hub's move `j`, `msg` signed field by field.
    fn post_move(&self, d: &Disputed, cid: u32, j: u32, msg: &[u8]) -> Result<u32> {
        let keys = move_secrets(&self.cfg.seed, cid, &d.program, j);
        let tx = d.finish(&link_name(j), sign_move(&d.program, j, &keys, msg)?)?;
        self.post(cid, &tx)
    }

    /// One step of a dispute in play.
    fn play(&self, cid: u32, d: Disputed, mut v: Verifier, awaiting: u32, last: u32) -> Result<Option<Outer>> {
        let (m, p) = (d.contract.m(), d.contract.spec.params);
        // her window for move `awaiting`, from the hub's last move
        let w = u32::from(d.contract.lock(Site::Next(awaiting - 1)));
        let id = d.txid(&link_name(awaiting));
        let ours = OutPoint { txid: d.txid(&link_name(awaiting - 1)), vout: 0 };
        let Some(at) = confirmed_at(self, &id)? else {
            if !self.chain.unspent(&ours)? && self.chain.get_tx(&id).is_none() {
                // spent, not by Alice's move: our own timeout, before a restart
                self.note(format!("contract {cid}: already settled by timeout"));
                self.close_settled(cid, ours.txid)?;
                return Ok(Some(Outer::Done));
            }
            if self.chain.height()? >= last + w {
                // Alice stopped: the ladder output after the hub's last move times out to it
                let name = format!("timeout_{}", awaiting - 1);
                let txid = self.terminal(&d, &name)?;
                self.note(format!("contract {cid}: the user stopped answering; timeout {txid}"));
                self.close(cid, txid)?;
                return Ok(Some(Outer::Done));
            }
            return Ok(bx(State::Playing { d: Box::new(d), v: Box::new(v), awaiting, last }));
        };
        let tx = self.chain.get_tx(&id).context("Alice's move")?;
        let signed = read_move(&tx, d.key(awaiting))?;
        if awaiting < m {
            let choice = v.choose(Some(&signed))?;
            let last = self.post_move(&d, cid, awaiting + 1, &choice)?;
            return Ok(bx(State::Playing { d: Box::new(d), v: Box::new(v), awaiting: awaiting + 2, last }));
        }
        // her final move: what BitVMX's verifier says to do
        let link = |name: &str| self.link(&d, name);
        let proves = |rec: &lngap_zk::game::Record| d.proves(rec, &link).map(|p| p.1).unwrap_or(false);
        let verdict = v.verdict(&signed, &proves)?;
        let op = OutPoint { txid: id, vout: 0 };
        if !self.chain.unspent(&op)? && self.chain.get_tx(&d.txid("path_split")).is_none() {
            // before a restart: by her proof (the hub's bit outputs to
            // collect) or by its disprove (nothing to collect)
            self.note(format!("contract {cid}: the last step is already settled"));
            return Ok(Some(Outer::Collect { link: id, since: self.chain.height()? }));
        }
        match verdict {
            Verdict::Proved if self.dispute_true_claims.load(std::sync::atomic::Ordering::Relaxed) => {
                self.note(format!("contract {cid}: the user's last step is valid; the hub's timeout races her proof"));
                Ok(bx(State::Waiting { d: Box::new(d), at, proved: true }))
            }
            Verdict::Proved => {
                self.note(format!("contract {cid}: the user's last step is valid; the user proves it"));
                Ok(bx(State::Proved { last: m }))
            }
            Verdict::Wait => {
                self.note(format!("contract {cid}: no rule applies, yet the user's step doesn't prove: waiting for the hub's timeout"));
                Ok(bx(State::Waiting { d: Box::new(d), at, proved: false }))
            }
            Verdict::ReadChallenge => anyhow::bail!("contract {cid}: a read challenge, and the statement has no jump list to settle it"),
            Verdict::Disprove(name, wit) => {
                while self.chain.height()? < at + u32::from(p.delta) {
                    self.stopping()?;
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                let wire = d.rule_wire(&d.contract.rule(m, &name)?, &wit, None, &link)?;
                let leaf_name = format!("disprove_{name}");
                let spend = self.spend_leaf(cid, &d.contract.ladder(m)?, &leaf_name, op, &tx.output[0], wire)?;
                let txid = self.chain.broadcast(&spend).with_context(|| format!("broadcasting {leaf_name}"))?;
                self.note(format!("contract {cid}: {leaf_name} ({} vB)", spend.vsize()));
                self.close(cid, txid)?;
                Ok(Some(Outer::Done))
            }
            Verdict::Path { kind, y } => {
                // a path from the agreed step back to y, over the hub's history
                let (mut path, pre_y) = v.path(y)?;
                if self.forge_paths.load(std::sync::atomic::Ordering::Relaxed) {
                    let i = path.n() / 2;
                    path.hashes[i][0] ^= 1;
                    self.note(format!("contract {cid}: forging hop {i} of the path"));
                }
                let h_t = lngap_ladder::moves::View { s: &d.program.schedule, msgs: &v.msgs }.step_hash();
                let chunks = path.messages(&h_t);
                let k = path.chunks();
                let name = match kind {
                    PathKind::Jump => "jump".to_string(),
                    PathKind::Read(r) => format!("read_{r}"),
                };
                self.note(format!("contract {cid}: the user's step is wrong ({name}, at step {y}): posting a path of {} hops in {k} chunks", path.n()));
                self.post(cid, &d.finish("path_split", vec![])?)?;
                let keys = path_secrets(&self.cfg.seed, cid, &d.program);
                let wires: Vec<Vec<Vec<u8>>> = (0..k).map(|c| sign_fields(&keys[c], &chunks[c], &chunk_fields(c))).collect::<Result<_>>()?;
                let at = self.post(cid, &d.finish_multi(&format!("combine_{k}"), wires)?)?;
                Ok(bx(State::Path(Box::new(Posted { d, v, path, pre_y, name, k, at }))))
            }
        }
    }

    /// No rule applied (or, `proved`, her step is valid and the hub races
    /// her proof): once her window passes, the last ladder output times
    /// out to the hub.
    fn wait_timeout(&self, cid: u32, d: Disputed, at: u32, proved: bool) -> Result<Option<Outer>> {
        let m = d.contract.m();
        let op = OutPoint { txid: d.txid(&link_name(m)), vout: 0 };
        if !self.chain.unspent(&op)? {
            if proved {
                self.note(format!("contract {cid}: settled: the user proved the last step before the hub's timeout"));
                return Ok(Some(Outer::Collect { link: op.txid, since: self.chain.height()? }));
            }
            self.note(format!("contract {cid}: settled: the user's last step"));
            self.close(cid, op.txid)?;
            return Ok(Some(Outer::Done));
        }
        if self.chain.height()? < at + u32::from(d.contract.lock(Site::FinalTimeout)) {
            return Ok(bx(State::Waiting { d: Box::new(d), at, proved }));
        }
        let name = format!("timeout_{m}");
        let txid = match self.terminal(&d, &name) {
            Ok(txid) => txid,
            // her proof first, in the mempool: whichever confirms settles it
            // (if hers, the hub collects its bit outputs)
            Err(e) if proved => {
                let once = format!("contract {cid}: the hub's timeout of the user's valid last step didn't broadcast");
                if !self.log.lock().unwrap().contains(&once) {
                    self.note(once);
                    eprintln!("hub: ({e:#})");
                }
                return Ok(bx(State::Waiting { d: Box::new(d), at, proved }));
            }
            Err(e) => return Err(e),
        };
        let how = if proved { "the user's last step was valid, but no proof came in her window" } else { "the user's step neither proved nor was disproved" };
        self.note(format!("contract {cid}: {how}; timeout {txid}"));
        self.close(cid, txid)?;
        Ok(Some(Outer::Done))
    }

    /// The path is posted: answer Alice's challenge of a hop by revealing
    /// it, or, if none comes in her window, take the output with the
    /// path's verdict.
    fn path_tick(&self, cid: u32, s: Posted) -> Result<Option<Outer>> {
        let Posted { d, v, path, pre_y, name, k, at } = &s;
        let k = *k;
        let p = d.contract.spec.params;
        let link = |n: &str| self.link(d, n);
        let hop_name = format!("hop_{k}");
        let p_op = OutPoint { txid: d.txid(&format!("combine_{k}")), vout: 0 };
        if let Some(h_at) = confirmed_at(self, &d.txid(&hop_name))? {
            // she challenged a hop: reveal it, after the delay
            let hop_tx = link(&hop_name)?;
            let h_op = OutPoint { txid: hop_tx.compute_txid(), vout: 0 };
            if !self.chain.unspent(&h_op)? {
                self.note(format!("contract {cid}: settled: the user's challenge of a hop stood"));
                self.close(cid, h_op.txid)?;
                return Ok(Some(Outer::Done));
            }
            if self.chain.height()? < h_at + u32::from(p.delta) {
                return Ok(bx(State::Path(Box::new(s))));
            }
            let i = read_move(&hop_tx, std::slice::from_ref(&d.tail()?.hop[k - 1]))?[0] as usize;
            let (rule, wit) = if i < path.n() { (format!("hop_{i}"), v.reveal(path, i)?) } else { ("hop_range".to_string(), vec![]) };
            let at_h = TailOut::Hop(k);
            let wire = d.rule_wire(&d.contract.tail_rule(at_h, &rule)?, &wit, Some(k), &link)?;
            let leaf_name = format!("disprove_{rule}");
            let spend = self.spend_leaf(cid, &d.contract.tail_tree(at_h)?, &leaf_name, h_op, &hop_tx.output[0], wire)?;
            let vsize = spend.vsize();
            match self.chain.broadcast(&spend) {
                Ok(txid) => {
                    self.note(format!("contract {cid}: the user challenged hop {i} of the path; revealed ({leaf_name}, {vsize} vB)"));
                    self.close(cid, txid)?;
                    return Ok(Some(Outer::Done));
                }
                // (a hop of a forged path: the user's timeout will take it)
                Err(e) => {
                    let once = format!("contract {cid}: the user challenged hop {i} of the path, and the hub can't reveal it");
                    if !self.log.lock().unwrap().contains(&once) {
                        self.note(once);
                        eprintln!("hub: ({e:#})");
                    }
                }
            }
            return Ok(bx(State::Path(Box::new(s))));
        }
        if !self.chain.unspent(&p_op)? {
            if self.chain.get_tx(&d.txid(&hop_name)).is_some() {
                // her challenge, not yet confirmed
                return Ok(bx(State::Path(Box::new(s))));
            }
            self.note(format!("contract {cid}: settled: the hub's path timed out"));
            self.close(cid, p_op.txid)?;
            return Ok(Some(Outer::Done));
        }
        if self.chain.height()? < at + u32::from(d.contract.lock(Site::VerdictAfter)) {
            return Ok(bx(State::Path(Box::new(s))));
        }
        // no challenge in her window: the verdict
        let at_p = TailOut::Path(k);
        let wire = d.rule_wire(&d.contract.tail_rule(at_p, name)?, pre_y, Some(k), &link)?;
        let leaf_name = format!("disprove_{name}");
        let comb = link(&format!("combine_{k}"))?;
        let spend = self.spend_leaf(cid, &d.contract.tail_tree(at_p)?, &leaf_name, p_op, &comb.output[0], wire)?;
        let txid = self.chain.broadcast(&spend).with_context(|| format!("broadcasting {leaf_name}"))?;
        self.note(format!("contract {cid}: the path stood; {leaf_name} ({} vB)", spend.vsize()));
        self.close(cid, txid)?;
        Ok(Some(Outer::Done))
    }
}

impl State {
    pub(crate) fn describe(&self) -> String {
        match self {
            State::Conceded => "the claim is true: conceded".into(),
            State::Playing { awaiting, .. } => format!("disputing: awaiting the user's move {awaiting}"),
            State::Proved { .. } => "the user's last step is valid: the user proves it".into(),
            State::Waiting { proved: false, .. } => "no rule applies: waiting for the hub's timeout".into(),
            State::Waiting { proved: true, .. } => "the user's last step is valid: the hub's timeout races her proof".into(),
            State::Path(p) => format!("the hub's path is posted ({}, {} chunks): the user's window to challenge a hop", p.name, p.k),
        }
    }
}

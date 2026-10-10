//! The hub's side of a dispute, run by its watcher, one step per tick.
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
//! Nothing of a dispute is kept but the contract: after a restart the hub
//! rebuilds its verifier from the claim on chain and replays the moves
//! already made (each of its own checked against what it would play now),
//! then carries on.

use anyhow::{Context, Result};
use bitcoin::{Amount, OutPoint, Transaction, TxOut, Txid};
use emulator::decision::challenge::ForceCondition;
use lichen_proto::{anchor_vout, input_from_words, link_name, sign_anchor, sign_fields, sign_move, Disputed, FEERATE};
use lngap_btc::sighash::sign_tapscript;
use lngap_btc::taptree::TapTree;
use lngap_btc::tx::build_spend;
use lngap_btc::witness::tapscript_witness;
use lngap_ladder::ladder::TailOut;
use lngap_ladder::tail::{chunk_fields, Path};
use lngap_sessions::play::{read_move, read_words, word_wires, PathKind, Verdict, Verifier};

use crate::{contract_keys, move_secrets, path_secrets, Inner};

/// A dispute's state at the hub.
pub(crate) enum State {
    /// The claim is true: the hub lets Alice's timeout pay her.
    Conceded,
    /// Playing: Alice's move `awaiting` is due; the hub's last link
    /// confirmed at `last`.
    Playing { d: Box<Disputed>, v: Box<Verifier>, awaiting: u32, last: u32 },
    /// Her last move (`last`) is valid: she proves it.
    Proved { last: u32 },
    /// No rule applies, yet her step doesn't prove: the hub's timeout,
    /// after her final move (confirmed at `at`).
    Waiting { d: Box<Disputed>, at: u32 },
    /// Under a jump list: the hub's path is posted (its combine of `k`
    /// chunks confirmed at `at`); Alice may challenge a hop, else the
    /// verdict `name` (its witness `pre_y`) takes the output.
    Path(Box<Posted>),
    Done,
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

fn confirmed_at(inner: &Inner, txid: &Txid) -> Result<Option<u32>> {
    let c = inner.chain.confirmations(txid)?;
    (c > 0).then(|| inner.chain.height().map(|h| h + 1 - c)).transpose()
}

impl Inner {
    /// Advance every dispute by what the chain shows now.
    pub(crate) fn disputes_tick(&self) -> Result<()> {
        let open: Vec<_> = self.open.lock().unwrap().values().filter(|o| o.closed.is_none()).map(|o| o.record.clone()).collect();
        for record in open {
            let cid = record.cid();
            let state = self.disputes.lock().unwrap().remove(&cid);
            let next = match state {
                None => self.start(&record)?,
                Some(State::Playing { d, v, awaiting, last }) => self.play(cid, *d, *v, awaiting, last)?,
                Some(State::Conceded) => self.settled_by_user(&record, None)?,
                Some(State::Proved { last }) => self.settled_by_user(&record, Some(last))?,
                Some(State::Waiting { d, at }) => self.wait_timeout(cid, *d, at)?,
                Some(State::Path(p)) => self.path_tick(cid, *p)?,
                Some(s) => Some(s),
            };
            if let Some(s) = next {
                self.disputes.lock().unwrap().insert(cid, s);
            }
        }
        Ok(())
    }

    /// A posted link by name (the txid the pre-signed set fixed).
    fn link(&self, d: &Disputed, name: &str) -> Result<Transaction> {
        self.chain.get_tx(&d.txid(name)).with_context(|| format!("{name} is not on chain"))
    }

    /// If the contract has been escalated (and its input published), read
    /// the claim and decide.
    fn start(&self, record: &lichen_proto::Record) -> Result<Option<State>> {
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
        // a claim whose words break the contract's checks (another
        // contract's memo, another program's image id) takes no search
        let wires = word_wires(&esc, &keys(&claim), Some(d.key(1)))?;
        for c in &d.contract.spec.checks {
            if words[c.word] != c.value {
                let k = claim.iter().position(|j| *j == c.word).context("a checked word outside the claim")?;
                return self.take_by_check(&d, cid, &c.name, wires[k].clone());
            }
        }
        if d.set.contains_key("inputs") {
            let id = d.txid("inputs");
            if confirmed_at(self, &id)?.is_none() {
                // the rest of the input is due within the window, or the hub's timeout
                let at = confirmed_at(self, &esc_id)?.unwrap();
                let p = d.contract.spec.params;
                if self.chain.height()? >= at + u32::from(p.delta + p.delta_prime) {
                    let txid = self.chain.post_terminal(&d.finish("timeout_inputs", vec![])?, &d.set["timeout_inputs"].prevout, Amount::from_sat(2_000))?;
                    self.note(format!("contract {cid}: the input never came; timeout {txid}"));
                    self.close(cid, txid)?;
                    return Ok(Some(State::Done));
                }
                return Ok(None);
            }
            let rest = d.contract.rest_words();
            for (j, w) in rest.iter().zip(read_words(&self.chain.get_tx(&id).context("the inputs")?, &keys(&rest), None)?) {
                words[*j] = w;
            }
        }
        let move1 = read_move(&esc, d.key(1))?;
        let force = if self.dispute_true_claims.load(std::sync::atomic::Ordering::Relaxed) { ForceCondition::ValidInputStepAndHash } else { ForceCondition::No };
        let dir = self.cfg.dir.join("disputes").join(cid.to_string());
        let Some(mut v) = Verifier::start(&d.program, &input_from_words(&words), &dir, &move1, force)? else {
            self.note(format!("contract {cid}: the claim is true; conceding"));
            return Ok(Some(State::Conceded));
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
                _ => return Ok(Some(State::Playing { d: Box::new(d), v: Box::new(v), awaiting: j + 1, last })),
            }
        }
    }

    /// A dispute the user settles: conceded (her timeout pays her, from the
    /// ladder output after move 1) or proved (her proof, from the output
    /// after her last move, `proved`). Once that output is spent, the
    /// contract is closed.
    fn settled_by_user(&self, record: &lichen_proto::Record, proved: Option<u32>) -> Result<Option<State>> {
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
            self.close(cid, op.txid)?;
            return Ok(Some(State::Done));
        }
        Ok(Some(match proved {
            Some(last) => State::Proved { last },
            None => State::Conceded,
        }))
    }

    /// Take the contract with the check `name` on the ladder output after
    /// move 1, re-revealing Alice's signature on the word (`wire`).
    fn take_by_check(&self, d: &Disputed, cid: u32, name: &str, wire: Vec<Vec<u8>>) -> Result<Option<State>> {
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
        Ok(Some(State::Done))
    }

    /// The hub's own spend of `(op, out)` under `tree`'s leaf `leaf_name`,
    /// `wire` below its signature, to its wallet at [`FEERATE`].
    fn spend_leaf(&self, cid: u32, tree: &TapTree, leaf_name: &str, op: OutPoint, out: &TxOut, wire: Vec<Vec<u8>>) -> Result<Transaction> {
        let leaf = tree.leaf(leaf_name)?;
        let kp = contract_keys(&self.cfg.seed, cid).payment;
        let to = self.chain.new_spk()?;
        let build = |fee: Amount| -> Result<Transaction> {
            let mut spend = build_spend(op, &leaf.timelock, vec![TxOut { value: out.value.checked_sub(fee).context("the output can't pay the fee")?, script_pubkey: to.clone() }]);
            let mut w = wire.clone();
            w.push(sign_tapscript(&kp, &spend, 0, std::slice::from_ref(out), &leaf.script)?.as_ref().to_vec());
            spend.input[0].witness = tapscript_witness(&w, &leaf.script, &tree.control_block(leaf_name)?);
            Ok(spend)
        };
        // sized once at no fee, then paid
        let vsize = build(Amount::ZERO)?.vsize() as u64;
        build(Amount::from_sat((vsize + 10) * FEERATE))
    }

    /// Post one of the hub's links (unless it is already there: replayed,
    /// checked to be the same), its child paying from the hub's anchor;
    /// its confirmation height.
    fn post(&self, cid: u32, tx: &Transaction) -> Result<u32> {
        let txid = tx.compute_txid();
        match self.chain.get_tx(&txid) {
            None => {
                let kp = contract_keys(&self.cfg.seed, cid).payment;
                let anchor = anchor_vout(tx, &kp.x_only_public_key().0)?;
                self.chain.post_link(tx, anchor, FEERATE, &|c, p| sign_anchor(&kp, c, p))?;
            }
            Some(posted) => anyhow::ensure!(posted.input.iter().zip(&tx.input).all(|(a, b)| a.witness == b.witness), "{txid} on chain is not the link replayed"),
        }
        let start = std::time::Instant::now();
        loop {
            if let Some(h) = confirmed_at(self, &txid)? {
                return Ok(h);
            }
            anyhow::ensure!(start.elapsed() < std::time::Duration::from_secs(300), "{txid} never confirmed");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    /// Post the hub's move `j`, `msg` signed field by field.
    fn post_move(&self, d: &Disputed, cid: u32, j: u32, msg: &[u8]) -> Result<u32> {
        let keys = move_secrets(&self.cfg.seed, cid, &d.program, j);
        let tx = d.finish(&link_name(j), sign_move(&d.program, j, &keys, msg)?)?;
        self.post(cid, &tx)
    }

    /// One step of a dispute in play.
    fn play(&self, cid: u32, d: Disputed, mut v: Verifier, awaiting: u32, last: u32) -> Result<Option<State>> {
        let (m, p) = (d.contract.m(), d.contract.spec.params);
        let w = u32::from(p.delta + p.delta_prime);
        let id = d.txid(&link_name(awaiting));
        let ours = OutPoint { txid: d.txid(&link_name(awaiting - 1)), vout: 0 };
        let Some(at) = confirmed_at(self, &id)? else {
            if !self.chain.unspent(&ours)? && self.chain.get_tx(&id).is_none() {
                // spent, not by Alice's move: our own timeout, before a restart
                self.note(format!("contract {cid}: already settled by timeout"));
                return Ok(Some(State::Done));
            }
            if self.chain.height()? >= last + w {
                // Alice stopped: the ladder output after the hub's last move times out to it
                let name = format!("timeout_{}", awaiting - 1);
                let txid = self.chain.post_terminal(&d.finish(&name, vec![])?, &d.set[&name].prevout, Amount::from_sat(2_000))?;
                self.note(format!("contract {cid}: the user stopped answering; timeout {txid}"));
                self.close(cid, txid)?;
                return Ok(Some(State::Done));
            }
            return Ok(Some(State::Playing { d: Box::new(d), v: Box::new(v), awaiting, last }));
        };
        let tx = self.chain.get_tx(&id).context("Alice's move")?;
        let signed = read_move(&tx, d.key(awaiting))?;
        if awaiting < m {
            let choice = v.choose(Some(&signed))?;
            let last = self.post_move(&d, cid, awaiting + 1, &choice)?;
            return Ok(Some(State::Playing { d: Box::new(d), v: Box::new(v), awaiting: awaiting + 2, last }));
        }
        // her final move: what BitVMX's verifier says to do
        let link = |name: &str| self.link(&d, name);
        let proves = |rec: &lngap_zk::game::Record| d.proves(rec, &link).map(|p| p.1).unwrap_or(false);
        let verdict = v.verdict(&signed, &proves)?;
        let op = OutPoint { txid: id, vout: 0 };
        if !self.chain.unspent(&op)? && self.chain.get_tx(&d.txid("path_split")).is_none() {
            self.note(format!("contract {cid}: the last step is already settled"));
            return Ok(Some(State::Done));
        }
        match verdict {
            Verdict::Proved => {
                self.note(format!("contract {cid}: the user's last step is valid; the user proves it"));
                Ok(Some(State::Proved { last: m }))
            }
            Verdict::Wait => {
                self.note(format!("contract {cid}: no rule applies, yet the user's step doesn't prove: waiting for the hub's timeout"));
                Ok(Some(State::Waiting { d: Box::new(d), at }))
            }
            Verdict::ReadChallenge => anyhow::bail!("contract {cid}: a read challenge, and the statement has no jump list to settle it"),
            Verdict::Disprove(name, wit) => {
                while self.chain.height()? < at + u32::from(p.delta) {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                let wire = d.rule_wire(&d.contract.rule(m, &name)?, &wit, None, &link)?;
                let leaf_name = format!("disprove_{name}");
                let spend = self.spend_leaf(cid, &d.contract.ladder(m)?, &leaf_name, op, &tx.output[0], wire)?;
                let txid = self.chain.broadcast(&spend).with_context(|| format!("broadcasting {leaf_name}"))?;
                self.note(format!("contract {cid}: {leaf_name} ({} vB)", spend.vsize()));
                self.close(cid, txid)?;
                Ok(Some(State::Done))
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
                Ok(Some(State::Path(Box::new(Posted { d, v, path, pre_y, name, k, at }))))
            }
        }
    }

    /// No rule applied: once her window passes, the last ladder output
    /// times out to the hub.
    fn wait_timeout(&self, cid: u32, d: Disputed, at: u32) -> Result<Option<State>> {
        let (m, p) = (d.contract.m(), d.contract.spec.params);
        let op = OutPoint { txid: d.txid(&link_name(m)), vout: 0 };
        if !self.chain.unspent(&op)? {
            self.note(format!("contract {cid}: settled: the user's last step"));
            self.close(cid, op.txid)?;
            return Ok(Some(State::Done));
        }
        let w = u32::from(p.delta + p.delta_prime);
        if self.chain.height()? < at + w + u32::from(p.delta_prime) {
            return Ok(Some(State::Waiting { d: Box::new(d), at }));
        }
        let name = format!("timeout_{m}");
        let txid = self.chain.post_terminal(&d.finish(&name, vec![])?, &d.set[&name].prevout, Amount::from_sat(2_000))?;
        self.note(format!("contract {cid}: the user's step neither proved nor was disproved; timeout {txid}"));
        self.close(cid, txid)?;
        Ok(Some(State::Done))
    }

    /// The path is posted: answer Alice's challenge of a hop by revealing
    /// it, or, if none comes in her window, take the output with the
    /// path's verdict.
    fn path_tick(&self, cid: u32, s: Posted) -> Result<Option<State>> {
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
                return Ok(Some(State::Done));
            }
            if self.chain.height()? < h_at + u32::from(p.delta) {
                return Ok(Some(State::Path(Box::new(s))));
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
                    return Ok(Some(State::Done));
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
            return Ok(Some(State::Path(Box::new(s))));
        }
        if !self.chain.unspent(&p_op)? {
            if self.chain.get_tx(&d.txid(&hop_name)).is_some() {
                // her challenge, not yet confirmed
                return Ok(Some(State::Path(Box::new(s))));
            }
            self.note(format!("contract {cid}: settled: the hub's path timed out"));
            self.close(cid, p_op.txid)?;
            return Ok(Some(State::Done));
        }
        if self.chain.height()? < at + u32::from(p.delta + p.delta_prime) {
            return Ok(Some(State::Path(Box::new(s))));
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
        Ok(Some(State::Done))
    }
}

impl State {
    pub(crate) fn describe(&self) -> String {
        match self {
            State::Conceded => "the claim is true: conceded".into(),
            State::Playing { awaiting, .. } => format!("disputing: awaiting the user's move {awaiting}"),
            State::Proved { .. } => "the user's last step is valid: the user proves it".into(),
            State::Waiting { .. } => "no rule applies: waiting for the hub's timeout".into(),
            State::Path(p) => format!("the hub's path is posted ({}, {} chunks): the user's window to challenge a hop", p.name, p.k),
            State::Done => "settled".into(),
        }
    }
}

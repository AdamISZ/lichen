//! The hub's side of a dispute, run by its watcher, one step per tick.
//!
//! When a contract's escalation appears on chain, the hub reads Alice's
//! claim (move 1 with the claim block) and her input words, and runs the
//! verifier on them. If her claim is true, an honest hub does not dispute
//! it: it lets her timeout pay her. Otherwise it plays BitVMX's search,
//! posting its choice after each of her midpoints; at the end it reads her
//! record and disproves it with the rule that applies. If she stops
//! answering, its timeout pays it.
//!
//! Nothing of a dispute is kept but the contract: after a restart the hub
//! rebuilds its verifier from the claim on chain and replays the moves
//! already made (each of its own checked against what it would play now),
//! then carries on.

use anyhow::{Context, Result};
use bitcoin::{Amount, OutPoint, TxOut};
use emulator::decision::challenge::ForceCondition;
use lichen_proto::{input_from_words, link_name, Disputed, FEERATE};
use lngap_btc::sighash::sign_tapscript;
use lngap_btc::tx::build_spend;
use lngap_btc::witness::tapscript_witness;
use lngap_pos::rebut::wots_wire;
use lngap_sessions::contract::move_message;
use lngap_sessions::play::{disprove_witness, move_wire, read_move, read_words, word_wires, Verdict, Verifier};

use crate::{contract_keys, move_secret, Inner};

/// A dispute's state at the hub.
pub(crate) enum State {
    /// The claim is true: the hub lets Alice's timeout pay her.
    Conceded,
    /// Playing: Alice's move `awaiting` is due; the hub's last link
    /// confirmed at `last`.
    Playing { d: Box<Disputed>, v: Box<Verifier>, awaiting: u32, last: u32 },
    Done,
}

fn confirmed_at(inner: &Inner, txid: &bitcoin::Txid) -> Result<Option<u32>> {
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
                Some(s) => Some(s),
            };
            if let Some(s) = next {
                self.disputes.lock().unwrap().insert(cid, s);
            }
        }
        Ok(())
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
                    eprintln!("hub: contract {cid}: the input never came; timeout {txid}");
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
        let force = if self.cfg.dispute_true_claims { ForceCondition::ValidInputStepAndHash } else { ForceCondition::No };
        let dir = self.cfg.dir.join("disputes").join(cid.to_string());
        let Some(mut v) = Verifier::start(&d.program, &input_from_words(&words), &dir, &move1, force)? else {
            eprintln!("hub: contract {cid}: the claim is true; conceding");
            return Ok(Some(State::Conceded));
        };
        eprintln!("hub: contract {cid}: disputing the claim");
        // replay what is already on chain, then carry on
        let m = d.contract.m();
        let mut alice: Option<Vec<u8>> = None;
        let mut j = 2;
        loop {
            let choice = v.choose(alice.as_deref())?;
            let last = self.post_move(&d, cid, j, &move_message(&choice))?;
            let next = link_name(j + 1);
            match confirmed_at(self, &d.txid(&next))? {
                Some(_) if j + 1 < m => {
                    alice = Some(read_move(&self.chain.get_tx(&d.txid(&next)).context("Alice's move")?, d.key(j + 1))?);
                    j += 2;
                }
                _ => return Ok(Some(State::Playing { d: Box::new(d), v: Box::new(v), awaiting: j + 1, last })),
            }
        }
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
        let tree = d.contract.ladder(1)?;
        let leaf = tree.leaf(name)?;
        let fee = Amount::from_sat(1_000 * FEERATE);
        let mut spend = build_spend(OutPoint { txid: id, vout: 0 }, &leaf.timelock, vec![TxOut { value: out.value - fee, script_pubkey: self.chain.new_spk()? }]);
        let mut w = wire;
        w.push(sign_tapscript(&contract_keys(&self.cfg.seed, cid).payment, &spend, 0, std::slice::from_ref(&out), &leaf.script)?.as_ref().to_vec());
        spend.input[0].witness = tapscript_witness(&w, &leaf.script, &tree.control_block(name)?);
        let txid = self.chain.broadcast(&spend).with_context(|| format!("the {name} check"))?;
        eprintln!("hub: contract {cid}: the claim breaks the {name} check; taken ({} vB)", spend.vsize());
        self.close(cid, txid)?;
        Ok(Some(State::Done))
    }

    /// Post the hub's move `j` (unless it is already there: replayed,
    /// checked to be the same); its confirmation height.
    fn post_move(&self, d: &Disputed, cid: u32, j: u32, msg: &[u8]) -> Result<u32> {
        let sig = move_secret(&self.cfg.seed, cid, j, d.contract.m()).sign(msg)?;
        let tx = d.finish(&link_name(j), wots_wire(&sig))?;
        match self.chain.get_tx(&tx.compute_txid()) {
            None => self.chain.post_link(&tx, 1, FEERATE)?,
            Some(posted) => anyhow::ensure!(posted.input[0].witness == tx.input[0].witness, "move {j} on chain is not the move replayed"),
        }
        let start = std::time::Instant::now();
        loop {
            if let Some(h) = confirmed_at(self, &tx.compute_txid())? {
                return Ok(h);
            }
            anyhow::ensure!(start.elapsed() < std::time::Duration::from_secs(300), "move {j} never confirmed");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
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
                eprintln!("hub: contract {cid}: already settled by timeout");
                return Ok(Some(State::Done));
            }
            if self.chain.height()? >= last + w {
                // Alice stopped: the ladder output after the hub's last move times out to it
                let name = format!("timeout_{}", awaiting - 1);
                let txid = self.chain.post_terminal(&d.finish(&name, vec![])?, &d.set[&name].prevout, Amount::from_sat(2_000))?;
                eprintln!("hub: contract {cid}: Alice stopped answering; timeout {txid}");
                self.close(cid, txid)?;
                return Ok(Some(State::Done));
            }
            return Ok(Some(State::Playing { d: Box::new(d), v: Box::new(v), awaiting, last }));
        };
        let tx = self.chain.get_tx(&id).context("Alice's move")?;
        let signed = read_move(&tx, d.key(awaiting))?;
        if awaiting < m {
            let choice = v.choose(Some(&signed))?;
            let last = self.post_move(&d, cid, awaiting + 1, &move_message(&choice))?;
            return Ok(Some(State::Playing { d: Box::new(d), v: Box::new(v), awaiting: awaiting + 2, last }));
        }
        // her record: the disprove that applies, after its delay
        match v.verdict(&signed, &d.final_disproves()?)? {
            Verdict::Proved => {
                eprintln!("hub: contract {cid}: her last step is valid; she proves it");
                Ok(Some(State::Done))
            }
            Verdict::Disprove(name) => {
                if !self.chain.unspent(&OutPoint { txid: id, vout: 0 })? {
                    eprintln!("hub: contract {cid}: the last step is already settled");
                    return Ok(Some(State::Done));
                }
                while self.chain.height()? < at + u32::from(p.delta) {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                let prior = self.chain.get_tx(&d.txid(&link_name(m - 1))).context("move m - 1")?;
                let file = [move_wire(&prior, d.key(m - 1))?, move_wire(&tx, d.key(m))?].concat();
                let e = v.entries.last().unwrap().clone();
                let state = v.entries[v.entries.len() - 2].state;
                let mut wit = disprove_witness(&d.contract, &d.program, &name, &state, &e.record.context("the record")?, &v.claim(), file)?;
                let tree = d.contract.ladder(m)?;
                let leaf_name = format!("disprove_{name}");
                let leaf = tree.leaf(&leaf_name)?;
                let out = tx.output[0].clone();
                let fee = Amount::from_sat(60_000 * FEERATE);
                let mut spend = build_spend(OutPoint { txid: id, vout: 0 }, &leaf.timelock, vec![TxOut { value: out.value - fee, script_pubkey: self.chain.new_spk()? }]);
                wit.push(sign_tapscript(&contract_keys(&self.cfg.seed, cid).payment, &spend, 0, std::slice::from_ref(&out), &leaf.script)?.as_ref().to_vec());
                spend.input[0].witness = tapscript_witness(&wit, &leaf.script, &tree.control_block(&leaf_name)?);
                let txid = self.chain.broadcast(&spend).with_context(|| format!("broadcasting {leaf_name}"))?;
                eprintln!("hub: contract {cid}: {leaf_name} ({} vB)", spend.vsize());
                self.close(cid, txid)?;
                Ok(Some(State::Done))
            }
        }
    }
}

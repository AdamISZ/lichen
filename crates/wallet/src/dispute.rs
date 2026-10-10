//! Alice's side of a dispute: when the hub won't fold her withdrawal, she
//! enforces it on Bitcoin. She escalates (her claim on chain with its
//! input words), then plays BitVMX's search move by move, reading the
//! hub's moves from the chain; if the hub stops answering she takes the
//! timeout; if she reaches the last step and no disprove comes, she proves
//! it. Either way she is paid `b` (in bits, from 512 sats up) and both
//! reserves, and sweeps them to her wallet.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxOut, Txid};
use lichen_chain::Chain;
use lichen_proto::{link_name, Disputed, Statement, FEERATE};
use lngap_btc::sighash::sign_tapscript;
use lngap_btc::witness::tapscript_witness;
use lngap_pos::rebut::wots_wire;
use lngap_sessions::contract::move_message;
use lngap_sessions::play::{move_wire, read_move, Prover};
use lngap_sessions::session::{bit_tree, reserve_tree};
use lngap_zk::final_d60::{input_message, input_words};
use lngap_zk::game::final_witness;

use crate::Wallet;

/// How a dispute ended for Alice.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Outcome {
    /// Stopped on request (`pause_after`); run again to resume.
    Paused,
    /// The hub stopped answering; her timeout paid her (its txid).
    HubTimedOut(Txid),
    /// She proved the disputed step; paid (the proof's txid).
    Proved(Txid),
    /// The hub disproved her claim (or she lost by timeout).
    Lost,
}

/// Her winnings swept to her wallet: the sweep's txid and what it pays.
pub type Swept = Option<(Txid, Amount)>;

/// How long to wait on the chain before giving up (the test's blocks come
/// fast; a real dispute waits blocks, not seconds).
const PATIENCE: Duration = Duration::from_secs(300);

/// The height a transaction confirmed at, if it has.
fn confirmed_at(chain: &Chain, txid: &Txid) -> Result<Option<u32>> {
    let c = chain.confirmations(txid)?;
    (c > 0).then(|| chain.height().map(|h| h + 1 - c)).transpose()
}

fn wait_confirmed(chain: &Chain, txid: &Txid) -> Result<u32> {
    let start = Instant::now();
    loop {
        if let Some(h) = confirmed_at(chain, txid)? {
            return Ok(h);
        }
        ensure!(start.elapsed() < PATIENCE, "{txid} never confirmed");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// What happened to the output a party's last link created.
enum Next {
    /// The other side's link, as expected.
    Link(Transaction),
    /// It didn't answer by the deadline: the timeout is ours.
    Deadline,
    /// Something else spent the output: a check or a disprove.
    Taken,
}

/// Wait for the other side's link `txid` spending `ours`, until the chain
/// reaches `deadline`.
fn wait_link(chain: &Chain, txid: &Txid, ours: &OutPoint, deadline: u32) -> Result<Next> {
    let start = Instant::now();
    loop {
        if confirmed_at(chain, txid)?.is_some() {
            return Ok(Next::Link(chain.get_tx(txid).context("the link")?));
        }
        if !chain.unspent(ours)? {
            // spent, and (just checked) not by the link
            std::thread::sleep(Duration::from_millis(300));
            if confirmed_at(chain, txid)?.is_none() && chain.get_tx(txid).is_none() {
                return Ok(Next::Taken);
            }
            continue;
        }
        if chain.height()? >= deadline {
            return Ok(Next::Deadline);
        }
        ensure!(start.elapsed() < PATIENCE, "the chain stalled");
        std::thread::sleep(Duration::from_millis(100));
    }
}

impl Wallet {
    /// Enforce a withdrawal of `b` from contract `cid` on Bitcoin, the
    /// claim's `input` the statement program's (for the mock, `(b, c)`;
    /// for Groth16, the verifier's input for her proof). Blocks until the
    /// dispute ends; on a win, sweeps her winnings to `chain`'s wallet.
    ///
    /// Resumable: the claim is kept with the contract, and what is
    /// already on chain is replayed, not posted again.
    pub fn dispute(&mut self, chain: &Chain, statement: &Statement, dir: &Path, cid: u32, b: u32, input: &[u8]) -> Result<(Outcome, Swept)> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        ensure!(self.contracts[k].closed.is_none(), "contract {cid} is closed");
        let d = Disputed::new(&self.contracts[k].record, statement, dir)?;
        let words = input_words(input);
        ensure!(words.len() == d.contract.spec.inputs.len(), "the input is {} words, the statement's {}", words.len(), d.contract.spec.inputs.len());
        ensure!(words[d.contract.spec.b_word] == b, "the input claims {}, not {b}", words[d.contract.spec.b_word]);
        // a claim that breaks a check (the memo, the image id) would lose
        // everything to it: refuse it here
        if !self.unchecked_claims {
            for c in &d.contract.spec.checks {
                ensure!(words[c.word] == c.value, "the input's {} is {:#x}, the contract's {:#x}", c.name, words[c.word], c.value);
            }
        }
        match &self.contracts[k].claim {
            Some((b0, i0)) => ensure!(*b0 == b && *i0 == hex::encode(input), "contract {cid} is already disputed with another claim"),
            None => {
                self.contracts[k].claim = Some((b, hex::encode(input)));
                self.save()?;
            }
        }
        let held = self.contracts[k].clone();
        if let Some(o) = held.payout.clone() {
            // the payout is posted: what's left is the sweep
            return self.won(chain, &d, k, b, o);
        }
        let (m, p) = (d.contract.m(), d.contract.spec.params);
        let w = u32::from(p.delta + p.delta_prime);
        let word_wire = |js: &[usize]| -> Result<Vec<Vec<u8>>> {
            let mut wire = vec![];
            for &j in js.iter().rev() {
                wire.extend(wots_wire(&self.input_secret(&held.nonce, j).sign(&input_message(words[j]))?));
            }
            Ok(wire)
        };
        let mut prover = Prover::start(&d.program, input, &dir.join(format!("dispute-{cid}")))?;
        let pause = self.pause_after;
        // escalate: move 1 with the claim's words; then the rest of the input
        let mut wire = word_wire(&d.contract.claim_words())?;
        wire.extend(wots_wire(&self.move_secret(&held.nonce, 1, m).sign(&move_message(prover.last()))?));
        let mut last = self.post(chain, &d, "escalate", wire)?;
        let mut last_id = d.txid("escalate");
        if d.set.contains_key("inputs") {
            last = self.post(chain, &d, "inputs", word_wire(&d.contract.rest_words())?)?;
            last_id = d.txid("inputs");
        }
        // the search: the hub moves at even depths
        for j in (2..m).step_by(2) {
            let tx = match wait_link(chain, &d.txid(&link_name(j)), &OutPoint { txid: last_id, vout: 0 }, last + w)? {
                Next::Link(tx) => tx,
                Next::Deadline => {
                    // the hub didn't answer in time: the ladder output after move j - 1 times out to her
                    let name = format!("timeout_{}", j - 1);
                    let txid = chain.post_terminal(&d.finish(&name, vec![])?, &d.set[&name].prevout, Amount::from_sat(2_000))?;
                    return self.paid(chain, &d, k, b, Outcome::HubTimedOut(txid));
                }
                Next::Taken => {
                    self.contracts[k].closed = Some(last_id);
                    self.save()?;
                    return Ok((Outcome::Lost, None));
                }
            };
            let next = prover.answer(&read_move(&tx, d.key(j))?)?;
            let sig = self.move_secret(&held.nonce, j + 1, m).sign(&move_message(&next))?;
            last = self.post(chain, &d, &link_name(j + 1), wots_wire(&sig))?;
            last_id = d.txid(&link_name(j + 1));
            if pause.is_some_and(|p| j + 1 >= p) && j + 1 < m {
                return Ok((Outcome::Paused, None));
            }
        }
        // the last step: unless the hub disproves it within its window, prove it
        while chain.height()? < last + w {
            std::thread::sleep(Duration::from_millis(100));
        }
        let (prior_link, last_link) = (chain.get_tx(&d.txid(&link_name(m - 1))).context("move m - 1")?, chain.get_tx(&d.txid(&link_name(m))).context("move m")?);
        if !chain.unspent(&OutPoint { txid: last_link.compute_txid(), vout: 0 })? {
            self.contracts[k].closed = Some(last_link.compute_txid());
            self.save()?;
            return Ok((Outcome::Lost, None));
        }
        let e = prover.last().clone();
        let state = prover.entries[prover.entries.len() - 2].state;
        let rec = e.record.context("the last move's record")?;
        let class = lngap_zk::guard::key_of(rec.read.opcode, rec.read.micro).context("the step's class")?;
        let name = format!("prove_{class}");
        let file = [move_wire(&prior_link, d.key(m - 1))?, move_wire(&last_link, d.key(m))?].concat();
        let proof = d.finish(&name, [final_witness(&state, &rec), file].concat())?;
        let fee = Amount::from_sat((proof.vsize() as u64 + 200) * FEERATE);
        let txid = chain.post_terminal(&proof, &d.set[&name].prevout, fee)?;
        self.paid(chain, &d, k, b, Outcome::Proved(txid))
    }

    /// The payout is posted: keep it (a resumed dispute goes straight to
    /// the sweep), then sweep.
    fn paid(&mut self, chain: &Chain, d: &Disputed, k: usize, b: u32, outcome: Outcome) -> Result<(Outcome, Swept)> {
        self.contracts[k].payout = Some(outcome.clone());
        self.save()?;
        self.won(chain, d, k, b, outcome)
    }

    /// Post a link of the chain, paying with a child, unless it is already
    /// there (a resumed dispute replays it); its confirmation height.
    fn post(&self, chain: &Chain, d: &Disputed, name: &str, wire: Vec<Vec<u8>>) -> Result<u32> {
        let tx = d.finish(name, wire)?;
        let id = tx.compute_txid();
        if chain.get_tx(&id).is_none() {
            chain.post_link(&tx, 1, FEERATE)?;
        } else {
            // posted before: it must be the move we would make now
            let posted = chain.get_tx(&id).context("the link")?;
            // (one-time signatures are deterministic, and both 2-of-2
            // signatures were made at the opening: the same witness)
            ensure!(posted.input[0].witness == tx.input[0].witness, "{name} on chain is not the move replayed");
        }
        wait_confirmed(chain, &id)
    }

    /// She won: once the payout confirms and her outputs' delay passes,
    /// sweep her bit outputs and the reserves to her wallet.
    fn won(&mut self, chain: &Chain, d: &Disputed, k: usize, b: u32, outcome: Outcome) -> Result<(Outcome, Swept)> {
        let txid = match &outcome {
            Outcome::HubTimedOut(t) | Outcome::Proved(t) => *t,
            Outcome::Lost | Outcome::Paused => bail!("not a win"),
        };
        let at = wait_confirmed(chain, &txid)?;
        let payout = chain.get_tx(&txid).context("the payout")?;
        let held = self.contracts[k].clone();
        let t = &d.contract.spec.terms;
        let ctx = d.contract.ctx();
        let b_key = d.contract.b_key().clone();
        let b_sig = self.input_secret(&held.nonce, d.contract.spec.b_word).sign(&input_message(b))?;
        let kp = self.contract_keys(&held.nonce).payment;
        // her outputs: the bits set in b, then the reserves
        let mut spends = vec![];
        for i in t.low_bits..t.bits {
            if (b >> i) & 1 == 1 {
                spends.push((i - t.low_bits, bit_tree(&ctx, i, &b_key)?, format!("alice_bit_{i}"), true));
            }
        }
        spends.push((t.bits - t.low_bits, reserve_tree(&ctx, t, &b_key)?, "alice_reserve".to_string(), false));
        let delta = d.contract.spec.params.delta;
        while chain.height()? < at + u32::from(delta) {
            std::thread::sleep(Duration::from_millis(100));
        }
        let prevouts: Vec<TxOut> = spends.iter().map(|s| payout.output[s.0 as usize].clone()).collect();
        let total: Amount = prevouts.iter().map(|o| o.value).sum();
        let fee = Amount::from_sat(400 * spends.len() as u64 * FEERATE);
        let ins: Vec<(OutPoint, Sequence)> = spends.iter().map(|s| (OutPoint { txid, vout: s.0 }, Sequence::from_height(delta))).collect();
        let mut sweep = lngap_btc::tx::build_tx(&ins, vec![TxOut { value: total - fee, script_pubkey: chain.new_spk()? }], bitcoin::absolute::LockTime::ZERO);
        for (n, (_, tree, name, with_b)) in spends.iter().enumerate() {
            let leaf = tree.leaf(name)?;
            let mut w = if *with_b { wots_wire(&b_sig) } else { vec![] };
            w.push(sign_tapscript(&kp, &sweep, n, &prevouts, &leaf.script)?.as_ref().to_vec());
            sweep.input[n].witness = tapscript_witness(&w, &leaf.script, &tree.control_block(name)?);
        }
        let swept = chain.broadcast(&sweep).context("sweeping the winnings")?;
        self.contracts[k].closed = Some(txid);
        self.save()?;
        Ok((outcome, Some((swept, total - fee))))
    }
}

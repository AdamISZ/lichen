//! Alice's side of a dispute: when the hub won't fold her withdrawal, she
//! enforces it on Bitcoin. She escalates (her claim on chain with its
//! input words), then plays BitVMX's search move by move, reading the
//! hub's moves from the chain; if the hub stops answering she takes the
//! timeout; if she reaches the last step and no disprove comes, she proves
//! it. Under a jump list the hub may instead post a path through its
//! history: she checks it against her own and challenges the first false
//! hop, which the hub can't reveal (her timeout pays her). Either way she
//! is paid `b` (in bits, from 512 sats up) and both reserves less the
//! links' floors, and sweeps them to her wallet.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxOut, Txid};
use lichen_chain::Chain;
use lichen_proto::{anchor_vout, link_name, sign_anchor, sign_move, Disputed, Patience, Stall, Statement, FEERATE};
use lngap_btc::sighash::sign_tapscript;
use lngap_btc::witness::tapscript_witness;
use lngap_ladder::script::wots_wire;
use lngap_ladder::tail::CHUNKS;
use lngap_sessions::play::{read_move, read_move_in, Prover};
use lngap_sessions::session::{bit_tree, reserve_tree};
use lngap_zk::final_d60::{input_message, input_words};

use crate::Wallet;

/// How a dispute ended for Alice.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Outcome {
    /// Stopped on request (`pause_after`); run again to resume.
    Paused,
    /// The hub stopped answering; her timeout paid her (its txid).
    HubTimedOut(Txid),
    /// She showed a hop of the hub's path false (it couldn't reveal it):
    /// her timeout paid her.
    PathRefuted(Txid),
    /// She proved the disputed step; paid (the proof's txid).
    Proved(Txid),
    /// The hub disproved her claim (or she lost by timeout).
    Lost,
}

/// Her winnings swept to her wallet: the sweep's txid and what it pays.
pub type Swept = Option<(Txid, Amount)>;


/// The height a transaction confirmed at, if it has.
fn confirmed_at(chain: &Chain, txid: &Txid) -> Result<Option<u32>> {
    let c = chain.confirmations(txid)?;
    (c > 0).then(|| chain.height().map(|h| h + 1 - c)).transpose()
}

fn wait_confirmed(chain: &Chain, txid: &Txid) -> Result<u32> {
    let patience = Patience::new(chain.height()?, chain.network);
    loop {
        if let Some(h) = confirmed_at(chain, txid)? {
            return Ok(h);
        }
        ensure!(!patience.expired(chain.height()?), "{txid} never confirmed");
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
    let mut stall = Stall::new(chain.height()?, chain.network);
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
        let h = chain.height()?;
        if h >= deadline {
            return Ok(Next::Deadline);
        }
        ensure!(!stall.stalled(h), "the chain stalled");
        std::thread::sleep(Duration::from_millis(100));
    }
}

impl Wallet {
    fn step(&self, msg: String) {
        if let Some(f) = &self.progress {
            f(msg);
        }
    }

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
        // escalating waits to_self_delay after the contract's funding
        let funded = held.record.funding.txid;
        let mut stall = Stall::new(chain.height()?, chain.network);
        while chain.confirmations(&funded)? < u32::from(p.to_self_delay) {
            ensure!(!stall.stalled(chain.height()?), "the chain stalled before the contract's funding was deep enough to escalate");
            std::thread::sleep(Duration::from_millis(200));
        }
        let mut prover = Prover::start_with(&d.program, input, &dir.join(format!("dispute-{cid}")), self.lie.clone())?;
        let pause = self.pause_after;
        // escalate: move 1 with the claim's words; then the rest of the input
        let mut wire = word_wire(&d.contract.claim_words())?;
        wire.extend(sign_move(&d.program, 1, &self.move_secrets(&held.nonce, &d.program, 1), prover.last())?);
        let mut last = self.post(chain, &d, &held.nonce, "escalate", wire)?;
        self.step(format!("escalated: the claim of {b} sats on chain (move 1 of {m})"));
        let mut last_id = d.txid("escalate");
        if d.set.contains_key("inputs") {
            last = self.post(chain, &d, &held.nonce, "inputs", word_wire(&d.contract.rest_words())?)?;
            last_id = d.txid("inputs");
            self.step("the rest of the claim's input published".into());
        }
        // the search: the hub moves at even depths
        for j in (2..m).step_by(2) {
            let tx = match wait_link(chain, &d.txid(&link_name(j)), &OutPoint { txid: last_id, vout: 0 }, last + w)? {
                Next::Link(tx) => tx,
                Next::Deadline => {
                    // the hub didn't answer in time: the ladder output after move j - 1 times out to her
                    self.step(format!("the hub didn't answer move {} in time: the user's timeout pays", j - 1));
                    let name = format!("timeout_{}", j - 1);
                    let txid = chain.post_terminal(&d.finish(&name, vec![])?, &d.set[&name].prevout, Amount::from_sat(2_000))?;
                    return self.paid(chain, &d, k, b, Outcome::HubTimedOut(txid));
                }
                Next::Taken => {
                    self.step("the user's output was taken (a check or a disprove): the claim lost".into());
                    self.contracts[k].closed = Some(last_id);
                    self.save()?;
                    return Ok((Outcome::Lost, None));
                }
            };
            self.step(format!("the hub chose a half (move {j})"));
            let next = prover.answer(&read_move(&tx, d.key(j))?)?;
            let wire = sign_move(&d.program, j + 1, &self.move_secrets(&held.nonce, &d.program, j + 1), &next)?;
            last = self.post(chain, &d, &held.nonce, &link_name(j + 1), wire)?;
            last_id = d.txid(&link_name(j + 1));
            self.step(if j + 1 == m { format!("move {m}: the record of the disputed step") } else { format!("move {}: the next midpoint", j + 1) });
            if pause.is_some_and(|p| j + 1 >= p) && j + 1 < m {
                return Ok((Outcome::Paused, None));
            }
        }
        // the last step: the hub may disprove it (after a delay) or post a
        // path against it (at once); if neither comes in her window, she
        // proves it
        let last_op = OutPoint { txid: last_id, vout: 0 };
        while chain.unspent(&last_op)? && chain.height()? < last + w {
            std::thread::sleep(Duration::from_millis(100));
        }
        if !chain.unspent(&last_op)? {
            if chain.get_tx(&d.txid("path_split")).is_some() {
                return self.answer_path(chain, &d, k, b, &prover);
            }
            self.step("the hub disproved the last step: the claim lost".into());
            self.contracts[k].closed = Some(last_id);
            self.save()?;
            return Ok((Outcome::Lost, None));
        }
        let rec = lngap_ladder::moves::View { s: &d.program.schedule, msgs: &prover.msgs }.record();
        let link = |name: &str| chain.get_tx(&d.txid(name)).with_context(|| format!("{name} is not on chain"));
        let (name, ok) = d.proves(&rec, &link)?;
        ensure!(ok, "the last step's proof ({name}) doesn't spend on the moves posted");
        let wire = d.rule_wire(&d.contract.rule(m, &name)?, &[], None, &link)?;
        let proof = d.finish(&name, wire)?;
        let fee = Amount::from_sat((proof.vsize() as u64 + 200) * FEERATE);
        let txid = chain.post_terminal(&proof, &d.set[&name].prevout, fee)?;
        self.step(format!("no disprove came: the last step proved ({name}): paid"));
        self.paid(chain, &d, k, b, Outcome::Proved(txid))
    }

    /// Under a jump list, the hub posted a path against her last step: if a
    /// hop of it isn't in her history, challenge it (the hub can't reveal
    /// it: her timeout pays her); if it is genuine, the hub's verdict
    /// takes the output, unless it never posts it. If the hub never
    /// finishes posting the path, her timeout pays her.
    fn answer_path(&mut self, chain: &Chain, d: &Disputed, k: usize, b: u32, prover: &Prover) -> Result<(Outcome, Swept)> {
        let p = d.contract.spec.params;
        let w = u32::from(p.delta + p.delta_prime);
        let nonce = self.contracts[k].nonce.clone();
        let split_at = wait_confirmed(chain, &d.txid("path_split"))?;
        self.step("the hub is posting a path against the last step".into());
        // the hub's combine of n chunks, or her timeout on the split
        let carrier = OutPoint { txid: d.txid("path_split"), vout: 0 };
        let mut stall = Stall::new(chain.height()?, chain.network);
        let (n, comb, comb_at) = loop {
            if let Some(n) = (1..=CHUNKS).find(|n| chain.get_tx(&d.txid(&format!("combine_{n}"))).is_some()) {
                let id = d.txid(&format!("combine_{n}"));
                let at = wait_confirmed(chain, &id)?;
                break (n, chain.get_tx(&id).context("the combine")?, at);
            }
            if chain.unspent(&carrier)? && chain.height()? >= split_at + w + u32::from(p.delta_prime) {
                self.step("the hub never finished its path: the user's timeout pays".into());
                let txid = chain.post_terminal(&d.finish("timeout_path_split", vec![])?, &d.set["timeout_path_split"].prevout, Amount::from_sat(2_000))?;
                return self.paid(chain, d, k, b, Outcome::HubTimedOut(txid));
            }
            ensure!(!stall.stalled(chain.height()?), "the chain stalled");
            std::thread::sleep(Duration::from_millis(100));
        };
        let tail = d.tail()?;
        let chunks: Vec<Vec<u8>> = (0..n).map(|c| read_move_in(&comb, c, &tail.path[c])).collect::<Result<_>>()?;
        let p_op = OutPoint { txid: comb.compute_txid(), vout: 0 };
        match prover.check_path(&chunks)? {
            Some(i) => {
                self.step(format!("hop {i} of the hub's path isn't in the user's history: challenging it"));
                let hop = format!("hop_{n}");
                let wire = wots_wire(&self.hop_secret(&nonce, n).sign(&[i as u8])?);
                let hop_at = self.post(chain, d, &nonce, &hop, wire)?;
                let h_op = OutPoint { txid: d.txid(&hop), vout: 0 };
                while chain.unspent(&h_op)? && chain.height()? < hop_at + w {
                    std::thread::sleep(Duration::from_millis(100));
                }
                if !chain.unspent(&h_op)? {
                    self.step("the hub revealed the hop: the claim lost".into());
                    self.contracts[k].closed = Some(h_op.txid);
                    self.save()?;
                    return Ok((Outcome::Lost, None));
                }
                let name = format!("timeout_{hop}");
                let txid = chain.post_terminal(&d.finish(&name, vec![])?, &d.set[&name].prevout, Amount::from_sat(2_000))?;
                self.step("the hub couldn't reveal the hop: the user's timeout pays".into());
                self.paid(chain, d, k, b, Outcome::PathRefuted(txid))
            }
            None => {
                self.step("the hub's path is genuine: its verdict will take the output".into());
                while chain.unspent(&p_op)? && chain.height()? < comb_at + w + u32::from(p.delta_prime) {
                    std::thread::sleep(Duration::from_millis(100));
                }
                if !chain.unspent(&p_op)? {
                    self.step("the hub's path proved its verdict: the claim lost".into());
                    self.contracts[k].closed = Some(p_op.txid);
                    self.save()?;
                    return Ok((Outcome::Lost, None));
                }
                let name = format!("timeout_combine_{n}");
                let txid = chain.post_terminal(&d.finish(&name, vec![])?, &d.set[&name].prevout, Amount::from_sat(2_000))?;
                self.step("the hub never posted its verdict: the user's timeout pays".into());
                self.paid(chain, d, k, b, Outcome::HubTimedOut(txid))
            }
        }
    }

    /// The payout is posted: keep it (a resumed dispute goes straight to
    /// the sweep), then sweep.
    fn paid(&mut self, chain: &Chain, d: &Disputed, k: usize, b: u32, outcome: Outcome) -> Result<(Outcome, Swept)> {
        self.contracts[k].payout = Some(outcome.clone());
        self.save()?;
        self.won(chain, d, k, b, outcome)
    }

    /// Post a link of the chain, paying with a child from her anchor,
    /// unless it is already there (a resumed dispute replays it); its
    /// confirmation height.
    fn post(&self, chain: &Chain, d: &Disputed, nonce: &str, name: &str, wire: Vec<Vec<u8>>) -> Result<u32> {
        let tx = d.finish(name, wire)?;
        let id = tx.compute_txid();
        if chain.get_tx(&id).is_none() {
            let kp = self.contract_keys(nonce).payment;
            let anchor = anchor_vout(&tx, &kp.x_only_public_key().0)?;
            chain.post_link(&tx, anchor, FEERATE, &|c, p| sign_anchor(&kp, c, p))?;
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
            Outcome::HubTimedOut(t) | Outcome::Proved(t) | Outcome::PathRefuted(t) => *t,
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
        self.step(format!("swept {} sats to the user's wallet", (total - fee).to_sat()));
        self.contracts[k].closed = Some(txid);
        self.save()?;
        Ok((outcome, Some((swept, total - fee))))
    }
}

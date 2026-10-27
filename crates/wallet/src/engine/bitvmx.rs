//! Alice's side of a BitVMX dispute ([`super::Engine::run`] dispatches
//! here). She escalates (her claim on chain with its input words), then
//! plays BitVMX's search move by move, reading the hub's moves from the
//! chain; if the hub stops answering she takes the timeout; if she reaches
//! the last step and no disprove comes, she proves it. Under a jump list
//! the hub may instead post a path through its history: she checks it
//! against her own and challenges the first false hop, which the hub can't
//! reveal (her timeout pays her).
//!
//! Also her BitVMX keys: their secrets ([`Secrets`], under her contract's
//! seed), and the keys an opening exchanges ([`request_keys`],
//! [`record_keys`]).

use std::path::Path;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use bitcoin::{OutPoint, Txid};
use lichen_chain::{Chain, Net};
use lichen_proto::bitvmx::{all_moves, link_name, sign_move, tail_keys, Disputed, Site};
use lichen_proto::{BitVmxKeys, BitVmxOffer, BitVmxRequest, DisputeKeys, Record, Stall, Statement};
use lngap_ladder::script::wots_wire;
use lngap_ladder::tail::CHUNKS;
use lngap_lamport::winternitz::{WotsParams, WotsSecret};
use lngap_sessions::contract::Program;
use lngap_sessions::play::{read_move, read_move_in, Prover};
use lngap_zk::final_d60::{input_message, input_words};

use super::{wait_confirmed, wait_link, ContractSecrets, Engine, Next, Outcome, WalletSigner};

/// Her one-time secrets for a BitVMX contract's dispute.
pub trait Secrets {
    /// Her move keys for depth `d`, one per field.
    fn move_secrets(&self, program: &Program, d: u32) -> Vec<WotsSecret>;
    /// Her signature on input word `j`, of value `word`, as a witness wire.
    fn input_wire(&self, j: usize, word: u32) -> Result<Vec<Vec<u8>>>;
    /// Her key for her choice of hop against a path of `k` chunks.
    fn hop_secret(&self, k: usize) -> WotsSecret;
}

impl ContractSecrets {
    /// The entropy of her key for field `f` of depth `d`.
    pub fn move_entropy(&self, d: u32, f: usize) -> [u8; 32] {
        self.wots(&format!("move/{d}/{f}"))
    }
    /// The entropy of her key for input word `j`.
    pub fn input_entropy(&self, j: usize) -> [u8; 32] {
        self.wots(&format!("input/{j}"))
    }
    /// The entropy of her key for her choice of hop against `k` chunks.
    pub fn hop_entropy(&self, k: usize) -> [u8; 32] {
        self.wots(&format!("hop/{k}"))
    }
    /// Her key for input word `j`.
    pub fn input_secret(&self, j: usize) -> WotsSecret {
        WotsSecret::from_entropy(lngap_zk::final_d60::input_key_params(), self.input_entropy(j))
    }
    /// Her move keys for depth `d`, one per field.
    pub fn move_secrets(&self, program: &Program, d: u32) -> Vec<WotsSecret> {
        program.field_bytes(d).into_iter().enumerate().map(|(f, n)| WotsSecret::from_entropy(WotsParams::for_bytes(n), self.move_entropy(d, f))).collect()
    }
    /// Her key for her choice of hop against a path of `k` chunks.
    pub fn hop_secret(&self, k: usize) -> WotsSecret {
        WotsSecret::from_entropy(WotsParams::for_bytes(1), self.hop_entropy(k))
    }
}

impl Secrets for WalletSigner {
    fn move_secrets(&self, program: &Program, d: u32) -> Vec<WotsSecret> {
        self.secrets.move_secrets(program, d)
    }
    fn input_wire(&self, j: usize, word: u32) -> Result<Vec<Vec<u8>>> {
        Ok(wots_wire(&self.secrets.input_secret(j).sign(&input_message(word))?))
    }
    fn hop_secret(&self, k: usize) -> WotsSecret {
        self.secrets.hop_secret(k)
    }
}

/// Her BitVMX keys for an opening request: her move keys for the odd
/// depths, her input-word keys, her hop keys under a jump list.
pub fn request_keys(s: &ContractSecrets, program: &Program) -> BitVmxRequest {
    let pub_of = |ks: Vec<WotsSecret>| ks.iter().map(|k| k.public()).collect::<Vec<_>>();
    let moves: Vec<_> = (1..=program.depths()).filter(|d| d % 2 == 1).map(|d| pub_of(s.move_secrets(program, d))).collect();
    let hops: Vec<_> = if program.schedule.jump.is_some() { (1..=CHUNKS).map(|k| s.hop_secret(k).public()).collect() } else { vec![] };
    let inputs: Vec<_> = (0..program.info.input_words).map(|j| s.input_secret(j).public()).collect();
    BitVmxRequest { moves, inputs, hops }
}

/// The contract's BitVMX keys, hers (`ours`) and the hub's (its offer's),
/// checked: the hub's windows never give her moves less time than the
/// network's (longer ones only slow a dispute).
pub fn record_keys(program: &Program, net: Net, ours: &BitVmxRequest, theirs: &BitVmxOffer) -> Result<DisputeKeys> {
    if let Some(w) = theirs.windows {
        let least = lichen_proto::bitvmx::windows(net).user;
        ensure!(w.user >= least, "the hub offers {} blocks for each of the user's moves, under the network's {least}", w.user);
    }
    Ok(DisputeKeys::BitVmx(BitVmxKeys { moves: all_moves(&ours.moves, &theirs.moves), inputs: ours.inputs.clone(), tail: tail_keys(program, &theirs.path, &ours.hops)?, windows: theirs.windows }))
}

/// Her signature on `b` as the payout's leaves take it: her key for the
/// input word that carries it.
pub fn b_wire(s: &ContractSecrets, record: &Record, statement: &Statement, b: u32) -> Result<Vec<Vec<u8>>> {
    let spec = record.spec(statement)?;
    Ok(wots_wire(&s.input_secret(spec.b_word).sign(&input_message(b))?))
}

impl Engine<'_> {
    /// Post the pre-signed terminal `name` with its runtime `wire` (a
    /// timeout's is empty).
    fn terminal_bx(&self, chain: &Chain, d: &Disputed, name: &str, wire: Vec<Vec<u8>>) -> Result<Txid> {
        self.post_terminal(chain, &d.finish(name, wire)?, &d.set[name].prevout)
    }

    /// Post the link `name` with its runtime `wire`.
    fn post_bx(&self, chain: &Chain, d: &Disputed, name: &str, wire: Vec<Vec<u8>>) -> Result<u32> {
        self.post_link(chain, name, d.finish(name, wire)?)
    }

    /// A BitVMX dispute ([`Engine::run`]): the withdrawal of `b` from the
    /// contract `record` on Bitcoin,
    /// the claim's `input` the statement program's (for the mock,
    /// `(b, c)`; for Groth16, the verifier's input for her proof). Blocks
    /// until the dispute ends, at the payout for a win.
    ///
    /// Resumable: the claim is kept in the store, and what is already on
    /// chain is replayed, not posted again.
    pub(super) fn run_bitvmx(&mut self, chain: &Chain, record: &Record, statement: &Statement, dir: &Path, b: u32, input: &[u8]) -> Result<Outcome> {
        let cid = record.cid();
        let d = Disputed::new(record, statement, dir)?;
        let words = input_words(input);
        ensure!(words.len() == d.contract.spec.inputs.len(), "the input is {} words, the statement's {}", words.len(), d.contract.spec.inputs.len());
        ensure!(words[d.contract.spec.b_word] == b, "the input claims {}, not {b}", words[d.contract.spec.b_word]);
        // a claim that breaks a check (the memo, the image id) would lose
        // everything to it: refuse it here
        if !self.opts.unchecked_claims {
            for c in &d.contract.spec.checks {
                ensure!(words[c.word] == c.value, "the input's {} is {:#x}, the contract's {:#x}", c.name, words[c.word], c.value);
            }
        }
        match self.store.claim() {
            Some((b0, i0)) => ensure!(b0 == b && i0 == hex::encode(input), "contract {cid} is already disputed with another claim"),
            None => self.store.set_claim(b, input)?,
        }
        let m = d.contract.m();
        let lock = |site| u32::from(d.contract.lock(site));
        let word_wire = |js: &[usize]| -> Result<Vec<Vec<u8>>> {
            let mut wire = vec![];
            for &j in js.iter().rev() {
                wire.extend(self.signer.bitvmx()?.input_wire(j, words[j])?);
            }
            Ok(wire)
        };
        // escalating waits to_self_delay after the contract's funding
        let funded = record.funding.txid;
        let mut stall = Stall::new(chain.height()?, chain.network);
        while chain.confirmations(&funded)? < u32::from(d.contract.spec.params.to_self_delay) {
            ensure!(!stall.stalled(chain.height()?), "the chain stalled before the contract's funding was deep enough to escalate");
            std::thread::sleep(Duration::from_millis(200));
        }
        let mut prover = Prover::start_with(&d.program, input, &dir.join(format!("dispute-{cid}")), self.opts.lie.clone())?;
        let pause = self.opts.pause_after;
        // escalate: move 1 with the claim's words; then the rest of the input
        let mut wire = word_wire(&d.contract.claim_words())?;
        wire.extend(sign_move(&d.program, 1, &self.signer.bitvmx()?.move_secrets(&d.program, 1), prover.last())?);
        self.step(format!("escalating: the claim of {b} sats and move 1 of {m}, {}", d.txid("escalate")));
        let mut last = self.post_bx(chain, &d, "escalate", wire)?;
        self.step(format!("escalated, confirmed at {last}"));
        let mut last_id = d.txid("escalate");
        if d.set.contains_key("inputs") {
            self.step(format!("publishing the rest of the claim's input, {}", d.txid("inputs")));
            last = self.post_bx(chain, &d, "inputs", word_wire(&d.contract.rest_words())?)?;
            last_id = d.txid("inputs");
            self.step(format!("published, confirmed at {last}"));
        }
        // the search: the hub moves at even depths
        for j in (2..m).step_by(2) {
            let w = lock(Site::Next(j - 1));
            self.step(format!("waiting for the hub's move {j}: its window ends at block {}", last + w));
            let tx = match wait_link(chain, &d.txid(&link_name(j)), &OutPoint { txid: last_id, vout: 0 }, last + w)? {
                Next::Link(tx) => tx,
                Next::Deadline => {
                    // the hub didn't answer in time: the ladder output after move j - 1 times out to her
                    self.step(format!("the hub didn't answer move {} in time: the user's timeout pays", j - 1));
                    let name = format!("timeout_{}", j - 1);
                    let txid = self.terminal_bx(chain, &d, &name, vec![])?;
                    self.step(format!("the timeout pays the user: {txid}"));
                    return self.paid(Outcome::HubTimedOut(txid));
                }
                Next::Taken => {
                    self.step("the user's output was taken (a check or a disprove): the claim lost".into());
                    return self.lost(last_id);
                }
            };
            self.step(format!("the hub chose a segment (move {j})"));
            let next = prover.answer(&read_move(&tx, d.key(j))?)?;
            let wire = sign_move(&d.program, j + 1, &self.signer.bitvmx()?.move_secrets(&d.program, j + 1), &next)?;
            last = self.post_bx(chain, &d, &link_name(j + 1), wire)?;
            last_id = d.txid(&link_name(j + 1));
            self.step(if j + 1 == m { format!("move {m}: the record of the disputed step") } else { format!("move {}: the trace's hashes at the seven boundaries inside that segment", j + 1) });
            if pause.is_some_and(|p| j + 1 >= p) {
                return Ok(Outcome::Paused);
            }
        }
        // the last step: the hub may disprove it (after a delay) or post a
        // path against it (at once); if neither comes in its window, she
        // proves it
        let last_op = OutPoint { txid: last_id, vout: 0 };
        self.step(format!("waiting for a disprove or a path against the last step: the hub's window ends at block {}", last + lock(Site::ProveAfter)));
        while chain.unspent(&last_op)? && chain.height()? < last + lock(Site::ProveAfter) {
            std::thread::sleep(Duration::from_millis(100));
        }
        if !chain.unspent(&last_op)? {
            if chain.get_tx(&d.txid("path_split")).is_some() {
                return self.answer_path(chain, &d, &prover);
            }
            self.step("the hub took the last step's output (a disprove, or its timeout after her window to prove): the claim lost".into());
            return self.lost(last_id);
        }
        let rec = lngap_ladder::moves::View { s: &d.program.schedule, msgs: &prover.msgs }.record();
        let link = |name: &str| chain.get_tx(&d.txid(name)).with_context(|| format!("{name} is not on chain"));
        let (name, ok) = d.proves(&rec, &link)?;
        ensure!(ok, "the last step's proof ({name}) doesn't spend on the moves posted");
        let wire = d.rule_wire(&d.contract.rule(m, &name)?, &[], None, &link)?;
        let txid = self.terminal_bx(chain, &d, &name, wire)?;
        self.step(format!("no disprove came: the last step proved ({name}), paid by {txid}"));
        self.paid(Outcome::Proved(txid))
    }

    /// Under a jump list, the hub posted a path against her last step: if a
    /// hop of it isn't in her history, challenge it (the hub can't reveal
    /// it: her timeout pays her); if it is genuine, the hub's verdict
    /// takes the output, unless it never posts it. If the hub never
    /// finishes posting the path, her timeout pays her.
    fn answer_path(&mut self, chain: &Chain, d: &Disputed, prover: &Prover) -> Result<Outcome> {
        let lock = |site| u32::from(d.contract.lock(site));
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
            if chain.unspent(&carrier)? && chain.height()? >= split_at + lock(Site::Carrier) {
                self.step("the hub never finished its path: the user's timeout pays".into());
                let txid = self.terminal_bx(chain, d, "timeout_path_split", vec![])?;
                return self.paid(Outcome::HubTimedOut(txid));
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
                let wire = wots_wire(&self.signer.bitvmx()?.hop_secret(n).sign(&[i as u8])?);
                let hop_at = self.post_bx(chain, d, &hop, wire)?;
                let h_op = OutPoint { txid: d.txid(&hop), vout: 0 };
                while chain.unspent(&h_op)? && chain.height()? < hop_at + lock(Site::HopTimeout) {
                    std::thread::sleep(Duration::from_millis(100));
                }
                if !chain.unspent(&h_op)? {
                    self.step("the hub revealed the hop: the claim lost".into());
                    return self.lost(h_op.txid);
                }
                let name = format!("timeout_{hop}");
                let txid = self.terminal_bx(chain, d, &name, vec![])?;
                self.step("the hub couldn't reveal the hop: the user's timeout pays".into());
                self.paid(Outcome::PathRefuted(txid))
            }
            None => {
                self.step("the hub's path is genuine: its verdict will take the output".into());
                while chain.unspent(&p_op)? && chain.height()? < comb_at + lock(Site::PathTimeout) {
                    std::thread::sleep(Duration::from_millis(100));
                }
                if !chain.unspent(&p_op)? {
                    self.step("the hub's path proved its verdict: the claim lost".into());
                    return self.lost(p_op.txid);
                }
                let name = format!("timeout_combine_{n}");
                let txid = self.terminal_bx(chain, d, &name, vec![])?;
                self.step("the hub never posted its verdict: the user's timeout pays".into());
                self.paid(Outcome::HubTimedOut(txid))
            }
        }
    }
}

//! Alice's side of a dispute, from the escalation to the payout, over what
//! it signs with ([`Signer`]) and where it keeps its state ([`Store`]): the
//! wallet's own keys and contract (`lichen dispute`), or a tower's package
//! (`lichen tower`). She escalates (her claim on chain with its input
//! words), then plays BitVMX's search move by move, reading the hub's
//! moves from the chain; if the hub stops answering she takes the timeout;
//! if she reaches the last step and no disprove comes, she proves it.
//! Under a jump list the hub may instead post a path through its history:
//! she checks it against her own and challenges the first false hop, which
//! the hub can't reveal (her timeout pays her). A win ends at the payout:
//! sweeping it takes her own key, which only the wallet holds.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use bitcoin::key::Keypair;
use bitcoin::{OutPoint, Transaction, Txid};
use lichen_chain::{Chain, KeyFees};
use lichen_proto::{anchor_vout, link_name, sign_anchor, sign_move, Disputed, Patience, Record, Site, Stall, Statement};
use lngap_btc::keys::Seed;
use lngap_channel::{PartyKeys, Role};
use lngap_ladder::script::wots_wire;
use lngap_ladder::tail::CHUNKS;
use lngap_lamport::winternitz::{WotsParams, WotsSecret};
use lngap_sessions::contract::Program;
use lngap_sessions::play::{read_move, read_move_in, Prover};
use lngap_zk::final_d60::{input_message, input_words};

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

impl Outcome {
    /// The payout's txid, for a win.
    pub fn payout(&self) -> Option<Txid> {
        match self {
            Outcome::HubTimedOut(t) | Outcome::Proved(t) | Outcome::PathRefuted(t) => Some(*t),
            Outcome::Lost | Outcome::Paused => None,
        }
    }
}

/// What a dispute signs with: Alice's one-time secrets for one contract,
/// her fee budget, and the key of her links' anchors if she lends it.
pub trait Signer {
    /// Her move keys for depth `d`, one per field.
    fn move_secrets(&self, program: &Program, d: u32) -> Vec<WotsSecret>;
    /// Her signature on input word `j`, of value `word`, as a witness wire.
    fn input_wire(&self, j: usize, word: u32) -> Result<Vec<Vec<u8>>>;
    /// Her key for her choice of hop against a path of `k` chunks.
    fn hop_secret(&self, k: usize) -> WotsSecret;
    /// The contract's fee budget.
    fn fees(&self) -> KeyFees;
    /// The key of her links' anchors, to bump their fees; none, and each
    /// link is posted at its floor.
    fn anchor(&self) -> Option<Keypair>;
}

/// Where a dispute keeps what must survive a restart.
pub trait Store {
    /// The claim (`b` and the statement's input, hex), once made.
    fn claim(&self) -> Option<(u32, String)>;
    fn set_claim(&mut self, b: u32, input: &[u8]) -> Result<()>;
    /// The payout, once posted.
    fn payout(&self) -> Option<Outcome>;
    fn set_payout(&mut self, outcome: &Outcome) -> Result<()>;
    /// The claim lost: the contract closed by `txid`.
    fn set_lost(&mut self, txid: Txid) -> Result<()>;
}

/// The secrets of Alice's contract with `nonce`, derived from her wallet's
/// key: each a hash of a label under the contract's seed, so that any one
/// of them can be handed out alone.
pub struct ContractSecrets {
    seed: String,
}

impl ContractSecrets {
    pub(crate) fn new(master: &[u8], nonce: &str) -> ContractSecrets {
        ContractSecrets { seed: format!("{}/contract/{nonce}", hex::encode(master)) }
    }
    /// Her keys for the contract (its payment key signs her 2-of-2s and
    /// sweeps her winnings).
    pub fn keys(&self) -> PartyKeys {
        PartyKeys::from_seed(Role::User, Seed::from_label(&self.seed))
    }
    fn wots(&self, label: &str) -> [u8; 32] {
        Seed::from_label(&format!("{}/{label}", self.seed)).derive_bytes("wots")
    }
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
    /// Her key in the contract's deposit tree.
    pub fn deposit_key(&self) -> Keypair {
        Seed::from_label(&self.seed).keypair("deposit")
    }
    /// Her move keys for depth `d`, one per field.
    pub fn move_secrets(&self, program: &Program, d: u32) -> Vec<WotsSecret> {
        program.field_bytes(d).into_iter().enumerate().map(|(f, n)| WotsSecret::from_entropy(WotsParams::for_bytes(n), self.move_entropy(d, f))).collect()
    }
    /// Her key for her choice of hop against a path of `k` chunks.
    pub fn hop_secret(&self, k: usize) -> WotsSecret {
        WotsSecret::from_entropy(WotsParams::for_bytes(1), self.hop_entropy(k))
    }
    /// The contract's fee budget, on `net`: one key's coins.
    pub fn fees(&self, net: lichen_chain::Net) -> KeyFees {
        KeyFees { keypair: Seed::from_label(&self.seed).keypair("fee"), feerate: lichen_proto::feerate(net) }
    }
}

/// The wallet as a dispute's signer: every secret of the contract, and her
/// payment key for the anchors.
pub struct WalletSigner {
    pub secrets: ContractSecrets,
    pub network: lichen_chain::Net,
}

impl Signer for WalletSigner {
    fn move_secrets(&self, program: &Program, d: u32) -> Vec<WotsSecret> {
        self.secrets.move_secrets(program, d)
    }
    fn input_wire(&self, j: usize, word: u32) -> Result<Vec<Vec<u8>>> {
        Ok(wots_wire(&self.secrets.input_secret(j).sign(&input_message(word))?))
    }
    fn hop_secret(&self, k: usize) -> WotsSecret {
        self.secrets.hop_secret(k)
    }
    fn fees(&self) -> KeyFees {
        self.secrets.fees(self.network)
    }
    fn anchor(&self) -> Option<Keypair> {
        Some(self.secrets.keys().payment)
    }
}

/// The height a transaction confirmed at, if it has.
pub(crate) fn confirmed_at(chain: &Chain, txid: &Txid) -> Result<Option<u32>> {
    let c = chain.confirmations(txid)?;
    (c > 0).then(|| chain.height().map(|h| h + 1 - c)).transpose()
}

pub(crate) fn wait_confirmed(chain: &Chain, txid: &Txid) -> Result<u32> {
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

/// A dispute's options besides its signer and store.
#[derive(Clone, Default)]
pub struct Options {
    /// Progress, one line a step.
    pub progress: Option<Arc<dyn Fn(String) + Send + Sync>>,
    /// For tests: stop after posting this move (a resume picks it up).
    pub pause_after: Option<u32>,
    /// For tests: escalate a claim that breaks a check.
    pub unchecked_claims: bool,
    /// For tests: lie in the dispute's execution (BitVMX's fault
    /// injection).
    pub lie: Option<emulator::executor::utils::FailConfiguration>,
}

/// One dispute: Alice's side of it.
pub struct Engine<'a> {
    pub signer: &'a dyn Signer,
    pub store: &'a mut dyn Store,
    pub opts: Options,
}

impl Engine<'_> {
    fn step(&self, msg: String) {
        if let Some(f) = &self.opts.progress {
            f(msg);
        }
    }

    /// Post the pre-signed terminal `name` with its runtime `wire` (a
    /// timeout's is empty), its fee a coin of exactly that from the
    /// contract's fee budget.
    fn terminal(&self, chain: &Chain, d: &Disputed, name: &str, wire: Vec<Vec<u8>>) -> Result<Txid> {
        let tx = d.finish(name, wire)?;
        let fee = lichen_proto::terminal_fee(&tx, chain.network);
        chain.post_terminal(&tx, &d.set[name].prevout, fee, &self.signer.fees())
    }

    /// Post a link of the chain, paying with a child from her anchor (with
    /// no anchor key, at its floor alone), unless it is already there (a
    /// resumed dispute replays it); its confirmation height.
    fn post(&self, chain: &Chain, d: &Disputed, name: &str, wire: Vec<Vec<u8>>) -> Result<u32> {
        let tx = d.finish(name, wire)?;
        let id = tx.compute_txid();
        if chain.get_tx(&id).is_none() {
            match self.signer.anchor() {
                Some(kp) => {
                    let anchor = anchor_vout(&tx, &kp.x_only_public_key().0)?;
                    chain.post_link(&tx, anchor, lichen_proto::feerate(chain.network), &|c, p| sign_anchor(&kp, c, p), &self.signer.fees())?;
                }
                None => {
                    chain.broadcast(&tx).with_context(|| format!("{name}, at its floor"))?;
                }
            }
        } else {
            // posted before: it must be the move we would make now
            let posted = chain.get_tx(&id).context("the link")?;
            // (one-time signatures are deterministic, and both 2-of-2
            // signatures were made at the opening: the same witness)
            ensure!(posted.input[0].witness == tx.input[0].witness, "{name} on chain is not the move replayed");
        }
        wait_confirmed(chain, &id)
    }

    /// The payout is posted: keep it (a resumed dispute goes straight to
    /// it).
    fn paid(&mut self, outcome: Outcome) -> Result<Outcome> {
        self.store.set_payout(&outcome)?;
        Ok(outcome)
    }

    fn lost(&mut self, txid: Txid) -> Result<Outcome> {
        self.store.set_lost(txid)?;
        Ok(Outcome::Lost)
    }

    /// Enforce a withdrawal of `b` from the contract `record` on Bitcoin,
    /// the claim's `input` the statement program's (for the mock,
    /// `(b, c)`; for Groth16, the verifier's input for her proof). Blocks
    /// until the dispute ends, at the payout for a win.
    ///
    /// Resumable: the claim is kept in the store, and what is already on
    /// chain is replayed, not posted again.
    pub fn run(&mut self, chain: &Chain, record: &Record, statement: &Statement, dir: &Path, b: u32, input: &[u8]) -> Result<Outcome> {
        let cid = record.cid();
        if let Some(o) = self.store.payout() {
            // the payout is posted: nothing left to play
            return Ok(o);
        }
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
                wire.extend(self.signer.input_wire(j, words[j])?);
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
        wire.extend(sign_move(&d.program, 1, &self.signer.move_secrets(&d.program, 1), prover.last())?);
        self.step(format!("escalating: the claim of {b} sats and move 1 of {m}, {}", d.txid("escalate")));
        let mut last = self.post(chain, &d, "escalate", wire)?;
        self.step(format!("escalated, confirmed at {last}"));
        let mut last_id = d.txid("escalate");
        if d.set.contains_key("inputs") {
            self.step(format!("publishing the rest of the claim's input, {}", d.txid("inputs")));
            last = self.post(chain, &d, "inputs", word_wire(&d.contract.rest_words())?)?;
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
                    let txid = self.terminal(chain, &d, &name, vec![])?;
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
            let wire = sign_move(&d.program, j + 1, &self.signer.move_secrets(&d.program, j + 1), &next)?;
            last = self.post(chain, &d, &link_name(j + 1), wire)?;
            last_id = d.txid(&link_name(j + 1));
            self.step(if j + 1 == m { format!("move {m}: the record of the disputed step") } else { format!("move {}: the trace's hashes at the seven boundaries inside that segment", j + 1) });
            if pause.is_some_and(|p| j + 1 >= p) && j + 1 < m {
                return Ok(Outcome::Paused);
            }
        }
        // the last step: the hub may disprove it (after a delay) or post a
        // path against it (at once); if neither comes in its window, she
        // proves it
        let last_op = OutPoint { txid: last_id, vout: 0 };
        while chain.unspent(&last_op)? && chain.height()? < last + lock(Site::ProveAfter) {
            std::thread::sleep(Duration::from_millis(100));
        }
        if !chain.unspent(&last_op)? {
            if chain.get_tx(&d.txid("path_split")).is_some() {
                return self.answer_path(chain, &d, &prover);
            }
            self.step("the hub disproved the last step: the claim lost".into());
            return self.lost(last_id);
        }
        let rec = lngap_ladder::moves::View { s: &d.program.schedule, msgs: &prover.msgs }.record();
        let link = |name: &str| chain.get_tx(&d.txid(name)).with_context(|| format!("{name} is not on chain"));
        let (name, ok) = d.proves(&rec, &link)?;
        ensure!(ok, "the last step's proof ({name}) doesn't spend on the moves posted");
        let wire = d.rule_wire(&d.contract.rule(m, &name)?, &[], None, &link)?;
        let txid = self.terminal(chain, &d, &name, wire)?;
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
                let txid = self.terminal(chain, d, "timeout_path_split", vec![])?;
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
                let wire = wots_wire(&self.signer.hop_secret(n).sign(&[i as u8])?);
                let hop_at = self.post(chain, d, &hop, wire)?;
                let h_op = OutPoint { txid: d.txid(&hop), vout: 0 };
                while chain.unspent(&h_op)? && chain.height()? < hop_at + lock(Site::HopTimeout) {
                    std::thread::sleep(Duration::from_millis(100));
                }
                if !chain.unspent(&h_op)? {
                    self.step("the hub revealed the hop: the claim lost".into());
                    return self.lost(h_op.txid);
                }
                let name = format!("timeout_{hop}");
                let txid = self.terminal(chain, d, &name, vec![])?;
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
                let txid = self.terminal(chain, d, &name, vec![])?;
                self.step("the hub never posted its verdict: the user's timeout pays".into());
                self.paid(Outcome::HubTimedOut(txid))
            }
        }
    }
}

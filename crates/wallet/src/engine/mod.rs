//! Alice's side of a dispute, from the escalation to the payout, over what
//! it signs with ([`Signer`]) and where it keeps its state ([`Store`]): the
//! wallet's own keys and contract (`lichen dispute`), or a tower's package
//! (`lichen tower`). The play is the contract's gadget's ([`bitvmx`]:
//! BitVMX's search); what every gadget shares is here: posting her links
//! and terminals, waiting on the hub's, keeping the claim and the outcome.
//! A win ends at the payout: sweeping it takes her own key, which only the
//! wallet holds.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use bitcoin::key::Keypair;
use bitcoin::{OutPoint, Transaction, TxOut, Txid};
use lichen_chain::{Chain, KeyFees};
use lichen_proto::{anchor_vout, sign_anchor, Gadget, Patience, Record, Stall, Statement};
use lngap_btc::keys::Seed;
use lngap_channel::{PartyKeys, Role};

pub mod babe;
pub mod bitvmx;

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
        /// Under BABE: the hub didn't challenge her proof; `success` paid her.
    Unchallenged(Txid),
    /// Under BABE: she answered the hub's challenge with a kept
    /// instance's `msg`; `wrongly_challenged` paid her.
    Answered(Txid),
    /// The hub disproved her claim (or she lost by timeout).
    Lost,
}

impl Outcome {
    /// The payout's txid, for a win.
    pub fn payout(&self) -> Option<Txid> {
        match self {
            Outcome::HubTimedOut(t) | Outcome::Proved(t) | Outcome::PathRefuted(t) | Outcome::Unchallenged(t) | Outcome::Answered(t) => Some(*t),
            Outcome::Lost | Outcome::Paused => None,
        }
    }
}

/// What a dispute signs with: her fee budget, the key of her links'
/// anchors if she lends it, and her one-time secrets for the contract's
/// gadget.
pub trait Signer {
    /// The contract's fee budget.
    fn fees(&self) -> KeyFees;
    /// The key of her links' anchors, to bump their fees; none, and each
    /// link is posted at its floor.
    fn anchor(&self) -> Option<Keypair>;
        /// Her BitVMX secrets, for a BitVMX contract.
    fn bitvmx(&self) -> Result<&dyn bitvmx::Secrets>;
    /// Her BABE secrets, for a BABE contract.
    fn babe(&self) -> Result<&dyn babe::Secrets>;
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
    /// The entropy of a one-time key of hers, by its label.
    pub(crate) fn wots(&self, label: &str) -> [u8; 32] {
        Seed::from_label(&format!("{}/{label}", self.seed)).derive_bytes("wots")
    }
    /// Her key in the contract's deposit tree.
    pub fn deposit_key(&self) -> Keypair {
        Seed::from_label(&self.seed).keypair("deposit")
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
    fn fees(&self) -> KeyFees {
        self.secrets.fees(self.network)
    }
    fn anchor(&self) -> Option<Keypair> {
        Some(self.secrets.keys().payment)
    }
    fn bitvmx(&self) -> Result<&dyn bitvmx::Secrets> {
        Ok(self)
    }
    fn babe(&self) -> Result<&dyn babe::Secrets> {
        Ok(self)
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
pub(crate) enum Next {
    /// The other side's link, as expected.
    Link(Transaction),
    /// It didn't answer by the deadline: the timeout is ours.
    Deadline,
    /// Something else spent the output: a check or a disprove.
    Taken,
}

/// Wait for the other side's link `txid` spending `ours`, until the chain
/// reaches `deadline`.
pub(crate) fn wait_link(chain: &Chain, txid: &Txid, ours: &OutPoint, deadline: u32) -> Result<Next> {
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
            // the link, unconfirmed: waited for, but never past the
            // deadline (a link left in the mempool must not hold off our
            // timeout)
            let h = chain.height()?;
            if h >= deadline {
                return Ok(Next::Deadline);
            }
            ensure!(!stall.stalled(h), "the chain stalled");
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
    /// For tests: stop after posting this move, the last too, before its
    /// proof (a resume picks it up).
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

    /// Post a pre-signed terminal `tx` (spending `prevout`), its fee a
    /// coin of exactly that from the contract's fee budget.
    fn post_terminal(&self, chain: &Chain, tx: &Transaction, prevout: &TxOut) -> Result<Txid> {
        let fee = lichen_proto::terminal_fee(tx, chain.network);
        chain.post_terminal(tx, prevout, fee, &self.signer.fees())
    }

    /// Post a link of the chain, `tx` (named `name`), paying with a child
    /// from her anchor (with no anchor key, at its floor alone), unless it
    /// is already there (a resumed dispute replays it); its confirmation
    /// height.
    fn post_link(&self, chain: &Chain, name: &str, tx: Transaction) -> Result<u32> {
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
        if let Some(o) = self.store.payout() {
            // the payout is posted: nothing left to play
            return Ok(o);
        }
        if let Some((b0, i0)) = self.store.claim() {
            ensure!(b0 == b && i0 == hex::encode(input), "contract {} is already disputed with another claim", record.cid());
        }
        match record.gadget() {
            Gadget::BitVmx => self.run_bitvmx(chain, record, statement, dir, b, input),
            Gadget::Babe => self.run_babe(chain, record, statement, dir, b, input),
        }
    }
}

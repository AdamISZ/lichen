//! Alice's side of a dispute, from her request to the payout, over what it
//! signs with ([`Signer`]) and where it keeps its state ([`Store`]): the
//! wallet's own keys and contract. The front is the L2's
//! ([`crate::WalletL2::run_front`]); then BABE's tail ([`tail`]): the
//! hub's assertion checked, challenged if false. Here also what both rest
//! on: posting her links and terminals, waiting on the hub's, keeping the
//! outcome. A win ends at the payout: sweeping it takes her own key.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use bitcoin::key::Keypair;
use bitcoin::{OutPoint, Transaction, TxOut, Txid};
use lichen_chain::{Chain, KeyFees};
use lichen_proto::{anchor_vout, sign_anchor, Patience, Record, Stall, Statement};
use lichen_btc::keys::Seed;
use lichen_contract::{PartyKeys, Role};
use lichen_babe::opening::Garbler;
use lichen_babe::reveal::{check_presigs, points};
use lichen_babe::setup::{Secret, VALUES};
use lichen_babe::statement::Kind;
use lichen_babe::vsss::{deal, Dealer};
use lichen_btc::adaptor::AdaptorSig;
use lichen_btc::secp256k1::{Message, XOnlyPublicKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

pub mod tail;

/// How a dispute ended for Alice.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Outcome {
    /// Stopped on request (`pause_after`); run again to resume.
    Paused,
    /// The hub didn't correct her claim (`request_timeout`), or corrected
    /// it, she contested, and it never proved (`ack_timeout`): paid her
    /// claim (its txid).
    HubTimedOut(Txid),
    /// The hub's assertion was false, it couldn't answer her challenge,
    /// and `failure` paid her.
    Refuted(Txid),
    /// The hub corrected her claim to `b_corr` units, and she accepted
    /// (`accept`) or it proved so (`success`): that payout (its txid) paid
    /// her `b_corr`, and her reserve.
    Corrected { success: Txid, b_corr: u32 },
    /// The hub answered her challenge (or took the contract otherwise).
    Lost,
}

impl Outcome {
    /// The payout's txid, for a win.
    pub fn payout(&self) -> Option<Txid> {
        match self {
            Outcome::HubTimedOut(t) | Outcome::Refuted(t) | Outcome::Corrected { success: t, .. } => Some(*t),
            Outcome::Lost | Outcome::Paused => None,
        }
    }
}

/// What a dispute signs with: her fee budget, the key of her links'
/// anchors, and her contract's secrets (her one-time keys; her challenge
/// reveals her dealing's).
pub trait Signer {
    /// The contract's fee budget.
    fn fees(&self) -> KeyFees;
    /// The key of her links' anchors, to bump their fees; none, and each
    /// link is posted at its floor.
    fn anchor(&self) -> Option<Keypair>;
    /// Her contract's secrets.
    fn contract(&self) -> &ContractSecrets;
}

/// Where a dispute keeps what must survive a restart.
pub trait Store {
    /// The payout, once posted.
    fn payout(&self) -> Option<Outcome>;
    fn set_payout(&mut self, outcome: &Outcome) -> Result<()>;
    /// The claim lost: the contract closed by `txid`.
    fn set_lost(&mut self, txid: Txid) -> Result<()>;
    /// The exit's claim, prepared before `request`.
    fn exit(&self) -> Option<serde_json::Value>;
    /// The unlock `correct` posted: if it opens the payment in flight on
    /// the contract's account, that payment completed (our new note
    /// settled; the seed is the counterparty's to have too). The new
    /// note's value, if so.
    fn unlocked(&mut self, z: &[u8]) -> Result<Option<u64>>;
}

/// The wallet's own Bitcoin key for payouts, derived from its key apart
/// from every contract's.
pub(crate) fn payout_keypair(master: &[u8]) -> Keypair {
    Seed::from_label(&format!("{}/payout", hex::encode(master))).keypair("payout")
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
    pub fn wots(&self, label: &str) -> [u8; 32] {
        Seed::from_label(&format!("{}/{label}", self.seed)).derive_bytes("wots")
    }
    /// The contract's L2 key: its owner, fresh for it, which holds the
    /// notes its claims take.
    pub fn l2(&self) -> Keypair {
        Seed::from_label(&self.seed).keypair("l2")
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
    fn contract(&self) -> &ContractSecrets {
        &self.secrets
    }
}

/// The height a transaction confirmed at, if it has.
pub fn confirmed_at(chain: &Chain, txid: &Txid) -> Result<Option<u32>> {
    let c = chain.confirmations(txid)?;
    (c > 0).then(|| chain.height().map(|h| h + 1 - c)).transpose()
}

pub fn wait_confirmed(chain: &Chain, txid: &Txid) -> Result<u32> {
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
pub enum Next {
    /// The other side's link, as expected.
    Link(Transaction),
    /// It didn't answer by the deadline: the timeout is ours.
    Deadline,
    /// Something else spent the output: a check or a disprove.
    Taken,
}

/// Wait for the other side's link `txid` spending `ours`, until the chain
/// reaches `deadline`.
pub fn wait_link(chain: &Chain, txid: &Txid, ours: &OutPoint, deadline: u32) -> Result<Next> {
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
    /// For tests: stop after posting `request` (1); a resume picks it up.
    pub pause_after: Option<u32>,
    /// For tests: challenge the hub's assertion even if its proof is
    /// valid.
    pub unchecked_claims: bool,
    /// For tests: contest the hub's correction (countersign it in `ack`)
    /// even if it is what we reckon we're owed, so that the hub must
    /// prove.
    pub contest: bool,
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

    /// Exit through the contract `record` with a claim of `b`, the
    /// store's ([`Store::exit`]). Blocks until the dispute ends, at the
    /// payout for a win.
    ///
    /// Resumable: what is already on chain is replayed, not posted again.
    pub fn run<L: crate::WalletL2>(&mut self, chain: &Chain, record: &Record, statement: &Statement, layer: &L, b: u32) -> Result<Outcome> {
        if let Some(o) = self.store.payout() {
            // the payout is posted: nothing left to play
            return Ok(o);
        }
        let d = lichen_proto::hp::Disputed::new(record, statement, layer)?;
        let plan = self.store.exit().context("a dispute is an exit: no claim kept")?;
        ensure!(L::plan_b(&plan)? == b, "the claim kept is of {}, not {b}", L::plan_b(&plan)?);
        let mut stall = Stall::new(chain.height()?, chain.network);
        while chain.confirmations(&record.funding.txid)? < u32::from(d.graph.core().params.to_self_delay) {
            ensure!(!stall.stalled(chain.height()?), "the chain stalled before the contract's funding was deep enough to request");
            std::thread::sleep(Duration::from_millis(200));
        }
        match L::run_front(self, chain, &d, &plan)? {
            crate::FrontEnd::Done(o) => Ok(o),
            crate::FrontEnd::Paused => Ok(Outcome::Paused),
            crate::FrontEnd::Asserting { at, b_corr } => {
                let journal = layer.journal(record)?;
                self.tail(chain, &d, statement, &journal, at, b_corr)
            }
        }
    }

    /// Say `msg` ([`Options::progress`]).
    pub fn say(&self, msg: String) {
        self.step(msg)
    }
    /// Post one of her links ([`Engine::post_link`]).
    pub fn link(&self, chain: &Chain, name: &str, tx: Transaction) -> Result<u32> {
        self.post_link(chain, name, tx)
    }
    /// Post one of her terminals, from the dispute's set.
    pub fn terminal(&self, chain: &Chain, d: &lichen_proto::hp::Disputed, name: &str) -> Result<Txid> {
        self.post_terminal(chain, &d.finish(name, vec![])?, &d.set[name].prevout)
    }
    /// Record the outcome: paid.
    pub fn pay(&mut self, outcome: Outcome) -> Result<Outcome> {
        self.paid(outcome)
    }
    /// Record the outcome: lost, its output taken by `txid`.
    pub fn lose(&mut self, txid: Txid) -> Result<Outcome> {
        self.lost(txid)
    }
}

/// Her garbler for a contract's setup (`n` instances, `m` kept) for the
/// statement `kind` on `journal`, from the contract's seed: the same
/// every time.
pub fn garbler(s: &ContractSecrets, n: u32, m: u32, kind: &Kind, journal: &[u8]) -> Garbler {
    Garbler::new(&s.hp_seed(), n, m, kind, journal)
}

/// Her dealer of a contract opened before the dealing was bound to the
/// contract's journal (from the contract's seed alone), for its dispute.
fn unbound_dealer(s: &ContractSecrets, n: u32, m: u32) -> Dealer {
    deal(lichen_babe::setup::DIGITS, (n - m) as usize, &mut ChaCha20Rng::from_seed(s.hp_seed().derive_bytes("dealing"))).0
}

/// The hub's adaptor keys, `challenge_assert`'s sighash and the hub's
/// pre-signatures on it, of a contract's record.
pub type HubPresigs<'a> = (&'a [[XOnlyPublicKey; VALUES]], &'a Message, &'a [[AdaptorSig; VALUES]]);

/// The secrets of π1's `digits`, as her challenge reveals them in the
/// contract of `journal` (`n` instances, `m` kept): of the dealing bound
/// to the journal or, for a contract opened before it was, of the one
/// from the contract's seed alone; whichever the hub's pre-signatures
/// are adapted to.
pub fn revealed(s: &ContractSecrets, n: u32, m: u32, kind: &Kind, journal: &[u8], (keys, msg, presigs): HubPresigs, digits: &[u8]) -> Vec<Secret> {
    let g = garbler(s, n, m, kind, journal);
    if check_presigs(keys, msg, &points(g.dealing()), presigs) {
        return g.reveal(digits);
    }
    let dealer = unbound_dealer(s, n, m);
    digits.iter().enumerate().map(|(j, v)| dealer.reveal(j, *v)).collect()
}

impl ContractSecrets {
    /// The seed of her setup (her dealing, her instances).
    pub fn hp_seed(&self) -> Seed {
        Seed::from_label(&format!("{}/hp", self.seed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_babe::reveal::{complete, extract, reveal_args, AdaptorKeys, LamportKey};
    use lichen_babe::setup::DIGITS;

    /// Her challenge reveals the secrets of the dealing the hub's
    /// pre-signatures are adapted to: bound to the journal, or, for a
    /// contract opened before, from the contract's seed alone. The hub
    /// extracts them from her completions either way.
    #[test]
    fn her_reveal_follows_the_dealing_the_hub_presigned() {
        let s = ContractSecrets::new(&[1; 32], "n");
        let (n, m, kind, journal) = (4, 2, Kind::Mock, [7u8; 68]);
        let hub = Seed::from_label("hub");
        let (lamport, adaptor) = (LamportKey::new(&hub, DIGITS), AdaptorKeys::new(&hub, DIGITS));
        let msg = Message::from_digest([3; 32]);
        let digits: Vec<u8> = (0..DIGITS).map(|j| (j % VALUES) as u8).collect();
        let bound = points(garbler(&s, n, m, &kind, &journal).dealing());
        let unbound = points(&deal(DIGITS, (n - m) as usize, &mut ChaCha20Rng::from_seed(s.hp_seed().derive_bytes("dealing"))).1);
        assert_ne!(bound, unbound);
        for pts in [bound, unbound] {
            let presigs = adaptor.presign(&msg, &pts);
            let secrets = revealed(&s, n, m, &kind, &journal, (&adaptor.public(), &msg, &presigs), &digits);
            let sigs = complete(&presigs, &digits, &secrets);
            // valid signatures under the keys her digits select: the chain
            // takes her challenge
            let keys = adaptor.public();
            assert!(sigs.iter().zip(&digits).enumerate().all(|(j, (sig, v))| lichen_btc::secp256k1::SECP256K1.verify_schnorr(sig, &msg, &keys[j][*v as usize]).is_ok()));
            let args = reveal_args(&lamport.sign(&digits), &sigs);
            assert_eq!(extract(&lamport.public(), &presigs, &args).unwrap(), (digits.clone(), secrets));
        }
    }
}

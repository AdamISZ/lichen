//! What an L2 adds to the wallet ([`WalletL2`]): its state in the wallet
//! file, its part of each contract (the statement's terms, the user's keys
//! for the dispute's front, the mint, a withdrawal's claim), and the
//! front's moves in a dispute. The wallet runs the rest: deposits, the
//! opening and BABE's garbling, the fold, the default, a dispute's tail,
//! and the sweep of a payout.

use anyhow::Result;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{OutPoint, Sequence, Transaction, TxOut};
use lichen_btc::taptree::TapTree;
use lichen_chain::Chain;
use lichen_proto::hp::{Disputed, HpOffer, HpSetup};
use lichen_proto::{Hash, Info, Layer, OpenOffer, Record};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::engine::{ContractSecrets, Engine, Outcome};
use crate::{Held, Quote, Wallet};

/// How a dispute's front ended, by the L2.
pub enum FrontEnd {
    /// A terminal of the front paid (or the user lost there).
    Done(Outcome),
    /// Stopped after a link, for a test.
    Paused,
    /// The front's last link confirmed at `at`: `assert` is the hub's to
    /// post before its window ends. If its proof stands, `success` pays
    /// `b_corr` (the hub's correction) or, with none, nothing to the user.
    Asserting { at: u32, b_corr: Option<u32> },
}

/// An input of a payout's sweep: the coin, its sequence, and the leaf
/// that spends it (its tree, its name, and whether her signature on `b`
/// goes below hers).
pub type SweepIn = (OutPoint, TxOut, Sequence, Option<(TapTree, String, bool)>);

/// An L2 in the wallet: its state (kept in the wallet file) and its hooks.
pub trait WalletL2: Layer + Serialize + DeserializeOwned + Clone + Send + Sync + Sized + 'static {
    /// A new wallet's L2 state, from the hub's info (its deployment, ...).
    fn create(info: &Info) -> Result<Self>;
    /// Whether the hub (its info) is the one this state is of, and proves
    /// with this wallet's guests.
    fn check_info(&self, info: &Info) -> Result<()>;
    /// The L2's version (this wallet's).
    fn version() -> String;

    /// The statement's terms the user asks for at the setup
    /// (`HpSetupRequest::l2`), for her contract's `owner`.
    fn setup_terms(w: &Wallet<Self>, cid: u32, quote: &Quote, owner: &Hash) -> Result<serde_json::Value>;
    /// The hub's setup, against what she asked.
    fn check_setup(w: &Wallet<Self>, setup: &HpSetup, asked: &serde_json::Value) -> Result<()>;
    /// Her keys for the dispute's front (`HpCommit::keys`), from her
    /// contract's secrets.
    fn alice_keys(s: &ContractSecrets) -> serde_json::Value;
    /// The journal of a setup and her keys.
    fn setup_journal(cid: u32, setup: &HpSetup, keys: &serde_json::Value) -> Result<Vec<u8>>;
    /// The contract's L2 keys (`HpKeys::l2`): from the setup, hers, and
    /// the hub's in its offer, checked.
    fn record_keys(w: &Wallet<Self>, setup: &HpSetup, keys: &serde_json::Value, offer: &HpOffer, quote: &Quote) -> Result<serde_json::Value>;
    /// The offer's L2 part (its mint, ...), checked before she signs.
    fn check_offer(w: &Wallet<Self>, record: &Record, offer: &OpenOffer) -> Result<()>;
    /// The funding is out and its adaptor secret `t` known: the contract
    /// (`held`) is open, its mint hers.
    fn minted(w: &mut Wallet<Self>, held: &Held, t: &SecretKey) -> Result<()>;

    /// A withdrawal's claim of `units` from contract `cid`, kept for the
    /// fold or an exit (an exit plan: [`WalletL2::plan_b`],
    /// [`WalletL2::plan_claim`]).
    fn withdrawal(w: &mut Wallet<Self>, chain: &Chain, cid: u32, units: u32) -> Result<serde_json::Value>;
    /// An exit plan's `b`.
    fn plan_b(plan: &serde_json::Value) -> Result<u32>;
    /// An exit plan's claim, as a cooperative withdrawal sends it (hex).
    fn plan_claim(plan: &serde_json::Value) -> Result<String>;
    /// Where the hub credits what the claimed note holds beyond `b`.
    fn rest_to(w: &Wallet<Self>) -> Option<Hash>;
    /// The fold is out (`units` withdrawn): the L2's account closes.
    fn folded(w: &mut Wallet<Self>, cid: u32, units: u32) -> Result<()>;
    /// An exit's plan: the claim she posts (made and kept now, if none).
    fn exit_plan(w: &mut Wallet<Self>, chain: &Chain, cid: u32) -> Result<serde_json::Value>;
    /// An exit played to its end.
    fn exited(w: &mut Wallet<Self>, cid: u32) -> Result<()>;

    /// A dispute's front showed an unlock `z` (the L2's): if it opens her
    /// payment in flight on contract `k`'s account, that step completes:
    /// her new note's value.
    fn unlocked(w: &mut Wallet<Self>, k: usize, z: &[u8]) -> Result<Option<u64>>;
    /// The dispute's front, from her request (`plan` her claim).
    fn run_front(e: &mut Engine<'_>, chain: &Chain, d: &Disputed, plan: &serde_json::Value) -> Result<FrontEnd>;
    /// The inputs of the sweep of a payout she won (`outcome`, its
    /// transaction `payout`), her signature on `b` for those that take it,
    /// and the blocks to wait after the payout.
    fn payout_inputs(w: &Wallet<Self>, chain: &Chain, held: &Held, statement: &lichen_proto::Statement, outcome: &Outcome, payout: &Transaction, b: u32) -> Result<(Vec<SweepIn>, Vec<Vec<u8>>, u16)>;
}

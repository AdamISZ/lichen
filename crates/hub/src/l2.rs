//! What an L2 adds to the hub ([`HubL2`]), and what the hub gives it
//! ([`Ctx`]).
//!
//! The hub runs the contract: deposits, the opening and BABE's setup, the
//! fold, the default, and every dispute's tail (proving, asserting,
//! answering a challenge, collecting a payout's bit outputs). The L2 runs
//! its ledger, and the parts of a contract its ledger decides: the
//! statement's terms and the parties' keys for the dispute's front, the
//! mint, a withdrawal's claim, and the front's moves, up to the input of
//! the proof the hub then makes.

use std::path::PathBuf;

use anyhow::Result;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Sequence, Transaction, TxOut, Txid};
use lichen_btc::taptree::TapTree;
use lichen_chain::Chain;
use lichen_contract::PartyKeys;
use lichen_proto::hp::{Disputed, HpSetup, HpSetupRequest};
use lichen_proto::{Hash, Layer, OpenRequest, Record};
use tiny_http::Method;

use crate::{Config, OpeningFault};

/// The hub's bit outputs of a payout, swept ([`Ctx::sweep`]).
pub enum Bits {
    /// None are the hub's.
    None,
    /// Not on chain yet (the payout unconfirmed, or not mature).
    NotYet,
    /// Swept: the transaction, how many, their value less the fee.
    Swept(Txid, usize, bitcoin::Amount),
}

/// What the hub gives an L2: its chain, its configuration, its log, its
/// contracts, and the chain's plumbing a dispute's front uses.
pub trait Ctx {
    fn chain(&self) -> &Chain;
    fn cfg(&self) -> &Config;
    /// Log what the hub did.
    fn note(&self, msg: String);
    /// [`Ctx::note`], unless the same line is among the last few.
    fn note_once(&self, msg: String);
    /// The hub's keys in contract `cid`.
    fn contract_keys(&self, cid: u32) -> PartyKeys;
    /// A secret of the hub's for contract `cid`, by label (derived from
    /// its seed).
    fn contract_secret(&self, cid: u32, label: &str) -> [u8; 32];
    /// Every contract's record, and whether it is closed.
    fn contracts(&self) -> Vec<(Record, bool)>;
    /// Where the hub keeps contract `cid`'s dispute files.
    fn hp_dir(&self, cid: u32) -> PathBuf;
    /// The height `txid` confirmed at, if it has.
    fn confirmed_at(&self, txid: &Txid) -> Result<Option<u32>>;
    /// Post one of the hub's links (unless it is there: replayed, checked
    /// to be the same), its child paying from the hub's anchor; its
    /// confirmation height.
    fn post(&self, cid: u32, tx: &Transaction) -> Result<u32>;
    /// [`Ctx::post`], its fee child carrying `extra` outputs: its
    /// confirmation height and the child.
    fn post_with(&self, cid: u32, tx: &Transaction, extra: &[TxOut]) -> Result<(u32, Option<Txid>)>;
    /// Post a pre-signed terminal of a dispute, a fee input added.
    fn post_terminal(&self, d: &Disputed, name: &str, wire: Vec<Vec<u8>>) -> Result<Txid>;
    /// Sweep to the hub's wallet the outputs of `trees` on chain, each by
    /// its named leaf: `wire`, then the hub's signature.
    fn sweep(&self, record: &Record, trees: Vec<(bitcoin::ScriptBuf, TapTree, String)>, wire: &[Vec<u8>], sequence: Sequence) -> Result<Bits>;
    /// Whether the hub is set to assert against true claims (tests).
    fn forging(&self) -> bool;
    /// An error once the hub is stopping.
    fn stopping(&self) -> Result<()>;
}

/// Where a dispute's front stands, by the L2.
pub enum FrontStep<S> {
    /// Still in the front: its state.
    Wait(S),
    /// A terminal of the front paid out, spending link `link`'s output:
    /// the hub collects what is its of the payout (`terminal`'s).
    Paid { link: Txid, terminal: String },
    /// The front is done (its last link confirmed at `at`): the hub proves
    /// and asserts before the last link's terminal window ends.
    Prove { at: u32 },
}

/// What the statement's input is, by the L2: the bytes the guest takes,
/// checked natively to hold with the contract's journal; or why it
/// doesn't (no assertion, the front's terminal pays the user).
pub enum ProverInput {
    Holds(Vec<u8>),
    Fails(String),
    /// Not yet (something the proof needs is still to come): why.
    NotYet(String),
}

/// An L2 at the hub.
pub trait HubL2: Layer + Sized + Send + Sync + 'static {
    /// The hub's state in a dispute's front.
    type Front: Send;

    /// What `GET /info` says of the L2 (its deployment, its guests, ...).
    fn info(&self) -> serde_json::Value;
    /// The hub's fee by [`lichen_proto::Pricing`], if the L2 prices so
    /// (`GET /info` names it, and the hub asks it): none keeps
    /// `Config::fee_ppm` of the liquidity.
    fn pricing(&self) -> Option<lichen_proto::Pricing> {
        None
    }
    /// The L2's version (`GET /info`).
    fn version(&self) -> String;
    /// The L2's own HTTP routes (payments, ...): `None` if not one.
    fn route(&self, ctx: &dyn Ctx, method: &Method, path: &str, body: &str) -> Option<Result<String>>;

    /// Whether `owner` may open a contract (asked at the deposit, if she
    /// names one, at the setup and at the opening).
    fn check_owner(&self, ctx: &dyn Ctx, owner: &Hash) -> Result<()>;
    /// The statement's terms for a setup (`HpSetup::l2`), from the request:
    /// checked, and the hub's own added.
    fn setup_terms(&self, ctx: &dyn Ctx, req: &HpSetupRequest) -> Result<serde_json::Value>;
    /// Whether `req` asks for the setup made already.
    fn same_setup(&self, setup: &HpSetup, req: &HpSetupRequest) -> bool;
    /// The user's keys in her commitment (`HpCommit::keys`): of the
    /// parameters the front takes.
    fn check_keys(&self, keys: &serde_json::Value) -> Result<()>;
    /// The journal of a setup and the user's keys.
    fn setup_journal(&self, cid: u32, setup: &HpSetup, keys: &serde_json::Value) -> Result<Vec<u8>>;
    /// At the opening: the contract's L2 keys (`HpKeys::l2`, from the
    /// setup, her keys and the hub's own) and the offer's (`HpOffer::l2`,
    /// the hub's keys she needs). The setup is checked against `req`;
    /// `t_close` the contract's.
    fn open_keys(&self, ctx: &dyn Ctx, setup: &HpSetup, keys: &serde_json::Value, req: &OpenRequest, t_close: u32) -> Result<(serde_json::Value, serde_json::Value)>;
    /// The offer is made: the L2's part of it (`OpenOffer::l2`; a mint
    /// behind `mint_point`, ...).
    fn offered(&self, ctx: &dyn Ctx, record: &Record, mint_point: &PublicKey, fault: OpeningFault) -> Result<serde_json::Value>;
    /// The funding is out: the contract's account opens.
    fn funded(&self, ctx: &dyn Ctx, record: &Record) -> Result<()>;
    /// A cooperative withdrawal's claim of `b` units (`claim`, hex),
    /// checked and taken into the L2; what the claimed note holds beyond
    /// `b` to `rest_to`, if any.
    fn take_claim(&self, ctx: &dyn Ctx, record: &Record, b: u32, claim: &str, rest_to: Option<Hash>) -> Result<()>;

    /// A dispute's front where the chain shows it (the first link is
    /// confirmed; `assert` isn't).
    fn front_start(&self, ctx: &dyn Ctx, d: &Disputed, requested_at: u32) -> Result<FrontStep<Self::Front>>;
    /// One step of a dispute's front.
    fn front_tick(&self, ctx: &dyn Ctx, d: &Disputed, s: Self::Front) -> Result<FrontStep<Self::Front>>;
    /// The statement's input for a dispute whose front is done.
    fn prover_input(&self, ctx: &dyn Ctx, d: &Disputed) -> Result<ProverInput>;
    /// The hub's outputs of a payout (terminal `terminal`, spending link
    /// `link`'s output), swept to its wallet.
    fn collect(&self, ctx: &dyn Ctx, d: &Disputed, link: Txid, terminal: &str) -> Result<Bits>;
    /// A front's state, in words.
    fn describe(&self, s: &Self::Front) -> String;

    /// The L2's own chores (refunds, sweeps, ...), run every
    /// [`L2_TICK`](crate::L2_TICK) on a thread of their own, so that a slow
    /// or failing one never delays the hub's moves: nothing by default. An
    /// error is logged, and the next tick comes as usual.
    fn tick(&self, _ctx: &dyn Ctx) -> Result<()> {
        Ok(())
    }
}

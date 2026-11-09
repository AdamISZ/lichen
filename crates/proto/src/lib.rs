//! What the wallet and the hub exchange to open a contract, and the record
//! each keeps of it.
//!
//! Opening (the wallet asks, the hub answers):
//! 1. [`OpenRequest`]: Alice's keys (for the dispute: the instances she
//!    garbled that the hub doesn't keep, opened, [`hp`]), her deposit `D`,
//!    cap and reserve, the coins she funds with and her change;
//! 2. [`OpenOffer`]: the contract's number (its memo `c`), `T_close`, the
//!    hub's reserve and keys, the funding transaction (unsigned), the
//!    hub's signatures on the whole pre-signed set, and `D` already minted
//!    on the L2 to the [`mint_owner`] of Alice's L2 key and an adaptor
//!    point `T` that is the funding transaction's own;
//! 3. [`Accept`]: having checked the offer, every signature in it and the
//!    mint (sealed), Alice's signatures on the set and an adaptor
//!    pre-signature on the funding's deposit input, locked to `T`; the hub
//!    completes it with `t`, signs its inputs and broadcasts, and answers
//!    with `t` ([`Opened`]). Neither side signs the funding before holding
//!    the other's pre-signed set.
//!
//! The funding and the mint are a swap: the hub can't spend the deposit
//! without completing Alice's pre-signature, and completing it puts `t`
//! in the funding's witness, which unlocks her `D` (it is in [`Opened`]
//! too; the witness is for a hub that doesn't answer). Until the deposit's
//! refund matures, nothing but the funding can spend the deposit, so the
//! hub broadcasts only well before then ([`broadcast_deadline`]). An
//! opening that never completes leaves its mint stranded: tokens no one
//! can spend, which cost the hub nothing. Amounts are in sats.
//!
//! A contract's dispute is the exit where only the hub proves ([`hp`]):
//! BABE with the roles swapped. Its withdrawal is cooperative, by claim
//! ([`WithdrawRequest`]): the hub records the claim on the L2 and folds.

use std::collections::HashMap;


use anyhow::{bail, ensure, Context, Result};
use bitcoin::secp256k1::{schnorr, Message, PublicKey, SecretKey, XOnlyPublicKey};
use bitcoin::{Amount, OutPoint, Transaction, TxOut, Txid};
use lngap_btc::adaptor::AdaptorSig;
use lngap_channel::{ChannelParams, PartyPubKeys};
use lngap_lamport::winternitz::WotsPublic;
use lngap_btc::taptree::TapTree;
use lngap_sessions::contract::{Presign, Signed};
use lngap_sessions::session::Terms;
use lngap_sessions::skeleton::Core;
pub use lichen_ledger::{Deployment, Hash};
use serde::{Deserialize, Serialize};

/// Each party's share of the funding transaction's fee.
pub const FEE_SHARE: Amount = Amount::from_sat(1_000);
/// The least a bit of the dispute's payout is worth (sats): a smaller
/// output would be dust. A contract's unit is from this to about twice it
/// ([`scale`]).
pub const MIN_UNIT: u64 = 512;
/// lichen's version (the workspace's): what a hub and a wallet report.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The guests a build proves and checks receipts with: each one's image
/// id, hex (`r0/guests/<g>.id`). A wallet proves with its own, and a
/// contract's statement pins them when it opens, so a hub's must be the
/// same as the wallet's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Guests {
    pub spend: String,
    pub chain: String,
}

impl Guests {
    /// This build's.
    pub fn ours() -> Guests {
        let id = |s: &str| s.trim().to_string();
        Guests {
            spend: id(lichen_ledger::SPEND_IMAGE_ID),
            chain: id(lichen_ledger::CHAIN_IMAGE_ID),
        }
    }
}

pub use lichen_chain::{Net, Patience, Stall};

pub mod exit;
pub mod hp;
pub mod setup;
pub use hp::{HpKeys, HpOffer, HpRequest};

/// The contracts' timing on a network, in blocks (ln-gap's skeleton): the
/// dispute's first link waits `to_self_delay` after the funding; a
/// payout's outputs wait δ. The dispute's own windows are
/// [`hp::windows`]'. Wide enough for a person, or a restart, at the
/// network's block time; on testnet4, whose blocks come in bursts, wide
/// in blocks so that a burst doesn't use one up.
pub fn params(net: Net) -> ChannelParams {
    let p = ChannelParams::regtest(Amount::from_sat(0));
    match net {
        Net::Regtest => p,
        // 30 s blocks: 5 min, 20 min windows
        Net::Mutinynet => ChannelParams { to_self_delay: 10, delta: 40, delta_prime: 40, deadline_margin: 20, ..p },
        // 10 min blocks: 30 min, 1 h windows
        Net::Signet => ChannelParams { to_self_delay: 3, delta: 6, delta_prime: 6, deadline_margin: 3, ..p },
        // nominally 10 min, in bursts: 6 h windows
        Net::Testnet4 => ChannelParams { to_self_delay: 6, delta: 36, delta_prime: 36, deadline_margin: 12, ..p },
    }
}

/// How long a deposit waits before Alice may take it back alone (CSV,
/// blocks from its confirmation): about a day; a hub that never funds the
/// contract costs her that wait, never the coins. The hub broadcasts the
/// funding only in the first half of it ([`broadcast_deadline`]); on
/// regtest, 1,000 blocks leave time to open with blocks every 150 ms (the
/// dispute tests) or every second (the demo).
pub fn deposit_timeout(net: Net) -> u16 {
    match net {
        Net::Regtest => 1_000,
        Net::Mutinynet => 2_880,
        Net::Signet | Net::Testnet4 => 144,
    }
}

/// What a deposit carries beyond the contract's `D + r_A` and the funding
/// fee's share: Alice's fee budget for a dispute. Where the target
/// feerate is the links' own floor (1 sat/vB) no child is needed, and
/// the budget covers the terminal transactions she posts
/// ([`Built::terminal_need`]; the wallet checks it at opening). Above the
/// floor, each of her links' children pays about `vsize · (feerate − 1)`
/// too (her `challenge_assert` is about 21 kvB).
pub fn fee_budget(net: Net) -> Amount {
    match net {
        Net::Mutinynet | Net::Signet => Amount::from_sat(30_000),
        Net::Regtest | Net::Testnet4 => Amount::from_sat(150_000),
    }
}

/// The deposit address's tree: the hub and Alice together (the funding
/// transaction spends it), or Alice alone after `timeout` blocks (her
/// refund). A NUMS key path: every spend is a script path. (With MuSig2 the
/// first leaf would be the key path, and the deposit an ordinary-looking
/// P2TR output.)
pub fn deposit_tree(alice: &bitcoin::XOnlyPublicKey, hub: &bitcoin::XOnlyPublicKey, timeout: u16) -> Result<lngap_btc::taptree::TapTree> {
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV, OP_DROP};
    use lngap_btc::taptree::Leaf;
    use lngap_btc::tx::Timelock;
    let open = bitcoin::script::Builder::new().push_x_only_key(hub).push_opcode(OP_CHECKSIGVERIFY).push_x_only_key(alice).push_opcode(OP_CHECKSIG).into_script();
    let refund = bitcoin::script::Builder::new().push_int(i64::from(timeout)).push_opcode(OP_CSV).push_opcode(OP_DROP).push_x_only_key(alice).push_opcode(OP_CHECKSIG).into_script();
    lngap_btc::taptree::TapTree::new(vec![Leaf::new(DEPOSIT_OPEN, open, Timelock::NONE), Leaf::new(DEPOSIT_REFUND, refund, Timelock { cltv: None, csv: Some(timeout) })])
}
pub const DEPOSIT_OPEN: &str = "deposit_open";
pub const DEPOSIT_REFUND: &str = "deposit_refund";

/// The shortest life a wallet accepts for a contract, opening to
/// `T_close`, in blocks: time to withdraw, and to dispute, before the
/// default (a day; regtest's tests open short contracts).
pub fn min_duration(net: Net) -> u32 {
    match net {
        Net::Regtest => 20,
        Net::Mutinynet => 2_880,
        Net::Signet | Net::Testnet4 => 144,
    }
}

/// A contract's default life, opening to `T_close`, in blocks: a week
/// (regtest: 1,000 blocks).
pub fn default_duration(net: Net) -> u32 {
    match net {
        Net::Regtest => 1_000,
        Net::Mutinynet => 20_160,
        Net::Signet | Net::Testnet4 => 1_008,
    }
}

/// The statement the disputes run: the hub's (`lichen_withdraw::hp`),
/// that a claim posted is false. `hub-proves` a proof of its guest (not
/// built yet), `hub-proves-mock` a proof of a toy circuit anyone can make,
/// for tests of the protocol (`lichen_babe::statement`). Both sides must
/// run the same one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Statement {
    HubProves { mock: bool },
}

impl std::str::FromStr for Statement {
    type Err = anyhow::Error;
    /// `hub-proves` or `hub-proves-mock`.
    fn from_str(s: &str) -> Result<Statement> {
        match s {
            "hub-proves" => Ok(Statement::HubProves { mock: false }),
            "hub-proves-mock" => Ok(Statement::HubProves { mock: true }),
            _ => bail!("a statement is `hub-proves` or `hub-proves-mock`"),
        }
    }
}

impl Statement {
    pub fn id(&self) -> &'static str {
        match self {
            Statement::HubProves { mock: false } => "hub-proves",
            Statement::HubProves { mock: true } => "hub-proves-mock",
        }
    }
    /// Whether it is the real statement rather than the mock.
    pub fn is_real(&self) -> bool {
        matches!(self, Statement::HubProves { mock: false })
    }
}

/// What the hub offers (`GET /info`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Info {
    /// The Bitcoin network; the wallet must be on the same.
    #[serde(default)]
    pub network: Net,
    /// The L2 deployment the hub is in (its sequencer's key and its own);
    /// the wallet must know the same.
    pub deployment: Deployment,
    /// The statement's id ([`Statement::id`]); the wallet must run the same.
    pub statement: String,
    /// The hub's reserve for a contract of cap `V_max`: `V_max` times this,
    /// in parts per million.
    pub reserve_ppm: u64,
    /// The hub's fee for the liquidity a contract asks: the liquidity
    /// times this, in parts per million ([`liquidity_fee`]).
    pub fee_ppm: u64,
    /// The most liquidity a contract may ask, in sats.
    pub max_liquidity: u64,
    /// Blocks from opening to `T_close`.
    pub duration: u32,
    /// lichen's version the hub runs ([`VERSION`]), and the commit it was
    /// built from, when the build was told (`deploy/build.sh` does).
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub commit: Option<String>,
    /// The guests it proves and checks with ([`Guests::ours`]); none from
    /// a hub older than the field.
    #[serde(default)]
    pub guests: Option<Guests>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenRequest {
    pub alice: PartyPubKeys,
    /// Where the hub mints `D` on the L2.
    pub l2_address: [u8; 32],
    /// What Alice pays in, `D`: she is minted `D - fee`.
    pub deposit: u64,
    /// The liquidity she asks, `L`: what she can receive beyond her
    /// balance. The cap is `D - fee + L` ([`terms`]).
    pub liquidity: u64,
    /// The hub's fee for it, as its rate in [`Info`] makes it, kept out of
    /// her minted balance.
    pub fee: u64,
    /// Alice's reserve `r_A`.
    pub reserve: u64,
    /// Alice's keys for the dispute.
    #[serde(flatten)]
    pub dispute: HpRequest,
    /// The contract number the hub gave the deposit ([`DepositOffer`]).
    pub cid: u32,
    /// Alice's deposit coin (to [`deposit_tree`]), confirmed: `D + r_A`,
    /// the funding fee's share, and the rest her fee budget.
    pub deposit_coin: (OutPoint, TxOut),
    /// Where the funding transaction pays her fee budget (a key of hers).
    pub fee_spk: bitcoin::ScriptBuf,
}

/// Alice asks for a deposit address (`POST /deposit`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositRequest {
    /// Her key in the deposit's tree.
    pub alice: bitcoin::XOnlyPublicKey,
    /// What she'll ask at the opening, `D` and `L`, so that the hub can
    /// refuse now a contract it couldn't fund then, before she pays (0:
    /// not said, by a wallet older than the fields).
    #[serde(default)]
    pub deposit: u64,
    #[serde(default)]
    pub liquidity: u64,
}

/// The hub's answer: the contract's number, its key in the deposit's
/// tree, the refund's timeout.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositOffer {
    pub cid: u32,
    pub hub: bitcoin::XOnlyPublicKey,
    pub timeout: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenOffer {
    /// The contract's number, its memo `c`.
    pub cid: u32,
    pub t_close: u32,
    pub reserve_hub: u64,
    pub hub: PartyPubKeys,
    /// The hub's keys for the dispute.
    #[serde(flatten)]
    pub dispute: HpOffer,
    /// Inputs: Alice's coins, then the hub's. Outputs: the contract, then
    /// Alice's change, then the hub's.
    pub funding: Transaction,
    /// The prevouts of the hub's inputs.
    pub hub_coins: Vec<(OutPoint, TxOut)>,
    pub hub_sigs: HashMap<String, Vec<u8>>,
    /// `T`, the adaptor point of this funding transaction.
    pub mint_point: PublicKey,
    /// The note minting `D` to [`mint_owner`]`(l2_address, T)`.
    pub mint_index: u32,
    /// In an anchored deployment, the contract's checkpoint.
    #[serde(default)]
    pub checkpoint: Option<Checkpoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Accept {
    pub cid: u32,
    pub alice_sigs: HashMap<String, Vec<u8>>,
    /// Alice's pre-signature on the funding transaction's deposit input
    /// (the `deposit_open` leaf), locked to `T`: the hub completes it with
        /// `t` and adds its own.
    pub deposit_presig: Presig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Opened {
    pub txid: Txid,
    /// The adaptor secret, once the funding is broadcast.
    pub t: SecretKey,
}

/// An adaptor pre-signature on the wire ([`lngap_btc::adaptor::AdaptorSig`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presig {
    pub r_final: XOnlyPublicKey,
    pub r: PublicKey,
    pub s_prime: SecretKey,
}

impl From<AdaptorSig> for Presig {
    fn from(a: AdaptorSig) -> Presig {
        Presig { r_final: a.r_final, r: a.r, s_prime: a.s_prime }
    }
}

impl From<&Presig> for AdaptorSig {
    fn from(p: &Presig) -> AdaptorSig {
        AdaptorSig { r_final: p.r_final, r: p.r, s_prime: p.s_prime }
    }
}

/// Who a deposit's `D` is minted to before the funding: Alice's L2 key
/// and the funding's adaptor point ([`lichen_ledger::mint_key`]).
pub fn mint_owner(l2_address: &Hash, mint_point: &PublicKey) -> Result<Hash> {
    lichen_ledger::mint_key(l2_address, &mint_point.serialize())
}

/// The message a signature on the funding's deposit input commits to
/// (SIGHASH_DEFAULT, the `deposit_open` leaf), and that input's index.
/// `coins`: the prevouts of every input of the funding.
pub fn deposit_open_msg(funding: &Transaction, deposit: &OutPoint, coins: &[(OutPoint, TxOut)], tree: &lngap_btc::taptree::TapTree) -> Result<(usize, Message)> {
    let prevouts: Vec<TxOut> = funding.input.iter().map(|i| coins.iter().find(|k| k.0 == i.previous_output).map(|k| k.1.clone()).context("an input of the funding not offered")).collect::<Result<_>>()?;
    let dep = funding.input.iter().position(|i| i.previous_output == *deposit).context("the deposit input")?;
    Ok((dep, lngap_btc::sighash::tapscript_sighash(funding, dep, &prevouts, &tree.leaf(DEPOSIT_OPEN)?.script)?))
}

/// Alice's signature in a funding transaction's deposit input, as
/// broadcast: the first witness item (`deposit_open` pops the hub's, then
/// hers).
pub fn deposit_sig_in(funding: &Transaction, deposit: &OutPoint) -> Option<schnorr::Signature> {
    let input = funding.input.iter().find(|i| i.previous_output == *deposit)?;
    schnorr::Signature::from_slice(input.witness.nth(0)?).ok()
}

/// The last height at which the hub may broadcast a funding transaction:
/// half the refund's timeout before the refund matures, so that the
/// funding confirms (fee-bumped by the hub's change if need be) while
/// nothing else can spend the deposit. `confirmed`: the deposit's
/// confirmation height.
pub fn broadcast_deadline(confirmed: u32, timeout: u16) -> u32 {
    confirmed + u32::from(timeout) - u32::from(timeout) / 2
}

/// The cooperative close's fee, from the hub's share.
pub const FOLD_FEE: Amount = Amount::from_sat(1_000);
/// The least a fold pays Alice when she withdraws nothing (`b` 0: her
/// reserve alone), the dust floor of her output.
pub const CLOSE_DUST: Amount = Amount::from_sat(330);
/// The default's fee coin, the hub's.
pub const DEFAULT_FEE: Amount = Amount::from_sat(2_000);

/// Alice asks the hub to fold contract `cid` for her return at `index`
/// (a sealed note of `b` sats to the hub with memo `cid`), with her
/// signature on the fold.
/// A cooperative withdrawal (`POST /withdraw`): Alice's claim of `b`
/// units from contract `cid` ([`lichen_withdraw::hp::Claim`]'s bytes, hex:
/// her notes by position, her signatures on its `E`), which the hub
/// records on the L2, retiring the notes, and her signature on the fold
/// paying her `b` units. At `b` 0, no claim: an early close, the fold
/// paying her reserve alone.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawRequest {
    pub cid: u32,
    pub b: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub claim: String,
    pub alice_sig: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Folded {
    pub txid: Txid,
}

/// A link's anchor: the output whose script is the poster's anchor for
/// its payment key.
pub fn anchor_vout(tx: &Transaction, payment: &bitcoin::XOnlyPublicKey) -> Result<u32> {
    let spk = lngap_sessions::contract::anchor_tree_for(payment)?.script_pubkey();
    tx.output.iter().position(|o| o.script_pubkey == spk).map(|v| v as u32).context("the link has no anchor of this party's")
}

/// The anchor's witness in a fee child (input 0 spends the anchor), signed
/// with the poster's payment key.
pub fn sign_anchor(kp: &bitcoin::key::Keypair, child: &Transaction, prevouts: &[TxOut]) -> Result<bitcoin::Witness> {
    let tree = lngap_sessions::contract::anchor_tree_for(&kp.x_only_public_key().0)?;
    let leaf = tree.leaf("fee")?;
    let sig = lngap_btc::sighash::sign_tapscript(kp, child, 0, prevouts, &leaf.script)?;
    Ok(lngap_btc::witness::tapscript_witness(&[sig.as_ref().to_vec()], &leaf.script, &tree.control_block("fee")?))
}

/// How many blocks' work, at the checkpoint's difficulty, a withdrawal
/// shows on top of the anchor of its root (docs/ANCHOR_PLAN.md).
pub const ANCHOR_DEPTH: u128 = 10;

/// The Bitcoin block a contract opened at, in an anchored deployment: its
/// difficulty fixes the work `W` a withdrawal shows on top of its anchor.
/// Each side checks it against its own view of the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: u32,
    pub hash: bitcoin::BlockHash,
    pub bits: u32,
}

impl Checkpoint {
    /// The checkpoint at the chain's tip.
    pub fn tip(chain: &lichen_chain::Chain) -> Result<Checkpoint> {
        let height = chain.height()?;
        let hash = chain.block_hash(height)?;
        let header = chain.header(&hash)?;
        Ok(Checkpoint { height, hash, bits: u32::from_le_bytes(header[72..76].try_into().unwrap()) })
    }
    /// `W`: [`ANCHOR_DEPTH`] blocks of its difficulty.
    pub fn work(&self) -> u128 {
        ANCHOR_DEPTH.saturating_mul(lichen_ledger::lichen_validity::btc::work(self.bits))
    }
    /// Check it against `chain`: its block on the best chain with these
    /// bits, at most `stale` blocks below the tip.
    pub fn check(&self, chain: &lichen_chain::Chain, stale: u32) -> Result<()> {
        ensure!(chain.block_hash(self.height)? == self.hash, "the checkpoint {} isn't the best chain's block {}", self.hash, self.height);
        let header = chain.header(&self.hash)?;
        ensure!(u32::from_le_bytes(header[72..76].try_into().unwrap()) == self.bits, "the checkpoint's bits aren't its block's");
        ensure!(chain.height()? <= self.height + stale, "the checkpoint, block {}, is stale", self.height);
        Ok(())
    }
}

/// Headers on top of block `from` (internal order), from the chain, until
/// their work reaches `work`: what a withdrawal shows on top of its
/// anchor. An error, saying how far it has got, if not there yet.
pub fn headers_for(chain: &lichen_chain::Chain, from: &Hash, work: u128) -> Result<Vec<[u8; 80]>> {
    use bitcoin::hashes::Hash as _;
    let block = bitcoin::BlockHash::from_byte_array(*from);
    let mut out = vec![];
    let mut sum = 0u128;
    for h in chain.headers_after(&block, 4 * ANCHOR_DEPTH as usize)? {
        sum = sum.saturating_add(lichen_ledger::lichen_validity::btc::work(u32::from_le_bytes(h[72..76].try_into().unwrap())));
        out.push(h);
        if sum >= work && !out.is_empty() {
            return Ok(out);
        }
    }
    bail!("the anchor isn't deep enough yet: {} blocks on it, {sum} of the {work} work the contract asks", out.len())
}

/// The journal's `D` a contract pins: the deployment's id, or in an
/// anchored deployment (a genesis seal) the contract's, of the genesis
/// seal, the checkpoint's `W` and the contract's unit too.
pub fn contract_word(d: &Deployment, checkpoint: Option<&Checkpoint>, unit: Amount) -> Result<Hash> {
    match (d.seal, checkpoint) {
        (None, None) => Ok(d.id()),
        (Some(seal), Some(c)) => Ok(lichen_ledger::lichen_withdraw_contract_id(&d.id(), &seal, c.work(), unit.to_sat())),
        (Some(_), None) => bail!("an anchored deployment's contract needs a checkpoint"),
        (None, Some(_)) => bail!("a checkpoint in a deployment that doesn't anchor"),
    }
}

/// A contract as each side keeps it: enough to rebuild every transaction
/// and both parties' signatures on the pre-signed set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub statement: String,
    /// The Bitcoin network, which fixes the contract's timing.
    #[serde(default)]
    pub network: Net,
    /// The claim's journal must carry this: the L2 deployment's id, or in
    /// an anchored deployment the contract's ([`contract_word`]).
    pub deployment: Hash,
    /// In an anchored deployment, the Bitcoin block the contract opened at,
    /// which fixes the work a withdrawal shows on top of its anchor.
    #[serde(default)]
    pub checkpoint: Option<Checkpoint>,
    pub terms: Terms,
    pub pubs: [PartyPubKeys; 2],
    pub l2_address: [u8; 32],
    pub funding: OutPoint,
    pub hub_sigs: HashMap<String, Vec<u8>>,
    pub alice_sigs: HashMap<String, Vec<u8>>,
    /// The hub's fee for the contract's liquidity: Alice was minted
    /// `terms.deposit - fee` ([`Record::minted`]).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub fee: u64,
    /// The dispute's keys.
    #[serde(flatten)]
    pub dispute: HpKeys,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Record {
    /// What the hub minted Alice for her deposit: `D` less its fee.
    pub fn minted(&self) -> u64 {
        u64::from(self.terms.deposit).saturating_sub(self.fee)
    }
}

impl Record {
    pub fn cid(&self) -> u32 {
        self.terms.id
    }
    /// The contract's graph, under `statement`, the contract's.
    pub fn build(&self, statement: &Statement) -> Result<Built> {
        ensure!(statement.id() == self.statement, "the contract runs {}, not {}", self.statement, statement.id());
        Ok(Built(Box::new(self.hp_graph()?)))
    }
    pub fn signed(&self) -> Signed {
        Signed { hub: self.hub_sigs.clone(), alice: self.alice_sigs.clone() }
    }
    /// The pre-signed set, both signatures checked (but on what Alice
    /// keeps from the hub, [`Built::withheld`]).
    pub fn presigned(&self, c: &Built) -> Result<Vec<Presign>> {
        let set = c.presign(self.funding)?;
        let shown: Vec<Presign> = set.iter().filter(|p| !c.withheld(&p.name)).cloned().collect();
        self.signed().verify(&shown, &self.pubs)?;
        Ok(set)
    }
}

/// A contract's graph ([`lichen_babe::hp::HubProves`]): the contract
/// output with its fold, default and dispute (ln-gap's skeleton,
/// [`Core`]), the dispute's links and terminals, the payout.
pub struct Built(pub Box<lichen_babe::hp::HubProves>);

impl Built {
    pub fn graph(&self) -> &lichen_babe::hp::HubProves {
        &self.0
    }
    pub fn core(&self) -> Core<'_> {
        self.0.core()
    }
    /// What the contract output holds: `V_max` and both reserves.
    pub fn value(&self) -> Amount {
        self.core().value()
    }
    /// The contract output's tree.
    pub fn tree(&self) -> Result<TapTree> {
        self.0.tree()
    }
    /// The cooperative close for a withdrawal of `b` sats.
    pub fn fold(&self, funding: OutPoint, b: Amount, fee: Amount) -> Result<Presign> {
        self.core().fold(&self.tree()?, funding, b, fee)
    }
    /// Every transaction the two parties pre-sign, the contract output at
    /// `funding`: the default and the dispute's.
    pub fn presign(&self, funding: OutPoint) -> Result<Vec<Presign>> {
        self.0.presign(funding)
    }
    /// Whether a party keeps its signature on `name` from the other: the
    /// hub, on `wrongly_challenged`.
    pub fn withheld(&self, name: &str) -> bool {
        lichen_babe::hp::HubProves::withheld(name)
    }
    /// The key Alice signs `b` with in a dispute; the payout's bit outputs
    /// read it.
    pub fn b_key(&self) -> &WotsPublic {
        &self.0.spec.b_key
    }
    /// What the heaviest of Alice's terminal transactions (in the
    /// pre-signed `set`) needs from her fee budget on `net`.
    pub fn terminal_need(&self, set: &[Presign], net: Net) -> Result<Amount> {
        hp::terminal_need(set, net)
    }
}

/// The hub's fee for `liquidity` sats at `fee_ppm` parts per million.
pub fn liquidity_fee(liquidity: u64, fee_ppm: u64) -> u64 {
    (u128::from(liquidity) * u128::from(fee_ppm) / 1_000_000) as u64
}

/// A cap's scale: the largest `K` with `MIN_UNIT (2^K - 1)` at most `cap`
/// (at most 32: `b` is a 32-bit word), and the unit `u = ceil(cap / (2^K -
/// 1))`. So `V_max = u (2^K - 1)` is the cap, or more by under `2^K` sats
/// (about 0.2%), and every bit of the payout is an output of at least
/// `MIN_UNIT`.
pub fn scale(cap: u64) -> Result<(u32, u64)> {
    ensure!(cap >= MIN_UNIT, "a cap of {cap} sats, under {MIN_UNIT}");
    let mut k = 1u32;
    while k < 32 && MIN_UNIT.saturating_mul((1u64 << (k + 1)) - 1) <= cap {
        k += 1;
    }
    Ok((k, cap.div_ceil((1u64 << k) - 1)))
}

/// The terms of a contract opened from `req` with the hub's choices: Alice
/// pays `D` in and is minted `D - fee`; the cap is `D - fee + L`, scaled
/// ([`scale`]).
pub fn terms(cid: u32, req: &OpenRequest, t_close: u32, reserve_hub: u64) -> Result<Terms> {
    // amounts that add up without overflow
    let most = Amount::MAX_MONEY.to_sat();
    ensure!(req.reserve <= most && reserve_hub <= most, "a reserve above 21 million bitcoin");
    ensure!(req.deposit <= most && req.liquidity <= most, "a deposit or liquidity above 21 million bitcoin");
    ensure!(req.fee < req.deposit, "a deposit of {} doesn't cover the fee of {}", req.deposit, req.fee);
    let (bits, unit) = scale(req.deposit - req.fee + req.liquidity)?;
    let v_max = unit * ((1u64 << bits) - 1);
    ensure!(req.deposit <= v_max, "a deposit of {} with a cap of {v_max}", req.deposit);
    Ok(Terms {
        id: cid,
        unit: Amount::from_sat(unit),
        bits,
        low_bits: 0,
        deposit: u32::try_from(req.deposit).context("the deposit")?,
        t_close,
        reserve_alice: Amount::from_sat(req.reserve),
        reserve_hub: Amount::from_sat(reserve_hub),
    })
}

/// What each side puts into the contract: Alice `D + r_A`, the hub
/// `V_max - D + r_H`.
pub fn contributions(t: &Terms) -> (Amount, Amount) {
    let d = Amount::from_sat(u64::from(t.deposit));
    (d + t.reserve_alice, t.v_max() - d + t.reserve_hub)
}

/// Check a funding transaction against the contract: output 0 is the
/// contract; `mine` are the checker's coins, which must all be spent, and
/// `change` its change, which must be paid in full; what it contributes is
/// exactly `want` plus its fee share.
pub fn check_funding(tx: &Transaction, c: &Built, mine: &[(OutPoint, TxOut)], change: &TxOut, want: Amount) -> Result<()> {
    let tree = c.tree()?;
    ensure!(tx.output.first().map(|o| (o.value, &o.script_pubkey)) == Some((c.value(), &tree.script_pubkey())), "output 0 is not the contract");
    for (op, _) in mine {
        ensure!(tx.input.iter().any(|i| i.previous_output == *op), "a coin of mine is missing");
    }
    ensure!(tx.output.contains(change), "my change is missing");
    let spent: Amount = mine.iter().map(|c| c.1.value).sum();
    if spent != want + FEE_SHARE + change.value {
        bail!("I would put in {}, not {}", spent - change.value, want + FEE_SHARE);
    }
    Ok(())
}

/// Alice's check of the funding transaction offered: it spends her
/// deposit, its output 0 is the contract, and it pays her fee budget
/// `fee` (the rest of the deposit). The hub's coins are its business.
pub fn check_deposit_funding(tx: &Transaction, c: &Built, deposit: &OutPoint, fee: &TxOut) -> Result<()> {
    let tree = c.tree()?;
    ensure!(tx.output.first().map(|o| (o.value, &o.script_pubkey)) == Some((c.value(), &tree.script_pubkey())), "output 0 is not the contract");
    ensure!(tx.input.iter().any(|i| i.previous_output == *deposit), "my deposit is not spent");
    ensure!(tx.output.contains(fee), "my fee budget is missing");
    Ok(())
}

/// The fee budget a deposit leaves: what it holds beyond `D + r_A` and the
/// funding fee's share.
pub fn fee_budget_of(deposit: Amount, t: &Terms) -> Result<Amount> {
    deposit.checked_sub(contributions(t).0 + FEE_SHARE).context("the deposit doesn't cover the deposit, the reserve and the funding fee")
}

// ----- disputes: what both sides' engines share -----

/// The feerate the parties aim for on a dispute's transactions, sat/vB:
/// the links' own floor (1) where that confirms (Mutinynet, signet: no
/// children), 2 on regtest (so the tests post children) and testnet4.
pub fn feerate(net: Net) -> u64 {
    match net {
        Net::Mutinynet | Net::Signet => 1,
        Net::Regtest | Net::Testnet4 => 2,
    }
}

/// The fee a terminal transaction's broadcaster adds with its coin
/// (`Chain::post_terminal`): the transaction's own size and the coin's
/// input (a key-path spend, 58 vB), at the network's feerate; at least
/// 330 sats, since the coin is worth exactly the fee and a P2TR output
/// under that is dust, which doesn't relay (a node's wallet won't make it:
/// at 1 sat/vB a small terminal, such as `failure`, would need one).
pub fn terminal_fee(tx: &Transaction, net: Net) -> Amount {
    Amount::from_sat(((tx.vsize() as u64 + 60) * feerate(net)).max(330))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cap's scale: `V_max` the cap or a little more, every bit's output
    /// at least `MIN_UNIT`; the terms of a request, its fee out of the
    /// minted deposit and in the cap.
    #[test]
    fn the_cap_scaled() {
        assert_eq!(scale(1_000_000).unwrap(), (10, 978));
        assert_eq!(scale(400_000 + 1_000_000).unwrap().1, 684);
        assert_eq!(scale(MIN_UNIT).unwrap(), (1, MIN_UNIT));
        assert!(scale(MIN_UNIT - 1).is_err());
        for cap in [512, 1_000, 1_535, 1_536, 99_999, 1_000_000, 16_777_215, 2_100_000_000_000] {
            let (k, u) = scale(cap).unwrap();
            let v_max = u * ((1u64 << k) - 1);
            assert!(v_max >= cap && v_max - cap < 1 << k && u >= MIN_UNIT && k <= 32, "{cap}: K {k}, u {u}");
        }
        let req = |deposit, liquidity, fee| OpenRequest {
            alice: lngap_channel::PartyKeys::from_seed(lngap_channel::Role::User, lngap_btc::keys::Seed::from_label("test/alice")).public(),
            l2_address: [7; 32],
            deposit,
            liquidity,
            fee,
            reserve: 20_000,
            dispute: HpRequest { hp_opened: vec![] },
            cid: 1000,
            deposit_coin: (OutPoint::null(), TxOut { value: Amount::ZERO, script_pubkey: bitcoin::ScriptBuf::new() }),
            fee_spk: bitcoin::ScriptBuf::new(),
        };
        let t = terms(1000, &req(100_000, 1_000_000, liquidity_fee(1_000_000, 10_000)), 500, 30_000).unwrap();
        assert_eq!((t.bits, t.unit, t.low_bits, t.deposit), (11, Amount::from_sat(533), 0, 100_000));
        assert_eq!(t.v_max(), Amount::from_sat(1_091_051), "the cap 1,090,000, scaled");
        // the hub puts in the liquidity, less the fee, and the overshoot
        assert_eq!(contributions(&t).1, Amount::from_sat(1_091_051 - 100_000 + 30_000));
        assert!(terms(1000, &req(10_000, 1_000_000, 10_000), 500, 30_000).is_err(), "a fee the deposit doesn't cover");
    }

    /// A reserve whose sum would overflow is refused before anything is
    /// built on it; the networks' names read back; the windows in blocks.
    #[test]
    fn a_request_checked() {
        let alice = lngap_channel::PartyKeys::from_seed(lngap_channel::Role::User, lngap_btc::keys::Seed::from_label("test/alice")).public();
        let mut req = OpenRequest {
            alice,
            l2_address: [7; 32],
            deposit: 100_000,
            liquidity: 1_000_000,
            fee: 10_000,
            reserve: 20_000,
            dispute: HpRequest { hp_opened: vec![] },
            cid: 1000,
            deposit_coin: (OutPoint::null(), TxOut { value: Amount::ZERO, script_pubkey: bitcoin::ScriptBuf::new() }),
            fee_spk: bitcoin::ScriptBuf::new(),
        };
        terms(1000, &req, 100, 20_000).unwrap();
        // a reserve near u64::MAX overflowed the contract's value
        req.reserve = u64::MAX - 5;
        assert!(format!("{:#}", terms(1000, &req, 100, 20_000).unwrap_err()).contains("21 million"));
        for n in ["regtest", "mutinynet", "signet", "testnet4"] {
            assert_eq!(n.parse::<Net>().unwrap().to_string(), n);
        }
        for s in ["hub-proves", "hub-proves-mock"] {
            assert_eq!(s.parse::<Statement>().unwrap().id(), s);
        }
        assert!("babe".parse::<Statement>().is_err());
        // the windows are in blocks: wider where blocks come faster or in bursts
        assert!(params(Net::Mutinynet).delta > params(Net::Signet).delta);
        assert!(params(Net::Testnet4).delta > params(Net::Signet).delta);
    }
}

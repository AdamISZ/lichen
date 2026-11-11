//! The user's wallet: a key, the notes it owns on the L2, transfers, and
//! its contracts with the hub (opening: [`Wallet::open_contract`]; the
//! cooperative withdrawal, by claim: [`Wallet::withdraw`]; the exit:
//! [`Wallet::exit`]).
//!
//! The ledger is transparent, so the wallet finds its notes by reading the
//! sequencer's state; it checks every sealed root's signature.

mod ack;
pub use ack::ACK_PATIENCE;
mod hp;
pub mod dispute;
pub mod engine;
pub mod exit;
pub mod finality;
pub mod shielded;

use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use lichen_ledger::k256::schnorr::SigningKey;
use lichen_ledger::{fresh_rho, mint_secret, note, sign, xonly, Deployment, Hash, Note, Spend, Transfer, Tx};
use lichen_chain::{Chain, KeyFees};
use bitcoin::secp256k1::{PublicKey, SecretKey, SECP256K1};
use lichen_proto::{check_deposit_funding, deposit_open_msg, deposit_sig_in, deposit_tree, mint_owner, Presig, fee_budget_of, terms, Accept, DepositOffer, DepositRequest, Folded, Info, OpenOffer, OpenRequest, Opened, Record, Statement, WithdrawRequest, CLOSE_DUST, DEFAULT_FEE, DEPOSIT_REFUND, FEE_SHARE, FOLD_FEE};
use lichen_l2::{Client, Equivocation, Seen, State};
use lngap_btc::adaptor::{adaptor_extract, adaptor_sign, AdaptorSig};
use lngap_channel::PartyKeys;
use lngap_sessions::contract::sign_all;
use crate::engine::ContractSecrets;
use serde::{Deserialize, Serialize};

/// What the wallet keeps on disk.
#[derive(Serialize, Deserialize)]
struct Stored {
    /// The secret key, hex.
    secret: String,
    /// The L2 deployment, pinned when the wallet was made (an older file
    /// without it pins it on first open).
    #[serde(default)]
    deployment: Option<Deployment>,
    /// Its contracts: each one's nonce (from which its keys derive) and
    /// record.
    #[serde(default)]
    contracts: Vec<Held>,
    /// Deposits paid (or to be paid) for contracts not yet open.
    #[serde(default)]
    deposits: Vec<Deposit>,
    /// Every signed root checked, by height.
    #[serde(default)]
    seen: Seen,
    /// What an exit needs, kept at anchored heights ([`exit::ExitSet`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    exit_sets: Vec<exit::ExitSet>,
    /// The spends this wallet signed ([`Signed`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    signed: Vec<Signed>,
}

/// A spend this wallet signed: the nullifiers of the notes it spends. So
/// that an exit with the sequencer gone knows which kept notes it may
/// have spent since (docs/HUB_PROVES_PLAN.md), and so that the wallet
/// acknowledges it ([`Wallet::acknowledge`]): its acknowledgment once
/// signed, and whether it is settled (acknowledged on the L2, void, or
/// needing none).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signed {
    pub nullifiers: Vec<Hash>,
    #[serde(default)]
    pub ack: Option<lichen_ledger::Ack>,
    #[serde(default)]
    pub done: bool,
    /// Its transparent outputs, by their nullifiers: a claim of one made
    /// without the sequencer (from the exit set kept) finds its
    /// acknowledgment by them.
    #[serde(default)]
    pub outputs: Vec<Hash>,
}

impl Signed {
    pub fn new(nullifiers: Vec<Hash>, outputs: &[Note]) -> Signed {
        Signed { nullifiers, ack: None, done: false, outputs: outputs.iter().map(lichen_ledger::nullifier).collect() }
    }
}

/// An anchor checked on Bitcoin, and the height of its block.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AnchorChecked {
    pub anchor: lichen_ledger::AnchorState,
    /// The history hash it committed.
    pub hist: Hash,
    pub block_height: u32,
}

/// A deposit for a contract not yet open: kept from before it is paid,
/// so that it can always be refunded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Deposit {
    /// The contract's nonce (its keys derive from it) and number.
    pub nonce: String,
    pub cid: u32,
    /// The hub's key in the tree, and the refund's timeout.
    pub hub: bitcoin::XOnlyPublicKey,
    pub timeout: u16,
    /// Where a refund goes.
    pub payout: bitcoin::ScriptBuf,
    /// The offer accepted, and its mint, kept before the hub is told: if
    /// its answer is lost, the funding on chain opens the contract all the
    /// same, and reveals `t` ([`Wallet::claim_mint`]).
    #[serde(default)]
    pub offered: Option<(Record, Locked)>,
    /// Offers accepted before `offered` (an opening resumed after the
    /// hub's failure): each pre-signature still lets the hub broadcast its
    /// funding, so each is kept until one is out or the deposit refunded.
    #[serde(default)]
    pub earlier: Vec<(Record, Locked)>,
}

impl Deposit {
    /// The offer accepted whose funding is on chain, if any.
    fn funded(&self, chain: &Chain) -> Option<(Record, Locked)> {
        self.offered.iter().chain(&self.earlier).find(|(r, _)| chain.get_tx(&r.funding.txid).is_some()).cloned()
    }
    /// Whether the hub holds a pre-signature of ours on this deposit.
    fn presigned(&self) -> bool {
        self.offered.is_some() || !self.earlier.is_empty()
    }
}

/// A contract's `D`, minted before its funding to [`mint_owner`] of our
/// address and the funding's adaptor point: ours once we know `t`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Locked {
    /// The note.
    pub index: u32,
    /// `T`.
    pub point: PublicKey,
    /// Our pre-signature on the funding's deposit input, and the deposit:
    /// the funding's completed signature, less it, is `t`.
    pub presig: Presig,
    pub deposit: bitcoin::OutPoint,
    /// Moved to our own key.
    #[serde(default)]
    pub claimed: bool,
}

/// A contract the wallet holds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Held {
    pub nonce: String,
    pub record: Record,
    /// How it ended: the fold's txid, or the dispute's payout (or the
    /// spend that took it).
    #[serde(default)]
    pub closed: Option<bitcoin::Txid>,
    /// A dispute's payout, once posted.
    #[serde(default)]
    pub payout: Option<dispute::Outcome>,
    /// Its `D`, minted before the funding (none for a contract opened when
    /// the hub minted after it).
    #[serde(default)]
    pub mint: Option<Locked>,
    /// The claim of a withdrawal or an exit in progress
    /// ([`exit::ExitPlan`]): a cooperative withdrawal's, sent to the hub,
    /// is the exit's too if the hub then won't fold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<exit::ExitPlan>,
}

/// sat/vB for payments from the wallet's payout key ([`Wallet::send_payout`]).
pub const PAYOUT_FEERATE: u64 = 2;

pub struct Wallet {
    /// For tests: stop an exit after posting `request` (it resumes from
    /// the chain when run again).
    pub pause_after: Option<u32>,
    /// For tests: challenge the hub's assertion even if its proof is
    /// valid.
    pub unchecked_claims: bool,
    /// For tests: sign acknowledgments and keep them, but send none (a
    /// sequencer that drops them, or withholds that it took them).
    pub acks_unsent: bool,
    /// Told each step of a dispute, in words (for a front end).
    pub progress: Option<std::sync::Arc<dyn Fn(String) + Send + Sync>>,
    /// How shielded spends are proved.
    pub spend_prover: shielded::SpendProver,
    key: SigningKey,
    path: PathBuf,
    seen: std::sync::Mutex<Seen>,
    /// The anchors checked on Bitcoin so far ([`Wallet::checked_anchors`]).
    anchors_checked: std::sync::Mutex<Vec<AnchorChecked>>,
    exit_sets: std::sync::Mutex<Vec<exit::ExitSet>>,
    /// When [`Wallet::state`] last looked to keep the exit set.
    exit_looked: std::sync::Mutex<Option<std::time::Instant>>,
    signed: Vec<Signed>,
    pub contracts: Vec<Held>,
    pub deposits: Vec<Deposit>,
    pub sequencer: Client,
}

/// An unspent note of ours.
#[derive(Clone, Copy, Debug)]
pub struct Owned {
    pub note: Note,
    pub index: u32,
}

impl Wallet {
    /// Create a wallet at `path` with a fresh key.
    pub fn create(path: &Path, sequencer: &str) -> Result<Wallet> {
        if path.exists() {
            bail!("{} already exists", path.display());
        }
        let key = SigningKey::from_bytes(&fresh_rho()).context("a key")?;
        // the deployment the sequencer announces, kept from now on
        let w = Wallet { pause_after: None, unchecked_claims: false, acks_unsent: false, progress: None, spend_prover: Default::default(), key, path: path.to_path_buf(), seen: Default::default(), anchors_checked: Default::default(), exit_sets: Default::default(), exit_looked: Default::default(), signed: vec![], contracts: vec![], deposits: vec![], sequencer: Client::new(sequencer)? };
        w.save()?;
        Ok(w)
    }
    pub fn open(path: &Path, sequencer: &str) -> Result<Wallet> {
        let s: Stored = serde_json::from_slice(&std::fs::read(path).with_context(|| format!("no wallet at {}", path.display()))?)?;
        let key = SigningKey::from_bytes(&hex::decode(&s.secret)?).context("the wallet's key")?;
        let client = match s.deployment {
            Some(d) => Client::pinned(sequencer, d),
            None => Client::new(sequencer)?,
        };
        let w = Wallet { pause_after: None, unchecked_claims: false, acks_unsent: false, progress: None, spend_prover: Default::default(), key, path: path.to_path_buf(), seen: std::sync::Mutex::new(s.seen), anchors_checked: Default::default(), exit_sets: std::sync::Mutex::new(s.exit_sets), exit_looked: Default::default(), signed: s.signed, contracts: s.contracts, deposits: s.deposits, sequencer: client };
        if s.deployment.is_none() {
            w.save()?;
        }
        Ok(w)
    }
    pub(crate) fn save(&self) -> Result<()> {
        let s = Stored {
            secret: hex::encode(self.key.to_bytes()),
            deployment: Some(self.sequencer.deployment),
            contracts: self.contracts.clone(),
            deposits: self.deposits.clone(),
            seen: self.seen.lock().unwrap().clone(),
            exit_sets: self.exit_sets.lock().unwrap().clone(),
            signed: self.signed.clone(),
        };
        if let Some(d) = self.path.parent() {
            std::fs::create_dir_all(d)?;
        }
        // the only copy of the wallet's key: replaced atomically, the owner's alone
        lichen_ledger::files::write_private(&self.path, &serde_json::to_vec_pretty(&s)?)?;
        Ok(())
    }
    /// The sequencer's state, its roots checked and recorded: an error if
    /// it shows a root at a height seen before other than the one seen
    /// (the evidence written beside the wallet, `<wallet>.equivocation.json`).
    /// Its exit set kept up to it as well, at most every
    /// [`exit::EXIT_SET_EVERY`] ([`Wallet::keep_exit_set`]).
    pub fn state(&self) -> Result<State> {
        let s = self.observe(self.sequencer.state()?)?;
        self.keep_exit_set_soon(&s);
        Ok(s)
    }
    /// A state of the sequencer fetched apart from the wallet (with a
    /// client pinned to its deployment, which checks its roots), recorded
    /// as [`Wallet::state`] records it: a caller holding the wallet in a
    /// lock fetches it first.
    pub fn observe(&self, state: State) -> Result<State> {
        let new = self.seen.lock().unwrap().record(&state.sealed);
        match new {
            Ok(true) => self.save()?,
            Ok(false) => {}
            Err(e) => bail!("{e}: it signed two histories. The evidence: {}", self.evidence(&e)?.display()),
        }
        Ok(state)
    }
    /// The signed roots seen, by height.
    pub fn seen(&self) -> Seen {
        self.seen.lock().unwrap().clone()
    }
    /// Check `roots` from elsewhere (another wallet's, another server's)
    /// against those seen: how many heights agree, or the first conflict,
    /// its evidence written as by [`Wallet::state`]. Each root's signature
    /// is checked first.
    pub fn compare_roots(&self, roots: &[lichen_ledger::SignedRoot]) -> Result<usize> {
        for r in roots {
            r.verify(&self.sequencer.deployment.sequencer).with_context(|| format!("height {}: not the sequencer's signature", r.height))?;
        }
        let mut theirs = Seen::default();
        theirs.record(roots).map_err(|e| anyhow::anyhow!("{e}: the roots given conflict among themselves"))?;
        let seen = self.seen();
        if let Err(e) = seen.clone().record(roots) {
            bail!("{e}: it signed two histories. The evidence: {}", self.evidence(&e)?.display());
        }
        Ok(theirs.roots.keys().filter(|h| seen.roots.contains_key(h)).count())
    }
    fn evidence(&self, e: &Equivocation) -> Result<PathBuf> {
        let path = self.path.with_extension("equivocation.json");
        std::fs::write(&path, serde_json::to_vec_pretty(e)?)?;
        Ok(path)
    }
    /// A line for whoever follows a long operation ([`Wallet::progress`]).
    pub(crate) fn say(&self, m: String) {
        if let Some(p) = &self.progress {
            p(m)
        }
    }
    /// The wallet's L2 address: its x-only public key.
    pub fn address(&self) -> Hash {
        xonly(&self.key)
    }
    /// Our unspent notes, unlocked (a locked one waits for its sender's
    /// acknowledgment: [`State::locked`]).
    pub fn notes(&self, state: &State) -> Vec<Owned> {
        self.notes_locked_too(state).into_iter().filter(|o| !state.locked(o.index)).collect()
    }
    /// Our unspent notes, locked or not.
    pub fn notes_locked_too(&self, state: &State) -> Vec<Owned> {
        let me = self.address();
        state.transparent().filter(|(_, n)| n.owner == me && !state.is_spent(n)).map(|(i, n)| Owned { note: *n, index: i }).collect()
    }
    /// The one-time acknowledgment key of our spend whose first nullifier
    /// is `nf0` (`lichen_validity::ack`).
    pub(crate) fn ak_key(&self, nf0: &Hash) -> SigningKey {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(b"lichen/ak");
        h.update(self.key.to_bytes());
        h.update(nf0);
        SigningKey::from_bytes(&h.finalize()).expect("a scalar, all but certainly")
    }
    /// What we hold on the L2: transparent and shielded notes.
    pub fn balance(&self) -> Result<u64> {
        let (t, s) = self.balances()?;
        Ok(t + s)
    }
    /// Pay `amount` to `to` with `memo`; the new notes' indices (the
    /// payment's first, then our change if any).
    pub fn send(&mut self, to: Hash, amount: u64, memo: u32) -> Result<Vec<u32>> {
        anyhow::ensure!(amount > 0, "nothing to send");
        let state = self.state()?;
        let mut mine = self.notes(&state);
        mine.sort_by_key(|o| std::cmp::Reverse(o.note.value));
        let (mut spends, mut total) = (vec![], 0u64);
        for o in mine {
            if total >= amount {
                break;
            }
            total += o.note.value;
            spends.push(Spend { note: o.note, index: o.index });
        }
        if total < amount {
            bail!("the balance is {total}, short of {amount}");
        }
        let mut outputs = vec![note(to, amount, memo)];
        if total > amount {
            outputs.push(note(self.address(), total - amount, 0));
        }
        let nfs: Vec<Hash> = spends.iter().map(|s| lichen_ledger::nullifier(&s.note)).collect();
        let ak = xonly(&self.ak_key(&nfs[0]));
        let digest = Transfer::digest(&spends, &outputs, &ak);
        let sigs = spends.iter().map(|_| sign(&self.key, &digest)).collect();
        // kept before it goes: an exit without the sequencer must know,
        // and the wallet acknowledges it
        self.record_signed(Signed::new(nfs, &outputs))?;
        self.sequencer.submit(&Tx::Transfer(Transfer { spends, outputs, sigs, ak }))
    }
}

/// What Alice asks for in a contract: her deposit `D`, the liquidity `L`
/// (what she can receive beyond her balance), her reserve `r_A`. The
/// hub's fee for `L` is kept out of what it mints her ([`Ask::quote`]).
#[derive(Clone, Copy, Debug)]
pub struct Ask {
    pub deposit: u64,
    pub liquidity: u64,
    pub reserve: u64,
}

/// A hub's terms for an [`Ask`], from its `/info`: its fee, what it
/// mints her (`D` less the fee), and the cap (`D - fee + L`, scaled).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quote {
    pub fee: u64,
    pub minted: u64,
    pub cap: u64,
    /// The contract's unit, which its `D` holds.
    pub unit: u64,
}

impl Ask {
    /// The hub's terms for this ask: its fee at its rate, and the cap
    /// they make. Refused if the liquidity is above the hub's most, or the
    /// deposit doesn't cover the fee.
    pub fn quote(&self, info: &Info) -> Result<Quote> {
        ensure!(self.liquidity <= info.max_liquidity, "liquidity of {} sats, above the hub's most, {}", self.liquidity, info.max_liquidity);
        let fee = lichen_proto::liquidity_fee(self.liquidity, info.fee_ppm);
        ensure!(fee < self.deposit, "a deposit of {} sats doesn't cover the hub's fee of {fee}", self.deposit);
        let (bits, unit) = lichen_proto::scale(self.deposit - fee + self.liquidity)?;
        Ok(Quote { fee, minted: self.deposit - fee, cap: unit * ((1u64 << bits) - 1), unit })
    }
}

/// The hub's offer (`GET /info`): its deployment, statement and terms.
pub fn hub_info(hub: &str) -> Result<Info> {
    hub_call(&format!("{hub}/info"), None, true)
}

/// The hub proves with this wallet's guests ([`lichen_proto::Guests`]): a
/// contract's statement pins them, and the wallet can only prove with its
/// own.
pub fn check_guests(info: &Info) -> Result<()> {
    let ours = lichen_proto::Guests::ours();
    let hub = info.guests.as_ref().with_context(|| format!("the hub doesn't name its guests: it runs a lichen older than this wallet's {}", lichen_proto::VERSION))?;
    let commit = info.commit.as_deref().map(|c| format!(" ({c})")).unwrap_or_default();
    ensure!(*hub == ours, "the hub proves with other guests than this wallet's: it runs lichen {}{commit}, this wallet {}; use a wallet of the hub's version", if info.version.is_empty() { "?" } else { &info.version }, lichen_proto::VERSION);
    Ok(())
}

/// A request to the hub, its error passed through: `quick` for one it
/// answers at once (`/info`), else the agent with no read timeout (it works
/// before answering: [`lichen_l2::http`]).
fn hub_call<T: for<'de> Deserialize<'de>>(url: &str, body: Option<String>, quick: bool) -> Result<T> {
    let agent = if quick { lichen_l2::http::quick() } else { lichen_l2::http::slow() };
    let r = match body {
        Some(b) => agent.post(url).set("Content-Type", "application/json").send_string(&b),
        None => agent.get(url).call(),
    };
    match r {
        Ok(r) => Ok(r.into_json()?),
        Err(ureq::Error::Status(_, r)) => {
            let v: serde_json::Value = r.into_json().unwrap_or_default();
            bail!("the hub refused: {}", v.get("error").and_then(|e| e.as_str()).unwrap_or("?"))
        }
        Err(e) => bail!("{url}: {e}"),
    }
}

impl Wallet {
    /// The secrets of the contract with `nonce`.
    pub fn secrets(&self, nonce: &str) -> ContractSecrets {
        ContractSecrets::new(&self.key.to_bytes()[..], nonce)
    }
    /// Alice's keys for a contract.
    pub fn contract_keys(&self, nonce: &str) -> PartyKeys {
        self.secrets(nonce).keys()
    }
    /// Alice's key in a contract's deposit tree.
    pub fn deposit_key(&self, nonce: &str) -> bitcoin::key::Keypair {
        self.secrets(nonce).deposit_key()
    }
    /// A contract's fee budget, on `net`: one key's coins.
    pub fn fees(&self, nonce: &str, net: lichen_chain::Net) -> KeyFees {
        self.secrets(nonce).fees(net)
    }
    /// The fee budget of contract `cid`.
    pub fn fees_for(&self, cid: u32) -> Result<KeyFees> {
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        Ok(self.fees(&h.nonce, h.record.network))
    }

    /// The amount a deposit for `ask` on `net` must carry: `D + r_A`, the
    /// funding fee's share, and the fee budget.
    pub fn deposit_amount(ask: &Ask, net: lichen_chain::Net) -> bitcoin::Amount {
        bitcoin::Amount::from_sat(ask.deposit + ask.reserve) + FEE_SHARE + lichen_proto::fee_budget(net)
    }

    /// Open a contract with the hub at `hub` on the terms `ask`, running
    /// `statement`. No wallet of the user's:
    /// the hub gives a deposit address, which `pay` is asked to pay (from
    /// anywhere: a wallet, a faucet), and every payout goes to `payout`.
    /// Waits for the deposit to confirm, then checks the hub's offer and
    /// every signature in it, and the deposit minted to us (locked to the
    /// funding), before signing anything; returns once the funding is
    /// broadcast and the deposit is ours on the L2.
    /// The deposit is kept from before it is paid ([`Wallet::refund`]).
    pub fn open_contract(&mut self, hub: &str, chain: &Chain, statement: &Statement, ask: Ask, payout: bitcoin::ScriptBuf, pay: &dyn Fn(&bitcoin::Address, bitcoin::Amount) -> Result<()>) -> Result<Held> {
        let info: Info = hub_call(&format!("{hub}/info"), None, true)?;
        let net = chain.network;
        ensure!(info.network == net, "the hub is on {}, this wallet's coins on {net}", info.network);
        let d = self.sequencer.deployment;
        ensure!(info.deployment == d, "the hub is in another deployment (sequencer {}, hub {}) than this wallet's (sequencer {}, hub {})", hex::encode(info.deployment.sequencer), hex::encode(info.deployment.hub), hex::encode(d.sequencer), hex::encode(d.hub));
        ensure!(info.statement == statement.id(), "the hub runs {}, this wallet {}", info.statement, statement.id());
        check_guests(&info)?;
        bitcoin::Address::from_script(&payout, net.bitcoin()).with_context(|| format!("the payout address isn't a {net} address"))?;
        let quote = ask.quote(&info)?;

        // the deposit: an address of the hub's and ours, paid, confirmed
        let nonce = hex::encode(fresh_rho());
        let dep_kp = self.deposit_key(&nonce);
        let offer: DepositOffer = hub_call(&format!("{hub}/deposit"), Some(serde_json::to_string(&DepositRequest { alice: dep_kp.x_only_public_key().0, deposit: ask.deposit, liquidity: ask.liquidity })?), false)?;
        // the refund's timeout is the network's: a hub naming a longer one
        // could lock the deposit up for as long
        ensure!(offer.timeout == lichen_proto::deposit_timeout(net), "the hub's deposit refund waits {} blocks, not the network's {}", offer.timeout, lichen_proto::deposit_timeout(net));
        let dep = Deposit { nonce: nonce.clone(), cid: offer.cid, hub: offer.hub, timeout: offer.timeout, payout: payout.clone(), offered: None, earlier: vec![] };
        self.deposits.push(dep.clone());
        self.save()?;
        let dep_spk = deposit_tree(&dep_kp.x_only_public_key().0, &dep.hub, dep.timeout)?.script_pubkey();
        chain.watch(&dep_spk)?;
        let amount = Wallet::deposit_amount(&ask, net);
        pay(&bitcoin::Address::from_script(&dep_spk, net.bitcoin())?, amount)?;
        let coin = self.wait_deposit(chain, &dep_spk, amount)?;
        self.open_with(hub, chain, statement, ask, quote, dep, coin)
    }

    /// Finish the opening of contract `cid` with the deposit already paid
    /// for it (an opening that failed after the deposit: the hub's
    /// refusal, a restart), on the terms `ask` (the deposit must cover
    /// them). Its payout address is the deposit's.
    pub fn resume_open(&mut self, hub: &str, chain: &Chain, statement: &Statement, ask: Ask, cid: u32) -> Result<Held> {
        let dep = self.deposits.iter().find(|d| d.cid == cid).cloned().with_context(|| format!("no deposit for contract {cid}"))?;
        // an offer accepted whose funding is out: the contract is open
        if dep.funded(chain).is_some() {
            self.claim_mint(chain, cid)?;
            return self.contracts.iter().find(|h| h.record.cid() == cid).cloned().context("the contract");
        }
        let info: Info = hub_call(&format!("{hub}/info"), None, true)?;
        ensure!(info.network == chain.network, "the hub is on {}, this wallet's coins on {}", info.network, chain.network);
        check_guests(&info)?;
        let quote = ask.quote(&info)?;
        let dep_spk = deposit_tree(&self.deposit_key(&dep.nonce).x_only_public_key().0, &dep.hub, dep.timeout)?.script_pubkey();
        chain.watch(&dep_spk)?;
        let coin = self.wait_deposit(chain, &dep_spk, Wallet::deposit_amount(&ask, chain.network))?;
        self.open_with(hub, chain, statement, ask, quote, dep, coin)
    }

    /// The opening, the deposit `coin` confirmed: the setup's
    /// cut-and-choose first (she garbles; the hub keeps some of her
    /// instances), then the hub's offer checked, the pre-signed set and
    /// the deposit input signed.
    #[allow(clippy::too_many_arguments)]
    fn open_with(&mut self, hub: &str, chain: &Chain, statement: &Statement, ask: Ask, quote: Quote, dep: Deposit, coin: (bitcoin::OutPoint, bitcoin::TxOut)) -> Result<Held> {
        let Ask { deposit, liquidity, reserve } = ask;
        let (net, d) = (chain.network, self.sequencer.deployment);
        let (nonce, payout) = (dep.nonce.clone(), dep.payout.clone());
        let dep_kp = self.deposit_key(&nonce);
        let dep_tree = deposit_tree(&dep_kp.x_only_public_key().0, &dep.hub, dep.timeout)?;

        let keys = self.contract_keys(&nonce);
        let mut alice = keys.public();
        alice.payout_spk = payout;
        // her keys for the dispute: the setup's instances she garbled,
        // those the hub keeps uploaded, the others opened
        let secrets = self.secrets(&nonce);
        let hp_open = self.hp_opening(hub, statement, dep.cid, coin.0, quote.unit, &secrets, net)?;
        let fees = self.fees(&nonce, net);
        let req = OpenRequest { alice, l2_address: self.address(), deposit, liquidity, fee: quote.fee, reserve, dispute: hp_open.request.clone(), cid: dep.cid, deposit_coin: coin.clone(), fee_spk: fees.spk() };
        let offer: OpenOffer = hub_call(&format!("{hub}/open"), Some(serde_json::to_string(&req)?), false)?;
        // the contract as the offer makes it, checked before signing
        ensure!(offer.cid == dep.cid, "the offer is for contract {}, the deposit for {}", offer.cid, dep.cid);
        let t = terms(offer.cid, &req, offer.t_close, offer.reserve_hub)?;
        ensure!(t.unit.to_sat() == quote.unit && t.v_max().to_sat() == quote.cap, "the terms aren't the quote's");
        // time to withdraw, and to dispute, before the default
        let least = chain.height()? + lichen_proto::min_duration(net);
        ensure!(offer.t_close >= least, "the hub's T_close, block {}, is too soon (at least block {least})", offer.t_close);
        // the contract's keys for the dispute: ours and the hub's (its
        // pre-signatures checked once the set is built, below)
        let dispute = Wallet::hp_keys(&secrets, &hp_open, offer.dispute.hp_windows, offer.dispute.hp_presigs.clone());
        ensure!(offer.checkpoint == hp_open.setup.checkpoint, "the offer's checkpoint is not the setup's");
        // an anchored deployment's contract: a checkpoint on our own view of
        // the chain (a stale or forked one could ask work no withdrawal
        // shows)
        if d.seal.is_some() {
            offer.checkpoint.context("the hub's offer has no checkpoint, in an anchored deployment")?.check(chain, 2016)?;
        }
        let mut record = Record {
            statement: statement.id().to_string(),
            network: net,
            deployment: lichen_proto::contract_word(&d, offer.checkpoint.as_ref(), t.unit)?,
            checkpoint: offer.checkpoint,
            terms: t,
            pubs: [req.alice.clone(), offer.hub.clone()],
            l2_address: self.address(),
            funding: bitcoin::OutPoint { txid: offer.funding.compute_txid(), vout: 0 },
            hub_sigs: offer.hub_sigs.clone(),
            alice_sigs: Default::default(),
            fee: quote.fee,
            dispute,
        };
        let c = record.build(statement)?;
        let fee_out = bitcoin::TxOut { value: fee_budget_of(coin.1.value, &t)?, script_pubkey: fees.spk() };
        check_deposit_funding(&offer.funding, &c, &coin.0, &fee_out)?;
        let set = c.presign(record.funding)?;
        for p in set.iter().filter(|p| !c.withheld(&p.name)) {
            for i in 0..p.inputs() {
                let n = lngap_sessions::contract::sig_name(&p.name, i);
                let s = record.hub_sigs.get(&n).with_context(|| format!("the hub didn't sign {n}"))?;
                p.verify_input(&record.pubs[1].payment, i, s)?;
            }
        }
        // the budget pays for her heaviest terminal (a guard: the
        // network's budget is sized for the statement's, and the deposit
        // is paid already)
        let need = c.terminal_need(&set, net)?;
        ensure!(fee_out.value >= need, "the fee budget, {}, can't pay for the heaviest transaction a dispute may need of the user, {need}", fee_out.value);
        // the hub's adaptor pre-signatures on her challenge
        Wallet::hp_check_offer(net, offer.t_close, &secrets, &hp_open, &offer.dispute, &set)?;
        record.alice_sigs = sign_all(&set, &keys.payment)?;
        // D, minted already to a key we can spend once this funding is out:
        // there, and sealed, before we sign the funding
        self.wait_mint(offer.mint_index, &mint_owner(&self.address(), &offer.mint_point)?, record.minted())?;
        // our pre-signature on the funding's deposit input, locked to T
        // (taproot signs every input's prevout: ours and the hub's coins)
        let known: Vec<(bitcoin::OutPoint, bitcoin::TxOut)> = std::iter::once(coin.clone()).chain(offer.hub_coins.iter().cloned()).collect();
        let (_, msg) = deposit_open_msg(&offer.funding, &coin.0, &known, &dep_tree)?;
        let locked = Locked { index: offer.mint_index, point: offer.mint_point, presig: adaptor_sign(&dep_kp, &msg, &offer.mint_point).into(), deposit: coin.0, claimed: false };
        if let Some(d) = self.deposits.iter_mut().find(|d| d.cid == dep.cid) {
            if let Some(old) = d.offered.replace((record.clone(), locked.clone())) {
                if old.0.funding != record.funding {
                    d.earlier.push(old);
                }
            }
        }
        self.save()?;
        chain.watch(&fees.spk())?;
        let accept = Accept { cid: offer.cid, alice_sigs: record.alice_sigs.clone(), deposit_presig: locked.presig.clone() };
        let opened: Opened = hub_call(&format!("{hub}/accept"), Some(serde_json::to_string(&accept)?), false)?;
        // the hub broadcast it before answering; an Esplora indexes it soon
        let start = std::time::Instant::now();
        let funded = loop {
            if chain.get_tx(&record.funding.txid).is_some() {
                break true;
            }
            if start.elapsed() > std::time::Duration::from_secs(30) {
                break false;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        };
        self.contracts.push(Held { nonce, record, closed: None, payout: None, mint: Some(locked), exit: None });
        // the deposit's record goes once the funding is out: until then a
        // hub that answered but never broadcast leaves the refund
        if funded {
            self.deposits.retain(|x| x.cid != dep.cid);
        }
        self.save()?;
        self.claim_mint_with(dep.cid, &opened.t)?;
        self.contracts.iter().find(|h| h.record.cid() == dep.cid).cloned().context("the contract")
    }

    /// Wait until note `index` is `value` to `owner` (memo 0), unspent and
    /// sealed: a contract's mint, before we sign its funding.
    fn wait_mint(&self, index: u32, owner: &Hash, value: u64) -> Result<()> {
        let start = std::time::Instant::now();
        loop {
            let state = self.state()?;
            if let Some(n) = state.note(index) {
                ensure!((n.owner, n.value, n.memo) == (*owner, value, 0), "note {index} is not the deposit minted to us, locked to the funding");
                ensure!(!state.is_spent(n), "the deposit minted to us is spent");
                if state.sealed.iter().any(|s| s.size > index) {
                    return Ok(());
                }
                let _ = self.sequencer.seal();
            }
            ensure!(start.elapsed() < std::time::Duration::from_secs(120), "the deposit minted to us was never sealed");
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    /// Move contract `cid`'s deposit, minted before its funding, to our own
    /// key, with `t` taken from the funding on chain (our completed
    /// signature in it): for a hub that didn't answer. Opens the contract
    /// first if its opening's answer was lost but its funding is out.
    pub fn claim_mint(&mut self, chain: &Chain, cid: u32) -> Result<()> {
        if !self.contracts.iter().any(|h| h.record.cid() == cid) {
            let dep = self.deposits.iter().find(|d| d.cid == cid).cloned().with_context(|| format!("no contract or deposit {cid}"))?;
            ensure!(dep.presigned(), "no offer accepted for contract {cid}");
            let (record, locked) = dep.funded(chain).with_context(|| format!("contract {cid}'s funding is not out: if the hub never broadcasts it, refund the deposit after its timeout"))?;
            self.contracts.push(Held { nonce: dep.nonce, record, closed: None, payout: None, mint: Some(locked), exit: None });
            self.deposits.retain(|d| d.cid != cid);
            self.save()?;
        }
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).cloned().context("the contract")?;
        let locked = h.mint.with_context(|| format!("contract {cid}'s deposit was minted after its funding: nothing to claim"))?;
        if locked.claimed {
            return Ok(());
        }
        let funding = chain.get_tx(&h.record.funding.txid).context("the funding is not out")?;
        // the deposit's record, kept until the funding was seen: done with
        if self.deposits.iter().any(|d| d.cid == cid) {
            self.deposits.retain(|d| d.cid != cid);
            self.save()?;
        }
        let sig = deposit_sig_in(&funding, &locked.deposit).context("no signature of ours in the funding's deposit input")?;
        let t = adaptor_extract(&AdaptorSig::from(&locked.presig), &sig).context("the funding's signature doesn't complete our pre-signature")?;
        self.claim_mint_with(cid, &t)
    }

    /// Move contract `cid`'s locked deposit to our own key, `t` in hand.
    fn claim_mint_with(&mut self, cid: u32, t: &SecretKey) -> Result<()> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).context("the contract")?;
        let locked = self.contracts[k].mint.clone().context("no locked deposit")?;
        ensure!(PublicKey::from_secret_key(SECP256K1, t) == locked.point, "not the adaptor point's secret");
        let key = mint_secret(&self.key, &t.secret_bytes())?;
        let state = self.state()?;
        let n = *state.note(locked.index).context("the deposit minted to us is gone")?;
        ensure!(n.owner == xonly(&key), "the deposit minted is not ours to claim");
        if !state.is_spent(&n) {
            let spends = vec![Spend { note: n, index: locked.index }];
            let outputs = vec![note(self.address(), n.value, 0)];
            let nf = lichen_ledger::nullifier(&n);
            let ak = xonly(&self.ak_key(&nf));
            let digest = Transfer::digest(&spends, &outputs, &ak);
            self.record_signed(Signed::new(vec![nf], &outputs))?;
            self.sequencer.submit(&Tx::Transfer(Transfer { sigs: vec![sign(&key, &digest)], spends, outputs, ak }))?;
        }
        self.contracts[k].mint.as_mut().expect("checked").claimed = true;
        self.save()
    }

    /// Send what is left of contract `cid`'s fee budget to its payout
    /// address, less `fee`. Only once the contract is closed (a dispute
    /// may still need it), unless `force`.
    pub fn sweep_fees(&self, chain: &Chain, cid: u32, fee: bitcoin::Amount, force: bool) -> Result<bitcoin::Txid> {
        use lichen_chain::Fees;
        let h = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        ensure!(force || h.closed.is_some(), "contract {cid} is open: its fee budget may still be needed (force to sweep anyway)");
        let fees = self.fees(&h.nonce, h.record.network);
        let coins = chain.coins_of(&fees.spk())?;
        ensure!(!coins.is_empty(), "contract {cid}'s fee budget is empty");
        let total: bitcoin::Amount = coins.iter().map(|c| c.1.value).sum();
        let ins: Vec<(bitcoin::OutPoint, bitcoin::Sequence)> = coins.iter().map(|c| (c.0, bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME)).collect();
        let out = bitcoin::TxOut { value: total.checked_sub(fee).context("the budget can't pay the fee")?, script_pubkey: h.record.pubs[0].payout_spk.clone() };
        let tx = lngap_btc::tx::build_tx(&ins, vec![out], bitcoin::absolute::LockTime::ZERO);
        let prevouts: Vec<_> = coins.into_iter().map(|c| (c.0, c.1)).collect();
        let tx = fees.sign(chain, &tx, &prevouts)?;
        chain.broadcast(&tx).context("the sweep of the fee budget")
    }

    /// The wallet's own Bitcoin key for payouts: an address of its own
    /// for withdrawals, refunds, reserves and swept fee budgets, so a user
    /// needs no other wallet. One key, its coins found by script.
    pub fn payout(&self) -> KeyFees {
        KeyFees { keypair: crate::engine::payout_keypair(&self.key.to_bytes()[..]), feerate: PAYOUT_FEERATE }
    }
    /// The payout key's address on `net`.
    pub fn payout_address(&self, net: lichen_chain::Net) -> bitcoin::Address {
        bitcoin::Address::from_script(&self.payout().spk(), net.bitcoin()).expect("a P2TR script has an address")
    }
    /// Send from the payout key's coins: [`send_from`].
    pub fn send_payout(&self, chain: &Chain, to: &bitcoin::Script, amount: Option<bitcoin::Amount>) -> Result<bitcoin::Txid> {
        send_from(&self.payout(), chain, to, amount)
    }

    /// Post contract `cid`'s default after `T_close`, as the hub would:
    /// the pre-signed transaction, both signatures in hand, with a fee
    /// coin from the contract's fee budget. It pays Alice her reserve.
    /// For when the hub doesn't (gone, say); refused once anything spent
    /// the contract output (the hub's default, a fold, a dispute).
    pub fn post_default(&mut self, chain: &Chain, statement: &Statement, cid: u32) -> Result<bitcoin::Txid> {
        use lichen_chain::Fees;
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        self.ensure_open(chain, k)?;
        let held = self.contracts[k].clone();
        let (t_close, height) = (held.record.terms.t_close, chain.height()?);
        ensure!(height >= t_close, "contract {cid}'s default is valid from block {t_close} (now {height})");
        ensure!(chain.unspent(&held.record.funding)?, "contract {cid} is closed already: its output is spent (the hub's default, a fold or a dispute)");
        let c = held.record.build(statement)?;
        let set = held.record.presigned(&c)?;
        let p = set.iter().find(|p| p.name == "default").context("no default")?;
        let sig = |sigs: &std::collections::HashMap<String, Vec<u8>>, whose: &str| sigs.get("default").cloned().with_context(|| format!("no signature of the {whose}'s on the default"));
        let mut tx = p.finish(vec![], &sig(&held.record.hub_sigs, "hub")?, &sig(&held.record.alice_sigs, "user")?);
        // pre-signed ALL|ANYONECANPAY, its outputs fixed: an exact coin
        let fees = self.fees(&held.nonce, held.record.network);
        let (op, coin) = fees.exact_coin(chain, DEFAULT_FEE)?;
        tx.input.push(bitcoin::TxIn { previous_output: op, sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME, ..Default::default() });
        let tx = fees.sign(chain, &tx, &[(held.record.funding, p.prevout.clone()), (op, coin)])?;
        let txid = chain.broadcast(&tx).context("broadcasting the default")?;
        self.contracts[k].closed = Some(txid);
        self.save()?;
        Ok(txid)
    }

    /// Wait for a confirmed coin of at least `amount` to `spk` (a deposit).
    fn wait_deposit(&self, chain: &Chain, spk: &bitcoin::Script, amount: bitcoin::Amount) -> Result<(bitcoin::OutPoint, bitcoin::TxOut)> {
        let mut stall = lichen_chain::Stall::new(chain.height()?, chain.network);
        loop {
            if let Some(c) = chain.coins_of(spk)?.into_iter().find(|c| c.2.is_some() && c.1.value >= amount) {
                return Ok((c.0, c.1));
            }
            ensure!(!stall.stalled(chain.height()?), "the chain stalled before the deposit confirmed");
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
    }

    /// Take back the deposit for contract `cid`, never opened, once its
    /// timeout has passed: to the payout address given, less `fee`.
    pub fn refund(&mut self, chain: &Chain, cid: u32, fee: bitcoin::Amount) -> Result<bitcoin::Txid> {
        let dep = self.deposits.iter().find(|x| x.cid == cid).cloned().with_context(|| format!("no deposit for contract {cid}"))?;
        let kp = self.deposit_key(&dep.nonce);
        let tree = deposit_tree(&kp.x_only_public_key().0, &dep.hub, dep.timeout)?;
        let coins = chain.coins_of(&tree.script_pubkey())?;
        let (op, out, at) = coins.into_iter().next().with_context(|| format!("the deposit for contract {cid} is not there (spent, or never paid)"))?;
        let at = at.context("the deposit is not confirmed")?;
        let ready = at + u32::from(dep.timeout) - 1;
        ensure!(chain.height()? >= ready, "the deposit can be refunded from height {ready} (now {})", chain.height()?);
        let leaf = tree.leaf(DEPOSIT_REFUND)?;
        let mut tx = lngap_btc::tx::build_spend(op, &leaf.timelock, vec![bitcoin::TxOut { value: out.value.checked_sub(fee).context("the deposit can't pay the fee")?, script_pubkey: dep.payout.clone() }]);
        let sig = lngap_btc::sighash::sign_tapscript(&kp, &tx, 0, std::slice::from_ref(&out), &leaf.script)?;
        tx.input[0].witness = lngap_btc::witness::tapscript_witness(&[sig.as_ref().to_vec()], &leaf.script, &tree.control_block(DEPOSIT_REFUND)?);
        let txid = chain.broadcast(&tx).context("the refund")?;
        // a deposit the hub holds a pre-signature on is kept: until the
        // refund confirms, the hub's funding may still replace it, and
        // then the contract is open
        if !dep.presigned() {
            self.deposits.retain(|x| x.cid != cid);
            self.save()?;
        }
        Ok(txid)
    }

    /// Withdraw `b` sats from contract `cid` cooperatively, by claim: her
    /// notes worth exactly the withdrawal's units (`b` rounded down to
    /// the contract's unit) claimed for the contract, and her signature
    /// on the fold paying them (and her reserve); the hub records the
    /// claim on the L2, retiring the notes, and folds at once. Whole notes
    /// only: a note to size is split off first, by a payment to herself.
    /// The claim is kept with the contract before it goes: if the hub
    /// recorded it but won't fold, `exit` posts the same claim (this
    /// contract's own record doesn't count against it). Run again after a
    /// failed fold, it asks again with the same claim. At `b` 0 it closes
    /// the contract early: no claim, the fold paying her reserve, as the
    /// default would at `T_close`. Returns the fold's txid.
    pub fn withdraw(&mut self, chain: &Chain, hub: &str, statement: &Statement, cid: u32, b: u64) -> Result<bitcoin::Txid> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let held = self.contracts[k].clone();
        ensure!(held.closed.is_none(), "contract {cid} is closed");
        ensure!(bitcoin::Amount::from_sat(b) <= held.record.terms.v_max(), "{b} sats is above the cap");
        let unit = held.record.terms.unit.to_sat();
        let units = u32::try_from(b / unit).context("b fits in a u32")?;
        let plan = match (&held.exit, units) {
            (Some(p), _) => {
                ensure!(p.b == units, "contract {cid} has a claim of {} units already, not folded: withdraw {} sats, or exit", p.b, u64::from(p.b) * unit);
                Some(p.clone())
            }
            (None, 0) => {
                ensure!(held.record.terms.reserve_alice >= CLOSE_DUST, "contract {cid}: nothing to withdraw and no reserve, so a fold would pay you nothing: the default closes it at block {}", held.record.terms.t_close);
                None
            }
            (None, _) => {
                let p = self.withdrawal_claim(chain, cid, units)?;
                self.contracts[k].exit = Some(p.clone());
                self.save()?;
                Some(p)
            }
        };
        let c = held.record.build(statement)?;
        let paid = bitcoin::Amount::from_sat(u64::from(units) * unit);
        let fold = c.fold(held.record.funding, paid, FOLD_FEE)?;
        let alice_sig = fold.sign(&self.contract_keys(&held.nonce).payment)?;
        let req = WithdrawRequest { cid, b: units, claim: plan.map(|p| p.posted).unwrap_or_default(), alice_sig };
        let done: Folded = hub_call(&format!("{hub}/withdraw"), Some(serde_json::to_string(&req)?), false)?;
        // the hub's txid must be the fold's
        ensure!(done.txid == fold.tx.compute_txid(), "the hub answered {} for the fold, not its txid {}", done.txid, fold.tx.compute_txid());
        self.contracts[k].closed = Some(done.txid);
        self.save()?;
        Ok(done.txid)
    }

    /// A cooperative withdrawal's claim of `units` from contract `cid`:
    /// her notes worth exactly `units` of the contract's unit, by
    /// position, signed for the contract. Her notes if some are worth it
    /// exactly (all of them, or one); else a note of that value split off
    /// by a payment to herself, waited for until acknowledged (its output
    /// unlocked: anchored, the margin deep).
    fn withdrawal_claim(&mut self, chain: &Chain, cid: u32, units: u32) -> Result<exit::ExitPlan> {
        let record = self.contracts.iter().find(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?.record.clone();
        let want = u64::from(units) * record.terms.unit.to_sat();
        // our own spends acknowledged first: their change unlocked
        self.acknowledge_all(chain, ack::ACK_PATIENCE)?;
        let mine = self.notes(&self.state()?);
        let total: u64 = mine.iter().map(|o| o.note.value).sum();
        ensure!(total >= want, "the transparent balance is {total} sats, short of {want}");
        let positions: Vec<u32> = if total == want && mine.len() <= lichen_withdraw::hp::MAX_NOTES {
            mine.iter().map(|o| o.index).collect()
        } else if let Some(o) = mine.iter().find(|o| o.note.value == want) {
            vec![o.index]
        } else {
            self.say(format!("splitting off a note of {want} sats to claim"));
            let i = self.send(self.address(), want, 0)?[0];
            self.say("waiting for the split to be anchored and acknowledged: until then its note is locked".into());
            self.acknowledge_all(chain, ack::ACK_PATIENCE)?;
            ensure!(!self.state()?.locked(i), "the note split off is still locked");
            vec![i]
        };
        let acks = self.acks_for(&self.state()?, &positions)?;
        self.claim_of(&record, units, positions, acks)
    }
}

/// Send from one key's coins, a wallet's payout key's (all of them,
/// confirmed or not), to `to`: `amount`, the change back to the key; or,
/// `amount` None, everything less the fee. At the key's feerate (sat/vB).
/// Apart from the wallet, so it can run while the wallet is busy (paying
/// a deposit the opening waits for).
pub fn send_from(payout: &KeyFees, chain: &Chain, to: &bitcoin::Script, amount: Option<bitcoin::Amount>) -> Result<bitcoin::Txid> {
    use lichen_chain::Fees;
    use bitcoin::{Amount, TxOut};
    chain.watch(&payout.spk())?;
    let coins = chain.coins_of(&payout.spk())?;
    ensure!(!coins.is_empty(), "nothing at the payout address");
    let total: Amount = coins.iter().map(|c| c.1.value).sum();
    // key-path inputs 57.5 vB each, P2TR outputs 43, 10.5 besides
    let fee = |outs: u64| Amount::from_sat((105 + 575 * coins.len() as u64 + 430 * outs).div_ceil(10) * payout.feerate);
    let outs = match amount {
        None => vec![TxOut { value: total.checked_sub(fee(1)).filter(|v| *v >= CLOSE_DUST).with_context(|| format!("the payout address has {} sats: too little to pay the fee", total.to_sat()))?, script_pubkey: to.to_owned() }],
        Some(a) => {
            ensure!(a >= CLOSE_DUST, "{} sats is below the dust floor", a.to_sat());
            let short = || format!("the payout address has {} sats: short of {} and the fee", total.to_sat(), a.to_sat());
            match total.checked_sub(a + fee(2)) {
                Some(change) if change >= CLOSE_DUST => vec![TxOut { value: a, script_pubkey: to.to_owned() }, TxOut { value: change, script_pubkey: payout.spk() }],
                // change below dust goes to the fee
                _ => {
                    ensure!(total >= a + fee(1), "{}", short());
                    vec![TxOut { value: a, script_pubkey: to.to_owned() }]
                }
            }
        }
    };
    let ins: Vec<(bitcoin::OutPoint, bitcoin::Sequence)> = coins.iter().map(|c| (c.0, bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME)).collect();
    let tx = lngap_btc::tx::build_tx(&ins, outs, bitcoin::absolute::LockTime::ZERO);
    let prevouts: Vec<_> = coins.into_iter().map(|c| (c.0, c.1)).collect();
    let tx = payout.sign(chain, &tx, &prevouts)?;
    chain.broadcast(&tx).context("the payment from the payout address")
}

//! The wallet's library: a key and its contracts with the hub (opening:
//! [`Wallet::open_contract`]; the cooperative withdrawal, by claim:
//! [`Wallet::withdraw`]; the exit: [`Wallet::exit`]), for an L2
//! ([`WalletL2`]) whose state the wallet keeps beside them. An L2's wallet
//! binary opens a [`Wallet`] of its [`WalletL2`].

mod hp;
pub mod dispute;
pub mod engine;
pub mod l2;

pub use l2::{FrontEnd, SweepIn, WalletL2};

use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use k256::schnorr::SigningKey;
use lichen_proto::{fresh_rho, Hash};
use lichen_chain::{Chain, KeyFees};
use bitcoin::secp256k1::{PublicKey, SecretKey, SECP256K1};
use lichen_proto::{check_deposit_funding, deposit_open_msg, deposit_sig_in, deposit_tree, Presig, fee_budget_of, terms, Accept, DepositOffer, DepositRequest, Folded, Info, OpenOffer, OpenRequest, Opened, Record, Statement, FoldNonce, FoldNonceRequest, WithdrawRequest, CLOSE_DUST, DEFAULT_FEE, DEPOSIT_REFUND, FEE_SHARE, FOLD_FEE};
use lichen_btc::adaptor::{adaptor_extract, adaptor_sign, AdaptorSig};
use lichen_contract::PartyKeys;
use lichen_contract::sign_all;
use crate::engine::ContractSecrets;
use serde::{Deserialize, Serialize};

/// What the wallet keeps on disk.
#[derive(Serialize, Deserialize)]
#[serde(bound = "L: WalletL2")]
struct Stored<L> {
    /// The secret key, hex.
    secret: String,
    /// The hub's URL.
    hub: String,
    /// The L2's state (its deployment, pinned when the wallet was made,
    /// its accounts, ...).
    l2: L,
    /// Its contracts: each one's nonce (from which its keys derive) and
    /// record.
    #[serde(default)]
    contracts: Vec<Held>,
    /// Deposits paid (or to be paid) for contracts not yet open.
    #[serde(default)]
    deposits: Vec<Deposit>,
}

/// A step of a contract's opening, for a front end to show where it is
/// ([`Wallet::opening`]); the same steps are said in words too
/// ([`Wallet::progress`]).
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum Opening {
    /// The deposit to pay: exactly `sats` to `address`.
    Pay { address: String, sats: u64 },
    /// The deposit seen on the network, not yet confirmed.
    DepositSeen { txid: String },
    /// The deposit confirmed.
    DepositConfirmed { txid: String },
    /// The setup's instances garbled so far, of `total`.
    Garbling { done: u32, total: u32 },
    /// The instances the hub keeps, uploaded so far (bytes).
    Uploading { sent: u64, total: u64 },
    /// The hub checks the instances opened to it, and signs the contract.
    HubChecking,
    /// The contract's account, at its mint, checked.
    Minted,
    /// The hub broadcast the contract's funding.
    Funding { txid: String },
    /// The contract is open.
    Open { cid: u32 },
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

/// A contract's funding as offered: our deposit's spend in it is locked to
/// the funding's adaptor point `T`, so the funding on chain reveals `t`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Locked {
    /// `T`.
    pub point: PublicKey,
    /// Our pre-signature on the funding's deposit input, and the deposit:
    /// the funding's completed signature, less it, is `t`.
    pub presig: Presig,
    pub deposit: bitcoin::OutPoint,
    /// The mint claimed (the L2 has it as ours).
    #[serde(default)]
    pub claimed: bool,
    /// What the hub's offer said of the mint, the L2's (`OpenOffer::l2_offer`).
    #[serde(default)]
    pub l2: serde_json::Value,
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
    pub exit: Option<serde_json::Value>,
}

/// sat/vB for payments from the wallet's payout key ([`Wallet::send_payout`]).
pub const PAYOUT_FEERATE: u64 = 2;

pub struct Wallet<L: WalletL2> {
    /// For tests: stop an exit after posting `request` (it resumes from
    /// the chain when run again).
    pub pause_after: Option<u32>,
    /// For tests: challenge the hub's assertion even if its proof is
    /// valid.
    pub unchecked_claims: bool,
    /// For tests: contest every correction, so that the hub must prove.
    pub contest: bool,
    /// Told each step of a dispute, in words (for a front end).
    pub progress: Option<std::sync::Arc<dyn Fn(String) + Send + Sync>>,
    /// Told each step of a contract's opening ([`Opening`]).
    pub opening: Option<std::sync::Arc<dyn Fn(Opening) + Send + Sync>>,
    key: SigningKey,
    path: PathBuf,
    /// The hub.
    pub hub: String,
    /// The L2's state.
    pub l2: L,
    pub contracts: Vec<Held>,
    pub deposits: Vec<Deposit>,
}

/// A key's x-only public key.
pub fn xonly(k: &SigningKey) -> Hash {
    k.verifying_key().to_bytes().into()
}

/// A keypair's x-only public key.
pub fn kp_xonly(k: &bitcoin::key::Keypair) -> Hash {
    k.x_only_public_key().0.serialize()
}

impl<L: WalletL2> Wallet<L> {
    /// Create a wallet at `path` with a fresh key, for the hub at `hub`
    /// (its deployment pinned from now on).
    pub fn create(path: &Path, hub: &str) -> Result<Wallet<L>> {
        if path.exists() {
            bail!("{} already exists", path.display());
        }
        let info = hub_info(hub)?;
        Self::create_with(path, hub, L::create(&info)?)
    }
    /// A wallet at `path` with a fresh key and the L2 `l2` (made by the
    /// caller: no hub need be reachable).
    pub fn create_with(path: &Path, hub: &str, l2: L) -> Result<Wallet<L>> {
        if path.exists() {
            bail!("{} already exists", path.display());
        }
        let key = SigningKey::from_bytes(&fresh_rho()).context("a key")?;
        let w = Wallet { pause_after: None, unchecked_claims: false, contest: false, progress: None, opening: None, key, path: path.to_path_buf(), hub: hub.trim_end_matches('/').to_string(), l2, contracts: vec![], deposits: vec![] };
        w.save()?;
        Ok(w)
    }
    /// The wallet file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// The wallet at `path`, talking to the hub at `hub` (the one it was
    /// made for: its deployment is checked at every call that matters).
    pub fn open(path: &Path, hub: &str) -> Result<Wallet<L>> {
        let s: Stored<L> = serde_json::from_slice(&std::fs::read(path).with_context(|| format!("no wallet at {}", path.display()))?)?;
        let key = SigningKey::from_bytes(&hex::decode(&s.secret)?).context("the wallet's key")?;
        let hub = if hub.is_empty() { s.hub } else { hub.trim_end_matches('/').to_string() };
        Ok(Wallet { pause_after: None, unchecked_claims: false, contest: false, progress: None, opening: None, key, path: path.to_path_buf(), hub, l2: s.l2, contracts: s.contracts, deposits: s.deposits })
    }
    pub fn save(&self) -> Result<()> {
        let s = Stored {
            secret: hex::encode(self.key.to_bytes()),
            hub: self.hub.clone(),
            l2: self.l2.clone(),
            contracts: self.contracts.clone(),
            deposits: self.deposits.clone(),
        };
        if let Some(d) = self.path.parent() {
            std::fs::create_dir_all(d)?;
        }
        // the only copy of the wallet's key: replaced atomically, the owner's alone
        lichen_proto::files::write_private(&self.path, &serde_json::to_vec_pretty(&s)?)?;
        Ok(())
    }
    /// A line for whoever follows a long operation ([`Wallet::progress`]).
    pub fn say(&self, m: String) {
        if let Some(p) = &self.progress {
            p(m)
        }
    }
    pub(crate) fn opened_step(&self, o: Opening) {
        if let Some(p) = &self.opening {
            p(o)
        }
    }
    /// The wallet's L2 address: the key of its contract open (the
    /// latest), whose claims take its account; else the wallet's own key,
    /// whose account is credit only. Each contract has a key of
    /// its own, fresh at its opening.
    pub fn address(&self) -> Hash {
        match self.contracts.iter().rev().find(|h| h.closed.is_none() && h.payout.is_none()) {
            Some(h) => h.record.l2_address,
            None => xonly(&self.key),
        }
    }
    /// The L2 key of the contract (or deposit) with `nonce`.
    pub fn owner_of(&self, nonce: &str) -> Hash {
        kp_xonly(&self.secrets(nonce).l2())
    }
    /// Every L2 key of ours: the wallet's own, each contract's and each
    /// deposit's.
    pub fn owners(&self) -> Vec<Hash> {
        std::iter::once(xonly(&self.key)).chain(self.contracts.iter().map(|h| h.nonce.as_str()).chain(self.deposits.iter().map(|d| d.nonce.as_str())).map(|n| self.owner_of(n))).collect()
    }
    /// The keypair of our L2 key `owner`.
    pub fn kp_of(&self, owner: &Hash) -> Result<bitcoin::key::Keypair> {
        if *owner == xonly(&self.key) {
            return bitcoin::key::Keypair::from_seckey_slice(bitcoin::secp256k1::SECP256K1, &self.key.to_bytes()).context("the wallet's key");
        }
        self.contracts.iter().map(|h| h.nonce.as_str()).chain(self.deposits.iter().map(|d| d.nonce.as_str())).map(|n| self.secrets(n).l2()).find(|k| kp_xonly(k) == *owner).with_context(|| format!("no key of ours is {}", hex::encode(owner)))
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
    /// The hub's terms for this ask: its fee ([`Info::fee`]), and the cap
    /// they make. Refused if the liquidity is above the hub's most, or the
    /// deposit doesn't cover the fee.
    pub fn quote(&self, info: &Info) -> Result<Quote> {
        ensure!(self.liquidity <= info.max_liquidity, "liquidity of {} sats, above the hub's most, {}", self.liquidity, info.max_liquidity);
        let fee = info.fee(self.deposit, self.liquidity);
        ensure!(fee < self.deposit, "a deposit of {} sats doesn't cover the hub's fee of {fee}", self.deposit);
        let (bits, unit) = lichen_proto::scale(self.deposit - fee + self.liquidity)?;
        Ok(Quote { fee, minted: self.deposit - fee, cap: unit * ((1u64 << bits) - 1), unit })
    }
}

/// The hub's offer (`GET /info`): its deployment, statement and terms.
pub fn hub_info(hub: &str) -> Result<Info> {
    hub_call(&format!("{hub}/info"), None, true)
}

/// A request to the hub, its error passed through: `quick` for one it
/// answers at once (`/info`), else the agent with no read timeout (it works
/// before answering: [`lichen_proto::http`]).
pub fn hub_call<T: for<'de> Deserialize<'de>>(url: &str, body: Option<String>, quick: bool) -> Result<T> {
    let agent = if quick { lichen_proto::http::quick() } else { lichen_proto::http::slow() };
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

impl<L: WalletL2> Wallet<L> {
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
        self.l2.check_info(&info)?;
        ensure!(info.statement == statement.id(), "the hub runs {}, this wallet {}", info.statement, statement.id());
        bitcoin::Address::from_script(&payout, net.bitcoin()).with_context(|| format!("the payout address isn't a {net} address"))?;
        let quote = ask.quote(&info)?;

        // the deposit: an address of the hub's and ours, paid, confirmed
        let nonce = hex::encode(fresh_rho());
        let dep_kp = self.deposit_key(&nonce);
        let offer: DepositOffer = hub_call(&format!("{hub}/deposit"), Some(serde_json::to_string(&DepositRequest { alice: dep_kp.x_only_public_key().0, deposit: ask.deposit, liquidity: ask.liquidity, owner: Some(self.owner_of(&nonce)) })?), false)?;
        // the refund's timeout is the network's: a hub naming a longer one
        // could lock the deposit up for as long
        ensure!(offer.timeout == lichen_proto::deposit_timeout(net), "the hub's deposit refund waits {} blocks, not the network's {}", offer.timeout, lichen_proto::deposit_timeout(net));
        let dep = Deposit { nonce: nonce.clone(), cid: offer.cid, hub: offer.hub, timeout: offer.timeout, payout: payout.clone(), offered: None, earlier: vec![] };
        self.deposits.push(dep.clone());
        self.save()?;
        let dep_spk = deposit_tree(&dep_kp.x_only_public_key().0, &dep.hub, dep.timeout)?.script_pubkey();
        chain.watch(&dep_spk)?;
        let amount = Self::deposit_amount(&ask, net);
        let address = bitcoin::Address::from_script(&dep_spk, net.bitcoin())?;
        self.opened_step(Opening::Pay { address: address.to_string(), sats: amount.to_sat() });
        pay(&address, amount)?;
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
        self.l2.check_info(&info)?;
        let quote = ask.quote(&info)?;
        let dep_spk = deposit_tree(&self.deposit_key(&dep.nonce).x_only_public_key().0, &dep.hub, dep.timeout)?.script_pubkey();
        chain.watch(&dep_spk)?;
        let coin = self.wait_deposit(chain, &dep_spk, Self::deposit_amount(&ask, chain.network))?;
        self.open_with(hub, chain, statement, ask, quote, dep, coin)
    }

    /// The opening, the deposit `coin` confirmed: the setup's
    /// cut-and-choose first (she garbles; the hub keeps some of her
    /// instances), then the hub's offer checked, the pre-signed set and
    /// the deposit input signed.
    #[allow(clippy::too_many_arguments)]
    fn open_with(&mut self, hub: &str, chain: &Chain, statement: &Statement, ask: Ask, quote: Quote, dep: Deposit, coin: (bitcoin::OutPoint, bitcoin::TxOut)) -> Result<Held> {
        let Ask { deposit, liquidity, reserve } = ask;
        let net = chain.network;
        let (nonce, payout) = (dep.nonce.clone(), dep.payout.clone());
        let dep_kp = self.deposit_key(&nonce);
        let dep_tree = deposit_tree(&dep_kp.x_only_public_key().0, &dep.hub, dep.timeout)?;

        let keys = self.contract_keys(&nonce);
        let mut alice = keys.public();
        alice.payout_spk = payout;
        // her keys for the dispute: the setup's instances she garbled,
        // those the hub keeps uploaded, the others opened
        let secrets = self.secrets(&nonce);
        let owner = self.owner_of(&nonce);
        let hp_open = self.hp_opening(hub, chain, statement, dep.cid, coin.0, &quote, &owner, &secrets, net)?;
        self.opened_step(Opening::HubChecking);
        let fees = self.fees(&nonce, net);
        let req = OpenRequest { alice, l2_address: owner, deposit, liquidity, fee: quote.fee, reserve, dispute: hp_open.request.clone(), cid: dep.cid, deposit_coin: coin.clone(), fee_spk: fees.spk() };
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
        let dispute = self.hp_keys(&hp_open, &offer.dispute, &quote)?;
        let mut record = Record {
            statement: statement.id().to_string(),
            network: net,
            terms: t,
            pubs: [req.alice.clone(), offer.hub.clone()],
            l2_address: owner,
            funding: bitcoin::OutPoint { txid: offer.funding.compute_txid(), vout: 0 },
            hub_sigs: offer.hub_sigs.clone(),
            alice_sigs: Default::default(),
            fee: quote.fee,
            dispute,
        };
        let c = record.build(statement, &self.l2)?;
        let fee_out = bitcoin::TxOut { value: fee_budget_of(coin.1.value, &t)?, script_pubkey: fees.spk() };
        check_deposit_funding(&offer.funding, &c, &coin.0, &fee_out)?;
        let set = c.presign(record.funding)?;
        for p in set.iter().filter(|p| !c.withheld(&p.name)) {
            for i in 0..p.inputs() {
                let n = lichen_contract::sig_name(&p.name, i);
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
        Self::hp_check_offer(net, &hp_open, &offer.dispute, &set)?;
        record.alice_sigs = sign_all(&set, &keys.payment)?;
        // the mint, D − fee, and the L2's part of the offer
        ensure!(record.minted() == quote.minted, "the contract mints {}, not the quote's {}", record.minted(), quote.minted);
        L::check_offer(self, &record, &offer)?;
        self.opened_step(Opening::Minted);
        // our pre-signature on the funding's deposit input, locked to T
        // (taproot signs every input's prevout: ours and the hub's coins)
        let known: Vec<(bitcoin::OutPoint, bitcoin::TxOut)> = std::iter::once(coin.clone()).chain(offer.hub_coins.iter().cloned()).collect();
        let (_, msg) = deposit_open_msg(&offer.funding, &coin.0, &known, &dep_tree)?;
        let locked = Locked { point: offer.mint_point, presig: adaptor_sign(&dep_kp, &msg, &offer.mint_point).into(), deposit: coin.0, claimed: false, l2: offer.l2_offer.clone() };
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
        self.opened_step(Opening::Funding { txid: record.funding.txid.to_string() });
        self.contracts.push(Held { nonce, record, closed: None, payout: None, mint: Some(locked), exit: None });
        // the deposit's record goes once the funding is out: until then a
        // hub that answered but never broadcast leaves the refund
        if funded {
            self.deposits.retain(|x| x.cid != dep.cid);
        }
        self.save()?;
        self.claim_mint_with(dep.cid, &opened.t)?;
        self.opened_step(Opening::Open { cid: dep.cid });
        self.contracts.iter().find(|h| h.record.cid() == dep.cid).cloned().context("the contract")
    }

    /// Settle contract `cid`'s deposit, pre-issued before its funding, with
    /// `t` taken from the funding on chain (our completed signature in it):
    /// for a hub that didn't answer. Opens the contract first if its
    /// opening's answer was lost but its funding is out.
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

    /// Contract `cid`'s account opened at its mint, `t` in hand (the
    /// funding is out): note 0 of its key, the deposit less the fee.
    fn claim_mint_with(&mut self, cid: u32, t: &SecretKey) -> Result<()> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).context("the contract")?;
        let locked = self.contracts[k].mint.clone().context("no funding offered")?;
        ensure!(PublicKey::from_secret_key(SECP256K1, t) == locked.point, "not the adaptor point's secret");
        let held = self.contracts[k].clone();
        L::minted(self, &held, t)?;
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
        let tx = lichen_btc::tx::build_tx(&ins, vec![out], bitcoin::absolute::LockTime::ZERO);
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
        let c = held.record.build(statement, &self.l2)?;
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
        let mut seen = false;
        loop {
            let coins = chain.coins_of(spk)?;
            if let Some(c) = coins.iter().find(|c| c.2.is_some() && c.1.value >= amount) {
                self.opened_step(Opening::DepositConfirmed { txid: c.0.txid.to_string() });
                return Ok((c.0, c.1.clone()));
            }
            if let (false, Some(c)) = (seen, coins.iter().find(|c| c.1.value >= amount)) {
                self.opened_step(Opening::DepositSeen { txid: c.0.txid.to_string() });
                seen = true;
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
        let mut tx = lichen_btc::tx::build_spend(op, &leaf.timelock, vec![bitcoin::TxOut { value: out.value.checked_sub(fee).context("the deposit can't pay the fee")?, script_pubkey: dep.payout.clone() }]);
        let sig = lichen_btc::sighash::sign_tapscript(&kp, &tx, 0, std::slice::from_ref(&out), &leaf.script)?;
        tx.input[0].witness = lichen_btc::witness::tapscript_witness(&[sig.as_ref().to_vec()], &leaf.script, &tree.control_block(DEPOSIT_REFUND)?);
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

    /// Withdraw `b` sats from contract `cid` cooperatively, by claim: all
    /// her notes claimed for the contract's units (`b` rounded down to its
    /// unit), and her signature on the fold paying them (and her reserve);
    /// the hub takes the claim (its notes spent, what they hold beyond the
    /// units back to her as change) and folds at once. The claim is kept
    /// with the contract before it goes: if the hub took it but won't
    /// fold, `exit` posts the same claim. Run again after a failed fold, it
    /// asks again with the same claim. At `b` 0 it closes the contract
    /// early: no claim, the fold paying her reserve, as the default would
    /// at `T_close`. Returns the fold's txid.
    pub fn withdraw(&mut self, _chain: &Chain, hub: &str, statement: &Statement, cid: u32, b: u64) -> Result<bitcoin::Txid> {
        let k = self.contracts.iter().position(|h| h.record.cid() == cid).with_context(|| format!("no contract {cid}"))?;
        let held = self.contracts[k].clone();
        ensure!(held.closed.is_none(), "contract {cid} is closed");
        ensure!(bitcoin::Amount::from_sat(b) <= held.record.terms.v_max(), "{b} sats is above the cap");
        let unit = held.record.terms.unit.to_sat();
        let units = u32::try_from(b / unit).context("b fits in a u32")?;
        let plan = match (&held.exit, units) {
            (Some(p), _) => {
                let pb = L::plan_b(p)?;
                ensure!(pb == units, "contract {cid} has a claim of {pb} units already, not folded: withdraw {} sats, or exit", u64::from(pb) * unit);
                Some(p.clone())
            }
            (None, 0) => {
                ensure!(held.record.terms.reserve_alice >= CLOSE_DUST, "contract {cid}: nothing to withdraw and no reserve, so a fold would pay you nothing: the default closes it at block {}", held.record.terms.t_close);
                None
            }
            (None, _) => {
                let p = L::withdrawal(self, _chain, cid, units)?;
                self.contracts[k].exit = Some(p.clone());
                self.save()?;
                Some(p)
            }
        };
        let c = held.record.build(statement, &self.l2)?;
        let paid = bitcoin::Amount::from_sat(u64::from(units) * unit);
        let fold = c.fold(held.record.funding, paid, FOLD_FEE)?;
        // MuSig2 on the contract output's key path: the hub's nonce, then
        // hers, and her partial signature under both
        let hub_nonce: FoldNonce = hub_call(&format!("{hub}/withdraw/nonce"), Some(serde_json::to_string(&FoldNonceRequest { cid })?), false)?;
        let kp = self.contract_keys(&held.nonce).payment;
        let (sec, alice_nonce) = fold.nonce(&kp, &cid.to_be_bytes())?;
        let nonces = [alice_nonce, lichen_btc::musig::PubNonce::from_slice(&hub_nonce.nonce)?];
        let alice_partial = fold.sign(&kp, sec, &nonces)?;
        let rest_to = L::rest_to(self);
        let claim = match &plan {
            Some(p) => L::plan_claim(p)?,
            None => String::new(),
        };
        let req = WithdrawRequest { cid, b: units, claim, hub_nonce: hub_nonce.nonce, alice_nonce: alice_nonce.0.to_vec(), alice_partial, rest_to };
        let done: Folded = hub_call(&format!("{hub}/withdraw"), Some(serde_json::to_string(&req)?), false)?;
        // the hub's txid must be the fold's
        ensure!(done.txid == fold.tx.compute_txid(), "the hub answered {} for the fold, not its txid {}", done.txid, fold.tx.compute_txid());
        self.contracts[k].closed = Some(done.txid);
        self.save()?;
        L::folded(self, cid, units)?;
        Ok(done.txid)
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
    let tx = lichen_btc::tx::build_tx(&ins, outs, bitcoin::absolute::LockTime::ZERO);
    let prevouts: Vec<_> = coins.into_iter().map(|c| (c.0, c.1)).collect();
    let tx = payout.sign(chain, &tx, &prevouts)?;
    chain.broadcast(&tx).context("the payment from the payout address")
}

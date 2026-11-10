//! The hub: opens contracts with users, issues their deposits as tokens on
//! the L2, and (later) pays withdrawals and answers disputes.
//!
//! HTTP (JSON): `GET /info`, the opening's cut-and-choose (`POST
//! /hp/setup`, `POST /hp/commit`, and `POST /hp/instance/<cid>/<i>`, an
//! instance's bytes: `lichen_proto::hp`), `POST /open` ([`OpenRequest`] to
//! [`OpenOffer`]), `POST /accept` ([`Accept`] to [`Opened`]), `POST
//! /withdraw` ([`WithdrawRequest`] to [`Folded`]: the cooperative
//! withdrawal, Alice's claim recorded on the L2, then the fold). An offer mints the
//! deposit to a key Alice can spend only once the funding is broadcast
//! (see `lichen_proto`); a watcher broadcasts, after `T_close`, the
//! default of any contract still open.

mod dispute;

use std::collections::HashMap;
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bitcoin::secp256k1::{PublicKey, SecretKey, SECP256K1};
use bitcoin::{Amount, OutPoint, Sequence, TxOut};
use lngap_btc::adaptor::{adaptor_complete, adaptor_verify, AdaptorSig};
use lichen_chain::Chain;
use lichen_ledger::{files, note, xonly, Mint, Tx};
use lichen_ledger::k256::schnorr::SigningKey;
use lichen_proto::{broadcast_deadline, check_funding, contributions, deposit_open_msg, deposit_timeout, deposit_tree, mint_owner, terms, Accept, DepositOffer, DepositRequest, Folded, Info, Net, OpenOffer, OpenRequest, Opened, Record, Statement, WithdrawRequest, CLOSE_DUST, DEFAULT_FEE, DEPOSIT_OPEN, FEE_SHARE, FOLD_FEE};
use lichen_l2::Client;
use lngap_btc::keys::Seed;
use lngap_channel::{PartyKeys, Role};
use lngap_sessions::contract::sign_all;
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Request, Response, Server};

pub struct Config {
    /// The Bitcoin network (the contracts' timing with it).
    pub network: Net,
    pub listen: String,
    pub sequencer: String,
    /// The node's RPC URL and cookie, and the hub's wallet there.
    pub rpc_url: String,
    pub cookie: PathBuf,
    pub wallet: String,
    pub statement: Statement,
    /// Where the hub keeps its contracts.
    pub dir: PathBuf,
    /// The hub's secret seed for its contract keys (a label: keep it
    /// secret; the binary makes a random one).
    pub seed: String,
    /// The hub's L2 key: it mints, and records exits. The sequencer must
    /// name it as the issuer.
    pub l2_key: SigningKey,
    pub reserve_ppm: u64,
    /// Its fee for a contract's liquidity, parts per million of it.
    pub fee_ppm: u64,
    /// The most liquidity a contract may ask, in sats.
    pub max_liquidity: u64,
    pub duration: u32,
    /// Misbehaviour, for tests: refuse every cooperative withdrawal, and
    /// assert a false proof against every exit claim that holds.
    pub refuse_folds: bool,
    pub forge_assertions: bool,
    /// The first contract's number (its memo); then one more each.
    pub first_cid: u32,
}

/// The hub's keys for contract `cid`.
pub(crate) fn contract_keys(seed: &str, cid: u32) -> PartyKeys {
    PartyKeys::from_seed(Role::Hub, Seed::from_label(&format!("{seed}/contract/{cid}")))
}

/// The hub's key in contract `cid`'s deposit tree.
pub(crate) fn deposit_key(seed: &str, cid: u32) -> bitcoin::key::Keypair {
    contract_keys(seed, cid).seed().keypair("deposit")
}

/// The adaptor secret `t` of a funding transaction: the hub's own, and a
/// different one for every funding offered (retries included), so that
/// the one funding that can confirm reveals the `t` of its own mint only.
pub(crate) fn mint_adaptor(seed: &str, cid: u32, l2_address: &lichen_ledger::Hash, funding: &bitcoin::Txid) -> SecretKey {
    Seed::from_label(&format!("{seed}/contract/{cid}/mint/{}/{funding}", hex::encode(l2_address))).keypair("adaptor").secret_key()
}

/// For tests: a fault in the opening, at the hub's end.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OpeningFault {
    #[default]
    None,
    /// Broadcast the funding, then fail to answer (Alice reads `t` from
    /// the chain).
    DropAnswer,
    /// Take Alice's pre-signature and never fund (she refunds; her mint
    /// stays locked).
    NeverFund,
    /// Mint a sat less than the deposit (Alice refuses the offer).
    ShortMint,
    /// Refuse the opening once the deposit is paid (as for terms the
    /// hub won't take): Alice keeps the deposit, to refund or to resume.
    Refuse,
}

struct Pending {
    req: OpenRequest,
    offer: OpenOffer,
    record: Record,
    /// The adaptor secret of the funding offered.
    t: SecretKey,
    /// When it was offered.
    made: std::time::Instant,
}

/// The largest request body (an opening request with all its keys is a
/// few hundred kilobytes).
const MAX_BODY: usize = 8 << 20;
/// The largest instance uploaded (a garbled circuit is about 24 MB).
const MAX_INSTANCE: usize = 64 << 20;
/// A pending offer is replaced by a new request for its contract only
/// this long after it was made.
const OFFER_REPLACED_AFTER: std::time::Duration = std::time::Duration::from_secs(60);
/// What the hub's coins for a funding carry beyond its share and fee: room
/// for the change.
const FUNDING_MARGIN: Amount = Amount::from_sat(10_000);

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Open {
    pub(crate) record: Record,
    /// How it ended: the fold's or the default's txid.
    #[serde(default)]
    pub(crate) closed: Option<bitcoin::Txid>,
    /// Whether anything of a closed contract is left for the hub to
    /// collect has been settled: always, for contracts closed since the hub
    /// collects its bit outputs; contracts closed before that are looked
    /// at once.
    #[serde(default)]
    pub(crate) collected: bool,
    /// Whether the closing transaction confirmed: until then the hub keeps
    /// looking, and watches the contract again if it vanishes (replaced by
    /// a conflicting spend: the user's escalation, mined instead).
    #[serde(default)]
    pub(crate) confirmed: bool,
}

pub(crate) struct Inner {
    cfg: Config,
    chain: Chain,
    seq: Client,
    /// Every signed root the hub has checked, by height (`seen.json`): a
    /// second root at one height is the sequencer signing two histories.
    seen: Mutex<lichen_l2::Seen>,
    pending: Mutex<HashMap<u32, Pending>>,
    /// The deposits asked for, not yet opened: Alice's key in each tree.
    deposits: Mutex<HashMap<u32, bitcoin::XOnlyPublicKey>>,
    open: Mutex<HashMap<u32, Open>>,
    next_cid: Mutex<u32>,
    disputes: Mutex<HashMap<u32, dispute::State>>,
    /// The misbehaviour switches (initially the config's), and a log of
    /// what the hub did.
    refuse_folds: AtomicBool,
    /// For tests: close a dispute the user won without collecting.
    leave_bits: AtomicBool,
    /// For tests: assert a false proof against every exit claim that
    /// holds.
    forge_assertions: AtomicBool,
    /// For tests: post no defaults (as a hub gone would not).
    hold_defaults: AtomicBool,
    /// For tests: a fault in each opening.
    opening_fault: Mutex<OpeningFault>,
    log: Mutex<Vec<String>>,
    /// The most the links' floors and anchors take from the hub's reserve
    /// on a dispute it loses (found at the first opening).
    floors: Mutex<Option<u64>>,
    /// The contracts whose hub's statement is being proved
    /// (`dispute::hp`).
    proving: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Set when the hub is dropped: a dispute waiting on the chain gives
    /// up, so that dropping a hub never waits for a block.
    stop: AtomicBool,
}

pub struct Hub {
    pub url: String,
    inner: Arc<Inner>,
    /// The listener: replaced if tiny_http's stops ([`listen`]).
    server: Arc<Mutex<Arc<Server>>>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Hub {
    pub fn start(cfg: Config) -> Result<Hub> {
        std::fs::create_dir_all(cfg.dir.join("contracts"))?;
        let chain = Chain::connect_on(&cfg.rpc_url, &cfg.cookie, &cfg.wallet, cfg.network)?;
        // coins locked for offers that didn't survive the restart
        chain.unlock(&[])?;
        let seq = Client::new(&cfg.sequencer)?;
        ensure!(seq.deployment.hub == xonly(&cfg.l2_key), "the sequencer's issuer is {}, not this hub's key {}", hex::encode(seq.deployment.hub), hex::encode(xonly(&cfg.l2_key)));
        // the sequencer may be another machine's: pin its key on first
        // contact, as a wallet does, and refuse another after
        let pin = cfg.dir.join("deployment.json");
        if pin.exists() {
            let d: lichen_ledger::Deployment = serde_json::from_slice(&std::fs::read(&pin)?).context("deployment.json")?;
            ensure!(d == seq.deployment, "the sequencer at {} has key {}, not {} as pinned in {}", cfg.sequencer, hex::encode(seq.deployment.sequencer), hex::encode(d.sequencer), pin.display());
        } else {
            files::write_atomic(&pin, &serde_json::to_vec_pretty(&seq.deployment)?)?;
        }
        let mut open = HashMap::new();
        for e in std::fs::read_dir(cfg.dir.join("contracts"))?.flatten() {
            let o: Open = serde_json::from_slice(&std::fs::read(e.path())?)?;
            open.insert(o.record.cid(), o);
        }
        std::fs::create_dir_all(cfg.dir.join("deposits"))?;
        let mut deposits = HashMap::new();
        for e in std::fs::read_dir(cfg.dir.join("deposits"))?.flatten() {
            let (cid, alice): (u32, bitcoin::XOnlyPublicKey) = serde_json::from_slice(&std::fs::read(e.path())?)?;
            deposits.insert(cid, alice);
        }
        let seen = match std::fs::read(cfg.dir.join("seen.json")) {
            Ok(b) => serde_json::from_slice(&b).context("seen.json")?,
            Err(_) => lichen_l2::Seen::default(),
        };
        let next = open.keys().chain(deposits.keys()).max().map_or(cfg.first_cid, |m| m + 1);
        let (cfg_refuse, cfg_forge) = (cfg.refuse_folds, cfg.forge_assertions);
        ensure!(!(cfg_refuse || cfg_forge) || cfg.network.is_test(), "a hub refuses withdrawals or asserts against true claims on test networks only, not {}", cfg.network);
        let server = Server::http(&cfg.listen).map_err(|e| anyhow!("listen on {}: {e}", cfg.listen))?;
        let port = server.server_addr().to_ip().context("an IP listener")?.port();
        let server = Arc::new(Mutex::new(Arc::new(server)));
        let inner = Arc::new(Inner { cfg, chain, seq, seen: Mutex::new(seen), pending: Mutex::new(HashMap::new()), deposits: Mutex::new(deposits), open: Mutex::new(open), next_cid: Mutex::new(next), disputes: Mutex::new(HashMap::new()), refuse_folds: AtomicBool::new(cfg_refuse), leave_bits: AtomicBool::new(false), forge_assertions: AtomicBool::new(cfg_forge), hold_defaults: AtomicBool::new(false), opening_fault: Mutex::new(OpeningFault::None), log: Mutex::new(vec![]), floors: Mutex::new(None), proving: Arc::new(Mutex::new(Default::default())), stop: AtomicBool::new(false) });
        let (srv, i1) = (server.clone(), inner.clone());
        let http = std::thread::spawn(move || {
            listen(&srv, &i1.stop, |mut req| {
                // an instance uploaded: bytes, not JSON
                if *req.method() == Method::Post && req.url().starts_with("/hp/instance/") {
                    let mut bytes = vec![];
                    let url = req.url().to_string();
                    let read = req.as_reader().take(MAX_INSTANCE as u64 + 1).read_to_end(&mut bytes);
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match read {
                        Err(e) => Err(anyhow!("the request's body: {e}")),
                        Ok(n) if n > MAX_INSTANCE => Err(anyhow!("an instance over {MAX_INSTANCE} bytes")),
                        Ok(_) => i1.hp_upload(&url, &bytes),
                    }));
                    let (code, json) = match r {
                        Ok(Ok(j)) => (200, j),
                        Ok(Err(e)) => (400, serde_json::json!({ "error": format!("{e:#}") }).to_string()),
                        Err(_) => (500, serde_json::json!({ "error": "the request failed" }).to_string()),
                    };
                    let ct = Header::from_bytes("Content-Type", "application/json").unwrap();
                    let _ = req.respond(Response::from_string(json).with_status_code(code).with_header(ct));
                    return;
                }
                let mut body = String::new();
                let read = req.as_reader().take(MAX_BODY as u64 + 1).read_to_string(&mut body);
                let error = |code: u16, e: String| (code, serde_json::json!({ "error": e }).to_string());
                let (code, json) = match read {
                    Err(e) => error(400, format!("the request's body: {e}")),
                    Ok(n) if n > MAX_BODY => error(413, format!("a body over {MAX_BODY} bytes")),
                    // a request that panics the handler is refused, and
                    // the hub goes on serving
                    Ok(_) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| route(&i1, req.method(), req.url(), &body))) {
                        Ok(Ok(j)) => (200, j),
                        Ok(Err(e)) => error(400, format!("{e:#}")),
                        Err(_) => error(500, "the request failed".into()),
                    },
                };
                let ct = Header::from_bytes("Content-Type", "application/json").unwrap();
                let _ = req.respond(Response::from_string(json).with_status_code(code).with_header(ct));
            });
        });
        let i2 = inner.clone();
        let watcher = std::thread::spawn(move || {
            while !i2.stop.load(Ordering::Relaxed) {
                if let Err(e) = i2.default_expired() {
                    eprintln!("hub: {e:#}");
                }
                if let Err(e) = i2.disputes_tick() {
                    eprintln!("hub: {e:#}");
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
        });
        Ok(Hub { url: format!("http://127.0.0.1:{port}"), inner, server, threads: vec![http, watcher] })
    }
    /// The contracts so far, and how each ended if it has.
    pub fn contracts(&self) -> Vec<(Record, Option<bitcoin::Txid>)> {
        self.inner.open.lock().unwrap().values().map(|o| (o.record.clone(), o.closed)).collect()
    }
    /// Each disputed contract's state, in words.
    pub fn disputes(&self) -> HashMap<u32, String> {
        self.inner.disputes.lock().unwrap().iter().map(|(c, s)| (*c, s.describe())).collect()
    }
    /// What the hub has done, in words.
    pub fn log(&self) -> Vec<String> {
        self.inner.log.lock().unwrap().clone()
    }
    /// Stop the hub, its threads joined, and return its whole log: what
    /// it noted up to the moment it stopped, which [`Hub::log`] taken
    /// before dropping it may miss.
    pub fn stop(self) -> Vec<String> {
        let inner = self.inner.clone();
        drop(self);
        let log = inner.log.lock().unwrap().clone();
        log
    }
    /// The misbehaviour switches are for test networks only.
    fn misbehave(&self) {
        let net = self.inner.cfg.network;
        assert!(net.is_test(), "a hub misbehaves on test networks only, not {net}");
    }
    /// The misbehaviour switches: refuse every cooperative withdrawal;
    /// assert against claims that are true ([`Hub::set_forge_assertions`]).
    pub fn set_refuse_folds(&self, on: bool) {
        self.misbehave();
        self.inner.refuse_folds.store(on, Ordering::Relaxed);
    }
    /// For tests: close a dispute the user won without collecting the
    /// hub's bit outputs, as hubs did before they collected them.
    pub fn set_leave_bits(&self, on: bool) {
        self.misbehave();
        self.inner.leave_bits.store(on, Ordering::Relaxed);
    }
    /// For tests: a fault in each opening from now on.
    pub fn set_opening_fault(&self, f: OpeningFault) {
        self.misbehave();
        *self.inner.opening_fault.lock().unwrap() = f;
    }
    /// With the hub proving, assert a false proof against every exit claim
    /// that holds.
    pub fn set_forge_assertions(&self, on: bool) {
        self.misbehave();
        self.inner.forge_assertions.store(on, Ordering::Relaxed);
    }
    /// For tests: post no defaults after `T_close`, as a hub gone would
    /// not (the user posts hers).
    pub fn set_hold_defaults(&self, on: bool) {
        self.misbehave();
        self.inner.hold_defaults.store(on, Ordering::Relaxed);
    }
    /// The switches: refusing folds, forging assertions.
    pub fn switches(&self) -> (bool, bool) {
        (self.inner.refuse_folds.load(Ordering::Relaxed), self.inner.forge_assertions.load(Ordering::Relaxed))
    }
    /// The hub's on-chain balance.
    pub fn balance(&self) -> Result<Amount> {
        self.inner.chain.balance()
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::Relaxed);
        // after `stop`: a listener made since is unblocked here, and one
        // being made sees `stop` ([`listen`])
        self.server.lock().unwrap().unblock();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// Serve each request on `server` with `handle` until `stop`. tiny_http's
/// listener ends for good at an error accepting a connection (a client
/// that resets before it is accepted, too many open files), and its
/// requests end with it, so the hub would answer nothing more while
/// running: say so, and listen again on the same address.
fn listen(server: &Mutex<Arc<Server>>, stop: &AtomicBool, mut handle: impl FnMut(Request)) {
    loop {
        let srv = server.lock().unwrap().clone();
        let e = loop {
            match srv.recv() {
                Ok(req) => handle(req),
                Err(e) => break e,
            }
        };
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let addr = srv.server_addr().to_ip().expect("an IP listener");
        eprintln!("hub: the listener stopped ({e}): listening again on {addr}");
        let mut said = false;
        let fresh = loop {
            match Server::http(addr) {
                Ok(s) => break s,
                Err(_) if stop.load(Ordering::Relaxed) => return,
                Err(e) => {
                    if !said {
                        eprintln!("hub: listening on {addr}: {e} (trying each second)");
                        said = true;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        };
        *server.lock().unwrap() = Arc::new(fresh);
        eprintln!("hub: listening again on {addr}");
        if stop.load(Ordering::Relaxed) {
            return;
        }
    }
}

fn route(inner: &Inner, method: &Method, url: &str, body: &str) -> Result<String> {
    Ok(match (method, url) {
        (Method::Get, "/info") => serde_json::to_string(&inner.info())?,
        (Method::Post, "/deposit") => serde_json::to_string(&inner.deposit(serde_json::from_str(body)?)?)?,
        (Method::Post, "/hp/setup") => serde_json::to_string(&inner.hp_setup(serde_json::from_str(body)?)?)?,
        (Method::Post, "/hp/commit") => serde_json::to_string(&inner.hp_commit(serde_json::from_str(body)?)?)?,
        (Method::Post, "/open") => serde_json::to_string(&inner.open(serde_json::from_str(body)?)?)?,
        (Method::Post, "/accept") => serde_json::to_string(&inner.accept(serde_json::from_str(body)?)?)?,
        (Method::Post, "/withdraw") => serde_json::to_string(&inner.withdraw(serde_json::from_str(body)?)?)?,
        _ => bail!("no {method} {url}"),
    })
}

impl Inner {
    /// Log what the hub did.
    pub(crate) fn note(&self, msg: String) {
        eprintln!("hub: {msg}");
        self.log.lock().unwrap().push(msg);
    }

    /// A note not already the last one logged (an error repeated each
    /// tick is logged once).
    pub(crate) fn note_once(&self, msg: String) {
        if self.log.lock().unwrap().last() != Some(&msg) {
            self.note(msg);
        }
    }

    fn info(&self) -> Info {
        Info { network: self.cfg.network, deployment: self.seq.deployment, statement: self.cfg.statement.id().to_string(), reserve_ppm: self.cfg.reserve_ppm, fee_ppm: self.cfg.fee_ppm, max_liquidity: self.cfg.max_liquidity, duration: self.cfg.duration, version: lichen_proto::VERSION.to_string(), commit: option_env!("LICHEN_COMMIT").filter(|c| !c.is_empty()).map(str::to_string), guests: Some(lichen_proto::Guests::ours()) }
    }

    /// A deposit address for a contract to come: its number, and the hub's
    /// key in the deposit's tree.
    fn deposit(&self, req: DepositRequest) -> Result<DepositOffer> {
        // the ask told: what the opening would refuse for want of coins,
        // refused before she pays rather than after (a deposit then waits
        // for its refund). Against everything the wallet holds, as some
        // may be unconfirmed change or locked for an offer that goes: the
        // opening's selection is the exact check, and deposits not yet
        // opened hold nothing back, so two at once may both pass here
        if req.deposit > 0 {
            ensure!(req.liquidity <= self.cfg.max_liquidity, "liquidity of {} sats, above the hub's most, {}", req.liquidity, self.cfg.max_liquidity);
            let fee = lichen_proto::liquidity_fee(req.liquidity, self.cfg.fee_ppm);
            ensure!(fee < req.deposit, "a deposit of {} sats doesn't cover the hub's fee of {fee}", req.deposit);
            let (bits, unit) = lichen_proto::scale(req.deposit - fee + req.liquidity)?;
            let v_max = unit * ((1u64 << bits) - 1);
            let floors = self.floors.lock().unwrap().unwrap_or(0);
            let reserve_hub = (v_max * self.cfg.reserve_ppm / 1_000_000).max(floors);
            let need = Amount::from_sat(v_max.saturating_sub(req.deposit) + reserve_hub) + FEE_SHARE + FUNDING_MARGIN;
            ensure!(self.chain.balance_pending()? >= need, "the hub can't fund a contract with {} sats of liquidity now: ask for less, or try later", req.liquidity);
        }
        let cid = {
            let mut n = self.next_cid.lock().unwrap();
            *n += 1;
            *n - 1
        };
        files::write_atomic(&self.cfg.dir.join("deposits").join(format!("{cid}.json")), &serde_json::to_vec(&(cid, req.alice))?)?;
        self.deposits.lock().unwrap().insert(cid, req.alice);
        Ok(DepositOffer { cid, hub: deposit_key(&self.cfg.seed, cid).x_only_public_key().0, timeout: deposit_timeout(self.cfg.network) })
    }

    /// The deposit tree of contract `cid`.
    /// Contract `cid`'s deposit at `op`: to its tree, confirmed, unspent,
    /// its refund far enough off to open on it. The coin.
    pub(crate) fn check_deposit(&self, cid: u32, op: &OutPoint) -> Result<TxOut> {
        let out = self.chain.get_tx(&op.txid).and_then(|t| t.output.get(op.vout as usize).cloned()).context("no such deposit on chain")?;
        ensure!(out.script_pubkey == self.deposit_tree(cid)?.script_pubkey(), "the deposit is not to contract {cid}'s address");
        ensure!(self.chain.confirmations(&op.txid)? >= 1, "the deposit is not confirmed");
        ensure!(self.chain.unspent(op)?, "the deposit is spent");
        let deadline = broadcast_deadline(self.deposit_confirmed_at(op)?, deposit_timeout(self.cfg.network));
        ensure!(self.chain.height()? < deadline, "the deposit's refund matures too soon to open on it (refund it and deposit again)");
        Ok(out)
    }

    fn deposit_tree(&self, cid: u32) -> Result<lngap_btc::taptree::TapTree> {
        let alice = *self.deposits.lock().unwrap().get(&cid).with_context(|| format!("no deposit asked for contract {cid}"))?;
        deposit_tree(&alice, &deposit_key(&self.cfg.seed, cid).x_only_public_key().0, deposit_timeout(self.cfg.network))
    }

    fn open(&self, req: OpenRequest) -> Result<OpenOffer> {
        ensure!(req.liquidity <= self.cfg.max_liquidity, "liquidity of {} sats, above the hub's most, {}", req.liquidity, self.cfg.max_liquidity);
        let fee = lichen_proto::liquidity_fee(req.liquidity, self.cfg.fee_ppm);
        ensure!(req.fee >= fee, "a fee of {} sats for {} sats of liquidity: the hub asks {fee}", req.fee, req.liquidity);
        ensure!(*self.opening_fault.lock().unwrap() != OpeningFault::Refuse, "refusing contract {}'s opening (a test's fault)", req.cid);
        let cid = req.cid;
        ensure!(!self.open.lock().unwrap().contains_key(&cid), "contract {cid} is open already");
        // one offer pending a contract: a new one replaces it (its answer
        // lost, say), its coins freed, but not sooner than a minute after
        // it (each offer mints)
        if let Some(p) = self.pending.lock().unwrap().get(&cid) {
            ensure!(p.made.elapsed() >= OFFER_REPLACED_AFTER, "an offer for contract {cid} is pending: accept it, or ask again in a minute");
        }
        // the deposit: to this contract's tree, confirmed, unspent
        let (dep_op, dep_out) = &req.deposit_coin;
        let on_chain = self.check_deposit(cid, dep_op)?;
        ensure!(on_chain == *dep_out, "no such deposit on chain");
        let keys = contract_keys(&self.cfg.seed, cid);
        let mut hub = keys.public();
        hub.payout_spk = self.chain.new_spk()?;
        let t_close = self.chain.height()? + self.cfg.duration;
        // the cap and its unit, as the request makes them
        let scaled = terms(cid, &req, t_close, 0)?;
        let v_max = scaled.v_max().to_sat();
        // the dispute's keys: Alice's, checked, and the hub's; the
        // statement fixed at the setup, its checkpoint with it
        let (dispute, mut offer_keys, checkpoint) = self.hp_open_keys(cid, &req.dispute, &req.deposit_coin.0, t_close, scaled.unit)?;
        let mut record = Record {
            statement: self.cfg.statement.id().to_string(),
            network: self.cfg.network,
            deployment: lichen_proto::contract_word(&self.seq.deployment, checkpoint.as_ref(), scaled.unit)?,
            checkpoint,
            // a reserve to measure the floors under (any amount above them:
            // they depend on the links' sizes, not on the amounts; the cap
            // isn't, for a small one); the real one below
            terms: terms(cid, &req, t_close, v_max.max(100_000_000))?,
            pubs: [req.alice.clone(), hub.clone()],
            l2_address: req.l2_address,
            funding: OutPoint::null(),
            hub_sigs: HashMap::new(),
            alice_sigs: HashMap::new(),
            fee: req.fee,
            dispute,
        };
        // the hub's reserve: its share of the cap, and at least what the
        // floors of a dispute it loses take from it
        let known = *self.floors.lock().unwrap();
        let floors = match known {
            Some(f) => f,
            None => {
                // the deepest output any dispute reaches, against the
                // contract's value (the same for every contract: the
                // links' sizes don't depend on the amounts)
                let c = self.built(&record)?;
                let set = c.presign(OutPoint::null())?;
                let f = set.iter().map(|p| (c.value() - p.prevout.value).to_sat()).max().unwrap_or(0);
                self.note(format!("a dispute's floors take up to {f} sats from the reserve of the side that loses"));
                *self.floors.lock().unwrap().get_or_insert(f)
            }
        };
        let reserve_hub = (v_max * self.cfg.reserve_ppm / 1_000_000).max(floors);
        let t = terms(cid, &req, t_close, reserve_hub)?;
        record.terms = t;
        let (_, hub_in) = contributions(&t);
        let fee_budget = lichen_proto::fee_budget_of(dep_out.value, &t)?;
        ensure!(fee_budget >= Amount::from_sat(330), "the deposit leaves no fee budget");
        let fee_out = TxOut { value: fee_budget, script_pubkey: req.fee_spk.clone() };
        let hub_coins = self.chain.select(hub_in + FEE_SHARE + FUNDING_MARGIN)?;
        let hub_spent: Amount = hub_coins.iter().map(|c| c.1.value).sum();
        let hub_change = TxOut { value: hub_spent - hub_in - FEE_SHARE, script_pubkey: self.chain.new_spk()? };
        let c = self.built(&record)?;
        let ins: Vec<(OutPoint, Sequence)> = std::iter::once(&req.deposit_coin).chain(&hub_coins).map(|c| (c.0, Sequence::ENABLE_RBF_NO_LOCKTIME)).collect();
        let outs = vec![TxOut { value: c.value(), script_pubkey: c.tree()?.script_pubkey() }, fee_out, hub_change.clone()];
        let funding = lngap_btc::tx::build_tx(&ins, outs, bitcoin::absolute::LockTime::ZERO);
        check_funding(&funding, &c, &hub_coins, &hub_change, hub_in)?;
        record.funding = OutPoint { txid: funding.compute_txid(), vout: 0 };
        let set = c.presign(record.funding)?;
        record.hub_sigs = sign_all(&set, &keys.payment)?;
        // with the roles swapped: the hub's pre-signatures on her challenge
        self.hp_presign(&mut record, &mut offer_keys, &set)?;
        // what the hub keeps from her stays its own
        let shown: HashMap<String, Vec<u8>> = record.hub_sigs.iter().filter(|(n, _)| !c.withheld(n)).map(|(n, s)| (n.clone(), s.clone())).collect();
        // D, minted now to a key Alice can spend once this funding is out
        let t = mint_adaptor(&self.cfg.seed, cid, &req.l2_address, &record.funding.txid);
        let mint_point = PublicKey::from_secret_key(SECP256K1, &t);
        let fault = *self.opening_fault.lock().unwrap();
        let d = record.minted() - u64::from(fault == OpeningFault::ShortMint);
        let owner = mint_owner(&req.l2_address, &mint_point)?;
        let mint_index = self.seq.submit(&Tx::Mint(Mint::new(&self.cfg.l2_key, &self.seq.deployment, vec![note(owner, d, 0)])))?[0];
        self.note(format!("contract {cid}: offered; minted {d} sats to the user (a fee of {} for {} sats of liquidity), locked to the funding", req.fee, req.liquidity));
        let offer = OpenOffer { cid, t_close, reserve_hub, hub, dispute: offer_keys, funding, hub_coins, hub_sigs: shown, mint_point, mint_index, checkpoint: record.checkpoint };
        let replaced = self.pending.lock().unwrap().insert(cid, Pending { req, offer: offer.clone(), record, t, made: std::time::Instant::now() });
        if let Some(old) = replaced {
            let _ = self.chain.unlock(&old.offer.hub_coins.iter().map(|c| c.0).collect::<Vec<_>>());
        }
        Ok(offer)
    }

    fn accept(&self, a: Accept) -> Result<Opened> {
        let p = self.pending.lock().unwrap().remove(&a.cid).context("no such offer")?;
        let coins: Vec<OutPoint> = p.offer.hub_coins.iter().map(|c| c.0).collect();
        let r = self.fund(a, p);
        if r.is_err() {
            // free the coins the offer locked (spent ones: nothing to do)
            let _ = self.chain.unlock(&coins);
        }
        r
    }

    fn fund(&self, a: Accept, p: Pending) -> Result<Opened> {
        let mut record = p.record;
        record.alice_sigs = a.alice_sigs;
        self.hp_accept(&record)?;
        let c = self.built(&record)?;
        record.presigned(&c).context("Alice's signatures")?;
        // the deposit input: Alice's signature and the hub's, then the hub's coins
        let prevouts: Vec<(OutPoint, TxOut)> = std::iter::once(&p.req.deposit_coin).chain(&p.offer.hub_coins).cloned().collect();
        let outs: Vec<TxOut> = prevouts.iter().map(|c| c.1.clone()).collect();
        let mut funding = p.offer.funding.clone();
        let tree = self.deposit_tree(a.cid)?;
        let leaf = tree.leaf(DEPOSIT_OPEN)?;
        // Alice's pre-signature, locked to this funding's T: completing it
        // (the only way to spend her deposit) puts t on chain
        let alice = *self.deposits.lock().unwrap().get(&a.cid).context("no deposit asked for this contract")?;
        let (dep, msg) = deposit_open_msg(&funding, &p.req.deposit_coin.0, &prevouts, &tree)?;
        let presig = AdaptorSig::from(&a.deposit_presig);
        ensure!(adaptor_verify(&alice, &msg, &p.offer.mint_point, &presig), "Alice's pre-signature is not locked to this funding's adaptor point");
        ensure!(*self.opening_fault.lock().unwrap() != OpeningFault::NeverFund, "not funding contract {} (a test's fault)", a.cid);
        let alice_sig = adaptor_complete(&presig, &p.t);
        SECP256K1.verify_schnorr(&alice_sig, &msg, &alice).context("the completed signature")?;
        // nothing but the funding can spend the deposit until its refund
        // matures: broadcast only with time to confirm before then
        let deadline = broadcast_deadline(self.deposit_confirmed_at(&p.req.deposit_coin.0)?, deposit_timeout(self.cfg.network));
        ensure!(self.chain.height()? < deadline, "the deposit's refund matures too soon to broadcast the funding (height {deadline} was the last)");
        let hub_sig = lngap_btc::sighash::sign_tapscript(&deposit_key(&self.cfg.seed, a.cid), &funding, dep, &outs, &leaf.script)?;
        funding.input[dep].witness = lngap_btc::witness::tapscript_witness(&[alice_sig.as_ref().to_vec(), hub_sig.as_ref().to_vec()], &leaf.script, &tree.control_block(DEPOSIT_OPEN)?);
        let signed = self.chain.sign_mine(&funding, &prevouts)?;
        // kept before the funding goes out: a contract the hub funded and
        // forgot (a crash between) would never be defaulted or disputed
        let o = Open { record, closed: None, collected: false, confirmed: false };
        self.save(&o)?;
        let txid = match self.chain.broadcast(&signed) {
            Ok(t) => t,
            Err(e) => {
                let _ = std::fs::remove_file(self.cfg.dir.join("contracts").join(format!("{}.json", a.cid)));
                return Err(e.context("broadcasting the funding"));
            }
        };
        self.note(format!("contract {}: opened (deposit {} sats, cap {} sats); funding broadcast", a.cid, o.record.terms.deposit, o.record.terms.v_max().to_sat()));
        self.open.lock().unwrap().insert(a.cid, o);
        self.deposits.lock().unwrap().remove(&a.cid);
        let _ = std::fs::remove_file(self.cfg.dir.join("deposits").join(format!("{}.json", a.cid)));
        ensure!(*self.opening_fault.lock().unwrap() != OpeningFault::DropAnswer, "funding {txid} broadcast, the answer dropped (a test's fault)");
        Ok(Opened { txid, t: p.t })
    }

    fn save(&self, o: &Open) -> Result<()> {
        files::write_atomic(&self.cfg.dir.join("contracts").join(format!("{}.json", o.record.cid())), &serde_json::to_vec_pretty(o)?)?;
        Ok(())
    }

    /// The sequencer's state, its roots checked and recorded: an error if
    /// it shows a root at a height seen before other than the one seen
    /// (the evidence in `equivocation.json`).
    fn state(&self) -> Result<lichen_l2::State> {
        let state = self.seq.state()?;
        let mut seen = self.seen.lock().unwrap();
        match seen.record(&state.sealed) {
            Ok(true) => files::write_atomic(&self.cfg.dir.join("seen.json"), &serde_json::to_vec(&*seen)?)?,
            Ok(false) => {}
            Err(e) => {
                let path = self.cfg.dir.join("equivocation.json");
                files::write_atomic(&path, &serde_json::to_vec_pretty(&e)?)?;
                self.note(format!("ALARM: {e}; the evidence: {}", path.display()));
                bail!("{e}: it signed two histories; the hub folds nothing until this is resolved");
            }
        }
        Ok(state)
    }

    /// The cooperative withdrawal: Alice's claim of `b` units checked
    /// against the hub's ledger, recorded on the L2 (retiring its notes),
    /// then her fold signed and broadcast at once. The record is the hub's
    /// protection: once it is sequenced the notes are gone, an earlier
    /// spend of them refused. If the hub then didn't fold, her exit would
    /// post the same claim, which this contract's own record doesn't
    /// refute (docs/HUB_PROVES_PLAN.md). At `b` 0, no claim: an early
    /// close, her reserve alone.
    fn withdraw(&self, w: WithdrawRequest) -> Result<Folded> {
        let o = self.open.lock().unwrap().get(&w.cid).cloned().context("no such contract")?;
        ensure!(o.closed.is_none(), "contract {} is closed", w.cid);
        let unit = o.record.terms.unit;
        let paid = unit.checked_mul(u64::from(w.b)).filter(|v| *v <= o.record.terms.v_max()).with_context(|| format!("{} units is above the cap", w.b))?;
        let c = self.built(&o.record)?;
        let p = c.fold(o.record.funding, paid, FOLD_FEE)?;
        p.verify(&o.record.pubs[0].payment, &w.alice_sig).context("Alice's signature on the fold")?;
        if w.b == 0 {
            // an early close: Alice takes her reserve alone, as the default
            // would pay her at T_close, so there's no claim to record
            ensure!(o.record.terms.reserve_alice >= CLOSE_DUST, "contract {}: a fold of nothing pays the user nothing (no reserve): the default closes it", w.cid);
        } else {
            self.record_claim(&o.record, w.b, &hex::decode(&w.claim).context("the claim's hex")?)?;
        }
        // a refusing hub (tests) records the claim first: the user's worst
        // case, her notes retired and no fold
        ensure!(!self.refuse_folds.load(Ordering::Relaxed), "this hub refuses cooperative withdrawals");
        let mine = p.sign(&contract_keys(&self.cfg.seed, w.cid).payment)?;
        let txid = self.chain.broadcast(&p.finish(vec![], &mine, &w.alice_sig)).context("broadcasting the fold")?;
        self.close(w.cid, txid)?;
        self.note(format!("contract {}: folded: {} units ({} sats) back to the user, with the user's reserve", w.cid, w.b, paid.to_sat()));
        Ok(Folded { txid })
    }

    /// Alice's claim (`posted`, its bytes) of `b` units from contract
    /// `record`, checked against the ledger now, and its exit record
    /// sequenced: well formed and of this contract's `E`; each position a
    /// transparent note, or the shielded note the claim opens, unspent;
    /// each owner signed; worth at least `b` units.
    fn record_claim(&self, record: &Record, b: u32, posted: &[u8]) -> Result<()> {
        use lichen_withdraw::hp::Claim;
        let cid = record.cid();
        let claim = Claim::from_bytes(posted).map_err(|e| anyhow!("the claim: {e:?}"))?;
        ensure!(claim.well_formed(), "the claim isn't well formed");
        let deposit = lichen_proto::setup::statement_outpoint(&record.hp().deposit);
        let e = claim.fingerprint(cid, &deposit, b);
        let state = self.state()?;
        // a locked note only with its spend's acknowledgment, carried
        let unlocked = |i: u32| -> Result<()> {
            if state.locked(i) {
                let t = state.leaf(&lichen_ledger::lichen_validity::ack::lock_key(i));
                ensure!(claim.acks.iter().any(|a| a.txid == t), "the note at {i} is locked: its spend isn't acknowledged, and the claim carries no acknowledgment of it");
            }
            Ok(())
        };
        let mut notes = vec![];
        for &i in &claim.positions {
            let n = *state.notes.get(i as usize).and_then(|l| l.note()).with_context(|| format!("position {i} isn't a transparent note"))?;
            ensure!(!state.is_spent(&n), "the note at {i} is spent");
            unlocked(i)?;
            notes.push(n);
        }
        let mut total: u64 = notes.iter().map(|n| n.value).sum();
        if let Some(sc) = &claim.shielded {
            for n in &sc.notes {
                let i = n.index;
                ensure!(state.notes.get(i as usize).map(|l| l.leaf()) == Some(sc.leaf(n)), "position {i} isn't the shielded note the claim opens");
                ensure!(!state.spent(&sc.nullifier(n)), "the note at {i} is spent");
                unlocked(i)?;
                total += n.value;
            }
        }
        ensure!(total / record.terms.unit.to_sat() >= u64::from(b), "the notes are worth {total} sats, less than {b} units");
        let tnotes: Vec<lichen_ledger::lichen_validity::TNote> = notes.iter().map(|n| lichen_ledger::lichen_validity::TNote { owner: n.owner, value: n.value, memo: n.memo, rho: n.rho }).collect();
        let (_, sigs) = claim.record(&tnotes, &e).context("a note's owner didn't sign the claim")?;
        let spends = notes.into_iter().zip(&claim.positions).map(|(note, &index)| lichen_ledger::Spend { note, index }).collect();
        let acks = claim.acks.iter().map(lichen_ledger::Ack::of).collect();
        let tx = Tx::Exit(lichen_ledger::Exit::new(&self.cfg.l2_key, &self.seq.deployment, cid, deposit, b, spends, claim.shielded.clone(), acks, sigs));
        self.seq.submit(&tx).context("recording the claim on the L2")?;
        self.note(format!("contract {cid}: the user's withdrawal claim of {b} units recorded on the L2: its notes are retired"));
        Ok(())
    }

    /// Close a contract: nothing of it is left to collect (a dispute the
    /// user won closes only once the hub's bit outputs are swept).
    pub(crate) fn close(&self, cid: u32, txid: bitcoin::Txid) -> Result<()> {
        let mut open = self.open.lock().unwrap();
        let o = open.get_mut(&cid).context("no such contract")?;
        o.closed = Some(txid);
        o.collected = true;
        o.confirmed = false;
        let o = o.clone();
        drop(open);
        self.save(&o)
    }

    /// Close a contract that a confirmed transaction `txid` settled.
    pub(crate) fn close_settled(&self, cid: u32, txid: bitcoin::Txid) -> Result<()> {
        self.close(cid, txid)?;
        let mut open = self.open.lock().unwrap();
        let o = open.get_mut(&cid).context("no such contract")?;
        o.confirmed = true;
        let o = o.clone();
        drop(open);
        self.save(&o)
    }

    /// Each contract closed by a transaction of the hub's not yet
    /// confirmed: confirmed now, or still waiting, or gone (replaced or
    /// evicted: then the contract is watched again from what the chain
    /// shows).
    fn check_closings(&self) -> Result<()> {
        let closing: Vec<(u32, bitcoin::Txid)> = self.open.lock().unwrap().values().filter(|o| !o.confirmed).filter_map(|o| o.closed.map(|t| (o.record.cid(), t))).collect();
        for (cid, txid) in closing {
            if self.chain.confirmations(&txid)? >= 1 {
                let mut open = self.open.lock().unwrap();
                let Some(o) = open.get_mut(&cid) else { continue };
                o.confirmed = true;
                let o = o.clone();
                drop(open);
                self.save(&o)?;
            } else if self.chain.get_tx(&txid).is_none() {
                let mut open = self.open.lock().unwrap();
                let Some(o) = open.get_mut(&cid) else { continue };
                o.closed = None;
                o.collected = false;
                let o = o.clone();
                drop(open);
                self.save(&o)?;
                self.disputes.lock().unwrap().remove(&cid);
                self.note(format!("contract {cid}: its closing transaction {txid} is gone (replaced?); watching the contract again"));
            }
        }
        Ok(())
    }

    /// Record whether what a closed contract left is collected.
    pub(crate) fn set_collected(&self, cid: u32, collected: bool) -> Result<()> {
        let mut open = self.open.lock().unwrap();
        let o = open.get_mut(&cid).context("no such contract")?;
        o.collected = collected;
        let o = o.clone();
        drop(open);
        self.save(&o)
    }

    /// After `T_close`, the default of every contract still open: the
    /// pre-signed transaction, both signatures in hand, plus a fee coin of
    /// the hub's.
    fn default_expired(&self) -> Result<()> {
        if self.hold_defaults.load(Ordering::Relaxed) {
            return Ok(());
        }
        let height = self.chain.height()?;
        let due: Vec<Open> = self.open.lock().unwrap().values().filter(|o| o.closed.is_none() && height >= o.record.terms.t_close).cloned().collect();
        for o in due {
            // one contract's trouble never holds up another's default
            if let Err(e) = self.default_one(&o) {
                self.note_once(format!("contract {}: the default: {e:#}", o.record.cid()));
            }
        }
        Ok(())
    }

    fn default_one(&self, o: &Open) -> Result<()> {
        // the funding output spent (an escalation, a fold) or never there:
        // no default to post, and no fee coin made for one
        if !self.chain.unspent(&o.record.funding)? {
            return Ok(());
        }
        {
            let c = self.built(&o.record)?;
            let set = o.record.presigned(&c)?;
            let p = set.iter().find(|p| p.name == "default").context("no default")?;
            let mut tx = p.finish(vec![], &o.record.hub_sigs["default"], &o.record.alice_sigs["default"]);
            let (op, coin) = self.chain.fee_coin(DEFAULT_FEE)?;
            tx.input.push(bitcoin::TxIn { previous_output: op, sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, ..Default::default() });
            let tx = self.chain.sign_mine(&tx, &[(o.record.funding, p.prevout.clone()), (op, coin)])?;
            let txid = self.chain.broadcast(&tx).context("broadcasting the default")?;
            self.close(o.record.cid(), txid)?;
            self.note(format!("contract {}: T_close passed; the default (the user's reserve back)", o.record.cid()));
        }
        Ok(())
    }

    /// The height at which the deposit `op` confirmed.
    fn deposit_confirmed_at(&self, op: &OutPoint) -> Result<u32> {
        let n = self.chain.confirmations(&op.txid)?;
        ensure!(n >= 1, "the deposit is not confirmed");
        Ok(self.chain.height()? + 1 - n)
    }
}

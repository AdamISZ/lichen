//! The hub: opens contracts with users, issues their deposits as tokens on
//! the L2, and (later) pays withdrawals and answers disputes.
//!
//! HTTP (JSON): `GET /info`, `POST /open` ([`OpenRequest`] to
//! [`OpenOffer`]), `POST /accept` ([`Accept`] to [`Opened`]), `POST /fold`
//! ([`FoldRequest`] to [`Folded`]: the cooperative withdrawal, once the
//! hub has seen Alice's return sealed on the L2). An offer mints the
//! deposit to a key Alice can spend only once the funding is broadcast
//! (see `lichen_proto`); a watcher broadcasts, after `T_close`, the
//! default of any contract still open.

mod dispute;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bitcoin::secp256k1::{PublicKey, SecretKey, SECP256K1};
use bitcoin::{Amount, OutPoint, Sequence, TxOut};
use lngap_btc::adaptor::{adaptor_complete, adaptor_verify, AdaptorSig};
use lichen_chain::Chain;
use lichen_ledger::{note, xonly, Mint, Tx};
use lichen_ledger::k256::schnorr::SigningKey;
use lichen_proto::{all_moves, broadcast_deadline, check_funding, deposit_open_msg, deposit_timeout, deposit_tree, mint_owner, tail_keys, contributions, terms, Accept, DepositOffer, DepositRequest, FoldRequest, Folded, Info, Net, OpenOffer, OpenRequest, Opened, Record, Statement, Windows, DEFAULT_FEE, DEPOSIT_OPEN, FEE_SHARE, FOLD_FEE};
use lichen_l2::Client;
use lngap_btc::keys::Seed;
use lngap_channel::{PartyKeys, Role};
use lngap_lamport::winternitz::{WotsParams, WotsSecret};
use lngap_sessions::contract::{sign_all, Program};
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Response, Server};

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
    /// The hub's L2 key: it mints, and returns are paid to it. The
    /// sequencer must name it as the issuer.
    pub l2_key: SigningKey,
    pub reserve_ppm: u64,
    pub max_bits: u32,
    pub duration: u32,
    /// The dispute's windows it offers (none: the network's,
    /// `lichen_proto::windows`): longer heavy windows for a hub with many
    /// contracts (the paper's congestion table).
    pub windows: Option<Windows>,
    /// Misbehaviour, for tests: refuse every cooperative withdrawal, and
    /// dispute claims that are true.
    pub refuse_folds: bool,
    pub dispute_true_claims: bool,
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

/// The hub's move keys for depth `d` of contract `cid`, one per field.
pub fn move_secrets(seed: &str, cid: u32, program: &Program, d: u32) -> Vec<WotsSecret> {
    let at = |f: usize, n: u32| WotsSecret::from_entropy(WotsParams::for_bytes(n), Seed::from_label(&format!("{seed}/contract/{cid}/move/{d}/{f}")).derive_bytes("wots"));
    program.field_bytes(d).into_iter().enumerate().map(|(f, n)| at(f, n)).collect()
}

/// The hub's keys for its path under a jump list, by chunk and field
/// (empty without one).
pub fn path_secrets(seed: &str, cid: u32, program: &Program) -> Vec<Vec<WotsSecret>> {
    if program.schedule.jump.is_none() {
        return vec![];
    }
    let at = |c: usize, f: usize, n: usize| WotsSecret::from_entropy(WotsParams::for_bytes(n as u32), Seed::from_label(&format!("{seed}/contract/{cid}/path/{c}/{f}")).derive_bytes("wots"));
    (0..lngap_ladder::tail::CHUNKS).map(|c| lngap_ladder::tail::chunk_fields(c).into_iter().enumerate().map(|(f, n)| at(c, f, n)).collect()).collect()
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
}

struct Pending {
    req: OpenRequest,
    offer: OpenOffer,
    record: Record,
    /// The adaptor secret of the funding offered.
    t: SecretKey,
}

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
}

pub(crate) struct Inner {
    cfg: Config,
    program: Program,
    chain: Chain,
    seq: Client,
    pending: Mutex<HashMap<u32, Pending>>,
    /// The deposits asked for, not yet opened: Alice's key in each tree.
    deposits: Mutex<HashMap<u32, bitcoin::XOnlyPublicKey>>,
    open: Mutex<HashMap<u32, Open>>,
    next_cid: Mutex<u32>,
    disputes: Mutex<HashMap<u32, dispute::State>>,
    /// The misbehaviour switches (initially the config's), and a log of
    /// what the hub did.
    refuse_folds: AtomicBool,
    dispute_true_claims: AtomicBool,
    /// For tests: forge a hash in every path the hub posts.
    forge_paths: AtomicBool,
    /// For tests: close a dispute the user won without collecting.
    leave_bits: AtomicBool,
    /// For tests: a fault in each opening.
    opening_fault: Mutex<OpeningFault>,
    log: Mutex<Vec<String>>,
    /// The most the links' floors and anchors take from the hub's reserve
    /// on a dispute it loses (the statement's, found at the first opening).
    floors: std::sync::OnceLock<u64>,
}

pub struct Hub {
    pub url: String,
    inner: Arc<Inner>,
    server: Arc<Server>,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Hub {
    pub fn start(cfg: Config) -> Result<Hub> {
        if let Some(w) = cfg.windows {
            w.check(lichen_proto::params(cfg.network).delta, lngap_sessions::contract::POST_CSV).map_err(|e| anyhow!(e))?;
            let least = lichen_proto::windows(cfg.network).user;
            ensure!(w.user >= least, "windows {w:?}: wallets refuse fewer than {least} blocks for each of the user's moves");
        }
        std::fs::create_dir_all(cfg.dir.join("contracts"))?;
        let program = cfg.statement.program(&cfg.dir)?;
        let chain = Chain::connect_on(&cfg.rpc_url, &cfg.cookie, &cfg.wallet, cfg.network)?;
        let seq = Client::new(&cfg.sequencer)?;
        ensure!(seq.deployment.hub == xonly(&cfg.l2_key), "the sequencer's issuer is {}, not this hub's key {}", hex::encode(seq.deployment.hub), hex::encode(xonly(&cfg.l2_key)));
        // the sequencer may be another machine's: pin its key on first
        // contact, as a wallet does, and refuse another after
        let pin = cfg.dir.join("deployment.json");
        if pin.exists() {
            let d: lichen_ledger::Deployment = serde_json::from_slice(&std::fs::read(&pin)?).context("deployment.json")?;
            ensure!(d == seq.deployment, "the sequencer at {} has key {}, not {} as pinned in {}", cfg.sequencer, hex::encode(seq.deployment.sequencer), hex::encode(d.sequencer), pin.display());
        } else {
            std::fs::write(&pin, serde_json::to_vec_pretty(&seq.deployment)?)?;
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
        let next = open.keys().chain(deposits.keys()).max().map_or(cfg.first_cid, |m| m + 1);
        let (cfg_refuse, cfg_dispute) = (cfg.refuse_folds, cfg.dispute_true_claims);
        let server = Arc::new(Server::http(&cfg.listen).map_err(|e| anyhow!("listen on {}: {e}", cfg.listen))?);
        let port = server.server_addr().to_ip().context("an IP listener")?.port();
        let inner = Arc::new(Inner { cfg, program, chain, seq, pending: Mutex::new(HashMap::new()), deposits: Mutex::new(deposits), open: Mutex::new(open), next_cid: Mutex::new(next), disputes: Mutex::new(HashMap::new()), refuse_folds: AtomicBool::new(cfg_refuse), dispute_true_claims: AtomicBool::new(cfg_dispute), forge_paths: AtomicBool::new(false), leave_bits: AtomicBool::new(false), opening_fault: Mutex::new(OpeningFault::None), log: Mutex::new(vec![]), floors: std::sync::OnceLock::new() });
        let stop = Arc::new(AtomicBool::new(false));
        let (srv, i1) = (server.clone(), inner.clone());
        let http = std::thread::spawn(move || {
            for mut req in srv.incoming_requests() {
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                let (code, json) = match route(&i1, req.method(), req.url(), &body) {
                    Ok(j) => (200, j),
                    Err(e) => (400, serde_json::json!({ "error": format!("{e:#}") }).to_string()),
                };
                let ct = Header::from_bytes("Content-Type", "application/json").unwrap();
                let _ = req.respond(Response::from_string(json).with_status_code(code).with_header(ct));
            }
        });
        let (i2, s2) = (inner.clone(), stop.clone());
        let watcher = std::thread::spawn(move || {
            while !s2.load(Ordering::Relaxed) {
                if let Err(e) = i2.default_expired() {
                    eprintln!("hub: {e:#}");
                }
                if let Err(e) = i2.disputes_tick() {
                    eprintln!("hub: {e:#}");
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
        });
        Ok(Hub { url: format!("http://127.0.0.1:{port}"), inner, server, stop, threads: vec![http, watcher] })
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
    /// The misbehaviour switches: refuse every cooperative withdrawal;
    /// dispute claims that are true.
    pub fn set_refuse_folds(&self, on: bool) {
        self.inner.refuse_folds.store(on, Ordering::Relaxed);
    }
    /// For tests: forge a hash in each path the hub posts (Alice should
    /// challenge that hop, and the hub fail to reveal it).
    pub fn set_forge_paths(&self, on: bool) {
        self.inner.forge_paths.store(on, Ordering::Relaxed);
    }
    /// For tests: close a dispute the user won without collecting the
    /// hub's bit outputs, as hubs did before they collected them.
    pub fn set_leave_bits(&self, on: bool) {
        self.inner.leave_bits.store(on, Ordering::Relaxed);
    }
    /// For tests: a fault in each opening from now on.
    pub fn set_opening_fault(&self, f: OpeningFault) {
        *self.inner.opening_fault.lock().unwrap() = f;
    }
    pub fn set_dispute_true_claims(&self, on: bool) {
        self.inner.dispute_true_claims.store(on, Ordering::Relaxed);
    }
    pub fn switches(&self) -> (bool, bool) {
        (self.inner.refuse_folds.load(Ordering::Relaxed), self.inner.dispute_true_claims.load(Ordering::Relaxed))
    }
    /// The hub's on-chain balance.
    pub fn balance(&self) -> Result<Amount> {
        self.inner.chain.balance()
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.server.unblock();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn route(inner: &Inner, method: &Method, url: &str, body: &str) -> Result<String> {
    Ok(match (method, url) {
        (Method::Get, "/info") => serde_json::to_string(&inner.info())?,
        (Method::Post, "/deposit") => serde_json::to_string(&inner.deposit(serde_json::from_str(body)?)?)?,
        (Method::Post, "/open") => serde_json::to_string(&inner.open(serde_json::from_str(body)?)?)?,
        (Method::Post, "/accept") => serde_json::to_string(&inner.accept(serde_json::from_str(body)?)?)?,
        (Method::Post, "/fold") => serde_json::to_string(&inner.fold(serde_json::from_str(body)?)?)?,
        _ => bail!("no {method} {url}"),
    })
}

impl Inner {
    /// Log what the hub did.
    pub(crate) fn note(&self, msg: String) {
        eprintln!("hub: {msg}");
        self.log.lock().unwrap().push(msg);
    }

    fn info(&self) -> Info {
        Info { network: self.cfg.network, deployment: self.seq.deployment, statement: self.cfg.statement.id().to_string(), depths: self.program.depths(), reserve_ppm: self.cfg.reserve_ppm, max_bits: self.cfg.max_bits, duration: self.cfg.duration }
    }

    /// A deposit address for a contract to come: its number, and the hub's
    /// key in the deposit's tree.
    fn deposit(&self, req: DepositRequest) -> Result<DepositOffer> {
        let cid = {
            let mut n = self.next_cid.lock().unwrap();
            *n += 1;
            *n - 1
        };
        std::fs::write(self.cfg.dir.join("deposits").join(format!("{cid}.json")), serde_json::to_vec(&(cid, req.alice))?)?;
        self.deposits.lock().unwrap().insert(cid, req.alice);
        Ok(DepositOffer { cid, hub: deposit_key(&self.cfg.seed, cid).x_only_public_key().0, timeout: deposit_timeout(self.cfg.network) })
    }

    /// The deposit tree of contract `cid`.
    fn deposit_tree(&self, cid: u32) -> Result<lngap_btc::taptree::TapTree> {
        let alice = *self.deposits.lock().unwrap().get(&cid).with_context(|| format!("no deposit asked for contract {cid}"))?;
        deposit_tree(&alice, &deposit_key(&self.cfg.seed, cid).x_only_public_key().0, deposit_timeout(self.cfg.network))
    }

    fn open(&self, req: OpenRequest) -> Result<OpenOffer> {
        let m = self.program.depths();
        ensure!(req.bits <= self.cfg.max_bits, "a cap above 2^{} sats", self.cfg.max_bits);
        ensure!(req.moves.len() as u32 == m.div_ceil(2), "{} move keys for the odd depths of {m}", req.moves.len());
        let program = &self.program;
        let cid = req.cid;
        ensure!(!self.open.lock().unwrap().contains_key(&cid), "contract {cid} is open already");
        // the deposit: to this contract's tree, confirmed, unspent
        let (dep_op, dep_out) = &req.deposit_coin;
        ensure!(dep_out.script_pubkey == self.deposit_tree(cid)?.script_pubkey(), "the deposit is not to contract {cid}'s address");
        let on_chain = self.chain.get_tx(&dep_op.txid).and_then(|t| t.output.get(dep_op.vout as usize).cloned());
        ensure!(on_chain.as_ref() == Some(dep_out), "no such deposit on chain");
        ensure!(self.chain.confirmations(&dep_op.txid)? >= 1, "the deposit is not confirmed");
        ensure!(self.chain.unspent(dep_op)?, "the deposit is spent");
        let deadline = broadcast_deadline(self.deposit_confirmed_at(dep_op)?, deposit_timeout(self.cfg.network));
        ensure!(self.chain.height()? < deadline, "the deposit's refund matures too soon to open on it (refund it and deposit again)");
        let keys = contract_keys(&self.cfg.seed, cid);
        let mut hub = keys.public();
        hub.payout_spk = self.chain.new_spk()?;
        let v_max = (1u64 << req.bits) - 1;
        let t_close = self.chain.height()? + self.cfg.duration;
        let pub_of = |ks: Vec<WotsSecret>| ks.iter().map(|k| k.public()).collect::<Vec<_>>();
        let hub_moves: Vec<_> = (1..=m).filter(|d| d % 2 == 0).map(|d| pub_of(move_secrets(&self.cfg.seed, cid, program, d))).collect();
        let path: Vec<_> = path_secrets(&self.cfg.seed, cid, program).into_iter().map(pub_of).collect();
        let mut record = Record {
            statement: self.cfg.statement.id().to_string(),
            network: self.cfg.network,
            deployment: self.seq.deployment.id(),
            // a reserve to measure the floors under (any amount above them:
            // they depend on the links' sizes, not on the amounts; the cap
            // isn't, for a small one); the real one below
            terms: terms(cid, &req, t_close, v_max.max(100_000_000))?,
            pubs: [req.alice.clone(), hub.clone()],
            moves: all_moves(&req.moves, &hub_moves),
            inputs: req.inputs.clone(),
            tail: tail_keys(program, &path, &req.hops)?,
            l2_address: req.l2_address,
            funding: OutPoint::null(),
            hub_sigs: HashMap::new(),
            alice_sigs: HashMap::new(),
            windows: Some(self.cfg.windows.unwrap_or(lichen_proto::windows(self.cfg.network))),
        };
        // the hub's reserve: its share of the cap, and at least what the
        // floors of a dispute it loses take from it
        let floors = match self.floors.get() {
            Some(f) => *f,
            None => {
                // the deepest output any dispute reaches, against the
                // contract's value (the same for every contract of the
                // statement: the links' sizes don't depend on the amounts)
                let c = record.contract(&self.cfg.statement, &self.program)?;
                let set = c.presign(OutPoint::null())?;
                let f = set.iter().map(|p| (c.value() - p.prevout.value).to_sat()).max().unwrap_or(0);
                self.note(format!("a dispute's floors take up to {f} sats from the reserve of the side that loses"));
                *self.floors.get_or_init(|| f)
            }
        };
        let reserve_hub = (v_max * self.cfg.reserve_ppm / 1_000_000).max(floors);
        let t = terms(cid, &req, t_close, reserve_hub)?;
        record.terms = t;
        let (_, hub_in) = contributions(&t);
        let fee_budget = lichen_proto::fee_budget_of(dep_out.value, &t)?;
        ensure!(fee_budget >= Amount::from_sat(330), "the deposit leaves no fee budget");
        let fee_out = TxOut { value: fee_budget, script_pubkey: req.fee_spk.clone() };
        let margin = Amount::from_sat(10_000);
        let hub_coins = self.chain.select(hub_in + FEE_SHARE + margin)?;
        let hub_spent: Amount = hub_coins.iter().map(|c| c.1.value).sum();
        let hub_change = TxOut { value: hub_spent - hub_in - FEE_SHARE, script_pubkey: self.chain.new_spk()? };
        let c = record.contract(&self.cfg.statement, &self.program)?;
        let ins: Vec<(OutPoint, Sequence)> = std::iter::once(&req.deposit_coin).chain(&hub_coins).map(|c| (c.0, Sequence::ENABLE_RBF_NO_LOCKTIME)).collect();
        let outs = vec![TxOut { value: c.value(), script_pubkey: c.tree()?.script_pubkey() }, fee_out, hub_change.clone()];
        let funding = lngap_btc::tx::build_tx(&ins, outs, bitcoin::absolute::LockTime::ZERO);
        check_funding(&funding, &c, &hub_coins, &hub_change, hub_in)?;
        record.funding = OutPoint { txid: funding.compute_txid(), vout: 0 };
        let set = c.presign(record.funding)?;
        record.hub_sigs = sign_all(&set, &keys.payment)?;
        // D, minted now to a key Alice can spend once this funding is out
        let t = mint_adaptor(&self.cfg.seed, cid, &req.l2_address, &record.funding.txid);
        let mint_point = PublicKey::from_secret_key(SECP256K1, &t);
        let fault = *self.opening_fault.lock().unwrap();
        let d = u64::from(record.terms.deposit) - u64::from(fault == OpeningFault::ShortMint);
        let owner = mint_owner(&req.l2_address, &mint_point)?;
        let mint_index = self.seq.submit(&Tx::Mint(Mint::new(&self.cfg.l2_key, vec![note(owner, d, 0)])))?[0];
        self.note(format!("contract {cid}: offered; minted {d} sats to the user, locked to the funding"));
        let offer = OpenOffer { cid, t_close, reserve_hub, hub, moves: hub_moves, path, funding, hub_coins, hub_sigs: record.hub_sigs.clone(), mint_point, mint_index, windows: record.windows };
        self.pending.lock().unwrap().insert(cid, Pending { req, offer: offer.clone(), record, t });
        Ok(offer)
    }

    fn accept(&self, a: Accept) -> Result<Opened> {
        let p = self.pending.lock().unwrap().remove(&a.cid).context("no such offer")?;
        let mut record = p.record;
        record.alice_sigs = a.alice_sigs;
        let c = record.contract(&self.cfg.statement, &self.program)?;
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
        let txid = self.chain.broadcast(&signed).context("broadcasting the funding")?;
        self.note(format!("contract {}: opened (deposit {} sats, cap {} sats); funding broadcast", a.cid, record.terms.deposit, record.terms.v_max().to_sat()));
        let o = Open { record, closed: None, collected: false };
        self.save(&o)?;
        self.open.lock().unwrap().insert(a.cid, o);
        self.deposits.lock().unwrap().remove(&a.cid);
        let _ = std::fs::remove_file(self.cfg.dir.join("deposits").join(format!("{}.json", a.cid)));
        ensure!(*self.opening_fault.lock().unwrap() != OpeningFault::DropAnswer, "funding {txid} broadcast, the answer dropped (a test's fault)");
        Ok(Opened { txid, t: p.t })
    }

    fn save(&self, o: &Open) -> Result<()> {
        std::fs::write(self.cfg.dir.join("contracts").join(format!("{}.json", o.record.cid())), serde_json::to_vec_pretty(o)?)?;
        Ok(())
    }

    /// The cooperative withdrawal: Alice's return must be sealed on the
    /// L2, owned by the hub, carry this contract's memo and the amount she
    /// asks for, within the cap; then the hub signs her fold and
    /// broadcasts it.
    fn fold(&self, f: FoldRequest) -> Result<Folded> {
        ensure!(!self.refuse_folds.load(Ordering::Relaxed), "this hub refuses cooperative withdrawals");
        let o = self.open.lock().unwrap().get(&f.cid).cloned().context("no such contract")?;
        ensure!(o.closed.is_none(), "contract {} is closed", f.cid);
        let input = self.seq.state()?.withdraw_input(f.index, &self.seq.deployment)?;
        ensure!(input.note.memo == f.cid && input.note.value == f.b, "note {} is not a return of {} with memo {}", f.index, f.b, f.cid);
        let c = o.record.contract(&self.cfg.statement, &self.program)?;
        let p = c.fold(o.record.funding, Amount::from_sat(f.b), FOLD_FEE)?;
        p.verify(&o.record.pubs[0].payment, &f.alice_sig).context("Alice's signature on the fold")?;
        let mine = p.sign(&contract_keys(&self.cfg.seed, f.cid).payment)?;
        let txid = self.chain.broadcast(&p.finish(vec![], &mine, &f.alice_sig)).context("broadcasting the fold")?;
        self.close(f.cid, txid)?;
        self.note(format!("contract {}: folded: {} sats back to the user, with the user's reserve", f.cid, f.b));
        Ok(Folded { txid })
    }

    /// Close a contract: nothing of it is left to collect (a dispute the
    /// user won closes only once the hub's bit outputs are swept).
    pub(crate) fn close(&self, cid: u32, txid: bitcoin::Txid) -> Result<()> {
        let mut open = self.open.lock().unwrap();
        let o = open.get_mut(&cid).context("no such contract")?;
        o.closed = Some(txid);
        o.collected = true;
        let o = o.clone();
        drop(open);
        self.save(&o)
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
        let height = self.chain.height()?;
        let due: Vec<Open> = self.open.lock().unwrap().values().filter(|o| o.closed.is_none() && height >= o.record.terms.t_close).cloned().collect();
        for o in due {
            let c = o.record.contract(&self.cfg.statement, &self.program)?;
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

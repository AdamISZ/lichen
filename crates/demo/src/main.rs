//! `lichen-demo`: Alice and Bob, each with a contract on a hub, on a
//! private regtest node, shown in a web page (four panes: Alice, Bob, the
//! ledger, the hub). Each deposit is shielded once minted; they pay each
//! other in shielded notes and withdraw; with the hub refusing, a
//! withdrawal is enforced on Bitcoin, the dispute playing out move by
//! move.
//!
//! Everything runs here: bitcoind (regtest, its own data directory), the
//! sequencer, the hub, the two wallets, a block every second. Every
//! shielded spend is proved for real (RISC Zero, r0/spend-prover.sh in the
//! prover image) and checked by the sequencer; the chain prover proves
//! each sealed height as it goes (r0/chain-prover.sh; off with
//! --no-chain-prover). The ledger pane shows what anyone sees: commitments,
//! nullifiers and proofs, not amounts or parties. Disputes run on the mock
//! statement, set so that every claim is true (the contract's memo check
//! still applies): a stand-in for the proof of the return, which the real
//! statement checks (minutes on x86, too slow to watch).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bitcoin::Amount;
use bitcoincore_rpc::{Auth, RpcApi};
use clap::Parser;
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_ledger::{regtest_sequencer, Hash, HUB_KEY};
use lichen_proto::Statement;
use lichen_l2::{Client, Event};
use lichen_sequencer::Sequencer;
use lichen_wallet::shielded::{SAddress, SpendProver};
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;
use serde::Deserialize;
use serde_json::{json, Value};
use tiny_http::{Header, Method, Response, Server};

const FIRST_CID: u32 = 1000;
/// Millions of sats, so that fees at a realistic feerate stay small beside
/// them: a cap of 2^24 sats (16.8M), and a reserve above the mock
/// dispute's floors (125k sats).
const ASK: Ask = Ask { deposit: 2_000_000, bits: 24, reserve: 250_000 };

#[derive(Parser)]
#[command(about = "lichen's web demo (local, regtest)")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:18330")]
    listen: String,
    /// Where the demo keeps its state (removed at start).
    #[arg(long, default_value = "/tmp/lichen-demo")]
    dir: PathBuf,
    /// Don't run the chain prover (each sealed height's validity proof,
    /// a minute or two each on a laptop, alongside the payments' proofs).
    #[arg(long)]
    no_chain_prover: bool,
}

/// lichen's r0/ (the provers' scripts), from this source tree.
fn r0() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../r0")
}

struct User {
    name: &'static str,
    wallet: Mutex<Wallet>,
    chain: Chain,
    dir: PathBuf,
    address: Hash,
    saddr: SAddress,
    cid: Mutex<u32>,
    activity: Mutex<String>,
    /// Proving, opening or withdrawing: one thing at a time.
    busy: AtomicBool,
    /// Our shielded notes as last seen (value, leaf), kept for while the
    /// wallet is busy.
    notes: Mutex<Vec<(u64, u32)>>,
}

impl User {
    fn say(&self, m: String) {
        *self.activity.lock().unwrap() = m;
    }
}

/// Run `f` for `u` in the background, if `u` isn't busy.
fn task(u: &Arc<User>, f: impl FnOnce(&Arc<User>) + std::marker::Send + 'static) -> Result<()> {
    if u.busy.swap(true, Ordering::SeqCst) {
        bail!("{} is busy", u.name);
    }
    let u = u.clone();
    std::thread::spawn(move || {
        f(&u);
        u.busy.store(false, Ordering::SeqCst);
    });
    Ok(())
}

/// Shield all of `u`'s transparent notes (a new deposit's), proving it.
fn shield_all(u: &User) {
    let mut w = u.wallet.lock().unwrap();
    let t = match w.balances() {
        Ok((t, _)) => t,
        Err(e) => return u.say(format!("the balance: {e:#}")),
    };
    if t == 0 {
        return;
    }
    u.say(format!("shielding the deposit, {t} sats: proving the spend (RISC Zero) ..."));
    let start = Instant::now();
    match w.shield(t) {
        Ok(_) => u.say(format!("shielded {t} sats: proved in {:.1} s, checked by the sequencer", start.elapsed().as_secs_f64())),
        Err(e) => u.say(format!("shielding failed: {e:#}")),
    }
}

/// The last height proved valid from genesis (each `<h>.chain` in turn).
fn proved_height(blocks: &Path) -> u64 {
    let mut h = 0;
    while blocks.join(format!("{}.chain", h + 1)).exists() {
        h += 1;
    }
    h
}

struct Demo {
    seq: Client,
    /// The sequencer's record of each sealed block, for the chain prover.
    blocks: PathBuf,
    chain_prover: bool,
    hub: Hub,
    users: Vec<Arc<User>>,
    statement: Statement,
    /// What happened on Bitcoin, in words.
    chain_log: Mutex<Vec<String>>,
    rt: Regtest,
}

impl Demo {
    fn log(&self, msg: String) {
        println!("{msg}");
        self.chain_log.lock().unwrap().push(msg);
    }
    fn user(&self, name: &str) -> Result<Arc<User>> {
        self.users.iter().find(|u| u.name.eq_ignore_ascii_case(name)).cloned().with_context(|| format!("no user {name}"))
    }
    fn name_of(&self, owner: &Hash) -> String {
        if *owner == HUB_KEY {
            return "the hub".into();
        }
        self.users.iter().find(|u| u.address == *owner).map(|u| u.name.to_string()).or_else(|| self.locked_for(owner).map(|n| format!("{n}, locked to the contract's funding"))).unwrap_or_else(|| hex::encode(&owner[..4]))
    }
    /// Whose deposit `owner` is the locked mint of (the key only she can
    /// spend, once her contract's funding is out). A wallet busy opening
    /// or disputing isn't waited for.
    fn locked_for(&self, owner: &Hash) -> Option<&'static str> {
        self.users.iter().find_map(|u| {
            let w = u.wallet.try_lock().ok()?;
            let mut locked = w.contracts.iter().filter_map(|h| h.mint.as_ref()).chain(w.deposits.iter().filter_map(|d| d.offered.as_ref().map(|o| &o.1)));
            locked.any(|l| lichen_proto::mint_owner(&u.address, &l.point).ok() == Some(*owner)).then_some(u.name)
        })
    }
}

fn open_contract(d: &Demo, u: &User) -> Result<u32> {
    let mut w = u.wallet.lock().unwrap();
    let h = w.open_contract(&d.hub.url, &u.chain, &d.statement, &u.dir, ASK, u.chain.new_spk()?, &|addr: &bitcoin::Address, v| u.chain.pay(&addr.script_pubkey(), v).map(|_| ()))?;
    let cid = h.record.cid();
    *u.cid.lock().unwrap() = cid;
    d.log(format!("{}: contract {cid} opened with the hub: deposit {} sats, cap {} sats, reserves {} + {} sats", u.name, ASK.deposit, h.record.terms.v_max().to_sat(), h.record.terms.reserve_alice.to_sat(), h.record.terms.reserve_hub.to_sat()));
    Ok(cid)
}

fn start(args: &Args) -> Result<Arc<Demo>> {
    let image = std::process::Command::new("docker").args(["image", "inspect", "lichen-r0"]).output();
    if !image.is_ok_and(|o| o.status.success()) {
        bail!("no prover image: every shielded spend is proved for real; build it first (docker build -f r0/Dockerfile -t lichen-r0 ., in lichen's root)");
    }
    let _ = std::fs::remove_dir_all(&args.dir);
    std::fs::create_dir_all(&args.dir)?;
    println!("starting bitcoind (regtest), the sequencer and the hub ...");
    let rt = Regtest::start()?;
    // a ledger file, so that the sequencer records each block for the
    // chain prover; no native proofs
    let ledger = args.dir.join("ledger.json");
    let blocks = lichen_sequencer::blocks_dir(&ledger);
    let seq = Sequencer::start("127.0.0.1:0", Some(ledger), regtest_sequencer(), HUB_KEY)?;
    let chain = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w);
    // several coins, so the hub can fund more than one contract a block
    let hub_chain = chain("hub")?;
    for _ in 0..8 {
        rt.fund(&hub_chain.new_spk()?, Amount::from_sat(50_000_000))?;
    }
    // every claim true: a stand-in for proving the return
    let any = lngap_sessions::statement::ANY;
    let statement = Statement::Mock { session: any, returns: vec![(any, any)] };
    let hub = Hub::start(Config {
        network: lichen_proto::Net::Regtest,
        listen: "127.0.0.1:0".into(),
        sequencer: seq.url.clone(),
        rpc_url: rt.rpc_url().to_string(),
        cookie: rt.cookie().clone(),
        wallet: "hub".into(),
        statement: statement.clone(),
        dir: args.dir.join("hub"),
        seed: "lichen-demo-hub".into(),
        l2_key: lichen_ledger::regtest_hub(),
        reserve_ppm: 20_000,
        max_bits: 24,
        duration: 5_000,
        refuse_folds: false,
        dispute_true_claims: false,
        first_cid: FIRST_CID,
        windows: None,
    })?;
    let mut users = vec![];
    for name in ["Alice", "Bob"] {
        let ch = chain(&name.to_lowercase())?;
        rt.fund(&ch.new_spk()?, Amount::from_sat(20_000_000))?;
        let mut w = Wallet::create(&args.dir.join(format!("{}.json", name.to_lowercase())), &seq.url)?;
        w.spend_prover = SpendProver::Command(r0().join("spend-prover.sh"));
        let (address, saddr) = (w.address(), w.shielded_address());
        users.push(Arc::new(User {
            name,
            wallet: Mutex::new(w),
            chain: ch,
            dir: args.dir.join(name.to_lowercase()),
            address,
            saddr,
            cid: Mutex::new(0),
            activity: Mutex::new(String::new()),
            busy: AtomicBool::new(false),
            notes: Mutex::new(vec![]),
        }));
    }
    let d = Arc::new(Demo { seq: Client::new(&seq.url)?, blocks: blocks.clone(), chain_prover: !args.no_chain_prover, hub, users, statement, chain_log: Mutex::new(vec![]), rt });
    if d.chain_prover {
        std::fs::create_dir_all(&blocks)?;
        let log = std::fs::File::create(args.dir.join("chain-prover.log"))?;
        std::process::Command::new(r0().join("chain-prover.sh")).arg(&blocks).stdout(log.try_clone()?).stderr(log).spawn().context("starting the chain prover")?;
    }
    // the sequencer seals, and blocks come, in the background
    std::mem::forget(seq); // runs for the demo's life
    let s = d.seq.clone();
    std::thread::spawn(move || loop {
        let _ = s.seal();
        std::thread::sleep(Duration::from_secs(2));
    });
    let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", d.rt.rpc_url()), Auth::CookieFile(d.rt.cookie().clone()))?;
    let addr = rpc.get_new_address(None, None)?.assume_checked();
    std::thread::spawn(move || loop {
        let _ = rpc.generate_to_address(1, &addr);
        std::thread::sleep(Duration::from_secs(1));
    });
    for u in &d.users {
        open_contract(&d, u)?;
        let start = Instant::now();
        while u.wallet.lock().unwrap().balance()? < ASK.deposit {
            if start.elapsed() > Duration::from_secs(60) {
                bail!("{}'s deposit was never minted", u.name);
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    for u in &d.users {
        task(u, |u| shield_all(u))?;
    }
    Ok(d)
}

/// Everything the page shows.
fn state(d: &Demo) -> Result<Value> {
    let st = d.seq.state()?;
    let l2 = |a: &Hash| -> u64 { st.transparent().filter(|(_, n)| n.owner == *a && !st.is_spent(n)).map(|(_, n)| n.value).sum() };
    let contracts = d.hub.contracts();
    let disputes = d.hub.disputes();
    let contract_view = |cid: u32| -> Value {
        match contracts.iter().find(|c| c.0.cid() == cid) {
            Some((r, closed)) => json!({
                "cid": cid,
                "deposit": r.terms.deposit,
                "cap": r.terms.v_max().to_sat(),
                "reserve": r.terms.reserve_alice.to_sat(),
                "reserve_hub": r.terms.reserve_hub.to_sat(),
                "t_close": r.terms.t_close,
                "funding": r.funding.txid.to_string(),
                "state": if closed.is_some() { "closed" } else { "open" },
                "dispute": disputes.get(&cid),
            }),
            None => Value::Null,
        }
    };
    let users: Vec<Value> = d
        .users
        .iter()
        .map(|u| {
            // our notes need our keys: the wallet's, unless it's busy
            if let Ok(w) = u.wallet.try_lock() {
                *u.notes.lock().unwrap() = w.shielded_notes(&st).iter().map(|n| (n.value, n.index)).collect();
            }
            let notes = u.notes.lock().unwrap().clone();
            json!({
                "name": u.name,
                "address": u.saddr.to_string(),
                "shielded": notes.iter().map(|n| n.0).sum::<u64>(),
                "notes": notes.iter().map(|n| json!({ "value": n.0, "leaf": n.1 })).collect::<Vec<_>>(),
                "transparent": l2(&u.address),
                "onchain": u.chain.balance().map(|b| b.to_sat()).unwrap_or(0),
                "contract": contract_view(*u.cid.lock().unwrap()),
                "activity": u.activity.lock().unwrap().clone(),
                "busy": u.busy.load(Ordering::SeqCst),
            })
        })
        .collect();
    let proved = if d.chain_prover { proved_height(&d.blocks) } else { 0 };
    let short = |h: &Hash| hex::encode(&h[..4]);
    let ledger: Vec<Value> = d
        .seq
        .events(0)?
        .into_iter()
        .map(|(n, e)| {
            let mut detail = String::new();
            let mut height = Value::Null;
            let (kind, text) = match e {
                Event::Mint { to } => ("mint", to.iter().map(|(o, v)| format!("the hub issued {v} sats to {}", d.name_of(o))).collect::<Vec<_>>().join("; ")),
                Event::Transfer { from, to } if d.locked_for(&from[0]).is_some() => {
                    let who = d.locked_for(&from[0]).expect("checked");
                    ("mint", format!("{who} claimed {} sats: the funding's t unlocked them", to.iter().map(|t| t.1).sum::<u64>()))
                }
                Event::Transfer { from, to } => {
                    let who = d.name_of(&from[0]);
                    let parts: Vec<String> = to
                        .iter()
                        .filter(|(o, _, _)| *o != from[0])
                        .map(|(o, v, memo)| if *o == HUB_KEY { format!("{who} returned {v} sats to the hub (memo {memo}): a withdrawal") } else { format!("{who} paid {v} sats to {}", d.name_of(o)) })
                        .collect();
                    (if to.iter().any(|t| t.0 == HUB_KEY) { "return" } else { "transfer" }, parts.join("; "))
                }
                Event::Shielded { from, spent, made, to, t_total, nfs, cms, proof } => {
                    // what anyone sees: the transparent ends in full, the
                    // shielded middle as hashes
                    let mut parts = vec![];
                    if let Some(o) = from.first() {
                        let back: u64 = to.iter().filter(|t| t.0 == *o).map(|t| t.1).sum();
                        parts.push(format!("{} shielded {} sats", d.name_of(o), t_total - back));
                    } else {
                        parts.push(format!("{spent} shielded note{} spent, {made} made: amounts and owners hidden", if spent == 1 { "" } else { "s" }));
                    }
                    parts.extend(to.iter().filter(|t| t.0 == HUB_KEY).map(|(_, v, memo)| format!("{v} sats returned to the hub (memo {memo}): a withdrawal")));
                    let list = |hs: &[Hash]| hs.iter().map(short).collect::<Vec<_>>().join(", ");
                    let spent = if nfs.is_empty() { String::new() } else { format!("nullifiers [{}] → ", list(&nfs)) };
                    detail = format!("{spent}commitments [{}] · proof {} KB", list(&cms), proof.div_ceil(1024));
                    (if to.iter().any(|t| t.0 == HUB_KEY) { "return" } else if from.is_empty() { "shielded" } else { "shield" }, parts.join("; "))
                }
                Event::Sealed { height: h, notes, root } => {
                    height = json!(h);
                    ("sealed", format!("height {h} sealed and signed: {notes} notes, root {}…", &hex::encode(root)[..12]))
                }
            };
            json!({ "n": n, "kind": kind, "text": text, "detail": detail, "height": height })
        })
        .collect();
    let open: Vec<_> = contracts.iter().filter(|c| c.1.is_none()).collect();
    let headroom: u64 = open.iter().map(|c| (c.0.terms.v_max() - Amount::from_sat(u64::from(c.0.terms.deposit)) + c.0.terms.reserve_hub).to_sat()).sum();
    let (refuse, dispute_all) = d.hub.switches();
    let hub_contracts: Vec<Value> = contracts
        .iter()
        .map(|(r, closed)| {
            let who = d.name_of(&r.l2_address);
            json!({ "cid": r.cid(), "user": who, "deposit": r.terms.deposit, "cap": r.terms.v_max().to_sat(), "state": if closed.is_some() { "closed" } else { "open" }, "dispute": disputes.get(&r.cid()) })
        })
        .collect();
    Ok(json!({
        "height": d.rt.height()?,
        "users": users,
        "ledger": ledger,
        "validity": { "running": d.chain_prover, "proved": proved, "sealed": st.sealed.last().map_or(0, |s| s.height) },
        "chain_log": d.chain_log.lock().unwrap().clone(),
        "hub": {
            "onchain": d.hub.balance().map(|b| b.to_sat()).unwrap_or(0),
            "returned": l2(&HUB_KEY),
            "headroom": headroom,
            "refuse_folds": refuse,
            "dispute_true_claims": dispute_all,
            "contracts": hub_contracts,
            "log": d.hub.log(),
        },
    }))
}

#[derive(Deserialize)]
struct Send {
    from: String,
    to: String,
    amount: u64,
}

#[derive(Deserialize)]
struct Withdraw {
    who: String,
    amount: u64,
}

#[derive(Deserialize)]
struct Switches {
    refuse_folds: Option<bool>,
    dispute_true_claims: Option<bool>,
}

#[derive(Deserialize)]
struct Who {
    who: String,
}

/// A shielded payment, proved (in the background; the page follows it).
fn send(d: &Demo, s: Send) -> Result<Value> {
    let (from, to) = (d.user(&s.from)?, d.user(&s.to)?);
    let amount = s.amount;
    task(&from, move |u| {
        u.say(format!("paying {} {amount} sats, shielded: proving the spend (RISC Zero) ...", to.name));
        let start = Instant::now();
        let r = u.wallet.lock().unwrap().send_shielded(&to.saddr, amount);
        match r {
            Ok(_) => u.say(format!("paid {} {amount} sats, shielded: proved in {:.1} s, checked by the sequencer", to.name, start.elapsed().as_secs_f64())),
            Err(e) => u.say(format!("the payment failed: {e:#}")),
        }
    })?;
    Ok(json!({ "ok": "started" }))
}

/// A withdrawal: the fold, or, if the hub refuses, the dispute (in the
/// background; the page follows it).
fn withdraw(d: &Arc<Demo>, r: Withdraw) -> Result<Value> {
    let u = d.user(&r.who)?;
    let cid = *u.cid.lock().unwrap();
    let d2 = d.clone();
    task(&u, move |u2| {
        let set = |m: String| u2.say(m);
        let mut w = u2.wallet.lock().unwrap();
        set(format!("returning {} sats to the hub from shielded notes (memo {cid}): proving the spend (RISC Zero), then the fold ...", r.amount));
        match w.withdraw(&d2.hub.url, &d2.statement, &u2.dir, cid, r.amount) {
            Ok(txid) => {
                set(format!("withdrawn: the hub folded the contract; {} sats and the reserve are on chain", r.amount));
                d2.log(format!("{}: contract {cid} folded cooperatively ({txid})", u2.name));
            }
            Err(e) => {
                set(format!("the hub refused ({e:#}); enforcing the withdrawal on Bitcoin ..."));
                d2.log(format!("{}: the hub refused to fold; escalating to Bitcoin", u2.name));
                let (d3, u3) = (d2.clone(), u2.clone());
                w.progress = Some(Arc::new(move |m: String| {
                    *u3.activity.lock().unwrap() = m.clone();
                    d3.log(format!("{}: {m}", u3.name));
                }));
                let input = d2.statement.mock_input(r.amount as u32, cid).expect("the mock's input");
                match w.dispute(&u2.chain, &d2.statement, &u2.dir, cid, r.amount as u32, &input) {
                    Ok((o, _)) => set(format!("the dispute ended: {o:?}")),
                    Err(e) => set(format!("the dispute failed: {e:#}")),
                }
                w.progress = None;
            }
        }
    })?;
    Ok(json!({ "ok": "started" }))
}

/// A new contract once the last is closed, its deposit then shielded.
fn reopen(d: &Arc<Demo>, who: Who) -> Result<Value> {
    let u = d.user(&who.who)?;
    if d.hub.contracts().iter().any(|c| c.0.cid() == *u.cid.lock().unwrap() && c.1.is_none()) {
        bail!("{}'s contract is still open", u.name);
    }
    let d2 = d.clone();
    task(&u, move |u| {
        u.say("opening a new contract ...".into());
        if let Err(e) = open_contract(&d2, u) {
            return u.say(format!("opening failed: {e:#}"));
        }
        let start = Instant::now();
        while u.wallet.lock().unwrap().balances().map_or(0, |b| b.0) < ASK.deposit {
            if start.elapsed() > Duration::from_secs(60) {
                return u.say("the deposit was never minted".into());
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        shield_all(u);
    })?;
    Ok(json!({ "ok": "started" }))
}

fn route(d: &Arc<Demo>, method: &Method, url: &str, body: &str) -> Result<(String, &'static str)> {
    let j = |v: Value| Ok((v.to_string(), "application/json"));
    match (method, url) {
        (Method::Get, "/") => Ok((include_str!("index.html").to_string(), "text/html; charset=utf-8")),
        (Method::Get, "/state") => j(state(d)?),
        (Method::Post, "/send") => j(send(d, serde_json::from_str(body)?)?),
        (Method::Post, "/withdraw") => j(withdraw(d, serde_json::from_str(body)?)?),
        (Method::Post, "/open") => j(reopen(d, serde_json::from_str(body)?)?),
        (Method::Post, "/switch") => {
            let s: Switches = serde_json::from_str(body)?;
            if let Some(v) = s.refuse_folds {
                d.hub.set_refuse_folds(v);
            }
            if let Some(v) = s.dispute_true_claims {
                d.hub.set_dispute_true_claims(v);
            }
            j(json!({ "ok": "set" }))
        }
        _ => bail!("no {method} {url}"),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let d = start(&args)?;
    let server = Server::http(&args.listen).map_err(|e| anyhow::anyhow!("listen on {}: {e}", args.listen))?;
    println!("lichen demo at http://{}", args.listen);
    for mut req in server.incoming_requests() {
        let mut body = String::new();
        let _ = std::io::Read::read_to_string(req.as_reader(), &mut body);
        let (code, text, ct) = match route(&d, req.method(), req.url(), &body) {
            Ok((t, ct)) => (200, t, ct),
            Err(e) => (400, json!({ "error": format!("{e:#}") }).to_string(), "application/json"),
        };
        let h = Header::from_bytes("Content-Type", ct).unwrap();
        let _ = req.respond(Response::from_string(text).with_status_code(code).with_header(h));
    }
    Ok(())
}

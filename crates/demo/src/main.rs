//! `lichen-demo`: Alice and Bob, each with a contract on a hub, on a
//! private regtest node, shown in a web page (four panes: Alice, Bob, the
//! ledger, the hub). They pay each other on the L2 and withdraw; with the
//! hub refusing, Alice's withdrawal is enforced on Bitcoin, the dispute
//! playing out move by move.
//!
//! Everything runs here: bitcoind (regtest, its own data directory), the
//! sequencer, the hub, the two wallets, a block every second. Disputes run
//! on the mock statement, set so that every claim is true (the contract's
//! memo check still applies): a stand-in for a proof of the return, which
//! the real statement checks.

use std::path::PathBuf;
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
use lichen_sequencer::{Client, Event, Sequencer};
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;
use serde::Deserialize;
use serde_json::{json, Value};
use tiny_http::{Header, Method, Response, Server};

const FIRST_CID: u32 = 1000;
const ASK: Ask = Ask { deposit: 400_000, bits: 21, reserve: 20_000 };

#[derive(Parser)]
#[command(about = "lichen's web demo (local, regtest)")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:18330")]
    listen: String,
    /// Where the demo keeps its state (removed at start).
    #[arg(long, default_value = "/tmp/lichen-demo")]
    dir: PathBuf,
}

struct User {
    name: &'static str,
    wallet: Mutex<Wallet>,
    chain: Chain,
    dir: PathBuf,
    address: Hash,
    cid: Mutex<u32>,
    activity: Mutex<String>,
}

struct Demo {
    seq: Client,
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
        self.users.iter().find(|u| u.address == *owner).map(|u| u.name.to_string()).unwrap_or_else(|| hex::encode(&owner[..4]))
    }
}

fn open_contract(d: &Demo, u: &User) -> Result<u32> {
    let mut w = u.wallet.lock().unwrap();
    let h = w.open_contract(&d.hub.url, &u.chain, &d.statement, &u.dir, ASK)?;
    let cid = h.record.cid();
    *u.cid.lock().unwrap() = cid;
    d.log(format!("{}: contract {cid} opened with the hub: deposit {} sats, cap {} sats, reserves {} + {} sats", u.name, ASK.deposit, h.record.terms.v_max().to_sat(), h.record.terms.reserve_alice.to_sat(), h.record.terms.reserve_hub.to_sat()));
    Ok(cid)
}

fn start(args: &Args) -> Result<Arc<Demo>> {
    let _ = std::fs::remove_dir_all(&args.dir);
    std::fs::create_dir_all(&args.dir)?;
    println!("starting bitcoind (regtest), the sequencer and the hub ...");
    let rt = Regtest::start()?;
    let seq = Sequencer::start("127.0.0.1:0", None, regtest_sequencer(), HUB_KEY)?;
    let chain = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w);
    // several coins, so the hub can fund more than one contract a block
    let hub_chain = chain("hub")?;
    for _ in 0..4 {
        rt.fund(&hub_chain.new_spk()?, Amount::from_sat(25_000_000))?;
    }
    // every claim true: a stand-in for proving the return
    let any = lngap_sessions::statement::ANY;
    let statement = Statement::Mock { session: any, returns: vec![(any, any)] };
    let hub = Hub::start(Config {
        listen: "127.0.0.1:0".into(),
        sequencer: seq.url.clone(),
        rpc_url: rt.rpc_url().to_string(),
        cookie: rt.cookie().clone(),
        wallet: "hub".into(),
        statement: statement.clone(),
        dir: args.dir.join("hub"),
        seed: "lichen-demo-hub".into(),
        reserve_ppm: 20_000,
        max_bits: 24,
        duration: 5_000,
        refuse_folds: false,
        dispute_true_claims: false,
        first_cid: FIRST_CID,
    })?;
    let mut users = vec![];
    for name in ["Alice", "Bob"] {
        let ch = chain(&name.to_lowercase())?;
        rt.fund(&ch.new_spk()?, Amount::from_sat(10_000_000))?;
        let w = Wallet::create(&args.dir.join(format!("{}.json", name.to_lowercase())), &seq.url)?;
        let address = w.address();
        users.push(Arc::new(User { name, wallet: Mutex::new(w), chain: ch, dir: args.dir.join(name.to_lowercase()), address, cid: Mutex::new(0), activity: Mutex::new(String::new()) }));
    }
    let d = Arc::new(Demo { seq: Client::new(&seq.url), hub, users, statement, chain_log: Mutex::new(vec![]), rt });
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
    Ok(d)
}

/// Everything the page shows.
fn state(d: &Demo) -> Result<Value> {
    let st = d.seq.state()?;
    let l2 = |a: &Hash| -> u64 { st.notes.iter().filter(|n| n.owner == *a && !st.is_spent(n)).map(|n| n.value).sum() };
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
            json!({
                "name": u.name,
                "address": hex::encode(u.address),
                "l2": l2(&u.address),
                "onchain": u.chain.balance().map(|b| b.to_sat()).unwrap_or(0),
                "contract": contract_view(*u.cid.lock().unwrap()),
                "activity": u.activity.lock().unwrap().clone(),
            })
        })
        .collect();
    let ledger: Vec<Value> = d
        .seq
        .events(0)?
        .into_iter()
        .map(|(n, e)| {
            let (kind, text) = match e {
                Event::Mint { to } => ("mint", to.iter().map(|(o, v)| format!("the hub issued {v} sats to {}", d.name_of(o))).collect::<Vec<_>>().join("; ")),
                Event::Transfer { from, to } => {
                    let who = d.name_of(&from[0]);
                    let parts: Vec<String> = to
                        .iter()
                        .filter(|(o, _, _)| *o != from[0])
                        .map(|(o, v, memo)| if *o == HUB_KEY { format!("{who} returned {v} sats to the hub (memo {memo}): a withdrawal") } else { format!("{who} paid {v} sats to {}", d.name_of(o)) })
                        .collect();
                    (if to.iter().any(|t| t.0 == HUB_KEY) { "return" } else { "transfer" }, parts.join("; "))
                }
                Event::Sealed { height, notes, root } => ("sealed", format!("height {height} sealed and signed: {notes} notes, root {}…", &hex::encode(root)[..12])),
            };
            json!({ "n": n, "kind": kind, "text": text })
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

fn send(d: &Demo, s: Send) -> Result<Value> {
    let (from, to) = (d.user(&s.from)?, d.user(&s.to)?);
    let mut w = from.wallet.try_lock().map_err(|_| anyhow::anyhow!("{} is busy", from.name))?;
    w.send(to.address, s.amount, 0)?;
    Ok(json!({ "ok": format!("{} paid {} sats to {}", from.name, s.amount, to.name) }))
}

/// A withdrawal: the fold, or, if the hub refuses, the dispute (in the
/// background; the page follows it).
fn withdraw(d: &Arc<Demo>, r: Withdraw) -> Result<Value> {
    let u = d.user(&r.who)?;
    let cid = *u.cid.lock().unwrap();
    if u.wallet.try_lock().is_err() {
        bail!("{} is busy", u.name);
    }
    let (d2, u2) = (d.clone(), u.clone());
    std::thread::spawn(move || {
        let set = |m: String| *u2.activity.lock().unwrap() = m;
        let mut w = u2.wallet.lock().unwrap();
        set(format!("returning {} sats to the hub on the L2 (memo {cid}) ...", r.amount));
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
    });
    Ok(json!({ "ok": "started" }))
}

fn reopen(d: &Arc<Demo>, who: Who) -> Result<Value> {
    let u = d.user(&who.who)?;
    if d.hub.contracts().iter().any(|c| c.0.cid() == *u.cid.lock().unwrap() && c.1.is_none()) {
        bail!("{}'s contract is still open", u.name);
    }
    let cid = open_contract(d, &u)?;
    Ok(json!({ "ok": format!("contract {cid} opened") }))
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

//! The hub: opens contracts with users, issues their deposits as tokens on
//! the L2, and (later) pays withdrawals and answers disputes.
//!
//! HTTP (JSON): `GET /info`, `POST /open` ([`OpenRequest`] to
//! [`OpenOffer`]), `POST /accept` ([`Accept`] to [`Opened`]), `POST /fold`
//! ([`FoldRequest`] to [`Folded`]: the cooperative withdrawal, once the
//! hub has seen Alice's return sealed on the L2). A watcher mints each
//! contract's deposit once its funding confirms, and after `T_close`
//! broadcasts the default of any contract still open.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bitcoin::{Amount, OutPoint, Sequence, TxOut};
use lichen_chain::Chain;
use lichen_ledger::{note, regtest_hub, Mint, Tx};
use lichen_proto::{all_moves, check_funding, contributions, terms, Accept, FoldRequest, Folded, Info, OpenOffer, OpenRequest, Opened, Record, Statement, DEFAULT_FEE, FEE_SHARE, FOLD_FEE};
use lichen_sequencer::Client;
use lngap_btc::keys::Seed;
use lngap_channel::{PartyKeys, Role};
use lngap_lamport::winternitz::{WotsParams, WotsSecret};
use lngap_sessions::contract::{sign_all, Program};
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Response, Server};

pub struct Config {
    pub listen: String,
    pub sequencer: String,
    /// The node's RPC URL and cookie, and the hub's wallet there.
    pub rpc_url: String,
    pub cookie: PathBuf,
    pub wallet: String,
    pub statement: Statement,
    /// Where the hub keeps its contracts.
    pub dir: PathBuf,
    /// The hub's secret seed (a label, on regtest).
    pub seed: String,
    pub reserve_ppm: u64,
    pub max_bits: u32,
    pub duration: u32,
}

/// The hub's keys for contract `cid`.
fn contract_keys(seed: &str, cid: u32) -> PartyKeys {
    PartyKeys::from_seed(Role::Hub, Seed::from_label(&format!("{seed}/contract/{cid}")))
}

/// The hub's move key for depth `d` of contract `cid`.
pub fn move_secret(seed: &str, cid: u32, d: u32) -> WotsSecret {
    WotsSecret::from_entropy(WotsParams::for_bytes(48), Seed::from_label(&format!("{seed}/contract/{cid}/move/{d}")).derive_bytes("wots"))
}

struct Pending {
    req: OpenRequest,
    offer: OpenOffer,
    record: Record,
}

#[derive(Clone, Serialize, Deserialize)]
struct Open {
    record: Record,
    minted: bool,
    /// How it ended: the fold's or the default's txid.
    #[serde(default)]
    closed: Option<bitcoin::Txid>,
}

struct Inner {
    cfg: Config,
    program: Program,
    chain: Chain,
    seq: Client,
    pending: Mutex<HashMap<u32, Pending>>,
    open: Mutex<HashMap<u32, Open>>,
    next_cid: Mutex<u32>,
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
        std::fs::create_dir_all(cfg.dir.join("contracts"))?;
        let program = cfg.statement.program(&cfg.dir)?;
        let chain = Chain::connect(&cfg.rpc_url, &cfg.cookie, &cfg.wallet)?;
        let seq = Client::new(&cfg.sequencer);
        let mut open = HashMap::new();
        for e in std::fs::read_dir(cfg.dir.join("contracts"))?.flatten() {
            let o: Open = serde_json::from_slice(&std::fs::read(e.path())?)?;
            open.insert(o.record.cid(), o);
        }
        let next = open.keys().max().map_or(1000, |m| m + 1);
        let server = Arc::new(Server::http(&cfg.listen).map_err(|e| anyhow!("listen on {}: {e}", cfg.listen))?);
        let port = server.server_addr().to_ip().context("an IP listener")?.port();
        let inner = Arc::new(Inner { cfg, program, chain, seq, pending: Mutex::new(HashMap::new()), open: Mutex::new(open), next_cid: Mutex::new(next) });
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
                if let Err(e) = i2.mint_confirmed() {
                    eprintln!("hub: {e:#}");
                }
                if let Err(e) = i2.default_expired() {
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
        (Method::Post, "/open") => serde_json::to_string(&inner.open(serde_json::from_str(body)?)?)?,
        (Method::Post, "/accept") => serde_json::to_string(&inner.accept(serde_json::from_str(body)?)?)?,
        (Method::Post, "/fold") => serde_json::to_string(&inner.fold(serde_json::from_str(body)?)?)?,
        _ => bail!("no {method} {url}"),
    })
}

impl Inner {
    fn info(&self) -> Info {
        Info { statement: self.cfg.statement.id().to_string(), depths: self.program.depths(), reserve_ppm: self.cfg.reserve_ppm, max_bits: self.cfg.max_bits, duration: self.cfg.duration }
    }

    fn open(&self, req: OpenRequest) -> Result<OpenOffer> {
        let m = self.program.depths();
        ensure!(req.bits <= self.cfg.max_bits, "a cap above 2^{} sats", self.cfg.max_bits);
        ensure!(req.moves.len() as u32 == m.div_ceil(2), "{} move keys for the odd depths of {m}", req.moves.len());
        let cid = {
            let mut n = self.next_cid.lock().unwrap();
            *n += 1;
            *n - 1
        };
        let keys = contract_keys(&self.cfg.seed, cid);
        let mut hub = keys.public();
        hub.payout_spk = self.chain.new_spk()?;
        let v_max = (1u64 << req.bits) - 1;
        let reserve_hub = v_max * self.cfg.reserve_ppm / 1_000_000;
        let t_close = self.chain.height()? + self.cfg.duration;
        let t = terms(cid, &req, t_close, reserve_hub)?;
        let (alice_in, hub_in) = contributions(&t);
        let alice_spent: Amount = req.coins.iter().map(|c| c.1.value).sum();
        ensure!(alice_spent == alice_in + FEE_SHARE + req.change.value, "your coins less your change should be {}", alice_in + FEE_SHARE);
        let margin = Amount::from_sat(10_000);
        let hub_coins = self.chain.select(hub_in + FEE_SHARE + margin)?;
        let hub_spent: Amount = hub_coins.iter().map(|c| c.1.value).sum();
        let hub_change = TxOut { value: hub_spent - hub_in - FEE_SHARE, script_pubkey: self.chain.new_spk()? };
        let hub_moves: Vec<_> = (1..=m).filter(|d| d % 2 == 0).map(|d| move_secret(&self.cfg.seed, cid, d).public()).collect();
        let mut record = Record {
            statement: self.cfg.statement.id().to_string(),
            terms: t,
            pubs: [req.alice.clone(), hub.clone()],
            moves: all_moves(&req.moves, &hub_moves),
            inputs: req.inputs.clone(),
            l2_address: req.l2_address,
            funding: OutPoint::null(),
            hub_sigs: HashMap::new(),
            alice_sigs: HashMap::new(),
        };
        let c = record.contract(&self.cfg.statement, &self.program)?;
        let ins: Vec<(OutPoint, Sequence)> = req.coins.iter().chain(&hub_coins).map(|c| (c.0, Sequence::ENABLE_RBF_NO_LOCKTIME)).collect();
        let outs = vec![TxOut { value: c.value(), script_pubkey: c.tree()?.script_pubkey() }, req.change.clone(), hub_change.clone()];
        let funding = lngap_btc::tx::build_tx(&ins, outs, bitcoin::absolute::LockTime::ZERO);
        check_funding(&funding, &c, &hub_coins, &hub_change, hub_in)?;
        record.funding = OutPoint { txid: funding.compute_txid(), vout: 0 };
        let set = c.presign(record.funding)?;
        record.hub_sigs = sign_all(&set, &keys.payment)?;
        let offer = OpenOffer { cid, t_close, reserve_hub, hub, moves: hub_moves, funding, hub_coins, hub_sigs: record.hub_sigs.clone() };
        self.pending.lock().unwrap().insert(cid, Pending { req, offer: offer.clone(), record });
        Ok(offer)
    }

    fn accept(&self, a: Accept) -> Result<Opened> {
        let p = self.pending.lock().unwrap().remove(&a.cid).context("no such offer")?;
        ensure!(a.funding.compute_txid() == p.offer.funding.compute_txid(), "not the funding transaction offered");
        let mut record = p.record;
        record.alice_sigs = a.alice_sigs;
        let c = record.contract(&self.cfg.statement, &self.program)?;
        record.presigned(&c).context("Alice's signatures")?;
        let prevouts: Vec<(OutPoint, TxOut)> = p.req.coins.iter().chain(&p.offer.hub_coins).cloned().collect();
        let signed = self.chain.sign_mine(&a.funding, &prevouts)?;
        let txid = self.chain.broadcast(&signed).context("broadcasting the funding")?;
        let o = Open { record, minted: false, closed: None };
        self.save(&o)?;
        self.open.lock().unwrap().insert(a.cid, o);
        Ok(Opened { txid })
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
        let o = self.open.lock().unwrap().get(&f.cid).cloned().context("no such contract")?;
        ensure!(o.closed.is_none(), "contract {} is closed", f.cid);
        let input = self.seq.state()?.withdraw_input(f.index)?;
        ensure!(input.note.memo == f.cid && input.note.value == f.b, "note {} is not a return of {} with memo {}", f.index, f.b, f.cid);
        let c = o.record.contract(&self.cfg.statement, &self.program)?;
        let p = c.fold(o.record.funding, Amount::from_sat(f.b), FOLD_FEE)?;
        p.verify(&o.record.pubs[0].payment, &f.alice_sig).context("Alice's signature on the fold")?;
        let mine = p.sign(&contract_keys(&self.cfg.seed, f.cid).payment)?;
        let txid = self.chain.broadcast(&p.finish(vec![], &mine, &f.alice_sig)).context("broadcasting the fold")?;
        self.close(f.cid, txid)?;
        Ok(Folded { txid })
    }

    fn close(&self, cid: u32, txid: bitcoin::Txid) -> Result<()> {
        let mut open = self.open.lock().unwrap();
        let o = open.get_mut(&cid).context("no such contract")?;
        o.closed = Some(txid);
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
        }
        Ok(())
    }

    /// Mint each newly confirmed contract's deposit to its user.
    fn mint_confirmed(&self) -> Result<()> {
        let due: Vec<Open> = self.open.lock().unwrap().values().filter(|o| !o.minted).cloned().collect();
        for mut o in due {
            if self.chain.confirmations(&o.record.funding.txid)? == 0 {
                continue;
            }
            let d = u64::from(o.record.terms.deposit);
            self.seq.submit(&Tx::Mint(Mint::new(&regtest_hub(), vec![note(o.record.l2_address, d, 0)])))?;
            o.minted = true;
            self.save(&o)?;
            self.open.lock().unwrap().insert(o.record.cid(), o);
        }
        Ok(())
    }
}

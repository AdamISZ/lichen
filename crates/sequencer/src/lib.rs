//! The sequencer: one party that orders the L2's transactions, applies
//! them to the ledger and seals heights, signing each state root. A small
//! HTTP service (JSON); its API, and the client the wallet and the hub
//! use, are in `lichen-l2`.
//!
//! The sequencer is trusted for the L2's finality, inclusion and
//! availability (the L2's own assumptions), and for nothing else.

pub mod anchor;

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use lichen_l2::{Applied, ChainReceipt, Event, Refused, State};
use lichen_ledger::k256::schnorr::SigningKey;
use lichen_ledger::{xonly, Deployment, Hash, Ledger, OutPoint, Proof, Tx};
use tiny_http::{Header, Method, Response, Server};

/// A running sequencer.
pub struct Sequencer {
    pub url: String,
    server: Arc<Server>,
    thread: Option<std::thread::JoinHandle<()>>,
    ledger: Arc<Mutex<Ledger>>,
    events: Arc<Mutex<Vec<Event>>>,
    path: Option<PathBuf>,
    key: SigningKey,
    stop: Arc<AtomicBool>,
    anchorer: Option<std::thread::JoinHandle<()>>,
}

/// How a sequencer runs.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Accept native proofs of shielded spends: the sender's private input
    /// in the clear (tests and demos).
    pub native_proofs: bool,
    /// The genesis seal of a new ledger that will be anchored
    /// ([`anchor::genesis_seal`]); a ledger kept from before has its own.
    pub seal: Option<OutPoint>,
}

impl Sequencer {
    /// Serve on `addr` (e.g. "127.0.0.1:0"), the ledger kept in `path` if
    /// given, signing with `key`, the hub's key `issuer` minting.
    pub fn start(addr: &str, path: Option<PathBuf>, key: SigningKey, issuer: Hash) -> Result<Sequencer> {
        Sequencer::start_with(addr, path, key, issuer, Options::default())
    }
    pub fn start_with(addr: &str, path: Option<PathBuf>, key: SigningKey, issuer: Hash, opts: Options) -> Result<Sequencer> {
        let deployment = Deployment { sequencer: xonly(&key), hub: issuer, seal: opts.seal };
        let mut ledger: Ledger = match &path {
            Some(p) if p.exists() => serde_json::from_slice(&std::fs::read(p)?).context("the ledger file")?,
            _ => Ledger::new(deployment),
        };
        ledger.native_proofs = opts.native_proofs;
        let d = ledger.deployment;
        anyhow::ensure!(d.sequencer == deployment.sequencer && d.hub == deployment.hub, "the ledger file is another deployment's (sequencer {}, hub {})", hex::encode(d.sequencer), hex::encode(d.hub));
        anyhow::ensure!(opts.seal.is_none() || d.seal == opts.seal, "the ledger file has another genesis seal");
        let server = Arc::new(Server::http(addr).map_err(|e| anyhow!("listen on {addr}: {e}"))?);
        let port = server.server_addr().to_ip().context("an IP listener")?.port();
        let ledger = Arc::new(Mutex::new(ledger));
        let events: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(vec![]));
        let srv = server.clone();
        let blocks = path.as_ref().map(|p| blocks_dir(p));
        let (shared, shared_events, shared_path, shared_key) = (ledger.clone(), events.clone(), path.clone(), key.clone());
        let thread = std::thread::spawn(move || {
            for mut req in srv.incoming_requests() {
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                let (code, json) = handle(&ledger, &events, &key, blocks.as_deref(), req.method(), req.url(), &body);
                if code == 200 {
                    if let Some(p) = &path {
                        let l = ledger.lock().unwrap();
                        let _ = std::fs::write(p, serde_json::to_vec(&*l).unwrap());
                    }
                }
                let ct = Header::from_bytes("Content-Type", "application/json").unwrap();
                let _ = req.respond(Response::from_string(json).with_status_code(code).with_header(ct));
            }
        });
        Ok(Sequencer { url: format!("http://127.0.0.1:{port}"), server, thread: Some(thread), ledger: shared, events: shared_events, path: shared_path, key: shared_key, stop: Arc::new(AtomicBool::new(false)), anchorer: None })
    }

    /// Anchor the history on Bitcoin from now on, through `chain` (a
    /// bitcoind wallet paying the fees): a thread until the sequencer
    /// stops.
    pub fn anchor(&mut self, chain: lichen_chain::Chain, opts: anchor::Anchoring) -> Result<()> {
        anyhow::ensure!(self.anchorer.is_none(), "already anchoring");
        anyhow::ensure!(self.ledger.lock().unwrap().deployment.seal.is_some(), "this deployment has no genesis seal: start a new ledger with one (Options::seal)");
        let a = anchor::Anchorer { ledger: self.ledger.clone(), events: self.events.clone(), path: self.path.clone(), key: self.key.clone(), chain, opts };
        let stop = self.stop.clone();
        self.anchorer = Some(std::thread::spawn(move || a.run(stop)));
        Ok(())
    }
}

impl Drop for Sequencer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = self.anchorer.take() {
            let _ = t.join();
        }
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Where the sequencer records each sealed block, beside the ledger file
/// `p`: `<p>.blocks/`.
pub fn blocks_dir(p: &Path) -> PathBuf {
    let mut d = p.as_os_str().to_owned();
    d.push(".blocks");
    PathBuf::from(d)
}

/// Record the block that seals height `h`, for the chain prover
/// (r0/chain-prover.sh): the block statement's input (`<h>.input`, its
/// bytes) and each shielded transaction's receipt, in order
/// (`<h>.<k>.receipt`).
fn record(dir: &Path, h: u64, input: &[u8], receipts: &[&[u8]]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    for (k, r) in receipts.iter().enumerate() {
        std::fs::write(dir.join(format!("{h}.{k}.receipt")), r)?;
    }
    // the input last: the prover takes a height once its input is there
    let tmp = dir.join(format!("{h}.input.tmp"));
    std::fs::write(&tmp, input)?;
    std::fs::rename(tmp, dir.join(format!("{h}.input")))
}

fn handle(ledger: &Mutex<Ledger>, events: &Mutex<Vec<Event>>, key: &SigningKey, blocks: Option<&Path>, method: &Method, url: &str, body: &str) -> (u16, String) {
    let refuse = |code: u16, e: String| (code, serde_json::to_string(&Refused { error: e }).unwrap());
    let mut l = ledger.lock().unwrap();
    if let (Method::Get, Some(q)) = (method, url.strip_prefix("/events?since=")) {
        let since: usize = q.parse().unwrap_or(0);
        let ev = events.lock().unwrap();
        let tail: Vec<(usize, Event)> = ev.iter().cloned().enumerate().skip(since).collect();
        return (200, serde_json::to_string(&tail).unwrap());
    }
    if let (Method::Get, Some(h)) = (method, url.strip_prefix("/chain/")) {
        // the chain prover's receipt that heights 1..h are valid, if made
        let Some(file) = h.parse::<u64>().ok().and_then(|h| blocks.map(|d| d.join(format!("{h}.chain")))) else {
            return refuse(404, format!("no chain receipt {h}"));
        };
        return match std::fs::read(&file) {
            Ok(r) => (200, serde_json::to_string(&ChainReceipt { receipt: hex::encode(r) }).unwrap()),
            Err(_) => refuse(404, format!("height {h} not proved (yet)")),
        };
    }
    match (method, url) {
        (Method::Post, "/tx") => match serde_json::from_str::<Tx>(body) {
            Ok(tx) => match l.apply(&tx) {
                Ok(indices) => {
                    events.lock().unwrap().push(Event::of(&tx));
                    (200, serde_json::to_string(&Applied { indices }).unwrap())
                }
                Err(e) => refuse(400, format!("{e:#}")),
            },
            Err(e) => refuse(400, format!("not a transaction: {e}")),
        },
        (Method::Post, "/seal") => {
            // nothing new since the last height (no transaction, not even
            // an anchor's record): no new height
            if let Some(last) = l.sealed.last() {
                if last.size == l.tree.len() && last.nullifiers == l.nullifiers.root() && l.pending.is_empty() {
                    return (200, serde_json::to_string(last).unwrap());
                }
            }
            let input = blocks.map(|_| l.block_input());
            let receipts: Vec<Vec<u8>> = l.pending.iter().filter_map(|t| match t {
                Tx::Shielded(s) => match &s.proof {
                    Proof::Risc0(r) => Some(r.clone()),
                    Proof::Native(_) => None,
                },
                _ => None,
            }).collect();
            let s = l.seal(key);
            if let (Some(dir), Some(input)) = (blocks, input) {
                let r = input.map_err(|e| e.to_string()).and_then(|i| record(dir, s.height, &i.to_bytes(), &receipts.iter().map(Vec::as_slice).collect::<Vec<_>>()).map_err(|e| e.to_string()));
                if let Err(e) = r {
                    eprintln!("sequencer: height {}'s block not recorded: {e}", s.height);
                }
            }
            events.lock().unwrap().push(Event::Sealed { height: s.height, notes: s.size, root: s.root() });
            (200, serde_json::to_string(&s).unwrap())
        }
        (Method::Get, "/info") => (200, serde_json::to_string(&l.deployment).unwrap()),
        (Method::Get, "/state") => (200, serde_json::to_string(&State::of(&l)).unwrap()),
        _ => refuse(404, format!("no {method} {url}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_the_chain_provers_receipts() {
        let dir = std::env::temp_dir().join(format!("lichen-seq-chain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ledger = dir.join("ledger.json");
        let s = Sequencer::start("127.0.0.1:0", Some(ledger.clone()), lichen_ledger::regtest_sequencer(), lichen_ledger::HUB_KEY).unwrap();
        let c = lichen_l2::Client::new(&s.url).unwrap();
        assert_eq!(c.chain_receipt(1).unwrap(), None, "not proved yet");
        std::fs::create_dir_all(blocks_dir(&ledger)).unwrap();
        std::fs::write(blocks_dir(&ledger).join("1.chain"), [1, 2, 3]).unwrap();
        assert_eq!(c.chain_receipt(1).unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(c.chain_receipt(2).unwrap(), None);
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

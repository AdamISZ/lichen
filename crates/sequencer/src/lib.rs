//! The sequencer: one party that orders the L2's transactions, applies
//! them to the ledger and seals heights, signing each state root. A small
//! HTTP service (JSON); its API, and the client the wallet and the hub
//! use, are in `lichen-l2`.
//!
//! The sequencer is trusted for the L2's finality, inclusion and
//! availability (the L2's own assumptions), and for nothing else.

pub mod anchor;

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use lichen_l2::{Applied, ChainReceipt, Event, Refused, State};
use lichen_ledger::k256::schnorr::SigningKey;
use lichen_ledger::{files, xonly, Deployment, Hash, Ledger, OutPoint, Proof, Tx};
use tiny_http::{Header, Method, Request, Response, Server};

/// The largest request body: a shielded transaction with its receipt,
/// in hex, is about half a megabyte.
const MAX_BODY: usize = 4 << 20;
/// At most this many requests served at once.
const MAX_CONCURRENT: usize = 64;

/// A running sequencer.
pub struct Sequencer {
    pub url: String,
    server: Arc<Server>,
    thread: Option<std::thread::JoinHandle<()>>,
    shared: Arc<Shared>,
    stop: Arc<AtomicBool>,
    anchorer: Option<std::thread::JoinHandle<()>>,
}

/// What the request handlers and the anchorer share.
pub(crate) struct Shared {
    pub ledger: Mutex<Ledger>,
    pub events: Mutex<Vec<Event>>,
    pub path: Option<PathBuf>,
    pub key: SigningKey,
    /// Set once a save failed: the ledger in memory is ahead of the file,
    /// so the sequencer serves nothing more (a restart from the file would
    /// sign another root at a height already signed).
    pub poisoned: AtomicBool,
}

impl Shared {
    /// Keep the ledger: the file replaced atomically. On failure the
    /// sequencer stops serving.
    pub fn save(&self, l: &Ledger) -> Result<()> {
        let Some(p) = &self.path else { return Ok(()) };
        let r = files::write_atomic(p, &serde_json::to_vec(l)?).with_context(|| format!("saving the ledger to {}", p.display()));
        if r.is_err() {
            self.poisoned.store(true, Ordering::SeqCst);
        }
        r
    }
    fn blocks(&self) -> Option<PathBuf> {
        self.path.as_deref().map(blocks_dir)
    }
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
        // blocks recorded for heights the file never kept (a crash between
        // recording a block and saving the ledger): stale
        if let Some(p) = &path {
            let last = ledger.sealed.last().map_or(0, |s| s.height);
            clear_from(&blocks_dir(p), last + 1).context("clearing stale block files")?;
        }
        let server = Arc::new(Server::http(addr).map_err(|e| anyhow!("listen on {addr}: {e}"))?);
        let port = server.server_addr().to_ip().context("an IP listener")?.port();
        let shared = Arc::new(Shared { ledger: Mutex::new(ledger), events: Mutex::new(vec![]), path, key, poisoned: AtomicBool::new(false) });
        let (srv, sh) = (server.clone(), shared.clone());
        let thread = std::thread::spawn(move || {
            let busy = Arc::new(AtomicUsize::new(0));
            for req in srv.incoming_requests() {
                if busy.load(Ordering::SeqCst) >= MAX_CONCURRENT {
                    let _ = req.respond(json_response(503, refused("too many requests at once".into())));
                    continue;
                }
                busy.fetch_add(1, Ordering::SeqCst);
                let (sh, busy) = (sh.clone(), busy.clone());
                // a request each: a slow client holds up only itself
                std::thread::spawn(move || {
                    serve(req, &sh);
                    busy.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Ok(Sequencer { url: format!("http://127.0.0.1:{port}"), server, thread: Some(thread), shared, stop: Arc::new(AtomicBool::new(false)), anchorer: None })
    }

    /// Anchor the history on Bitcoin from now on, through `chain` (a
    /// bitcoind wallet paying the fees): a thread until the sequencer
    /// stops.
    pub fn anchor(&mut self, chain: lichen_chain::Chain, opts: anchor::Anchoring) -> Result<()> {
        anyhow::ensure!(self.anchorer.is_none(), "already anchoring");
        anyhow::ensure!(self.shared.ledger.lock().unwrap().deployment.seal.is_some(), "this deployment has no genesis seal: start a new ledger with one (Options::seal)");
        let a = anchor::Anchorer { shared: self.shared.clone(), chain, opts };
        let stop = self.stop.clone();
        self.anchorer = Some(std::thread::spawn(move || a.run(stop)));
        Ok(())
    }
}

impl Drop for Sequencer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
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

/// Remove the block files (inputs, receipts, chain receipts) of heights
/// `h` and above in `dir`.
fn clear_from(dir: &Path, h: u64) -> std::io::Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Ok(()) };
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        let height = name.split('.').next().and_then(|n| n.parse::<u64>().ok());
        if height.is_some_and(|n| n >= h) {
            std::fs::remove_file(e.path())?;
        }
    }
    Ok(())
}

/// Record the block that seals height `h`, for the chain prover
/// (r0/chain-prover.sh): the block statement's input (`<h>.input`, its
/// bytes) and each shielded transaction's receipt, in order
/// (`<h>.<k>.receipt`). Files left from an earlier block at `h` or above
/// (one sealed but never saved) go first.
fn record(dir: &Path, h: u64, input: &[u8], receipts: &[&[u8]]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    clear_from(dir, h)?;
    for (k, r) in receipts.iter().enumerate() {
        std::fs::write(dir.join(format!("{h}.{k}.receipt")), r)?;
    }
    // the input last: the prover takes a height once its input is there
    let tmp = dir.join(format!("{h}.input.tmp"));
    std::fs::write(&tmp, input)?;
    std::fs::rename(tmp, dir.join(format!("{h}.input")))
}

fn refused(e: String) -> String {
    serde_json::to_string(&Refused { error: e }).unwrap()
}

fn json_response(code: u16, json: String) -> Response<std::io::Cursor<Vec<u8>>> {
    let ct = Header::from_bytes("Content-Type", "application/json").unwrap();
    Response::from_string(json).with_status_code(code).with_header(ct)
}

fn serve(mut req: Request, sh: &Shared) {
    let mut body = Vec::new();
    let read = req.as_reader().take(MAX_BODY as u64 + 1).read_to_end(&mut body);
    let (code, json) = match (read, String::from_utf8(body)) {
        (Err(e), _) => (400, refused(format!("the request's body: {e}"))),
        (_, Err(_)) => (400, refused("the request's body isn't UTF-8".into())),
        (Ok(n), _) if n > MAX_BODY => (413, refused(format!("a body over {MAX_BODY} bytes"))),
        (Ok(_), Ok(body)) => handle(sh, req.method(), req.url(), &body),
    };
    let _ = req.respond(json_response(code, json));
}

fn handle(sh: &Shared, method: &Method, url: &str, body: &str) -> (u16, String) {
    let refuse = |code: u16, e: String| (code, refused(e));
    if sh.poisoned.load(Ordering::SeqCst) {
        return refuse(503, "the ledger couldn't be saved: the sequencer serves nothing until restarted".into());
    }
    let blocks = sh.blocks();
    let mut l = sh.ledger.lock().unwrap();
    if let (Method::Get, Some(q)) = (method, url.strip_prefix("/events?since=")) {
        let since: usize = q.parse().unwrap_or(0);
        let ev = sh.events.lock().unwrap();
        let tail: Vec<(usize, Event)> = ev.iter().cloned().enumerate().skip(since).collect();
        return (200, serde_json::to_string(&tail).unwrap());
    }
    if let (Method::Get, Some(h)) = (method, url.strip_prefix("/chain/")) {
        // the chain prover's receipt that heights 1..h are valid, if made
        let Some(file) = h.parse::<u64>().ok().and_then(|h| blocks.as_ref().map(|d| d.join(format!("{h}.chain")))) else {
            return refuse(404, format!("no chain receipt {h}"));
        };
        return match std::fs::read(&file) {
            Ok(r) => (200, serde_json::to_string(&ChainReceipt { receipt: hex::encode(r) }).unwrap()),
            Err(_) => refuse(404, format!("height {h} not proved (yet)")),
        };
    }
    match (method, url) {
        (Method::Post, "/tx") => match serde_json::from_str::<Tx>(body) {
            // the anchorer's alone: it applies a record once it has found
            // its own anchor confirmed (a record is checked against the
            // seal, not against Bitcoin's work)
            Ok(Tx::Anchor(_)) => refuse(400, "anchor records come from the sequencer's anchorer only".into()),
            Ok(tx) => match l.apply(&tx) {
                Ok(indices) => {
                    if let Err(e) = sh.save(&l) {
                        return refuse(503, format!("{e:#}"));
                    }
                    sh.events.lock().unwrap().push(Event::of(&tx));
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
            let input = blocks.as_ref().map(|_| l.block_input());
            let receipts: Vec<Vec<u8>> = l.pending.iter().filter_map(|t| match t {
                Tx::Shielded(s) => match &s.proof {
                    Proof::Risc0(r) => Some(r.clone()),
                    Proof::Native(_) => None,
                },
                _ => None,
            }).collect();
            let s = l.seal(&sh.key);
            if let (Some(dir), Some(input)) = (&blocks, input) {
                let r = input.map_err(|e| e.to_string()).and_then(|i| record(dir, s.height, &i.to_bytes(), &receipts.iter().map(Vec::as_slice).collect::<Vec<_>>()).map_err(|e| e.to_string()));
                if let Err(e) = r {
                    eprintln!("sequencer: height {}'s block not recorded: {e}", s.height);
                }
            }
            // kept before anyone sees the signature
            if let Err(e) = sh.save(&l) {
                return refuse(503, format!("{e:#}"));
            }
            sh.events.lock().unwrap().push(Event::Sealed { height: s.height, notes: s.size, root: s.root() });
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

    /// An anchor record from a client is refused (the anchorer's alone),
    /// as is a body over the limit; a read doesn't rewrite the ledger; a
    /// restart clears the block files of heights the ledger never kept.
    #[test]
    fn refuses_what_isnt_a_clients() {
        let dir = std::env::temp_dir().join(format!("lichen-seq-refuse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ledger = dir.join("ledger.json");
        let s = Sequencer::start("127.0.0.1:0", Some(ledger.clone()), lichen_ledger::regtest_sequencer(), lichen_ledger::HUB_KEY).unwrap();
        let c = lichen_l2::Client::new(&s.url).unwrap();
        let e = c.submit(&Tx::Anchor(vec![0; 300])).unwrap_err();
        assert!(format!("{e:#}").contains("anchorer only"), "{e:#}");
        let big = "x".repeat(MAX_BODY + 1);
        match ureq::post(&format!("{}/tx", s.url)).send_string(&big) {
            Err(ureq::Error::Status(413, _)) => {}
            r => panic!("a body over the limit: {r:?}"),
        }
        // a mint and a seal: saved; then reads leave the file alone
        let mint = Tx::Mint(lichen_ledger::Mint::new(&lichen_ledger::regtest_hub(), vec![lichen_ledger::note([7; 32], 5, 0)]));
        c.submit(&mint).unwrap();
        c.seal().unwrap();
        let saved = std::fs::read(&ledger).unwrap();
        std::fs::write(&ledger, &saved).unwrap();
        let before = std::fs::metadata(&ledger).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        c.state().unwrap();
        lichen_l2::Client::new(&s.url).unwrap();
        assert_eq!(std::fs::metadata(&ledger).unwrap().modified().unwrap(), before, "a read rewrote the ledger");
        drop(s);
        // files of a height 2 sealed but never saved (a crash between):
        // gone at the restart; height 1's kept
        let blocks = blocks_dir(&ledger);
        std::fs::create_dir_all(&blocks).unwrap();
        std::fs::write(blocks.join("1.chain"), [1]).unwrap();
        for f in ["2.input", "2.0.receipt", "2.chain", "3.chain"] {
            std::fs::write(blocks.join(f), [2]).unwrap();
        }
        let s = Sequencer::start("127.0.0.1:0", Some(ledger.clone()), lichen_ledger::regtest_sequencer(), lichen_ledger::HUB_KEY).unwrap();
        let mut left: Vec<String> = std::fs::read_dir(&blocks).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        assert!(left.contains(&"1.chain".to_string()) && !left.iter().any(|f| f.starts_with("2.") || f.starts_with("3.")), "{left:?}");
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

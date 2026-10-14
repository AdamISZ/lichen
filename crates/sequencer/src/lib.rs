//! The sequencer: one party that orders the L2's transactions, applies
//! them to the ledger and seals heights, signing each state root. A small
//! HTTP service (JSON); its API, and the client the wallet and the hub
//! use, are in `lichen-l2`.
//!
//! The sequencer is trusted for the L2's finality, inclusion and
//! availability (the L2's own assumptions), and for nothing else.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use lichen_l2::{Applied, Event, Refused, State};
use lichen_ledger::k256::schnorr::SigningKey;
use lichen_ledger::{xonly, Deployment, Hash, Ledger, Tx};
use tiny_http::{Header, Method, Response, Server};

/// A running sequencer.
pub struct Sequencer {
    pub url: String,
    server: Arc<Server>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Sequencer {
    /// Serve on `addr` (e.g. "127.0.0.1:0"), the ledger kept in `path` if
    /// given, signing with `key`, the hub's key `issuer` minting.
    pub fn start(addr: &str, path: Option<PathBuf>, key: SigningKey, issuer: Hash) -> Result<Sequencer> {
        let deployment = Deployment { sequencer: xonly(&key), hub: issuer };
        let ledger: Ledger = match &path {
            Some(p) if p.exists() => serde_json::from_slice(&std::fs::read(p)?).context("the ledger file")?,
            _ => Ledger::new(deployment),
        };
        anyhow::ensure!(ledger.deployment == deployment, "the ledger file is another deployment's (sequencer {}, hub {})", hex::encode(ledger.deployment.sequencer), hex::encode(ledger.deployment.hub));
        let server = Arc::new(Server::http(addr).map_err(|e| anyhow!("listen on {addr}: {e}"))?);
        let port = server.server_addr().to_ip().context("an IP listener")?.port();
        let ledger = Arc::new(Mutex::new(ledger));
        let events: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(vec![]));
        let srv = server.clone();
        let thread = std::thread::spawn(move || {
            for mut req in srv.incoming_requests() {
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                let (code, json) = handle(&ledger, &events, &key, req.method(), req.url(), &body);
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
        Ok(Sequencer { url: format!("http://127.0.0.1:{port}"), server, thread: Some(thread) })
    }
}

impl Drop for Sequencer {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn handle(ledger: &Mutex<Ledger>, events: &Mutex<Vec<Event>>, key: &SigningKey, method: &Method, url: &str, body: &str) -> (u16, String) {
    let refuse = |code: u16, e: String| (code, serde_json::to_string(&Refused { error: e }).unwrap());
    let mut l = ledger.lock().unwrap();
    if let (Method::Get, Some(q)) = (method, url.strip_prefix("/events?since=")) {
        let since: usize = q.parse().unwrap_or(0);
        let ev = events.lock().unwrap();
        let tail: Vec<(usize, Event)> = ev.iter().cloned().enumerate().skip(since).collect();
        return (200, serde_json::to_string(&tail).unwrap());
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
            // nothing new since the last height: no new height
            if let Some(last) = l.sealed.last() {
                if last.size == l.tree.len() && last.nullifiers == l.nullifiers.root() {
                    return (200, serde_json::to_string(last).unwrap());
                }
            }
            let s = l.seal(key);
            events.lock().unwrap().push(Event::Sealed { height: s.height, notes: s.size, root: s.root() });
            (200, serde_json::to_string(&s).unwrap())
        }
        (Method::Get, "/info") => (200, serde_json::to_string(&l.deployment).unwrap()),
        (Method::Get, "/state") => (200, serde_json::to_string(&State::of(&l)).unwrap()),
        _ => refuse(404, format!("no {method} {url}")),
    }
}

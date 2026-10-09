//! The sequencer: one party that orders the L2's transactions, applies
//! them to the ledger and seals heights, signing each state root. A small
//! HTTP service (JSON), and the client the wallet and the hub use.
//!
//! - `POST /tx`: a [`Tx`]; the new notes' indices, or the reason it was
//!   refused;
//! - `POST /seal`: seal a height; its [`SignedRoot`];
//! - `GET /state`: every note's opening, the nullifiers, the sealed
//!   heights (the ledger is transparent; fine at this scale).
//!
//! The sequencer is trusted for the L2's finality, inclusion and
//! availability (the L2's own assumptions), and for nothing else: a
//! client checks every signed root, and a withdrawal's input against the
//! statement.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use lichen_ledger::k256::schnorr::SigningKey;
use lichen_ledger::{Hash, Ledger, Note, SignedRoot, Tree, Tx, WithdrawInput, SEQUENCER_KEY};
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Response, Server};

/// What `GET /state` returns.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub notes: Vec<Note>,
    pub nullifiers: Vec<Hash>,
    pub sealed: Vec<SignedRoot>,
}

impl State {
    fn of(l: &Ledger) -> State {
        State { notes: l.notes.clone(), nullifiers: l.nullifiers.iter().copied().collect(), sealed: l.sealed.clone() }
    }
    /// The commitment tree, rebuilt from the notes.
    pub fn tree(&self) -> Tree {
        let mut t = Tree::default();
        for n in &self.notes {
            t.append(n.commitment()).expect("the sequencer's tree fits");
        }
        t
    }
    /// Check every sealed root's signature and that the notes reach it.
    pub fn verify(&self) -> Result<()> {
        let tree = self.tree();
        for s in &self.sealed {
            s.verify(&SEQUENCER_KEY).with_context(|| format!("height {}", s.height))?;
            anyhow::ensure!(s.size <= tree.len() && tree.root_at(s.size) == s.tree, "height {}: the notes don't reach its root", s.height);
        }
        Ok(())
    }
    pub fn is_spent(&self, note: &Note) -> bool {
        self.nullifiers.contains(&lichen_ledger::nullifier(note))
    }
    /// The withdrawal statement's input for the return at `index`, built
    /// and checked locally.
    pub fn withdraw_input(&self, index: u32) -> Result<WithdrawInput> {
        let note = *self.notes.get(index as usize).context("no such note")?;
        let s = self.sealed.iter().find(|s| s.size > index).context("the return is not sealed yet")?;
        let input = WithdrawInput { height: s.height, nullifiers: s.nullifiers, signature: s.signature.clone(), note, index, path: self.tree().path_at(index, s.size) };
        lichen_ledger::check(&input, &SEQUENCER_KEY, &lichen_ledger::HUB_KEY).map_err(|r| anyhow!("the statement would reject this return: {r:?}"))?;
        Ok(input)
    }
}

#[derive(Serialize, Deserialize)]
struct Applied {
    indices: Vec<u32>,
}

#[derive(Serialize, Deserialize)]
struct Refused {
    error: String,
}

/// A running sequencer.
pub struct Sequencer {
    pub url: String,
    server: Arc<Server>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Sequencer {
    /// Serve on `addr` (e.g. "127.0.0.1:0"), the ledger kept in `path` if
    /// given, signing with `key`.
    pub fn start(addr: &str, path: Option<PathBuf>, key: SigningKey, issuer: Hash) -> Result<Sequencer> {
        let ledger = match &path {
            Some(p) if p.exists() => serde_json::from_slice(&std::fs::read(p)?).context("the ledger file")?,
            _ => Ledger::new(issuer),
        };
        let server = Arc::new(Server::http(addr).map_err(|e| anyhow!("listen on {addr}: {e}"))?);
        let port = server.server_addr().to_ip().context("an IP listener")?.port();
        let ledger = Arc::new(Mutex::new(ledger));
        let srv = server.clone();
        let thread = std::thread::spawn(move || {
            for mut req in srv.incoming_requests() {
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                let (code, json) = handle(&ledger, &key, req.method(), req.url(), &body);
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

fn handle(ledger: &Mutex<Ledger>, key: &SigningKey, method: &Method, url: &str, body: &str) -> (u16, String) {
    let refuse = |code: u16, e: String| (code, serde_json::to_string(&Refused { error: e }).unwrap());
    let mut l = ledger.lock().unwrap();
    match (method, url) {
        (Method::Post, "/tx") => match serde_json::from_str::<Tx>(body) {
            Ok(tx) => match l.apply(&tx) {
                Ok(indices) => (200, serde_json::to_string(&Applied { indices }).unwrap()),
                Err(e) => refuse(400, format!("{e:#}")),
            },
            Err(e) => refuse(400, format!("not a transaction: {e}")),
        },
        (Method::Post, "/seal") => (200, serde_json::to_string(&l.seal(key)).unwrap()),
        (Method::Get, "/state") => (200, serde_json::to_string(&State::of(&l)).unwrap()),
        _ => refuse(404, format!("no {method} {url}")),
    }
}

/// A client of the sequencer.
#[derive(Clone, Debug)]
pub struct Client {
    pub url: String,
}

impl Client {
    pub fn new(url: &str) -> Client {
        Client { url: url.trim_end_matches('/').to_string() }
    }
    fn post<T: for<'de> Deserialize<'de>>(&self, path: &str, body: &str) -> Result<T> {
        match ureq::post(&format!("{}{path}", self.url)).set("Content-Type", "application/json").send_string(body) {
            Ok(r) => Ok(r.into_json()?),
            Err(ureq::Error::Status(_, r)) => {
                let e: Refused = r.into_json().unwrap_or(Refused { error: "refused".into() });
                Err(anyhow!("the sequencer refused: {}", e.error))
            }
            Err(e) => Err(anyhow!("{path}: {e}")),
        }
    }
    /// Submit a transaction; the new notes' indices.
    pub fn submit(&self, tx: &Tx) -> Result<Vec<u32>> {
        Ok(self.post::<Applied>("/tx", &serde_json::to_string(tx)?)?.indices)
    }
    pub fn seal(&self) -> Result<SignedRoot> {
        let s: SignedRoot = self.post("/seal", "")?;
        s.verify(&SEQUENCER_KEY).context("the sealed root's signature")?;
        Ok(s)
    }
    /// The ledger, its sealed roots checked.
    pub fn state(&self) -> Result<State> {
        let s: State = ureq::get(&format!("{}/state", self.url)).call().map_err(|e| anyhow!("/state: {e}"))?.into_json()?;
        s.verify()?;
        Ok(s)
    }
}

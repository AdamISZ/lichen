//! The L2's wire types and the sequencer's client: what the wallet and
//! the hub use to talk to a sequencer, which may run on another machine
//! (`lichen-sequencer` serves this API).
//!
//! - `POST /tx`: a [`Tx`]; the new notes' indices ([`Applied`]), or the
//!   reason it was refused ([`Refused`]);
//! - `POST /seal`: seal a height, if anything changed since the last;
//!   its [`SignedRoot`];
//! - `GET /state`: every leaf (a transparent note's opening, or a
//!   shielded note's commitment and ciphertext), the nullifiers, the
//!   sealed heights ([`State`]; fine at this scale);
//! - `GET /info`: the deployment, the sequencer's and the hub's keys (a
//!   client pins it on first contact: [`Client::new`]);
//! - `GET /events?since=<n>`: what happened, in order, from event `n`
//!   ([`Event`]).
//!
//! The sequencer is trusted for the L2's finality, inclusion and
//! availability (the L2's own assumptions), and for nothing else: a
//! client checks every signed root, and a withdrawal's input against the
//! statement.

use anyhow::{anyhow, Context, Result};
use lichen_ledger::{Deployment, Hash, Leaf, Ledger, Note, SignedRoot, Tree, Tx, WithdrawInput};
use serde::{Deserialize, Serialize};

/// What `GET /state` returns.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub notes: Vec<Leaf>,
    pub nullifiers: Vec<Hash>,
    pub sealed: Vec<SignedRoot>,
}

impl State {
    /// The state of ledger `l`.
    pub fn of(l: &Ledger) -> State {
        State { notes: l.notes.clone(), nullifiers: l.nullifiers.iter().copied().collect(), sealed: l.sealed.clone() }
    }
    /// The commitment tree, rebuilt from the leaves.
    pub fn tree(&self) -> Tree {
        let mut t = Tree::default();
        for l in &self.notes {
            t.append(l.commitment()).expect("the sequencer's tree fits");
        }
        t
    }
    /// The transparent note at `index`, if it is one.
    pub fn note(&self, index: u32) -> Option<&Note> {
        self.notes.get(index as usize).and_then(Leaf::note)
    }
    /// The transparent notes, with their indices.
    pub fn transparent(&self) -> impl Iterator<Item = (u32, &Note)> {
        self.notes.iter().enumerate().filter_map(|(i, l)| l.note().map(|n| (i as u32, n)))
    }
    /// Check every sealed root's signature (the sequencer's key) and that
    /// the notes reach it.
    pub fn verify(&self, sequencer: &Hash) -> Result<()> {
        let tree = self.tree();
        for s in &self.sealed {
            s.verify(sequencer).with_context(|| format!("height {}", s.height))?;
            anyhow::ensure!(s.size <= tree.len() && tree.root_at(s.size) == s.tree, "height {}: the notes don't reach its root", s.height);
        }
        Ok(())
    }
    pub fn is_spent(&self, note: &Note) -> bool {
        self.nullifiers.contains(&lichen_ledger::nullifier(note))
    }
    /// The withdrawal statement's input for the return at `index` in
    /// deployment `d`, built and checked locally.
    pub fn withdraw_input(&self, index: u32, d: &Deployment) -> Result<WithdrawInput> {
        let note = *self.note(index).context("no such note")?;
        let s = self.sealed.iter().find(|s| s.size > index).context("the return is not sealed yet")?;
        let input = WithdrawInput { height: s.height, nullifiers: s.nullifiers, signature: s.signature.clone(), note, index, path: self.tree().path_at(index, s.size), sequencer: d.sequencer, hub: d.hub };
        lichen_ledger::check(&input).map_err(|r| anyhow!("the statement would reject this return: {r:?}"))?;
        Ok(input)
    }
}
/// What the sequencer did, for observers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    /// The hub issued notes: (owner, value).
    Mint { to: Vec<(Hash, u64)> },
    /// A transfer: the owners of the notes spent, and the new notes
    /// (owner, value, memo).
    Transfer { from: Vec<Hash>, to: Vec<(Hash, u64, u32)> },
    /// A shielded transaction: the owners of the transparent notes spent,
    /// how many shielded notes were spent and made, and the transparent
    /// notes made (owner, value, memo).
    Shielded { from: Vec<Hash>, spent: usize, made: usize, to: Vec<(Hash, u64, u32)> },
    /// A height sealed: the notes so far, its signed root.
    Sealed { height: u64, notes: u32, root: Hash },
}

impl Event {
    /// The event of applying `tx`.
    pub fn of(tx: &Tx) -> Event {
        match tx {
            Tx::Mint(m) => Event::Mint { to: m.outputs.iter().map(|n| (n.owner, n.value)).collect() },
            Tx::Transfer(t) => Event::Transfer { from: t.spends.iter().map(|s| s.note.owner).collect(), to: t.outputs.iter().map(|n| (n.owner, n.value, n.memo)).collect() },
            Tx::Shielded(t) => Event::Shielded { from: t.t_spends.iter().map(|s| s.note.owner).collect(), spent: t.nfs.len(), made: t.outputs.len(), to: t.t_outputs.iter().map(|n| (n.owner, n.value, n.memo)).collect() },
        }
    }
}
/// What `POST /tx` returns when the transaction is applied.
#[derive(Serialize, Deserialize)]
pub struct Applied {
    pub indices: Vec<u32>,
}

/// What the sequencer returns when it refuses a request.
#[derive(Serialize, Deserialize)]
pub struct Refused {
    pub error: String,
}
/// A client of the sequencer, pinned to a deployment: every root it
/// reads is checked against the deployment's sequencer key.
#[derive(Clone, Debug)]
pub struct Client {
    pub url: String,
    pub deployment: Deployment,
}

impl Client {
    /// Connect, taking the deployment the sequencer announces (trust on
    /// first use: keep it, and use [`Client::pinned`] after).
    pub fn new(url: &str) -> Result<Client> {
        let url = url.trim_end_matches('/').to_string();
        let deployment: Deployment = ureq::get(&format!("{url}/info")).call().map_err(|e| anyhow!("{url}/info: {e}"))?.into_json()?;
        Ok(Client { url, deployment })
    }
    /// A client of a deployment already known.
    pub fn pinned(url: &str, deployment: Deployment) -> Client {
        Client { url: url.trim_end_matches('/').to_string(), deployment }
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
        s.verify(&self.deployment.sequencer).context("the sealed root's signature")?;
        Ok(s)
    }
    /// The events from number `since` on, with their numbers.
    pub fn events(&self, since: usize) -> Result<Vec<(usize, Event)>> {
        Ok(ureq::get(&format!("{}/events?since={since}", self.url)).call().map_err(|e| anyhow!("/events: {e}"))?.into_json()?)
    }
    /// The ledger, its sealed roots checked.
    pub fn state(&self) -> Result<State> {
        let s: State = ureq::get(&format!("{}/state", self.url)).call().map_err(|e| anyhow!("/state: {e}"))?.into_json()?;
        s.verify(&self.deployment.sequencer)?;
        Ok(s)
    }
}

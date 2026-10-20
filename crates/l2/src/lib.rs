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
//! statement. A party that keeps the roots it has seen ([`Seen`]) notices
//! the sequencer signing two histories ([`Equivocation`]).

use std::collections::BTreeMap;

use anyhow::{anyhow, ensure, Context, Result};
use lichen_ledger::{Deployment, Hash, Leaf, Ledger, Note, SignedRoot, Tree, Tx, WithdrawInput};
use serde::{Deserialize, Serialize};

/// What `GET /state` returns.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub notes: Vec<Leaf>,
    pub nullifiers: Vec<Hash>,
    pub sealed: Vec<SignedRoot>,
    /// Each anchoring state on Bitcoin, from the height that first carried
    /// it (none for a sequencer that doesn't anchor).
    #[serde(default)]
    pub anchors: Vec<lichen_ledger::Anchored>,
}

impl State {
    /// The state of ledger `l`.
    pub fn of(l: &Ledger) -> State {
        State { notes: l.notes.clone(), nullifiers: l.nullifiers.iter().copied().collect(), sealed: l.sealed.clone(), anchors: l.anchors.clone() }
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
    /// deployment `d`, built and checked locally: ln-gap's, under the first
    /// sealed root that includes it.
    pub fn withdraw_input(&self, index: u32, d: &Deployment) -> Result<WithdrawInput> {
        let s = self.sealed.iter().find(|s| s.size > index).context("the return is not sealed yet")?;
        self.withdraw_input_at(index, s.height, d)
    }
    /// As [`State::withdraw_input`], under the root sealed at `height`.
    pub fn withdraw_input_at(&self, index: u32, height: u64, d: &Deployment) -> Result<WithdrawInput> {
        let note = *self.note(index).context("no such note")?;
        let s = self.sealed.iter().find(|s| s.height == height).with_context(|| format!("no height {height}"))?;
        ensure!(s.size > index, "note {index} isn't in the tree at height {height}");
        let input = WithdrawInput { height: s.height, nullifiers: s.nullifiers, signature: s.signature.clone(), note, index, path: self.tree().path_at(index, s.size), sequencer: d.sequencer, hub: d.hub };
        lichen_ledger::check(&input).map_err(|r| anyhow!("the statement would reject this return: {r:?}"))?;
        Ok(input)
    }
    /// In an anchored deployment, the return at `index` under the first
    /// anchor that covers it (docs/ANCHOR_PLAN.md): ln-gap's input at the
    /// anchored height, and that anchor's state with the height whose
    /// chain receipt first carries it.
    pub fn anchored_input(&self, index: u32, d: &Deployment) -> Result<(WithdrawInput, lichen_ledger::Anchored)> {
        let sealed = self.sealed.iter().find(|s| s.size > index).context("the return is not sealed yet")?;
        let a = *self.anchors.iter().find(|a| a.anchor.height >= sealed.height).with_context(|| format!("the return, at height {}, isn't anchored on Bitcoin yet", sealed.height))?;
        let input = self.withdraw_input_at(index, a.anchor.height, d)?;
        let root = self.sealed.iter().find(|s| s.height == a.anchor.height).map(|s| s.root());
        ensure!(root == Some(a.anchor.root), "the anchor of height {} isn't of the root signed there", a.anchor.height);
        Ok((input, a))
    }
}
/// The signed roots a party has seen, by height: a second, different root
/// at a height already seen is the sequencer signing two histories.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Seen {
    pub roots: BTreeMap<u64, SignedRoot>,
}

impl Seen {
    /// Record `roots`, each already checked against the sequencer's key
    /// (as [`State::verify`] does): whether any was new, or the first
    /// conflict with one seen before.
    pub fn record<'a>(&mut self, roots: impl IntoIterator<Item = &'a SignedRoot>) -> Result<bool, Equivocation> {
        let mut new = false;
        for r in roots {
            match self.roots.get(&r.height) {
                Some(s) if s.root() != r.root() => return Err(Equivocation { first: s.clone(), second: r.clone() }),
                Some(_) => {}
                None => {
                    self.roots.insert(r.height, r.clone());
                    new = true;
                }
            }
        }
        Ok(new)
    }
}

/// Two different roots the sequencer signed at one height: proof, which
/// anyone with its key can check, that it signed two histories.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Equivocation {
    pub first: SignedRoot,
    pub second: SignedRoot,
}

impl Equivocation {
    pub fn verify(&self, sequencer: &Hash) -> Result<()> {
        ensure!(self.first.height == self.second.height, "roots at two heights ({} and {})", self.first.height, self.second.height);
        ensure!(self.first.root() != self.second.root(), "the same root twice");
        self.first.verify(sequencer).context("the first root's signature")?;
        self.second.verify(sequencer).context("the second root's signature")?;
        Ok(())
    }
}

impl std::fmt::Display for Equivocation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "the sequencer signed two roots at height {}: {} and {}", self.first.height, hex::encode(self.first.root()), hex::encode(self.second.root()))
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
    /// A shielded transaction: the owners of the transparent notes spent
    /// and their total, how many shielded notes were spent and made, the
    /// transparent notes made (owner, value, memo); and what else is
    /// public of it, as an explorer would show it: the nullifiers, the new
    /// notes' commitments, the proof's size in bytes (0: a native proof).
    Shielded {
        from: Vec<Hash>,
        spent: usize,
        made: usize,
        to: Vec<(Hash, u64, u32)>,
        #[serde(default)]
        t_total: u64,
        #[serde(default)]
        nfs: Vec<Hash>,
        #[serde(default)]
        cms: Vec<Hash>,
        #[serde(default)]
        proof: usize,
    },
    /// A height sealed: the notes so far, its signed root.
    Sealed { height: u64, notes: u32, root: Hash },
    /// An anchor on Bitcoin recorded: the height it commits, its txid
    /// (internal order). Unknown to readers from before: skipped.
    Anchored { height: u64, txid: Hash },
}

impl Event {
    /// The event of applying `tx`.
    pub fn of(tx: &Tx) -> Event {
        match tx {
            Tx::Mint(m) => Event::Mint { to: m.outputs.iter().map(|n| (n.owner, n.value)).collect() },
            Tx::Transfer(t) => Event::Transfer { from: t.spends.iter().map(|s| s.note.owner).collect(), to: t.outputs.iter().map(|n| (n.owner, n.value, n.memo)).collect() },
            Tx::Anchor(r) => match lichen_ledger::lichen_validity::AnchorRecord::from_bytes(r) {
                Ok(rec) => {
                    let at = lichen_ledger::lichen_validity::btc::parse_tx(&rec.tx).and_then(|t| t.outputs.get(1).map(|o| o.1)).filter(|c| c.len() == 48).map_or(0, |c| u64::from_be_bytes(c[8..16].try_into().unwrap()));
                    Event::Anchored { height: at, txid: lichen_ledger::lichen_validity::btc::sha256d(&rec.tx) }
                }
                Err(_) => Event::Anchored { height: 0, txid: [0; 32] },
            },
            Tx::Shielded(t) => Event::Shielded {
                from: t.t_spends.iter().map(|s| s.note.owner).collect(),
                spent: t.nfs.len(),
                made: t.outputs.len(),
                to: t.t_outputs.iter().map(|n| (n.owner, n.value, n.memo)).collect(),
                t_total: t.t_spends.iter().map(|s| s.note.value).sum(),
                nfs: t.nfs.clone(),
                cms: t.outputs.iter().map(|o| o.cm).collect(),
                proof: match &t.proof {
                    lichen_ledger::Proof::Risc0(r) => r.len(),
                    lichen_ledger::Proof::Native(_) => 0,
                },
            },
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

/// A chain receipt (`GET /chain/<h>`): the chain prover's receipt
/// (bincode, hex) that heights 1..h are valid from genesis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainReceipt {
    pub receipt: String,
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
    /// The chain receipt at height `h` (bincode), if the sequencer has
    /// proved it. Not checked here: whoever proves a withdrawal with it
    /// does.
    pub fn chain_receipt(&self, h: u64) -> Result<Option<Vec<u8>>> {
        match ureq::get(&format!("{}/chain/{h}", self.url)).call() {
            Ok(r) => Ok(Some(hex::decode(r.into_json::<ChainReceipt>()?.receipt).context("a chain receipt's hex")?)),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(anyhow!("/chain/{h}: {e}")),
        }
    }
    /// The ledger, its sealed roots checked.
    pub fn state(&self) -> Result<State> {
        let s: State = ureq::get(&format!("{}/state", self.url)).call().map_err(|e| anyhow!("/state: {e}"))?.into_json()?;
        s.verify(&self.deployment.sequencer)?;
        Ok(s)
    }
}

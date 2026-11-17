//! The exit where only the hub proves: BABE with the roles swapped, on
//! [`lichen_babe::graph`]'s graph (an L2's front, then BABE's tail). The
//! hub's statement is fixed at the opening by its journal, which the L2
//! makes from the setup's terms and the user's keys; the user garbles for
//! it.
//!
//! Its opening takes three steps before the request, each by the user:
//!
//! 1. **`POST /hp/setup`** ([`HpSetupRequest`]): the hub fixes the
//!    statement's terms (the L2's, in `l2`) and gives its prover's keys, a
//!    Lamport key for π1 and adaptor keys ([`HpSetup`]).
//! 2. **`POST /hp/commit`** ([`HpCommit`]): the user, having fixed her
//!    keys for the dispute (the L2's, in `keys`, so the journal), dealt the
//!    input secrets and built `N` instances, commits to them; the hub
//!    chooses the `M` it keeps ([`HpKept`]).
//! 3. **`POST /hp/instance/<cid>/<i>`** (bytes): she uploads each kept
//!    instance, which the hub checks against its commitment and keeps.
//!
//! Her opening request then opens the others ([`HpRequest`]). The hub's
//! offer carries its adaptor pre-signatures on `challenge_assert` and the
//! L2's keys of its own ([`HpOffer`]); the hub keeps its signatures on
//! `wrongly_challenged` from her, as she gives hers.

use std::collections::HashMap;

use anyhow::{ensure, Context, Result};
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::Amount;
use lichen_babe::graph::{Graph, Payout, Windows};
use lichen_babe::reveal::LamportPub;
use lichen_babe::setup::{Hash, DIGITS, VALUES};
use lichen_babe::statement::Kind;
use lichen_contract::Presign;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::setup::Opened;
use crate::{feerate, terminal_fee, Net, Presig, Record, Statement};

/// The user asks for a setup (`POST /hp/setup`), once she has paid her
/// deposit for contract `cid`; `l2`, the L2's terms she asks for.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpSetupRequest {
    pub cid: u32,
    pub deposit: bitcoin::OutPoint,
    pub unit: u64,
    #[serde(default)]
    pub l2: serde_json::Value,
}

/// The hub's setup: the cut-and-choose (`n` instances, `m` kept), its
/// keys as the prover, and the statement's terms (the L2's, in `l2`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpSetup {
    pub cid: u32,
    pub n: u32,
    pub m: u32,
    pub unit: u64,
    pub deposit: bitcoin::OutPoint,
    pub lamport: LamportPub,
    pub adaptor: Vec<[XOnlyPublicKey; VALUES]>,
    #[serde(default)]
    pub l2: serde_json::Value,
}

/// The user's commitment to her instances (`POST /hp/commit`): her keys
/// for the dispute (the L2's), each instance's hash (hex), and the
/// dealing's commitments ([`crate::setup::dealing_to_hex`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpCommit {
    pub cid: u32,
    #[serde(default)]
    pub keys: serde_json::Value,
    pub commitments: Vec<String>,
    pub dealing: String,
}

/// The instances the hub keeps (1-based).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpKept {
    pub cid: u32,
    pub kept: Vec<u32>,
}

/// In her opening request: the instances not kept, opened.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpRequest {
    pub hp_opened: Vec<Opened>,
}

/// The hub's keys in an offer: BABE's windows, its adaptor pre-signatures
/// on `challenge_assert` (a digit and value), and the L2's keys of the
/// hub's (`l2`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpOffer {
    pub hp_windows: Windows,
    pub hp_presigs: Vec<[Presig; VALUES]>,
    #[serde(default)]
    pub l2: serde_json::Value,
}

/// The keys a contract keeps (in its [`Record`]): BABE's, and the L2's
/// (`l2`: the statement's terms, both parties' keys for the front).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpKeys {
    /// The hub's Lamport key for π1 and its adaptor keys.
    pub hub_lamport: LamportPub,
    pub hub_adaptor: Vec<[XOnlyPublicKey; VALUES]>,
    /// The cut-and-choose: `n` instances, those kept, and their
    /// hashlocks.
    pub n: u32,
    pub kept: Vec<u32>,
    #[serde(with = "lichen_babe::hexbytes::vec_fixed")]
    pub hmsg: Vec<Hash>,
    pub hp_windows: Windows,
    /// The contract's deposit coin.
    pub deposit: bitcoin::OutPoint,
    /// The hub's adaptor pre-signatures on `challenge_assert`.
    #[serde(default)]
    pub hub_presigs: Vec<[Presig; VALUES]>,
    #[serde(default)]
    pub l2: serde_json::Value,
}

impl HpKeys {
    /// The L2's part, typed.
    pub fn l2<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(self.l2.clone()).context("the contract's L2 keys")
    }
    /// BABE's tail of the graph.
    pub fn tail(&self) -> lichen_babe::graph::Tail {
        lichen_babe::graph::Tail { lamport: self.hub_lamport.clone(), adaptor: self.hub_adaptor.clone(), hmsg: self.hmsg.clone(), windows: self.hp_windows }
    }
}

/// BABE's windows on a network: `Δ2` for her challenge (only a false
/// assertion, or a liar, gets there, so it can be long), `Δ1` for the
/// hub's answer.
pub fn windows(net: Net) -> Windows {
    let (delta2, delta1) = match net {
        // blocks every 150 ms in the tests
        Net::Regtest => (40, 40),
        // 30 s blocks: a day, 2 h
        Net::Mutinynet => (2880, 240),
        // 10 min blocks: a day, 6 h
        Net::Signet => (144, 36),
        Net::Testnet4 => (288, 72),
    };
    Windows { delta2, delta1 }
}

impl Statement {
    /// The hub's statement's kind: RISC Zero's (the L2's guest), or the
    /// mock.
    pub fn hp_kind(&self) -> Result<Kind> {
        Ok(if self.mock { Kind::Mock } else { Kind::Risc0(self.image) })
    }
}

impl Record {
    /// The dispute's keys.
    pub fn hp(&self) -> &HpKeys {
        &self.dispute
    }
}

/// A commitment's count: `n` instances.
pub fn check_commit(c: &HpCommit, n: u32) -> Result<()> {
    ensure!(c.commitments.len() == n as usize, "{} commitments for {n} instances", c.commitments.len());
    Ok(())
}

/// The keys of a setup: a Lamport and an adaptor key set per digit.
pub fn check_setup(s: &HpSetup) -> Result<()> {
    ensure!(s.lamport.0.len() == DIGITS && s.adaptor.len() == DIGITS, "a Lamport and an adaptor key set per digit of π1");
    ensure!(s.m >= 1 && s.m < s.n, "a cut-and-choose keeping {} of {}", s.m, s.n);
    Ok(())
}

/// What the heaviest of the user's terminal transactions (those paying
/// her claim) needs from her fee budget on `net`.
pub fn terminal_need(graph: &Graph, set: &[Presign], net: Net) -> Result<Amount> {
    let mut names = vec![];
    for l in graph.front.links()? {
        if l.pays == Payout::User {
            names.push(l.terminal.to_string());
        }
    }
    names.push("failure".into());
    let mut most = Amount::ZERO;
    for p in set.iter().filter(|p| !p.link && names.contains(&p.name)) {
        most = most.max(terminal_fee(&p.finish(vec![], &[0; 65], &[0; 65]), net));
    }
    Ok(most + lichen_chain::KeyFees::split_cost(feerate(net)))
}

/// A contract as a dispute needs it: its graph and pre-signed set, by
/// name.
pub struct Disputed {
    pub record: Record,
    pub graph: Graph,
    pub set: HashMap<String, Presign>,
}

impl Disputed {
    pub fn new(record: &Record, statement: &Statement, layer: &dyn crate::Layer) -> Result<Disputed> {
        let built = record.build(statement, layer)?;
        let set = record.presigned(&built)?.into_iter().map(|p| (p.name.clone(), p)).collect();
        Ok(Disputed { record: record.clone(), graph: built.0, set })
    }
    /// A pre-signed transaction with both signatures, `wire` below them.
    pub fn finish(&self, name: &str, wire: Vec<Vec<u8>>) -> Result<bitcoin::Transaction> {
        let p = self.set.get(name).with_context(|| format!("no pre-signed {name}"))?;
        let hub = self.record.hub_sigs.get(name).with_context(|| format!("no signature of the hub's on {name}"))?;
        let alice = self.record.alice_sigs.get(name).with_context(|| format!("no signature of the user's on {name}"))?;
        Ok(p.finish(wire, hub, alice))
    }
    pub fn txid(&self, name: &str) -> bitcoin::Txid {
        self.set[name].tx.compute_txid()
    }
    /// The front's last link: what `assert` spends.
    pub fn last_front(&self) -> Result<&'static str> {
        self.graph.front_names()?.pop().context("an empty front")
    }
    /// What `assert` put on chain: π1's digits (read under the hub's
    /// Lamport key), their preimages, and the proof, if its points are
    /// points.
    pub fn asserted(&self, assert: &bitcoin::Transaction) -> Result<crate::setup::Asserted> {
        let args = crate::setup::link_args(assert);
        let (signed, pi2, pi3) = Graph::read_assert(&args).context("assert's arguments")?;
        let lamport = &self.graph.tail.lamport;
        let preimages: Vec<lichen_babe::reveal::Preimage> = signed.iter().map(|a| a[..].try_into().context("a preimage's length")).collect::<Result<_>>()?;
        let digits: Vec<u8> = preimages.iter().enumerate().map(|(d, p)| lamport.read(d, p).context("a preimage of no digit")).collect::<Result<_>>()?;
        let bits: Vec<bool> = digits.iter().flat_map(|v| [v & 1 == 1, v & 2 == 2]).collect();
        Ok(crate::setup::Asserted { proof: lichen_babe::statement::proof_from_chain(&bits, pi2, pi3), digits, bits, preimages })
    }
}

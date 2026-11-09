//! The exit where only the hub proves (docs/HUB_PROVES_PLAN.md): BABE
//! with the roles swapped, `lichen_babe::hp`'s graph. The hub's statement
//! (`lichen_withdraw::hp`) is fixed at opening, and Alice garbles for it.
//!
//! Its opening takes three steps before the request, each by Alice:
//!
//! 1. **`POST /hp/setup`** ([`HpSetupRequest`]): the hub fixes the
//!    statement (the checkpoint, the unit, the margin) and gives its
//!    prover's keys, a Lamport key for π1 and adaptor keys ([`HpSetup`]).
//! 2. **`POST /hp/commit`** ([`HpCommit`]): Alice, having dealt the input
//!    secrets and built `N` instances for the hub's statement, commits to
//!    them; the hub chooses the `M` it keeps ([`HpKept`]).
//! 3. **`POST /hp/instance/<cid>/<i>`** (bytes): she uploads each kept
//!    instance, which the hub checks against its commitment and keeps.
//!
//! Her opening request then opens the others ([`HpRequest`]: their seeds
//! and shares), which the hub checks and rebuilds before it offers. Its
//! offer carries its adaptor pre-signatures on `challenge_assert`
//! ([`HpOffer`]), which she checks against her dealing's points; and the
//! hub keeps its signatures on `wrongly_challenged` from her, as she gives
//! hers.

use anyhow::{ensure, Context, Result};
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::Amount;
use lichen_babe::graph::Windows;
use lichen_babe::hp::{HubProves, Spec};
use lichen_babe::reveal::LamportPub;
use lichen_babe::setup::{Hash, DIGITS, VALUES};
use lichen_babe::statement::Kind;
use lngap_lamport::winternitz::{WotsParams, WotsPublic};
use lngap_sessions::contract::Presign;
use serde::{Deserialize, Serialize};

use crate::babe::Opened;
use crate::{feerate, params, terminal_fee, Checkpoint, Net, Presig, Record, Statement};

/// Alice asks for a setup (`POST /hp/setup`), once she has paid her
/// deposit for contract `cid`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpSetupRequest {
    pub cid: u32,
    pub deposit: bitcoin::OutPoint,
    pub unit: u64,
}

/// The hub's setup: what its statement is (the checkpoint, the unit, the
/// margin), the cut-and-choose (`n` instances, `m` kept), and its keys as
/// the prover.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpSetup {
    pub cid: u32,
    pub n: u32,
    pub m: u32,
    pub margin: u32,
    pub checkpoint: Option<Checkpoint>,
    pub unit: u64,
    pub deposit: bitcoin::OutPoint,
    pub lamport: LamportPub,
    pub adaptor: Vec<[XOnlyPublicKey; VALUES]>,
}

/// Alice's commitment to her instances (`POST /hp/commit`): her keys
/// for `b` and `E`, each instance's hash (hex), and the dealing's
/// commitments ([`crate::babe::dealing_to_hex`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpCommit {
    pub cid: u32,
    pub b_key: WotsPublic,
    pub e_key: WotsPublic,
    pub commitments: Vec<String>,
    pub dealing: String,
}

/// The instances the hub keeps (from 1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpKept {
    pub cid: u32,
    pub kept: Vec<u32>,
}

/// Alice's keys in an opening request: the instances the hub doesn't
/// keep, opened.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpRequest {
    pub hp_opened: Vec<Opened>,
}

/// The hub's keys in an offer: the windows, and its adaptor
/// pre-signatures on `challenge_assert`, a digit and value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpOffer {
    pub hp_windows: Windows,
    pub hp_presigs: Vec<[Presig; VALUES]>,
}

/// The keys a contract keeps (in its [`Record`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpKeys {
    /// Alice's one-time keys for `b` and `E`.
    pub b_key: WotsPublic,
    pub e_key: WotsPublic,
    /// The hub's Lamport key for π1 and its adaptor keys.
    pub hub_lamport: LamportPub,
    pub hub_adaptor: Vec<[XOnlyPublicKey; VALUES]>,
    /// The cut-and-choose: `N` instances, those kept (from 1), their
    /// hashlocks.
    pub n: u32,
    pub kept: Vec<u32>,
    pub hmsg: Vec<Hash>,
    pub hp_windows: Windows,
    /// The hub's statement's margin, and the contract's deposit coin.
    pub margin: u32,
    pub deposit: bitcoin::OutPoint,
    /// The hub's adaptor pre-signatures on `challenge_assert`.
    #[serde(default)]
    pub hub_presigs: Vec<[Presig; VALUES]>,
}

/// The windows on a network: `w_H` for the hub's assertion (it proves
/// first), `Δ2` for her challenge (only a false assertion, or a liar, gets
/// there, so it can be long), `Δ1` for the hub's answer. `t_a`: her
/// request's latest, before `T_close`.
pub fn windows(net: Net, t_close: u32) -> Windows {
    let (w_h, delta2, delta1) = match net {
        // blocks every 150 ms in the tests: the request's block needs the
        // contract's work on it (ten blocks) before the hub can assert
        Net::Regtest => (80, 40, 40),
        // 30 s blocks: 2 h, a day, 2 h
        Net::Mutinynet => (240, 2880, 240),
        // 10 min blocks: 6 h, a day, 6 h
        Net::Signet => (36, 144, 36),
        Net::Testnet4 => (72, 288, 72),
    };
    Windows { w_h, t_a: t_close.saturating_sub(u32::from(w_h) + u32::from(delta2) + u32::from(delta1)), delta2, delta1 }
}

/// The hub's statement's margin on a network, in blocks: covers her
/// request's confirmation (docs/HUB_PROVES_PLAN.md, "The margin").
pub fn margin(net: Net) -> u32 {
    match net {
        Net::Regtest => 6,
        Net::Mutinynet => 20,
        Net::Signet | Net::Testnet4 => 6,
    }
}

impl Statement {
    /// The hub's statement's kind, for a hub-proves statement: the mock
    /// only, for now (no guest yet).
    pub fn hp_kind(&self) -> Result<Kind> {
        match self {
            Statement::HubProves { mock: true } => Ok(Kind::Mock),
            Statement::HubProves { mock: false } => anyhow::bail!("the hub's statement has no guest yet: hub-proves runs on the mock only"),
            _ => anyhow::bail!("not a hub-proves statement"),
        }
    }
}

impl Record {
    /// The keys, for a hub-proves contract.
    pub fn hp(&self) -> Result<&HpKeys> {
        match &self.dispute {
            crate::DisputeKeys::HubProves(k) => Ok(k),
            _ => anyhow::bail!("contract {} is not a hub-proves contract", self.cid()),
        }
    }
    /// Its graph.
    pub fn hp_graph(&self) -> Result<HubProves> {
        let k = self.hp()?;
        HubProves::new(Spec {
            terms: self.terms,
            params: params(self.network),
            pubs: self.pubs.clone(),
            b_key: k.b_key.clone(),
            e_key: k.e_key.clone(),
            lamport: k.hub_lamport.clone(),
            adaptor: k.hub_adaptor.clone(),
            hmsg: k.hmsg.clone(),
            windows: k.hp_windows,
        })
    }
    /// The hub's statement's journal: `c ‖ D ‖ H(O_D ‖ margin)`.
    pub fn hp_journal(&self) -> Result<[u8; lichen_withdraw::hp::JOURNAL_LEN]> {
        let k = self.hp()?;
        Ok(lichen_withdraw::hp::journal(self.cid(), &self.deployment, &crate::babe::statement_outpoint(&k.deposit), k.margin))
    }
}

/// The journal of contract `c` in `D`, of deposit coin `deposit` and
/// margin `margin`.
pub fn journal(c: u32, d: &Hash, deposit: &bitcoin::OutPoint, margin: u32) -> [u8; lichen_withdraw::hp::JOURNAL_LEN] {
    lichen_withdraw::hp::journal(c, d, &crate::babe::statement_outpoint(deposit), margin)
}

/// The keys of a commitment: of the parameters the scripts are built for,
/// `n` instances.
pub fn check_commit(c: &HpCommit, n: u32) -> Result<()> {
    ensure!(c.b_key.params == WotsParams::for_bytes(4) && c.b_key.digits.len() == 10, "a key for b of other parameters");
    ensure!(c.e_key.params == WotsParams::for_bytes(32), "a key for E of other parameters");
    ensure!(c.commitments.len() == n as usize, "{} commitments for {n} instances", c.commitments.len());
    Ok(())
}

/// The keys of a setup: a Lamport and an adaptor key set per digit.
pub fn check_setup(s: &HpSetup) -> Result<()> {
    ensure!(s.lamport.0.len() == DIGITS && s.adaptor.len() == DIGITS, "a Lamport and an adaptor key set per digit of π1");
    ensure!(s.m >= 1 && s.m < s.n, "a cut-and-choose keeping {} of {}", s.m, s.n);
    Ok(())
}

/// What the heaviest of Alice's terminal transactions needs from her fee
/// budget on `net`: `request_timeout`, `failure`.
pub fn terminal_need(set: &[Presign], net: Net) -> Result<Amount> {
    let mut most = Amount::ZERO;
    for p in set.iter().filter(|p| !p.link && (p.name == "request_timeout" || p.name == "failure")) {
        most = most.max(terminal_fee(&p.finish(vec![], &[0; 65], &[0; 65]), net));
    }
    Ok(most + lichen_chain::KeyFees::split_cost(feerate(net)))
}

/// A hub-proves contract as a dispute needs it: its graph and pre-signed
/// set, by name.
pub struct HpDisputed {
    pub record: Record,
    pub graph: HubProves,
    pub set: std::collections::HashMap<String, Presign>,
}

impl HpDisputed {
    pub fn new(record: &Record, statement: &Statement) -> Result<HpDisputed> {
        let built = record.build(statement, None)?;
        let set = record.presigned(&built)?.into_iter().map(|p| (p.name.clone(), p)).collect();
        let crate::Built::HubProves(graph) = built else { anyhow::bail!("contract {} is not a hub-proves contract", record.cid()) };
        Ok(HpDisputed { record: record.clone(), graph: *graph, set })
    }
    /// A pre-signed transaction with both signatures, `wire` below them.
    pub fn finish(&self, name: &str, wire: Vec<Vec<u8>>) -> Result<bitcoin::Transaction> {
        let p = self.set.get(name).with_context(|| format!("no pre-signed {name}"))?;
        let hub = self.record.hub_sigs.get(name).with_context(|| format!("no signature of the hub's on {name}"))?;
        let alice = self.record.alice_sigs.get(name).with_context(|| format!("no signature of Alice's on {name}"))?;
        Ok(p.finish(wire, hub, alice))
    }
    pub fn txid(&self, name: &str) -> bitcoin::Txid {
        self.set[name].tx.compute_txid()
    }
    /// `request`'s claim: `b`, `E` and the claim's bytes, from its
    /// arguments.
    pub fn requested(request: &bitcoin::Transaction) -> Result<(u32, [u8; 32], Vec<u8>)> {
        let (b, e, posted) = lichen_babe::hp::HubProves::read_request(&crate::babe::Disputed::args(request))?;
        let b = u32::from_be_bytes(b.message().try_into().map_err(|_| anyhow::anyhow!("b's signature signs 4 bytes"))?);
        let e = e.message().try_into().map_err(|_| anyhow::anyhow!("E's signature signs 32 bytes"))?;
        Ok((b, e, posted))
    }
    /// What `assert` put on chain: π1's digits (read under the hub's
    /// Lamport key), their preimages, and the proof, if its points are
    /// points.
    pub fn asserted(&self, assert: &bitcoin::Transaction) -> Result<crate::babe::Asserted> {
        let args = crate::babe::Disputed::args(assert);
        let (signed, pi2, pi3) = lichen_babe::graph::Babe::read_assert(&args).context("assert's arguments")?;
        let lamport = &self.graph.spec.lamport;
        let preimages: Vec<lichen_babe::reveal::Preimage> = signed.iter().map(|a| a[..].try_into().context("a preimage's length")).collect::<Result<_>>()?;
        let digits: Vec<u8> = preimages.iter().enumerate().map(|(d, p)| lamport.read(d, p).context("a preimage of no digit")).collect::<Result<_>>()?;
        let bits: Vec<bool> = digits.iter().flat_map(|v| [v & 1 == 1, v & 2 == 2]).collect();
        Ok(crate::babe::Asserted { proof: lichen_babe::statement::proof_from_chain(&bits, pi2, pi3), digits, bits, preimages })
    }
}

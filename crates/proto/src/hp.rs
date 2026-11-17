//! The grants L2's contract (papers/lichen-grants-v0.5.6, §5–6): BABE with
//! the roles swapped, on `lichen_babe::countersigned`'s graph. The hub's
//! statement (`lichen_withdraw::accounts::check`) is fixed at the opening
//! by its journal `J = c ‖ D`, which binds the issuer, the contract's key,
//! the unit, the mint's value and Alice's four one-time keys; Alice garbles
//! for it.
//!
//! Its opening takes three steps before the request, each by Alice:
//!
//! 1. **`POST /hp/setup`** ([`HpSetupRequest`]): the hub fixes the
//!    statement's terms (the unit, the mint's value, the owner, the issuer)
//!    and gives its prover's keys, a Lamport key for π1 and adaptor keys
//!    ([`HpSetup`]).
//! 2. **`POST /hp/commit`** ([`HpCommit`]): Alice, having fixed her four
//!    one-time keys (so the journal), dealt the input secrets and built `N`
//!    instances, commits to them; the hub chooses the `M` it keeps
//!    ([`HpKept`]).
//! 3. **`POST /hp/instance/<cid>/<i>`** (bytes): she uploads each kept
//!    instance, which the hub checks against its commitment and keeps.
//!
//! Her opening request then opens the others ([`HpRequest`]). The hub's
//! offer carries its one-time keys for `b_corr` and `U` and its adaptor
//! pre-signatures on `challenge_assert` ([`HpOffer`]).

use anyhow::{ensure, Context, Result};
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::Amount;
use lichen_babe::countersigned::{Countersigned, Spec, Windows, Q_LEN, U_LEN};
use lichen_babe::reveal::LamportPub;
use lichen_babe::setup::{Hash, DIGITS, VALUES};
use lichen_babe::statement::Kind;
use lichen_withdraw::accounts;
use lichen_wots::{Wots256Public, WotsParams, WotsPublic};
use lichen_contract::Presign;
use serde::{Deserialize, Serialize};

use crate::setup::Opened;
use crate::{feerate, params, terminal_fee, Net, Presig, Record, Statement};

/// Alice asks for a setup (`POST /hp/setup`), once she has paid her
/// deposit for contract `cid`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpSetupRequest {
    pub cid: u32,
    pub deposit: bitcoin::OutPoint,
    pub unit: u64,
    /// The contract's owner (its L2 key) and the mint's value, which the
    /// journal binds.
    #[serde(with = "lichen_babe::hexbytes::fixed")]
    pub owner: Hash,
    pub v0: u64,
}

/// The hub's setup: the statement's terms, the cut-and-choose (`n`
/// instances, `m` kept), and its keys as the prover.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpSetup {
    pub cid: u32,
    pub n: u32,
    pub m: u32,
    pub unit: u64,
    pub deposit: bitcoin::OutPoint,
    #[serde(with = "lichen_babe::hexbytes::fixed")]
    pub owner: Hash,
    pub v0: u64,
    /// The issuer's key, which signs every note.
    #[serde(with = "lichen_babe::hexbytes::fixed")]
    pub issuer: Hash,
    pub lamport: LamportPub,
    pub adaptor: Vec<[XOnlyPublicKey; VALUES]>,
}

/// Alice's one-time keys: `K_Q`, `K_b` (in `request`), `A_corr`, `A_U` (in
/// `ack`). SHA-256 chains: the statement verifies them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliceKeys {
    #[serde(with = "lichen_babe::hexbytes::wots")]
    pub q_key: Wots256Public,
    #[serde(with = "lichen_babe::hexbytes::wots")]
    pub b_key: Wots256Public,
    #[serde(with = "lichen_babe::hexbytes::wots")]
    pub a_corr_key: Wots256Public,
    #[serde(with = "lichen_babe::hexbytes::wots")]
    pub a_u_key: Wots256Public,
}

impl AliceKeys {
    /// Of the parameters the graph takes.
    pub fn check(&self) -> Result<()> {
        let w = |n: usize| WotsParams::for_bytes(n as u32);
        ensure!(self.q_key.params == w(Q_LEN) && self.q_key.digits.len() == w(Q_LEN).total_digits() as usize, "K_Q of other parameters");
        for (k, n) in [(&self.b_key, 4), (&self.a_corr_key, 4), (&self.a_u_key, U_LEN)] {
            ensure!(k.params == w(n) && k.digits.len() == w(n).total_digits() as usize, "a one-time key of other parameters");
        }
        Ok(())
    }
    /// The journal's keys, in its order.
    pub fn chains(&self) -> [Vec<Hash>; 4] {
        [self.q_key.digits.clone(), self.b_key.digits.clone(), self.a_corr_key.digits.clone(), self.a_u_key.digits.clone()]
    }
}

/// The contract as the statement's journal binds it.
pub fn contract(cid: u32, issuer: &Hash, owner: &Hash, unit: u64, v0: u64, keys: &AliceKeys) -> accounts::Contract {
    accounts::Contract { c: cid, issuer: *issuer, owner: *owner, unit, v0, keys: keys.chains() }
}

/// Alice's commitment to her instances (`POST /hp/commit`): her one-time
/// keys, each instance's hash (hex), and the dealing's commitments
/// ([`crate::setup::dealing_to_hex`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpCommit {
    pub cid: u32,
    pub keys: AliceKeys,
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

/// The hub's keys in an offer: the windows, its one-time keys for `b_corr`
/// and `U` (HASH160: only script reads them), and its adaptor
/// pre-signatures on `challenge_assert`, a digit and value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpOffer {
    pub hp_windows: Windows,
    #[serde(with = "lichen_babe::hexbytes::wots")]
    pub corr_key: WotsPublic,
    #[serde(with = "lichen_babe::hexbytes::wots")]
    pub u_key: WotsPublic,
    pub hp_presigs: Vec<[Presig; VALUES]>,
}

/// The keys a contract keeps (in its [`Record`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HpKeys {
    pub alice_keys: AliceKeys,
    #[serde(with = "lichen_babe::hexbytes::wots")]
    pub corr_key: WotsPublic,
    #[serde(with = "lichen_babe::hexbytes::wots")]
    pub u_key: WotsPublic,
    /// The hub's Lamport key for π1 and its adaptor keys.
    pub hub_lamport: LamportPub,
    pub hub_adaptor: Vec<[XOnlyPublicKey; VALUES]>,
    /// The cut-and-choose: `N` instances, those kept (from 1), their
    /// hashlocks.
    pub n: u32,
    pub kept: Vec<u32>,
    #[serde(with = "lichen_babe::hexbytes::vec_fixed")]
    pub hmsg: Vec<Hash>,
    pub hp_windows: Windows,
    /// The contract's deposit coin, the issuer, the mint's value.
    pub deposit: bitcoin::OutPoint,
    #[serde(with = "lichen_babe::hexbytes::fixed")]
    pub issuer: Hash,
    pub v0: u64,
    /// The hub's adaptor pre-signatures on `challenge_assert`.
    #[serde(default)]
    pub hub_presigs: Vec<[Presig; VALUES]>,
}

/// The windows on a network: `w_H` for the hub's moves (`correct`, and
/// `assert`, which must cover proving), `w_A` for her `ack`, `Δ2` for her
/// challenge, `Δ1` for the hub's answer.
pub fn windows(net: Net) -> Windows {
    let (w_h, w_a, delta2, delta1) = match net {
        // blocks every 150 ms in the tests
        Net::Regtest => (40, 30, 40, 40),
        // 30 s blocks: 2 h, a day, a day, 2 h
        Net::Mutinynet => (240, 2880, 2880, 240),
        // 10 min blocks: 6 h, a day, a day, 6 h
        Net::Signet => (36, 144, 144, 36),
        Net::Testnet4 => (72, 288, 288, 72),
    };
    Windows { w_h, w_a, delta2, delta1 }
}

impl Statement {
    /// The hub's statement's kind: RISC Zero's, or the mock.
    pub fn hp_kind(&self) -> Result<Kind> {
        match self {
            Statement::HubProves { mock: true } => Ok(Kind::Mock),
            Statement::HubProves { mock: false } => Ok(Kind::Risc0),
        }
    }
}

impl Record {
    /// The dispute's keys.
    pub fn hp(&self) -> &HpKeys {
        &self.dispute
    }
    /// Its graph.
    pub fn hp_graph(&self) -> Result<Countersigned> {
        let k = self.hp();
        let a = &k.alice_keys;
        Countersigned::new(Spec {
            terms: self.terms,
            params: params(self.network),
            pubs: self.pubs.clone(),
            b_key: a.b_key.clone(),
            q_key: a.q_key.clone(),
            a_corr_key: a.a_corr_key.clone(),
            a_u_key: a.a_u_key.clone(),
            corr_key: k.corr_key.clone(),
            u_key: k.u_key.clone(),
            lamport: k.hub_lamport.clone(),
            adaptor: k.hub_adaptor.clone(),
            hmsg: k.hmsg.clone(),
            windows: k.hp_windows,
        })
    }
    /// The contract as the journal binds it.
    pub fn hp_contract(&self) -> accounts::Contract {
        let k = self.hp();
        contract(self.cid(), &k.issuer, &self.l2_address, self.terms.unit.to_sat(), k.v0, &k.alice_keys)
    }
    /// The hub's statement's journal: `c ‖ D`.
    pub fn hp_journal(&self) -> [u8; accounts::JOURNAL_LEN] {
        self.hp_contract().journal()
    }
}

/// The keys of a commitment: of the parameters the scripts are built for,
/// `n` instances.
pub fn check_commit(c: &HpCommit, n: u32) -> Result<()> {
    c.keys.check()?;
    ensure!(c.commitments.len() == n as usize, "{} commitments for {n} instances", c.commitments.len());
    Ok(())
}

/// The keys of a setup: a Lamport and an adaptor key set per digit.
pub fn check_setup(s: &HpSetup) -> Result<()> {
    ensure!(s.lamport.0.len() == DIGITS && s.adaptor.len() == DIGITS, "a Lamport and an adaptor key set per digit of π1");
    ensure!(s.m >= 1 && s.m < s.n, "a cut-and-choose keeping {} of {}", s.m, s.n);
    Ok(())
}

/// The hub's keys in an offer: of the parameters the graph takes.
pub fn check_offer_keys(o: &HpOffer) -> Result<()> {
    ensure!(o.corr_key.params == WotsParams::for_bytes(4), "K_corr of other parameters");
    ensure!(o.u_key.params == WotsParams::for_bytes(U_LEN as u32), "K_U of other parameters");
    Ok(())
}

/// What the heaviest of Alice's terminal transactions needs from her fee
/// budget on `net`: `request_timeout`, `ack_timeout`, `failure`.
pub fn terminal_need(set: &[Presign], net: Net) -> Result<Amount> {
    let mut most = Amount::ZERO;
    for p in set.iter().filter(|p| !p.link && matches!(p.name.as_str(), "request_timeout" | "ack_timeout" | "failure")) {
        most = most.max(terminal_fee(&p.finish(vec![], &[0; 65], &[0; 65]), net));
    }
    Ok(most + lichen_chain::KeyFees::split_cost(feerate(net)))
}

/// A contract as a dispute needs it: its graph and pre-signed set, by
/// name.
pub struct HpDisputed {
    pub record: Record,
    pub graph: Countersigned,
    pub set: std::collections::HashMap<String, Presign>,
}

impl HpDisputed {
    pub fn new(record: &Record, statement: &Statement) -> Result<HpDisputed> {
        let built = record.build(statement)?;
        let set = record.presigned(&built)?.into_iter().map(|p| (p.name.clone(), p)).collect();
        Ok(HpDisputed { record: record.clone(), graph: *built.0, set })
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
    /// `request`'s: `b`, the posted claim's bytes, and her signatures on
    /// them.
    pub fn requested(request: &bitcoin::Transaction) -> Result<(u32, Vec<u8>, accounts::Wots, accounts::Wots)> {
        let (b, q) = Countersigned::read_request(&crate::setup::link_args(request))?;
        let bv = u32::from_be_bytes(b.message().try_into().map_err(|_| anyhow::anyhow!("b's signature signs 4 bytes"))?);
        Ok((bv, q.message(), wots(&q), wots(&b)))
    }
    /// `correct`'s: `b_corr` and `U`, as the hub signed them.
    pub fn corrected(correct: &bitcoin::Transaction) -> Result<(u32, accounts::Seed)> {
        let (c, u) = Countersigned::read_correct(&crate::setup::link_args(correct))?;
        let b_corr = u32::from_be_bytes(c.message().try_into().map_err(|_| anyhow::anyhow!("b_corr's signature signs 4 bytes"))?);
        Ok((b_corr, u.message().try_into().map_err(|_| anyhow::anyhow!("U's signature signs 16 bytes"))?))
    }
    /// `ack`'s: her countersignatures on `b_corr` and `U`.
    pub fn acked(ack: &bitcoin::Transaction) -> Result<(accounts::Wots, accounts::Wots)> {
        let (c, u) = Countersigned::read_ack(&crate::setup::link_args(ack))?;
        Ok((wots(&c), wots(&u)))
    }
    /// What `assert` put on chain: π1's digits (read under the hub's
    /// Lamport key), their preimages, and the proof, if its points are
    /// points.
    pub fn asserted(&self, assert: &bitcoin::Transaction) -> Result<crate::setup::Asserted> {
        let args = crate::setup::link_args(assert);
        let (signed, pi2, pi3) = Countersigned::read_assert(&args).context("assert's arguments")?;
        let lamport = &self.graph.spec.lamport;
        let preimages: Vec<lichen_babe::reveal::Preimage> = signed.iter().map(|a| a[..].try_into().context("a preimage's length")).collect::<Result<_>>()?;
        let digits: Vec<u8> = preimages.iter().enumerate().map(|(d, p)| lamport.read(d, p).context("a preimage of no digit")).collect::<Result<_>>()?;
        let bits: Vec<bool> = digits.iter().flat_map(|v| [v & 1 == 1, v & 2 == 2]).collect();
        Ok(crate::setup::Asserted { proof: lichen_babe::statement::proof_from_chain(&bits, pi2, pi3), digits, bits, preimages })
    }
}

/// A one-time signature as the statement takes it.
pub fn wots(s: &lichen_wots::Wots256Sig) -> accounts::Wots {
    accounts::Wots { hashes: s.hashes.clone(), digits: s.digits.clone() }
}

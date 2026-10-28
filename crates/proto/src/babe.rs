//! The BABE gadget's part of the protocol (docs/BABE_GADGET_PLAN.md):
//! a dispute is BABE's witness encryption of a Groth16 proof, checked by a
//! garbled circuit, the graph `lichen_babe::graph`'s.
//!
//! Its opening takes a step before the request: the setup's
//! cut-and-choose. Alice asks for it ([`SetupRequest`]); the hub deals the
//! input secrets and builds `N` instances, and commits to them
//! ([`Setup`]: the dealing's commitments, each instance's hash). Alice then
//! chooses the `M` she keeps and asks to open with them
//! ([`BabeRequest`]); the hub opens the others ([`BabeOffer`]: their seeds
//! and shares), which she checks and rebuilds, and sends the kept ones
//! (`GET /babe/instance/<cid>/<i>`, bytes), which she checks against
//! their hashes and keeps. With her signatures on the set she gives her
//! adaptor pre-signatures on `challenge_assert` ([`crate::Accept`]).

use anyhow::{ensure, Context, Result};
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::Amount;
use lichen_babe::graph::{Babe, Spec, Windows};
use lichen_babe::reveal::LamportPub;
use lichen_babe::setup::{Hash, Secret, DIGITS, VALUES};
use lichen_babe::statement::{journal, Kind};
use lichen_babe::vsss::Dealing;
use lngap_lamport::winternitz::{Wots256Public, WotsParams, WotsPublic};
use lngap_sessions::contract::Presign;
use serde::{Deserialize, Serialize};

use crate::{feerate, params, terminal_fee, Checkpoint, Net, Presig, Record, Statement};

/// The BABE keys a contract keeps (in its [`Record`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BabeKeys {
    /// Alice's one-time key for `b`; the hub's (SHA-256 chains, `pk_H`).
    pub b_key: WotsPublic,
    pub hub_b: Wots256Public,
    /// Alice's Lamport key for π1, 2-bit digits, and her adaptor keys.
    pub lamport: LamportPub,
    pub adaptor: Vec<[XOnlyPublicKey; VALUES]>,
    /// The cut-and-choose: `N` instances, those kept (from 1), their
    /// hashlocks.
    pub n: u32,
    pub kept: Vec<u32>,
    pub hmsg: Vec<Hash>,
    pub windows: Windows,
    /// Alice's adaptor pre-signatures on `challenge_assert`, a digit and
    /// value (none until she accepts).
    #[serde(default)]
    pub presigs: Vec<[Presig; VALUES]>,
}

/// Alice asks for a setup (`POST /babe/setup`), once she has a deposit
/// address for contract `cid`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetupRequest {
    pub cid: u32,
}

/// The hub's setup: what the contract's statement is (its journal's
/// checkpoint and `pk_H`), and its commitments to `n` instances, of which
/// Alice keeps `m`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Setup {
    pub cid: u32,
    pub n: u32,
    pub m: u32,
    pub checkpoint: Option<Checkpoint>,
    pub hub_b: Wots256Public,
    /// Each instance's hash, hex.
    pub commitments: Vec<String>,
    /// The dealing's commitments, compressed points, hex
    /// ([`dealing_to_hex`]).
    pub dealing: String,
}

/// Alice's BABE keys in an opening request, and the instances she keeps.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BabeRequest {
    pub b_key: WotsPublic,
    pub lamport: LamportPub,
    pub adaptor: Vec<[XOnlyPublicKey; VALUES]>,
    pub kept: Vec<u32>,
}

/// An opened instance: its index, seed and secrets (hex).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Opened {
    pub i: u32,
    pub seed: String,
    pub shares: String,
}

/// The hub's BABE answer in an offer: the windows, the kept instances'
/// hashlocks, the others opened.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BabeOffer {
    pub windows: Windows,
    pub hmsg: Vec<Hash>,
    pub opened: Vec<Opened>,
}

/// The dispute's windows on a network, `T_A` from `T_close`: `w_H` for
/// the hub's response, `Δ2` for its challenge, `Δ1` for her answer to it,
/// and the assertion's deadline early enough before `T_close` for both.
pub fn windows(net: Net, t_close: u32) -> Windows {
    let (w_h, delta2, delta1) = match net {
        // blocks every 150 ms in the dispute tests
        Net::Regtest => (10, 24, 12),
        // 30 s blocks: 20 min, 2 h, 40 min
        Net::Mutinynet => (40, 240, 80),
        // 10 min blocks: 2 h, 12 h, 6 h
        Net::Signet => (12, 72, 36),
        // nominally 10 min, in bursts: 6 h, a day, 12 h
        Net::Testnet4 => (36, 144, 72),
    };
    Windows { w_h, t_a: t_close.saturating_sub(u32::from(delta2) + u32::from(delta1) + u32::from(w_h)), delta2, delta1 }
}

/// The least soundness a wallet accepts of the cut-and-choose, as bits:
/// `C(N, M) ≥ 2^bits` (regtest's tests keep a few instances).
pub fn min_soundness(net: Net) -> u32 {
    match net {
        Net::Regtest => 2,
        _ => 40,
    }
}

/// `log2 C(n, m)`, rounded down.
pub fn soundness(n: u32, m: u32) -> u32 {
    let ln: f64 = (0..m).map(|k| ((n - k) as f64 / (m - k) as f64).log2()).sum();
    ln.floor() as u32
}

pub fn dealing_to_hex(d: &Dealing) -> String {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let mut v = Vec::new();
    for poly in &d.commitments {
        for coeffs in poly {
            for p in coeffs {
                v.extend_from_slice(p.to_affine().to_encoded_point(true).as_bytes());
            }
        }
    }
    hex::encode(v)
}

/// The dealing of `hex` for `DIGITS` digits of polynomials of `degree`.
pub fn dealing_from_hex(h: &str, degree: usize) -> Result<Dealing> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    let b = hex::decode(h)?;
    ensure!(b.len() == DIGITS * VALUES * (degree + 1) * 33, "a dealing of {} bytes", b.len());
    let mut points = b.chunks(33).map(|c| {
        let e = k256::EncodedPoint::from_bytes(c).ok().context("a point's encoding")?;
        Option::<k256::AffinePoint>::from(k256::AffinePoint::from_encoded_point(&e)).map(k256::ProjectivePoint::from).context("not a point")
    });
    let mut commitments = Vec::with_capacity(DIGITS);
    for _ in 0..DIGITS {
        let mut poly: [Vec<k256::ProjectivePoint>; VALUES] = Default::default();
        for c in poly.iter_mut() {
            *c = (0..=degree).map(|_| points.next().expect("counted")).collect::<Result<_>>()?;
        }
        commitments.push(poly);
    }
    Ok(Dealing { commitments })
}

pub fn shares_to_hex(s: &[[Secret; VALUES]]) -> String {
    hex::encode(s.iter().flatten().flatten().copied().collect::<Vec<u8>>())
}

pub fn shares_from_hex(h: &str) -> Result<Vec<[Secret; VALUES]>> {
    let b = hex::decode(h)?;
    ensure!(b.len() == DIGITS * VALUES * 32, "shares of {} bytes", b.len());
    Ok(b.chunks(VALUES * 32).map(|d| core::array::from_fn(|v| d[32 * v..32 * v + 32].try_into().expect("32"))).collect())
}

/// The keys of an opening request: of the parameters the scripts are
/// built for, a set per digit, and `m` distinct instances of `n` kept.
pub fn check_request(req: &BabeRequest, n: u32, m: u32) -> Result<()> {
    ensure!(req.b_key.params == WotsParams::for_bytes(4) && req.b_key.digits.len() == 10, "a key for b of other parameters");
    ensure!(req.lamport.0.len() == DIGITS && req.adaptor.len() == DIGITS, "a Lamport and an adaptor key set per digit of π1");
    let mut k = req.kept.clone();
    k.sort_unstable();
    k.dedup();
    ensure!(k.len() == m as usize && k.len() == req.kept.len() && k.iter().all(|i| (1..=n).contains(i)), "{} instances kept of {n}, not {m} distinct", req.kept.len());
    Ok(())
}

impl Statement {
    /// The BABE statement's kind, for a BABE statement.
    pub fn babe_kind(&self) -> Option<Kind> {
        match self {
            Statement::Babe { mock: true } => Some(Kind::Mock),
            Statement::Babe { mock: false } => Some(Kind::Risc0),
            _ => None,
        }
    }
}

impl Record {
    /// The BABE keys, for a BABE contract.
    pub fn babe(&self) -> Result<&BabeKeys> {
        match &self.dispute {
            crate::DisputeKeys::Babe(k) => Ok(k),
            _ => anyhow::bail!("contract {} is not a BABE contract", self.cid()),
        }
    }
    /// The BABE contract's graph.
    pub fn babe_graph(&self) -> Result<Babe> {
        let k = self.babe()?;
        Babe::new(Spec {
            terms: self.terms,
            params: params(self.network),
            pubs: self.pubs.clone(),
            b_key: k.b_key.clone(),
            hub_b: k.hub_b.clone(),
            lamport: k.lamport.clone(),
            adaptor: k.adaptor.clone(),
            hmsg: k.hmsg.clone(),
            windows: k.windows,
        })
    }
    /// The statement's journal: `c ‖ D ‖ H(pk_H)`.
    pub fn babe_journal(&self) -> Result<[u8; lichen_withdraw::fixed::JOURNAL_LEN]> {
        Ok(babe_journal(self.cid(), &self.deployment, &self.babe()?.hub_b))
    }
}

/// The journal of contract `c` in `D` with the hub's key `hub_b`.
pub fn babe_journal(c: u32, d: &Hash, hub_b: &Wots256Public) -> [u8; lichen_withdraw::fixed::JOURNAL_LEN] {
    let k: [Hash; lichen_withdraw::fixed::DIGITS] = hub_b.digits.clone().try_into().expect("the key's digits, checked");
    journal(c, d, &k)
}

/// What the heaviest of Alice's terminal transactions needs from her fee
/// budget on `net`: `wrongly_challenged` (with `msg`), `success`,
/// `request_timeout`.
pub fn terminal_need(set: &[Presign], net: Net) -> Result<Amount> {
    let mut most = Amount::ZERO;
    for p in set.iter().filter(|p| !p.link) {
        let wire = if p.name.starts_with("wrongly_challenged_") {
            vec![vec![0u8; 32]]
        } else if p.name == "success" || p.name == "request_timeout" {
            vec![]
        } else {
            continue;
        };
        most = most.max(terminal_fee(&p.finish(wire, &[0; 65], &[0; 65]), net));
    }
    Ok(most + lichen_chain::KeyFees::split_cost(feerate(net)))
}

/// A BABE contract as a dispute needs it: its graph and pre-signed set
/// (both signatures checked, but on what Alice keeps from the hub), by
/// name.
pub struct Disputed {
    pub record: Record,
    pub babe: Babe,
    pub set: std::collections::HashMap<String, Presign>,
}

impl Disputed {
    pub fn new(record: &Record, statement: &Statement) -> Result<Disputed> {
        let built = record.build(statement, None)?;
        let set = record.presigned(&built)?.into_iter().map(|p| (p.name.clone(), p)).collect();
        let crate::Built::Babe(babe) = built else { anyhow::bail!("contract {} is not a BABE contract", record.cid()) };
        Ok(Disputed { record: record.clone(), babe: *babe, set })
    }
    /// A pre-signed transaction with both signatures, `wire` below them.
    pub fn finish(&self, name: &str, wire: Vec<Vec<u8>>) -> Result<bitcoin::Transaction> {
        let p = self.set.get(name).with_context(|| format!("no pre-signed {name}"))?;
        let hub = self.record.hub_sigs.get(name).with_context(|| format!("no signature of the hub's on {name}"))?;
        let alice = self.record.alice_sigs.get(name).with_context(|| format!("no signature of Alice's on {name}"))?;
        Ok(p.finish(wire, hub, alice))
    }
    /// The txid the set fixed for `name`.
    pub fn txid(&self, name: &str) -> bitcoin::Txid {
        self.set[name].tx.compute_txid()
    }
    /// A link's witness arguments below both signatures, consumption order.
    pub fn args(tx: &bitcoin::Transaction) -> Vec<Vec<u8>> {
        lngap_btc::witness::witness_args_consumption_order(&tx.input[0].witness).into_iter().skip(2).collect()
    }
    /// Alice's signature on `b`, from `request`.
    pub fn alice_b(request: &bitcoin::Transaction) -> Result<lngap_lamport::winternitz::WotsSig> {
        lngap_lamport::winternitz::WotsSig::from_consumption_order(WotsParams::for_bytes(4), &Self::args(request))
    }
    /// The hub's signature on `b`, from `respond` (its arguments first).
    pub fn hub_b(respond: &bitcoin::Transaction) -> Result<lngap_lamport::winternitz::Wots256Sig> {
        let args = Self::args(respond);
        let n = 2 * WotsParams::for_bytes(4).total_digits() as usize;
        ensure!(args.len() >= n, "respond's arguments are too few");
        lngap_lamport::winternitz::Wots256Sig::from_consumption_order(WotsParams::for_bytes(4), &args[..n])
    }
    /// The hub's key and its signature on `b` from `respond`, as the BABE
    /// prover takes them (`lichen-r0 babe`'s hub auth: JSON, `key` and
    /// `sig`, ten 32-byte hashes each, hex), checked.
    pub fn hub_auth(&self, respond: &bitcoin::Transaction) -> Result<serde_json::Value> {
        let sig = Self::hub_b(respond)?;
        let key = &self.record.babe()?.hub_b;
        ensure!(sig.hashes.len() == key.digits.len(), "the hub's signature and key differ in length");
        key.verify(&sig).context("respond's signature on b, under the hub's key")?;
        let h = |v: &[[u8; 32]]| v.iter().map(hex::encode).collect::<Vec<_>>();
        Ok(serde_json::json!({ "key": h(&key.digits), "sig": h(&sig.hashes) }))
    }
    /// What `assert` put on chain: π1's digits (read under Alice's Lamport
    /// key), their preimages, and the proof, if its points are points.
    pub fn asserted(&self, assert: &bitcoin::Transaction) -> Result<Asserted> {
        let args = Self::args(assert);
        let (signed, pi2, pi3) = Babe::read_assert(&args).context("assert's arguments")?;
        let lamport = &self.babe.spec.lamport;
        let preimages: Vec<lichen_babe::reveal::Preimage> = signed.iter().map(|a| a[..].try_into().context("a preimage's length")).collect::<Result<_>>()?;
        let digits: Vec<u8> = preimages.iter().enumerate().map(|(d, p)| lamport.read(d, p).context("a preimage of no digit")).collect::<Result<_>>()?;
        let bits: Vec<bool> = digits.iter().flat_map(|v| [v & 1 == 1, v & 2 == 2]).collect();
        Ok(Asserted { proof: lichen_babe::statement::proof_from_chain(&bits, pi2, pi3), digits, bits, preimages })
    }
}

/// What `assert` put on chain.
pub struct Asserted {
    pub digits: Vec<u8>,
    pub bits: Vec<bool>,
    pub preimages: Vec<lichen_babe::reveal::Preimage>,
    pub proof: Option<ark_groth16::Proof<ark_bn254::Bn254>>,
}

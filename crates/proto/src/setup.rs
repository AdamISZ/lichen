//! The cut-and-choose's shared parts (BABE, docs/BABE_GADGET_PLAN.md),
//! as the hub-proves opening uses them ([`crate::hp`]): an opened
//! instance, the soundness a wallet asks, the dealing's and the shares'
//! encodings; and what a dispute reads off the chain: a link's
//! arguments, `assert`'s proof.

use anyhow::{ensure, Context, Result};
use lichen_babe::setup::{Secret, DIGITS, VALUES};
use lichen_babe::vsss::Dealing;
use serde::{Deserialize, Serialize};

use crate::Net;

/// An opened instance: its index, seed and secrets (hex).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Opened {
    pub i: u32,
    pub seed: String,
    pub shares: String,
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

/// A Bitcoin outpoint as the statements read one (txid in internal byte
/// order).
pub fn statement_outpoint(o: &bitcoin::OutPoint) -> lichen_ledger::OutPoint {
    use bitcoin::hashes::Hash as _;
    lichen_ledger::OutPoint { txid: o.txid.to_byte_array(), vout: o.vout }
}

/// A link's witness arguments below both signatures, consumption order.
pub fn link_args(tx: &bitcoin::Transaction) -> Vec<Vec<u8>> {
    lngap_btc::witness::witness_args_consumption_order(&tx.input[0].witness).into_iter().skip(2).collect()
}

/// What `assert` put on chain.
pub struct Asserted {
    pub digits: Vec<u8>,
    pub bits: Vec<bool>,
    pub preimages: Vec<lichen_babe::reveal::Preimage>,
    pub proof: Option<ark_groth16::Proof<ark_bn254::Bn254>>,
}

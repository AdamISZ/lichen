//! A RISC Zero 3.0 Groth16 receipt's check over substrate-bn: whether a
//! proof's points prove that the guest `image_id` halted with exit code 0
//! and wrote `journal`. The BABE guest checks the hub's counter `K` with
//! it (docs/EXIT_PLAN.md, "The statement's three branches"), with RISC
//! Zero's accelerated substrate-bn patched in: about 47M cycles, against
//! 174M for `risc0-groth16`'s arkworks (step 0).
//!
//! The points are compressed as ln-gap's native check reads them
//! (`lngap_zk::groth16`, BitVMX's verifier's input): 128 bytes, A, B, C,
//! each x little-endian with the top bit of its last byte set iff y is
//! odd; B as x.c0 then x.c1, the flag from y.c0. The verifying key, the
//! control root and id, and the claim's hashing are RISC Zero's
//! (risc0-groth16 3.0.5, risc0-zkvm 3.0.6; Apache-2.0), as there; this
//! crate's tests check that the two agree.

#![no_std]

use sha2::{Digest, Sha256};
use substrate_bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Gt, G1, G2};

/// The points' length: A and C 32 bytes, B 64.
pub const POINTS_LEN: usize = 128;

/// RISC Zero 3.0's recursion control root (`ALLOWED_CONTROL_ROOT`).
const CONTROL_ROOT: [u8; 32] = hex32("a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56");
/// RISC Zero 3.0's BN254 identity control id.
const BN254_CONTROL_ID: [u8; 32] = hex32("c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404");

/// The verifying key (risc0-groth16 3.0.5), decimal; G2 coordinates as
/// `(c1, c0)`.
const ALPHA: [&str; 2] = ["20491192805390485299153009773594534940189261866228447918068658471970481763042", "9383485363053290200918347156157836566562967994039712273449902621266178545958"];
const BETA: [&str; 4] = [
    "4252822878758300859123897981450591353533073413197771768651442665752259397132",
    "6375614351688725206403948262868962793625744043794305715222011528459656738731",
    "21847035105528745403288232691147584728191162732299865338377159692350059136679",
    "10505242626370262277552901082094356697409835680220590971873171140371331206856",
];
const GAMMA: [&str; 4] = [
    "11559732032986387107991004021392285783925812861821192530917403151452391805634",
    "10857046999023057135944570762232829481370756359578518086990519993285655852781",
    "4082367875863433681332203403145435568316851327593401208105741076214120093531",
    "8495653923123431417604973247489272438418190587263600148770280649306958101930",
];
const DELTA: [&str; 4] = [
    "1668323501672964604911431804142266013250380587483576094566949227275849579036",
    "12043754404802191763554326994664886008979042643626290185762540825416902247219",
    "7710631539206257456743780535472368339139328733484942210876916214502466455394",
    "13740680757317479711909903993315946540841369848973133181051452051592786724563",
];
const IC: [[&str; 2]; 6] = [
    ["8446592859352799428420270221449902464741693648963397251242447530457567083492", "1064796367193003797175961162477173481551615790032213185848276823815288302804"],
    ["3179835575189816632597428042194253779818690147323192973511715175294048485951", "20895841676865356752879376687052266198216014795822152491318012491767775979074"],
    ["5332723250224941161709478398807683311971555792614491788690328996478511465287", "21199491073419440416471372042641226693637837098357067793586556692319371762571"],
    ["12457994489566736295787256452575216703923664299075106359829199968023158780583", "19706766271952591897761291684837117091856807401404423804318744964752784280790"],
    ["19617808913178163826953378459323299110911217259216006187355745713323154132237", "21663537384585072695701846972542344484111393047775983928357046779215877070466"],
    ["6834578911681792552110317589222010969491336870276623105249474534788043166867", "15060583660288623605191393599883223885678013570733629274538391874953353488393"],
];

const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        _ => c - b'a' + 10,
    }
}

const fn hex32(s: &str) -> [u8; 32] {
    let s = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nib(s[2 * i]) << 4 | nib(s[2 * i + 1]);
        i += 1;
    }
    out
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// RISC Zero's tagged struct hash (`risc0_binfmt::tagged_struct`), for at
/// most four digests and two words.
fn tagged(tag: &str, down: &[[u8; 32]], data: &[u32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(sha256(&[tag.as_bytes()]));
    for d in down {
        h.update(d);
    }
    for w in data {
        h.update(w.to_le_bytes());
    }
    h.update((down.len() as u16).to_le_bytes());
    h.finalize().into()
}

/// The digest of RISC Zero's receipt claim for a guest that halted with
/// exit code 0 (`ReceiptClaim::ok(image_id, journal)`).
pub fn claim_digest(image_id: &[u8; 32], journal: &[u8]) -> [u8; 32] {
    let zero = [0u8; 32];
    let post = tagged("risc0.SystemState", &[zero], &[0]);
    let output = tagged("risc0.Output", &[sha256(&[journal]), zero], &[]);
    tagged("risc0.ReceiptClaim", &[zero, *image_id, post, output], &[0, 0])
}

fn dec(s: &str) -> Fq {
    Fq::from_str(s).expect("a field element")
}

fn g1_const(c: [&str; 2]) -> G1 {
    AffineG1::new(dec(c[0]), dec(c[1])).expect("a G1 point").into()
}

fn g2_const(c: [&str; 4]) -> G2 {
    AffineG2::new(Fq2::new(dec(c[1]), dec(c[0])), Fq2::new(dec(c[3]), dec(c[2]))).expect("a G2 point").into()
}

/// A scalar from little-endian bytes (at most 32), below the order.
fn fr_le(b: &[u8]) -> Option<Fr> {
    let mut be = [0u8; 32];
    for (i, x) in b.iter().enumerate() {
        be[31 - i] = *x;
    }
    Fr::from_slice(&be).ok()
}

/// A base field element from 32 little-endian bytes, below the modulus.
fn fq_le(b: &[u8]) -> Option<Fq> {
    let mut be = [0u8; 32];
    for (i, x) in b.iter().enumerate() {
        be[31 - i] = *x;
    }
    Fq::from_slice(&be).ok()
}

fn odd(y: Fq) -> bool {
    y.into_u256().get_bit(0).expect("bit 0")
}

/// The x of a compressed point (32 little-endian bytes) and its flag.
fn x_and_flag(b: &[u8]) -> Option<(Fq, bool)> {
    let mut x = [0u8; 32];
    x.copy_from_slice(b);
    let flag = x[31] & 0x80 != 0;
    x[31] &= 0x7f;
    Some((fq_le(&x)?, flag))
}

fn g1(b: &[u8]) -> Option<G1> {
    let (x, flag) = x_and_flag(b)?;
    let y = (x * x * x + G1::b()).sqrt()?;
    AffineG1::new(x, if odd(y) == flag { y } else { -y }).ok().map(Into::into)
}

fn g2(b: &[u8]) -> Option<G2> {
    let (c1, flag) = x_and_flag(&b[32..])?;
    let x = Fq2::new(fq_le(&b[..32])?, c1);
    let y = (x * x * x + G2::b()).sqrt()?;
    AffineG2::new(x, if odd(y.real()) == flag { y } else { -y }).ok().map(Into::into)
}

/// The proof's public inputs: the control root's halves, the claim's
/// halves (each half a little-endian integer), the BN254 control id.
fn inputs(claim: &[u8; 32]) -> Option<[Fr; 5]> {
    Some([fr_le(&CONTROL_ROOT[..16])?, fr_le(&CONTROL_ROOT[16..])?, fr_le(&claim[..16])?, fr_le(&claim[16..])?, fr_le(&BN254_CONTROL_ID)?])
}

/// Whether `points` (A, B, C compressed: [`POINTS_LEN`] bytes) prove that
/// the guest `image_id` halted with exit code 0 and wrote `journal`.
/// Points that don't decode (off the curve or its subgroup, a coordinate
/// beyond the field) don't.
pub fn verify(image_id: &[u8; 32], points: &[u8], journal: &[u8]) -> bool {
    let run = || -> Option<bool> {
        if points.len() != POINTS_LEN {
            return None;
        }
        let (a, b, c) = (g1(&points[..32])?, g2(&points[32..96])?, g1(&points[96..])?);
        let ic = IC.map(g1_const);
        let mut vk_x = ic[0];
        for (x, base) in inputs(&claim_digest(image_id, journal))?.iter().zip(&ic[1..]) {
            vk_x = vk_x + *base * *x;
        }
        // e(A, B) = e(alpha, beta) e(vk_x, gamma) e(C, delta)
        let pairs = [(a, b), (-g1_const(ALPHA), g2_const(BETA)), (-vk_x, g2_const(GAMMA)), (-c, g2_const(DELTA))];
        Some(pairing_batch(&pairs) == Gt::one())
    };
    run().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Real receipts as BitVMX's verifier takes them: the BABE guest's on
    /// a return of 60 with memo 42 (the BABE tests'), and ln-gap's
    /// withdrawal guest's on (9, 42).
    fn inputs() -> Vec<Vec<u8>> {
        [include_str!("../../proto/tests/data/babe-claim-60-42.hex"), include_str!("../../babe/tests/data/babe-60-42.hex")].iter().map(|h| hex::decode(h.trim()).unwrap()).collect()
    }

    #[test]
    fn agrees_with_ln_gaps_check() {
        for input in inputs() {
            let (id, points, journal) = lngap_zk::groth16::split_input(&input).unwrap();
            assert_eq!(claim_digest(&id, journal), lngap_zk::groth16::claim_digest(&id, journal));
            assert!(lngap_zk::groth16::verify(&id, points, journal).is_ok());
            assert!(verify(&id, points, journal));
            // each point, its flag, the image id, the journal: refused by
            // both
            let flip = |at: usize, x: u8| {
                let mut p = points.to_vec();
                p[at] ^= x;
                p
            };
            for (what, p) in [("A", flip(0, 1)), ("A's flag", flip(31, 0x80)), ("B.c0", flip(32, 1)), ("B's flag", flip(95, 0x80)), ("C", flip(96, 1)), ("C's flag", flip(127, 0x80))] {
                assert!(!verify(&id, &p, journal), "{what}");
                assert!(lngap_zk::groth16::verify(&id, &p, journal).is_err(), "{what}, ln-gap's");
            }
            let mut other = id;
            other[0] ^= 1;
            assert!(!verify(&other, points, journal));
            let mut j = journal.to_vec();
            j[0] ^= 1;
            assert!(!verify(&id, points, &j));
            assert!(!verify(&id, &points[..127], journal) && !verify(&id, &[0xff; 128], journal));
        }
    }
}

//! BABE's garbled circuit for `π ↦ r·π` (§5.6, Construction 2), `r`
//! hard-coded.
//!
//! - **The Boolean part** ([`crate::gadget`]), garbled privacy-free
//!   (π is public, Lamport-signed on chain): free XOR and NOT, one
//!   ciphertext an AND (Zahur, Rosulek, Evans 2015, privacy-free half
//!   gates). The evaluator knows every wire's value; only the labels are
//!   secret, so that she holds one label of each output, not both.
//! - **The DRE** (Theorem 4, Remark 4): for output bit `k` (`u_k`), point
//!   `i` (`r_i·π + ρ_i`) and coordinate `j`, the evaluator learns
//!   `t_ijk = D_ijk·u_k + s_ijk`. The shift `s_ijk` is a hash of the
//!   0-label, so one ciphertext `c_ijk = D_ijk + H(L⁰) − H(L¹)` serves
//!   both labels: `H(L^u) + u·c`. The constant feature's term is public,
//!   `D_ij0 − Σ_k s_ijk`, so the `s` cancel in the sum. Entries that are
//!   zero for every `r_i` (Lemma 5's zeros) are left out: `n(8n + 3)`
//!   field elements.
//! - **Decoding**: `Q_i = (Σ_k t_ijk)_j`, Jacobian, is `λ_i`-randomized
//!   `r_i·π + ρ_i`; `Σ 2^i Q_i = r·π` as `Σ 2^i ρ_i = O`.
//!
//! The input labels are the encoding key `ek`: under BABE, the Lamport
//! key whose signature on π1 is its encoding (§6.1.3).

use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField, UniformRand, Zero};
use ark_std::rand::Rng;

use crate::circuit::Gate;
use crate::field::BITS;
use crate::gadget::{circuit, BLOCKS, OUTPUTS};

pub type Label = u128;

/// The feature blocks (1 to 5: x, y, x², y², xy) each Jacobian
/// coordinate's row of `C(δ, ϕ)` reads (Lemma 5), besides the constant.
const ROWS: [&[usize]; 3] = [&[1, 2, 3], &[2, 3, 4, 5], &[1]];

/// What the evaluator keeps: the AND gates' ciphertexts, the DRE's, and
/// the constant terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Garbled {
    pub ands: Vec<Label>,
    pub dre: Vec<Fq>,
    pub constant: Vec<[Fq; 3]>,
}

/// The encoding key: each input bit's labels, for 0 and for 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoding(pub Vec<[Label; 2]>);

impl Encoding {
    /// The labels of `input`: what the garbler reveals for it.
    pub fn encode(&self, input: &[bool]) -> Vec<Label> {
        self.0.iter().zip(input).map(|(l, b)| l[*b as usize]).collect()
    }
}

impl Garbled {
    /// Its size serialized: 16 bytes a label, 32 a field element.
    pub fn size(&self) -> usize {
        16 * self.ands.len() + 32 * (self.dre.len() + 3 * self.constant.len())
    }
}

fn hash(l: Label, gate: usize) -> Label {
    let mut h = blake3::Hasher::new();
    h.update(b"lichen/babe/and");
    h.update(&l.to_le_bytes());
    h.update(&(gate as u64).to_le_bytes());
    u128::from_le_bytes(h.finalize().as_bytes()[..16].try_into().unwrap())
}

/// The shift a label gives entry (i, j) of output `k`: 64 bytes reduced,
/// so uniform in Fq.
fn shift(l: Label, k: usize, i: usize, j: usize) -> Fq {
    let mut h = blake3::Hasher::new();
    h.update(b"lichen/babe/dre");
    h.update(&l.to_le_bytes());
    h.update(&[(k as u32).to_le_bytes(), (i as u32).to_le_bytes()].concat());
    h.update(&[j as u8]);
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    Fq::from_le_bytes_mod_order(&wide)
}

/// `C(δ, ϕ)` (Lemma 5): `C·u(π)` is a Jacobian `ϕ + δπ` when
/// `x(ϕ) ≠ x(π)`, `u = (1, x, y, x², y², xy)`.
fn coeffs(delta: bool, phi: &G1Affine) -> [[Fq; 1 + BLOCKS]; 3] {
    let (x, y) = (phi.x, phi.y);
    let z = Fq::zero();
    if delta {
        let (x2, three) = (x * x, Fq::from(3u64));
        [
            [Fq::from(6u64), x2, -y.double(), x, z, z],
            [Fq::from(9u64) * y, z, -(y * y + Fq::from(9u64)), three * x * y, y, -three * x2],
            [-x, Fq::from(1u64), z, z, z, z],
        ]
    } else {
        [[x, z, z, z, z, z], [y, z, z, z, z, z], [Fq::from(1u64), z, z, z, z, z]]
    }
}

/// `ρ_0, …, ρ_{n−1}`, nonzero, uniform subject to `Σ 2^i ρ_i = O`.
fn masks<R: Rng>(rng: &mut R) -> Vec<G1Affine> {
    loop {
        let mut rho: Vec<G1Projective> = (0..BITS).map(|_| G1Projective::rand(rng)).collect();
        let sum = rho[1..].iter().rev().fold(G1Projective::zero(), |acc, p| acc.double() + p).double();
        rho[0] = -sum;
        if rho.iter().all(|p| !p.is_zero()) {
            return G1Projective::normalize_batch(&rho);
        }
    }
}

/// Garbles `π ↦ r·π`.
pub fn garble<R: Rng>(r: Fr, rng: &mut R) -> (Garbled, Encoding) {
    let c = circuit();
    let delta: Label = rng.gen();
    let mut zero: Vec<Label> = Vec::with_capacity(c.inputs + c.gates.len());
    zero.extend((0..c.inputs).map(|_| rng.gen::<Label>()));
    let mut ands = Vec::with_capacity(c.ands());
    for (g, gate) in c.gates.iter().enumerate() {
        let l = match *gate {
            Gate::Xor(a, b) => zero[a as usize] ^ zero[b as usize],
            Gate::Not(a) => zero[a as usize] ^ delta,
            Gate::And(a, b) => {
                let a0 = zero[a as usize];
                let h0 = hash(a0, g);
                ands.push(h0 ^ hash(a0 ^ delta, g) ^ zero[b as usize]);
                h0
            }
        };
        zero.push(l);
    }
    let out: Vec<Label> = c.outputs.iter().map(|w| zero[*w as usize]).collect();

    let r = r.into_bigint().to_bits_le();
    let rho = masks(rng);
    let mut dre = Vec::with_capacity(BITS * (8 * BITS + 3));
    let mut constant = Vec::with_capacity(BITS);
    for (i, phi) in rho.iter().enumerate() {
        let cf = coeffs(r[i], phi);
        let lambda = loop {
            let l = Fq::rand(rng);
            if !l.is_zero() {
                break l;
            }
        };
        let scale = [lambda.square(), lambda.square() * lambda, lambda];
        let mut terms = [Fq::zero(); 3];
        for j in 0..3 {
            let mut term = scale[j] * cf[j][0];
            for &blk in ROWS[j] {
                // D_ijk = λ-scaled C[j][blk] · 2^t
                let mut d = scale[j] * cf[j][blk];
                for t in 0..BITS {
                    let k = (blk - 1) * BITS + t;
                    let s = shift(out[k], k, i, j);
                    dre.push(d + s - shift(out[k] ^ delta, k, i, j));
                    term -= s;
                    d.double_in_place();
                }
            }
            terms[j] = term;
        }
        constant.push(terms);
    }
    let ek = Encoding(zero[..c.inputs].iter().map(|l| [*l, l ^ delta]).collect());
    (Garbled { ands, dre, constant }, ek)
}

/// Evaluates on `input` (π's bits, [`crate::gadget::input`]) and its
/// labels: `r·π`, or `r·g` if π isn't a point.
pub fn evaluate(gc: &Garbled, input: &[bool], labels: &[Label]) -> G1Projective {
    let c = circuit();
    let v = c.values(input);
    let mut label: Vec<Label> = Vec::with_capacity(v.len());
    label.extend_from_slice(labels);
    let mut ands = gc.ands.iter();
    for (g, gate) in c.gates.iter().enumerate() {
        let l = match *gate {
            Gate::Xor(a, b) => label[a as usize] ^ label[b as usize],
            Gate::Not(a) => label[a as usize],
            Gate::And(a, b) => {
                let t = ands.next().expect("an AND's ciphertext");
                let h = hash(label[a as usize], g);
                if v[a as usize] {
                    h ^ t ^ label[b as usize]
                } else {
                    h
                }
            }
        };
        label.push(l);
    }
    let out: Vec<(bool, Label)> = c.outputs.iter().map(|w| (v[*w as usize], label[*w as usize])).collect();
    assert_eq!(out.len(), OUTPUTS);

    let mut dre = gc.dre.iter();
    let mut q = Vec::with_capacity(BITS);
    for (i, terms) in gc.constant.iter().enumerate() {
        let mut xyz = *terms;
        for (j, sum) in xyz.iter_mut().enumerate() {
            for &blk in ROWS[j] {
                for t in 0..BITS {
                    let k = (blk - 1) * BITS + t;
                    let (u, l) = out[k];
                    let cipher = dre.next().expect("a DRE entry");
                    *sum += shift(l, k, i, j);
                    if u {
                        *sum += cipher;
                    }
                }
            }
        }
        q.push(G1Projective::new_unchecked(xyz[0], xyz[1], xyz[2]));
    }
    q.iter().rev().fold(G1Projective::zero(), |acc, p| acc.double() + p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadget::input;
    use ark_ec::AffineRepr;
    use std::time::Instant;

    #[test]
    fn coeffs_add_points() {
        let rng = &mut ark_std::test_rng();
        for delta in [false, true] {
            let phi: G1Affine = G1Projective::rand(rng).into();
            let pi: G1Affine = G1Projective::rand(rng).into();
            let cf = coeffs(delta, &phi);
            let u = [Fq::from(1u64), pi.x, pi.y, pi.x * pi.x, pi.y * pi.y, pi.x * pi.y];
            let row = |j: usize| cf[j].iter().zip(&u).map(|(a, b)| *a * b).sum::<Fq>();
            let got = G1Projective::new_unchecked(row(0), row(1), row(2));
            assert_eq!(got, if delta { phi + pi } else { phi.into_group() });
        }
    }

    #[test]
    fn r_times_pi() {
        let rng = &mut ark_std::test_rng();
        let r = Fr::rand(rng);
        let t = Instant::now();
        let (gc, ek) = garble(r, rng);
        let garbling = t.elapsed();
        println!(
            "garbled in {:.2?}: {} AND ciphertexts, {} DRE entries, {:.2} MiB",
            garbling,
            gc.ands.len(),
            gc.dre.len(),
            gc.size() as f64 / (1 << 20) as f64
        );
        assert_eq!(gc.dre.len() + 3 * gc.constant.len(), BITS * (8 * BITS + 3), "the paper's n(8n + 3)");
        let pi: G1Affine = G1Projective::rand(rng).into();
        let x = input(&pi);
        let t = Instant::now();
        let out = evaluate(&gc, &x, &ek.encode(&x));
        println!("evaluated in {:.2?}", t.elapsed());
        assert_eq!(out, pi * r);
        // not a point: r·g
        let mut bad = x.clone();
        bad[BITS] ^= true;
        assert_eq!(evaluate(&gc, &bad, &ek.encode(&bad)), G1Affine::generator() * r);
        // a wrong label: garbage, not r·π
        let mut labels = ek.encode(&x);
        labels[3] ^= 1;
        assert_ne!(evaluate(&gc, &x, &labels), pi * r);
    }
}

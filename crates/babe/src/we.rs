//! The witness encryption for Groth16 with π1 known (BABE §4,
//! Construction 1). With `Y = e(α, β) + e(X, γ)`, `X` the public input's
//! combination of the key's `γ_abc`:
//!
//! - at setup, `ct_setup = (r·[δ]₂, RO(r·Y) ⊕ msg)`;
//! - at proving, `ct_prove = r·π1`, from the garbled circuit;
//! - a valid proof's `e(π1, π2) − e(π3, [δ]₂) = Y`, so
//!   `e(r·π1, π2) − e(π3, r·[δ]₂) = r·Y` and `msg` follows.
//!
//! `msg` is the hashlock's preimage that `wrongly_challenged` reveals.

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;

pub type Msg = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setup {
    pub r_delta: G2Affine,
    pub masked: Msg,
}

/// `Y`: the verification equation's constant side, for `public`.
fn target(vk: &VerifyingKey<Bn254>, public: &[Fr]) -> PairingOutput<Bn254> {
    assert_eq!(public.len() + 1, vk.gamma_abc_g1.len(), "the public input's length");
    let x = public.iter().zip(&vk.gamma_abc_g1[1..]).fold(vk.gamma_abc_g1[0].into_group(), |acc, (s, g)| acc + *g * s);
    Bn254::pairing(vk.alpha_g1, vk.beta_g2) + Bn254::pairing(x.into_affine(), vk.gamma_g2)
}

/// The random oracle on `r·Y`.
fn pad(t: &PairingOutput<Bn254>) -> Msg {
    let mut bytes = Vec::new();
    t.serialize_compressed(&mut bytes).expect("serialize");
    let mut h = blake3::Hasher::new();
    h.update(b"lichen/babe/we");
    h.update(&bytes);
    *h.finalize().as_bytes()
}

fn xor(a: &Msg, b: &Msg) -> Msg {
    core::array::from_fn(|i| a[i] ^ b[i])
}

/// `ct_setup`: `msg` under the statement `public`, for the `r` the
/// garbled circuit hard-codes.
pub fn encrypt(vk: &VerifyingKey<Bn254>, public: &[Fr], msg: &Msg, r: Fr) -> Setup {
    Setup { r_delta: (vk.delta_g2 * r).into_affine(), masked: xor(msg, &pad(&(target(vk, public) * r))) }
}

/// `msg`, given `r·π1` (the garbled circuit's output) and the proof's
/// other elements. A proof that doesn't verify gives some other value.
pub fn decrypt(ct: &Setup, r_pi1: &G1Projective, proof: &Proof<Bn254>) -> Msg {
    let ry = Bn254::pairing(r_pi1.into_affine(), proof.b) - Bn254::pairing(proof.c, ct.r_delta);
    xor(&ct.masked, &pad(&ry))
}

/// π1, as the prover signs it and the garbled circuit takes it.
pub fn pi1(proof: &Proof<Bn254>) -> G1Affine {
    proof.a
}

//! The statement BABE encrypts under: a RISC Zero 3.0 Groth16 proof of the
//! receipt claim "the guest `image_id` halted with exit code 0 and wrote
//! `journal`". The key, the public inputs and the claim are ln-gap's
//! (`lngap_zk::groth16`, the native check of BitVMX's verifier), here in
//! arkworks' types.
//!
//! Under the fixed statement (`lichen_withdraw::fixed`) the journal is
//! `c ‖ D ‖ H(pk_H)`, known at setup: so are the public inputs, and the
//! hub encrypts before Alice proves.

use anyhow::Result;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, VerifyingKey};
use lngap_zk::groth16;

pub fn verifying_key() -> VerifyingKey<Bn254> {
    let k = groth16::key();
    VerifyingKey { alpha_g1: k.alpha, beta_g2: k.beta, gamma_g2: k.gamma, delta_g2: k.delta, gamma_abc_g1: k.ic.to_vec() }
}

/// The public inputs of the claim that `image_id` wrote `journal`.
pub fn public_inputs(image_id: &[u8; 32], journal: &[u8]) -> [Fr; 5] {
    groth16::public_inputs(&groth16::claim_digest(image_id, journal))
}

/// A proof from its points, compressed as BitVMX's verifier takes them
/// (128 bytes).
pub fn proof(points: &[u8]) -> Result<Proof<Bn254>> {
    let p = groth16::decode(points)?;
    Ok(Proof { a: p.a, b: p.b, c: p.c })
}

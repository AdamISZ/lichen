//! The statement BABE encrypts under, for real: a RISC Zero 3.0 Groth16
//! proof of the receipt claim "the guest `image_id` halted with exit code
//! 0 and wrote `journal`". The key, the public inputs and the claim are
//! ln-gap's (`lngap_zk::groth16`), here in arkworks' types.
//!
//! Under the hub's statement (`lichen_withdraw::hp`) the journal is
//! `c ‖ D ‖ H(O_D ‖ margin)`, known at opening: so are the public inputs,
//! and Alice garbles before anyone proves.

use anyhow::{ensure, Context, Result};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
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

/// A proof from RISC Zero's Groth16 seal (256 bytes: A, B, C, each
/// coordinate big-endian, B's as `x.c1, x.c0, y.c1, y.c0`), as
/// `lichen-r0 hp-proof` writes it: its points on the curve, in the group.
pub fn proof_from_seal(seal: &[u8]) -> Result<Proof<Bn254>> {
    ensure!(seal.len() == 256, "a Groth16 seal is 256 bytes, not {}", seal.len());
    let fq = |i: usize| -> Result<Fq> {
        let be = &seal[32 * i..32 * (i + 1)];
        let x = Fq::from_be_bytes_mod_order(be);
        ensure!(x.into_bigint().to_bytes_be() == be, "a coordinate beyond the field");
        Ok(x)
    };
    let g1 = |i: usize| -> Result<G1Affine> {
        let p = G1Affine::new_unchecked(fq(i)?, fq(i + 1)?);
        ensure!(p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve(), "not a G1 point");
        Ok(p)
    };
    let b = G2Affine::new_unchecked(Fq2::new(fq(3)?, fq(2)?), Fq2::new(fq(5)?, fq(4)?));
    ensure!(b.is_on_curve() && b.is_in_correct_subgroup_assuming_on_curve(), "not a G2 point");
    Ok(Proof { a: g1(0).context("A")?, b, c: g1(6).context("C")? })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;

    /// ln-gap's vector: a receipt of its placeholder guest on (9, 42), the
    /// seal as RISC Zero writes it.
    const SEAL: &str = "1c6a455ff5b8f2d3c0ca9eb31802250955c88065d11fec7b691f18b8210d9855128d7fd898e6113182af26563e6efd40445a16a4bd3cdaa51c24647c933edb4c1d187c8d5467a0feb82a85d379f644065673cd0bf743bf1dfe790a4f5fa4cc9f103f6ec5c6a9f044d4d13c7929af31348ad0958d809a5a57b71f1cb1808283d02a926437b087dedb1c0a27ceab343029468584c20edee5954ba81aa0846e2c5806044b9bfbbc563a93d941cf9b21a482d734cf625ea31aff8a6f92d13c8cecdb1034347d87372b0e061ae70beb1707bb523574a4fc5757b0a560a7592dd83b520e14d5bc1097c394158e0158ca467e750c46bb93b6c9f7e1aa4d6ed0025860d2";
    /// The same proof as BitVMX's verifier takes it (FairgateLabs'
    /// compression), its image id, its journal.
    const POINTS: &str = "55980d21b8181f697bec1fd16580c85509250218b39ecac0d3f2b8f55f456a1cd0838280b11c1fb7575a9a808d95d08a3431af29793cd1d444f0a9c6c56e3f109fcca45f4f0a79fe1dbf43f70bcd73560644f679d3852ab8fea067548d7c189d523bd82d59a760a5b05757fca4743552bb0717eb0be71a060e2b37877d343410";
    const ID: &str = "c2bf393e7d9cbb53a5b6f0c1bc9767d42c04f632a9824a572eb7a5d6d77cd250";

    #[test]
    fn a_seal_is_the_proof_bitvmx_reads_and_verifies() {
        let p = proof_from_seal(&hex::decode(SEAL).unwrap()).unwrap();
        let q = groth16::decode(&hex::decode(POINTS).unwrap()).unwrap();
        assert_eq!((p.a, p.b, p.c), (q.a, q.b, q.c));
        let id: [u8; 32] = hex::decode(ID).unwrap().try_into().unwrap();
        let journal = [9, 0, 0, 0, 42, 0, 0, 0];
        assert!(Groth16::<Bn254>::verify(&verifying_key(), &public_inputs(&id, &journal), &p).unwrap());
        assert!(!Groth16::<Bn254>::verify(&verifying_key(), &public_inputs(&id, &[9, 0, 0, 0, 43, 0, 0, 0]), &p).unwrap());
        let mut bad = hex::decode(SEAL).unwrap();
        bad[31] ^= 1;
        assert!(proof_from_seal(&bad).is_err());
    }
}

//! The statement BABE encrypts under, for real: a RISC Zero 3.1 Groth16
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

    /// ln-gap's vector (its `tests/data/withdraw-9-42.hex`): a RISC Zero 3.1
    /// receipt of its withdrawal guest on (9, 42), the seal as RISC Zero
    /// writes it.
    const SEAL: &str = "0ba8e7d2d9c2827cb8235019a650a7afc68995e98244023b6ce345bab42394ce257d716d952235c977936cb9b3eb54f3f57ff337ca939c1b1f574bbff50f4ee404d594f91d4acf9545ef1b55f828f00acd6910d0d013b55447bb59220b671d8909f3f293908350d1373205c65280d53f3c3cf42ce50d36caa47a8475e82a3b42027938696128aeba14fb4f42253c7ca89d697751a0f31da6947506c56a3758501480fae8b4a8946e142162907a4f4ea3fc40544e2681d720c99c1d70035997510c55e58beb1602c2466d584be32d91b19d61fdbc47ddbd9e130a37796c807c4d2945323d6a971598cb1569ddcefafeb858373ff11cbcc924a316b09283d166af";
    /// The same proof decoded independently, from ln-gap's compressed
    /// points (FairgateLabs' encoding); its image id, its journal.
    const POINTS: &str = "ce9423b4ba45e36c3b024482e99589c6afa750a6195023b87c82c2d9d2e7a80b423b2ae875847aa4ca360de52cf43c3c3fd58052c6053237d150839093f2f309891d670b2259bb4754b513d0d01069cd0af028f8551bef4595cf4a1df994d5844d7c806c79370a139ebddd47bcfd619db1912de34b586d46c20216eb8be5558c";
    const ID: &str = "c7971df34f391e8fbfe45012e93372dca29d9524b28004a3ed3b75de217eb541";

    #[test]
    fn a_seal_decodes_to_the_same_points_and_verifies() {
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

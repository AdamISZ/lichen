//! BABE's cryptography (ePrint 2026/065; docs/BABE_GADGET_PLAN.md, step
//! 4): the witness encryption for Groth16 ([`we`]) and the garbled
//! circuit that computes its `ct_prove = r·π1` from π1's bits
//! ([`garble`]), its Boolean part ([`gadget`]) built over BN254's base
//! field in gates ([`field`], [`circuit`]).
//!
//! The verifier (the hub) garbles with a fresh `r` and encrypts `msg`
//! under the contract's statement; the prover (Alice) signs π1, is given
//! its labels, evaluates, and decrypts `msg` if and only if she holds a
//! valid proof for the statement.
//!
//! Honest setup only, so far: no cut-and-choose, no VSSS.

pub mod circuit;
pub mod field;
pub mod gadget;
pub mod garble;
pub mod we;

#[cfg(test)]
mod tests {
    use crate::gadget::input;
    use crate::garble::{evaluate, garble};
    use crate::we::{decrypt, encrypt, pi1};
    use ark_bn254::{Bn254, Fr};
    use ark_ff::{Field, UniformRand};
    use ark_groth16::Groth16;
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    /// A statement to prove: knowledge of a cube root of the public `y`.
    #[derive(Clone)]
    struct Cube {
        x: Option<Fr>,
        y: Option<Fr>,
    }

    impl ConstraintSynthesizer<Fr> for Cube {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
            let x2 = cs.new_witness_variable(|| self.x.map(|x| x.square()).ok_or(SynthesisError::AssignmentMissing))?;
            let y = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + x2)?;
            cs.enforce_constraint(lc!() + x2, lc!() + x, lc!() + y)?;
            Ok(())
        }
    }

    /// BABE off chain: the hub garbles and encrypts; Alice, with a proof,
    /// evaluates on her π1's labels and decrypts `msg`.
    #[test]
    fn a_valid_proof_decrypts_msg() {
        let rng = &mut StdRng::seed_from_u64(1);
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(Cube { x: None, y: None }, rng).unwrap();
        let x = Fr::from(5u64);
        let y = x * x * x;
        let proof = Groth16::<Bn254>::prove(&pk, Cube { x: Some(x), y: Some(y) }, rng).unwrap();
        assert!(Groth16::<Bn254>::verify(&vk, &[y], &proof).unwrap());

        // the hub, at setup
        let r = Fr::rand(rng);
        let msg = [7u8; 32];
        let (gc, ek) = garble(r, rng);
        let ct = encrypt(&vk, &[y], &msg, r);

        // Alice: π1's bits signed; the hub reveals their labels
        let bits = input(&pi1(&proof));
        let r_pi1 = evaluate(&gc, &bits, &ek.encode(&bits));
        assert_eq!(decrypt(&ct, &r_pi1, &proof), msg);

        // a valid proof, of another statement: no msg
        let x1 = x + Fr::from(1u64);
        let other = Groth16::<Bn254>::prove(&pk, Cube { x: Some(x1), y: Some(x1 * x1 * x1) }, rng).unwrap();
        let bits = input(&pi1(&other));
        let r_pi1 = evaluate(&gc, &bits, &ek.encode(&bits));
        assert_ne!(decrypt(&ct, &r_pi1, &other), msg);
        // the same proof under another statement's encryption: no msg
        let ct2 = encrypt(&vk, &[y + Fr::from(1u64)], &msg, r);
        let bits = input(&pi1(&proof));
        let r_pi1 = evaluate(&gc, &bits, &ek.encode(&bits));
        assert_ne!(decrypt(&ct2, &r_pi1, &proof), msg);
    }
}

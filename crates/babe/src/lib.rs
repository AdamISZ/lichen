//! BABE's cryptography (ePrint 2026/065; agent notes:
//! docs/BABE_GADGET_PLAN.md, step 4): the witness encryption for Groth16
//! ([`we`]) and the garbled circuit that computes its `ct_prove = r·π1`
//! from π1's bits ([`garble`]), its Boolean part ([`gadget`]) built over
//! BN254's base field in gates ([`field`], [`circuit`]).
//!
//! The verifier (the hub) garbles with a fresh `r` and encrypts `msg`
//! under the contract's statement; the prover (Alice) signs π1, is given
//! its labels, evaluates, and decrypts `msg` if and only if she holds a
//! valid proof for the statement.
//!
//! The setup is checked by cut-and-choose ([`setup`]; both sides of it,
//! [`opening`]), the instances' input secrets shared ([`vsss`]) so that
//! one set revealed on chain opens every kept instance; the garbler
//! reveals it in `challenge_assert` by completing the prover's adaptor
//! pre-signatures ([`reveal`]). Here the roles are swapped ([`graph`]):
//! Alice garbles and the hub proves (the
//! mock statement, [`statement`]; a RISC Zero receipt's Groth16 form,
//! [`risc0`]); the transactions, on `lichen_contract`, are [`graph`]'s:
//! an L2's front, then BABE's tail.

pub mod circuit;
pub mod field;
pub mod gadget;
pub mod garble;
pub mod hexbytes;
pub mod graph;
pub mod opening;
pub mod reveal;
pub mod risc0;
pub mod setup;
pub mod statement;
pub mod vsss;
pub mod we;

#[cfg(test)]
mod tests {
    use crate::gadget::input;
    use crate::garble::{evaluate, garble};
    use crate::setup::{check_opened, choose, digits, instance, Secret, DIGITS, VALUES};
    use crate::vsss::{deal, interpolate, scalar};
    use crate::we::{decrypt, encrypt, pi1};
    use ark_bn254::{Bn254, Fr};
    use ark_ff::{Field, UniformRand};
    use ark_groth16::Groth16;
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use k256::ProjectivePoint;

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

    /// The setup by cut-and-choose over shared secrets, then a dispute's
    /// reveal: Alice keeps M of N, checks the rest, and with the secrets
    /// revealed for π1's bits opens a kept instance, even with another
    /// kept one false.
    #[test]
    fn cut_and_choose_with_shared_secrets() {
        let rng = &mut StdRng::seed_from_u64(4);
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(Cube { x: None, y: None }, rng).unwrap();
        let x = Fr::from(3u64);
        let y = [x * x * x];
        let proof = Groth16::<Bn254>::prove(&pk, Cube { x: Some(x), y: Some(y[0]) }, rng).unwrap();
        let (n, m) = (6u64, 2u64);

        // the hub: the sharing, N instances, their commitments
        let (dealer, dealing) = deal(DIGITS, (n - m) as usize, rng);
        let seeds: Vec<[u8; 32]> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
        // instance 1 a lie, under another statement: cut-and-choose can't
        // tell a kept one, so Alice keeps it below
        let wrong = [y[0] + Fr::from(1u64)];
        let made: Vec<_> = (1..=n).map(|i| instance(&seeds[i as usize - 1], &dealer.shares(i), &vk, if i == 1 { &wrong } else { &y })).collect();
        let commitments: Vec<_> = made.iter().map(|(inst, _)| inst.commitment()).collect();

        // Alice keeps M; here, to test the lie, instance 1 among them
        let mut kept: Vec<u64> = choose(n as usize, m as usize, rng).iter().map(|k| *k as u64 + 1).collect();
        if !kept.contains(&1) {
            kept[0] = 1;
            kept.sort();
        }
        let opened: Vec<u64> = (1..=n).filter(|i| !kept.contains(i)).collect();
        // the hub opens the others: Alice checks their shares, rebuilds them
        let shares: Vec<(u64, Vec<[Secret; VALUES]>)> = opened.iter().map(|i| (*i, dealer.shares(*i))).collect();
        assert!(dealing.verify(&shares, rng));
        for (i, s) in &shares {
            assert!(check_opened(&commitments[*i as usize - 1], &seeds[*i as usize - 1], s, &vk, &y));
        }
        // a lie in an opened instance is caught
        assert!(!check_opened(&commitments[0], &seeds[0], &dealer.shares(1), &vk, &y));
        // an instance as sent and kept
        let bytes = made[1].0.to_bytes();
        assert_eq!(crate::setup::Instance::from_bytes(&bytes).as_ref(), Some(&made[1].0));
        assert!(crate::setup::Instance::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        // A commitment to malformed lengths is not a safe kept circuit.
        // Refuse it before funding, not by panicking during a dispute.
        for part in 0..4 {
            let mut bad = made[1].0.clone();
            match part {
                0 => { bad.gc.ands.pop(); }
                1 => { bad.gc.dre.pop(); }
                2 => { bad.gc.constant.pop(); }
                _ => { bad.table.pop(); }
            }
            assert!(!bad.has_shape());
            assert!(crate::setup::Instance::from_bytes(&bad.to_bytes()).is_none());
        }
        // the kept instances, as committed
        for k in &kept {
            assert_eq!(made[*k as usize - 1].0.commitment(), commitments[*k as usize - 1]);
        }

        // the dispute: π1's digits signed, the hub reveals their secrets
        let pi = input(&pi1(&proof));
        let ds = digits(&pi);
        let revealed: Vec<Secret> = ds.iter().enumerate().map(|(j, v)| dealer.reveal(j, *v)).collect();
        for (j, v) in ds.iter().enumerate() {
            assert_eq!(ProjectivePoint::GENERATOR * scalar(&revealed[j]).unwrap(), dealing.point(j, *v), "the adaptor point's");
        }
        let of_digits: Vec<(u64, Vec<Secret>)> = shares.iter().map(|(i, s)| (*i, s.iter().zip(&ds).map(|(p, v)| p[*v as usize]).collect())).collect();
        let opens: Vec<bool> = kept
            .iter()
            .map(|k| {
                let (inst, _) = &made[*k as usize - 1];
                let secrets = interpolate(*k, &of_digits, &revealed).unwrap();
                let r_pi1 = evaluate(&inst.gc, &pi, &inst.labels(&pi, &secrets));
                inst.is_msg(&decrypt(&inst.ct, &r_pi1, &proof))
            })
            .collect();
        assert_eq!(opens, kept.iter().map(|k| *k != 1).collect::<Vec<_>>(), "the true kept instance opens, the lie doesn't");

        // The hub's answer tries every kept instance, whatever fails of
        // those before: missing, not an instance, not of the circuit's
        // shape, panicking, a lie; the true one, last, answers.
        let true_k = *kept.iter().find(|k| **k != 1).unwrap();
        let (good, _) = &made[true_k as usize - 1];
        let mut short = good.clone();
        short.gc.ands.pop();
        let bytes = |k: u64| Ok(made[k as usize - 1].0.to_bytes());
        let tries: Vec<(u64, anyhow::Result<Vec<u8>>)> = vec![
            (true_k, Err(anyhow::anyhow!("no such file"))),
            (true_k, Ok(good.to_bytes()[..100].to_vec())),
            (true_k, Ok(short.to_bytes())),
            (1, bytes(1)),
            (true_k, bytes(true_k)),
        ];
        let mut failures = Vec::new();
        let (k, msg) = crate::setup::answer(tries, &of_digits, &revealed, &pi, &proof, |i, e| failures.push((i, e.to_string()))).unwrap();
        assert_eq!(k, 4);
        assert!(good.is_msg(&msg));
        assert_eq!(failures.len(), 4, "{failures:?}");
        assert!(crate::setup::answer(vec![(1, bytes(1))], &of_digits, &revealed, &pi, &proof, |_, _| ()).is_none());
        // an instance whose evaluation would panic fails as any other
        let e = crate::setup::kept_msg(&short, true_k, &of_digits, &revealed, &pi, &proof).unwrap_err();
        assert!(e.to_string().contains("shape"), "{e}");
        let e = crate::setup::kept_msg(good, true_k, &of_digits, &revealed, &pi[..8], &proof).unwrap_err();
        assert!(e.to_string().contains("panicked"), "{e}");
    }
}

//! BABE on a real proof: the fixed statement's guest (r0/babe-guest)
//! proved and wrapped on a return of 60 with memo 42 (r0/guests/README.md),
//! its Groth16 receipt as BitVMX's verifier takes it (`lichen-r0
//! bitvmx-input`): the image id, the points, the journal `c ‖ D ‖ H(pk_H)`.

use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use lichen_babe::gadget::input;
use lichen_babe::garble::{evaluate, garble};
use lichen_babe::risc0::{proof, public_inputs, verifying_key};
use lichen_babe::we::{decrypt, encrypt, pi1};
use lngap_zk::groth16::{claim_digest, split_input};

#[test]
fn a_risc0_proof_decrypts_msg() {
    let data = hex::decode(include_str!("data/babe-60-42.hex").trim()).unwrap();
    let (id, points, journal) = split_input(&data).unwrap();
    assert_eq!(hex::encode(id), include_str!("../../../r0/guests/babe.id").trim(), "the BABE guest's");
    assert_eq!(journal.len(), 68, "c ‖ D ‖ H(pk_H)");
    assert_eq!(
        hex::encode(claim_digest(&id, journal)),
        "5a323805c794a61d7a07d8640b7d154a05ee33a68173b5e919ad12df75da72c6",
        "the claim digest the host printed"
    );
    let vk = verifying_key();
    let x = public_inputs(&id, journal);
    let pf = proof(points).unwrap();
    assert!(Groth16::<Bn254>::verify(&vk, &x, &pf).unwrap());

    // the hub, at setup: the journal is known before the proof
    let rng = &mut StdRng::seed_from_u64(2);
    let r = Fr::rand(rng);
    let msg = [9u8; 32];
    let (gc, ek) = garble(r, rng);
    let ct = encrypt(&vk, &x, &msg, r);

    // Alice: π1 signed, its labels revealed
    let bits = input(&pi1(&pf));
    let r_pi1 = evaluate(&gc, &bits, &ek.encode(&bits));
    assert_eq!(decrypt(&ct, &r_pi1, &pf), msg);

    // another contract's journal (D changed): the proof doesn't open it
    let mut other = journal.to_vec();
    other[4] ^= 1;
    let ct = encrypt(&vk, &public_inputs(&id, &other), &msg, r);
    assert_ne!(decrypt(&ct, &r_pi1, &pf), msg);
}

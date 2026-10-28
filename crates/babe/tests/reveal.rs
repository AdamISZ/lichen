//! The reveal on regtest, under mainnet's relay policy: Alice asserts
//! π1's digits under her Lamport key, the hub reveals their secrets in
//! `challenge_assert` by completing her pre-signatures, and Alice reads
//! them from the mined transaction. And the stack limit that makes it two
//! bits a step.

use lichen_babe::reveal::{challenge_args, challenge_leaf, check_presigs, complete, extract, points, AdaptorKeys, LamportKey};
use lichen_babe::setup::{Secret, DIGITS};
use lichen_babe::vsss::{deal, scalar};
use lngap_btc::bitcoin::opcodes::all::*;
use lngap_btc::bitcoin::script::Builder;
use lngap_btc::bitcoin::{absolute, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxOut, Witness};
use lngap_btc::keys::{xonly, Seed};
use lngap_btc::regtest::Regtest;
use lngap_btc::secp256k1::SECP256K1;
use lngap_btc::sighash::{sign_tapscript, tapscript_sighash};
use lngap_btc::taptree::{Leaf, TapTree};
use lngap_btc::tx::{build_tx, Timelock};
use lngap_btc::witness::{witness_args_consumption_order, WitnessStack};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn one_leaf(name: &str, script: ScriptBuf) -> TapTree {
    TapTree::new(vec![Leaf::new(name, script, Timelock::NONE)]).unwrap()
}

fn spend(prev: OutPoint, value: Amount, to: ScriptBuf) -> Transaction {
    build_tx(&[(prev, Sequence::MAX)], vec![TxOut { value, script_pubkey: to }], absolute::LockTime::ZERO)
}

fn witness(args: &[Vec<u8>], tree: &TapTree, name: &str) -> Witness {
    let mut w = WitnessStack::new();
    w.extend(args.iter().cloned());
    w.build(&tree.leaf(name).unwrap().script, &tree.control_block(name).unwrap())
}

#[test]
fn challenge_assert_reveals_the_asserted_secrets() {
    let rt = Regtest::start_standard().unwrap();
    let rng = &mut ChaCha20Rng::seed_from_u64(6);

    // setup: the hub deals (N − M = 2 here), Alice makes her keys
    let (dealer, dealing) = deal(DIGITS, 2, rng);
    let alice = Seed::from_label("alice");
    let lamport = LamportKey::new(&alice, DIGITS);
    let lpub = lamport.public();
    let akeys = AdaptorKeys::new(&alice, DIGITS);
    let hub = Seed::from_label("hub").keypair("challenge");
    let hub_out = ScriptBuf::new_p2tr(SECP256K1, xonly(&hub), None);

    // assert spends a funded output under her Lamport check; its output
    // is challenge_assert's
    let assert_tree = one_leaf("assert", lpub.verify(Builder::new()).push_opcode(OP_PUSHNUM_1).into_script());
    let challenge_tree = one_leaf("challenge", challenge_leaf(&lpub, &akeys.public(), &xonly(&hub)));
    let (funded, _) = rt.fund(&assert_tree.script_pubkey(), Amount::from_sat(1_000_000)).unwrap();
    let mut assert_tx = spend(funded, Amount::from_sat(980_000), challenge_tree.script_pubkey());
    let challenge_prev = assert_tx.output[0].clone();
    let mut challenge_tx = spend(OutPoint { txid: assert_tx.compute_txid(), vout: 0 }, Amount::from_sat(930_000), hub_out);

    // Alice pre-signs challenge_assert, before anything is posted; the
    // hub checks
    let leaf = &challenge_tree.leaf("challenge").unwrap().script;
    let msg = tapscript_sighash(&challenge_tx, 0, std::slice::from_ref(&challenge_prev), leaf).unwrap();
    let pts = points(&dealing);
    let presigs = akeys.presign(&msg, &pts);
    assert!(check_presigs(&akeys.public(), &msg, &pts, &presigs));

    // Alice asserts π1's digits
    let digits: Vec<u8> = (0..DIGITS).map(|_| (rng.next_u32() % 4) as u8).collect();
    let preimages = lamport.sign(&digits);
    assert_tx.input[0].witness = witness(&preimages.iter().map(|p| p.to_vec()).collect::<Vec<_>>(), &assert_tree, "assert");
    let assert_vsize = assert_tx.vsize();
    let (assert_id, _) = rt.send_and_confirm(&assert_tx).unwrap();

    // the hub reads her preimages from the chain, completes the selected
    // pre-signatures with their secrets, and signs
    let posted: Vec<[u8; 20]> =
        witness_args_consumption_order(&rt.get_tx(&assert_id).unwrap().input[0].witness).iter().map(|a| a[..].try_into().unwrap()).collect();
    let read: Vec<u8> = posted.iter().enumerate().map(|(d, p)| lpub.read(d, p).unwrap()).collect();
    assert_eq!(read, digits);
    let secrets: Vec<Secret> = read.iter().enumerate().map(|(d, v)| dealer.reveal(d, *v)).collect();
    let sigs = complete(&presigs, &read, &secrets);
    let hub_sig = sign_tapscript(&hub, &challenge_tx, 0, std::slice::from_ref(&challenge_prev), leaf).unwrap();

    // a completion for the other value of a digit doesn't satisfy the leaf
    let mut wrong = read.clone();
    wrong[17] ^= 1;
    let mut bad = sigs.clone();
    bad[17] = complete(&presigs[17..18], &wrong[17..18], &[dealer.reveal(17, wrong[17])])[0];
    challenge_tx.input[0].witness = witness(&challenge_args(&posted, &bad, &hub_sig), &challenge_tree, "challenge");
    let err = rt.test_accept(&challenge_tx).unwrap_err();
    assert!(err.contains("Invalid Schnorr signature"), "{err}");

    let args = challenge_args(&posted, &sigs, &hub_sig);
    assert_eq!(args.len(), 2 * DIGITS + 1, "509 elements, within the 1,000");
    challenge_tx.input[0].witness = witness(&args, &challenge_tree, "challenge");
    let challenge_vsize = challenge_tx.vsize();
    let (challenge_id, _) = rt.send_and_confirm(&challenge_tx).unwrap();
    println!("assert: {assert_vsize} vB; challenge_assert: {challenge_vsize} vB, leaf {} B", leaf.len());

    // Alice reads the secrets of the digits she asserted, and only those
    let mined = rt.get_tx(&challenge_id).unwrap();
    let (got, revealed) = extract(&lpub, &presigs, &witness_args_consumption_order(&mined.input[0].witness)).unwrap();
    assert_eq!(got, digits);
    assert_eq!(revealed, secrets);
    for (d, (v, t)) in got.iter().zip(&revealed).enumerate() {
        assert_eq!(k256::ProjectivePoint::GENERATOR * scalar(t).unwrap(), dealing.point(d, *v), "the committed f(0)");
    }
}

/// Tapscript's initial stack: 1,000 elements pass, 1,017 (bit by bit:
/// a preimage and a signature for each of π1's 508 bits, and the hub's
/// signature) don't.
#[test]
fn the_initial_stack_is_at_most_1000() {
    let rt = Regtest::start_standard().unwrap();
    let try_with = |n: usize| {
        let script = (0..n / 2).fold(Builder::new(), |b, _| b.push_opcode(OP_2DROP));
        let script = if n % 2 == 1 { script.push_opcode(OP_DROP) } else { script }.push_opcode(OP_PUSHNUM_1).into_script();
        let tree = one_leaf("drop", script);
        let (funded, _) = rt.fund(&tree.script_pubkey(), Amount::from_sat(100_000)).unwrap();
        let mut tx = spend(funded, Amount::from_sat(90_000), tree.script_pubkey());
        tx.input[0].witness = witness(&vec![vec![1u8]; n], &tree, "drop");
        rt.test_accept(&tx)
    };
    assert!(try_with(1000).is_ok());
    let err = try_with(1017).unwrap_err();
    assert!(err.contains("Stack size limit exceeded"), "{err}");
}

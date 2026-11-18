//! A one-time signature's digits on regtest, under mainnet's relay policy:
//! the script reads each digit as a number clamped to 15, so a digit
//! written 16 verifies as 15, and the statement must read it so too
//! (`lichen_statement::script_digit`): else a holder's request that
//! Bitcoin accepted would be one the hub can't prove an exit of.

use lichen_babe::graph::verify_drop;
use lichen_btc::bitcoin::script::Builder;
use lichen_btc::bitcoin::{Amount, TxOut};
use lichen_btc::regtest::Regtest;
use lichen_btc::taptree::{Leaf, TapTree};
use lichen_btc::tx::{build_spend, Timelock};
use lichen_btc::witness::WitnessStack;
use lichen_statement::script_digit;
use lichen_wots::{WotsParams, WotsSecret};

#[test]
fn bitcoin_reads_a_digit_as_the_statement_does() {
    let rt = Regtest::start_standard().unwrap();
    let sk = WotsSecret::from_entropy(WotsParams::for_bytes(4), [5; 32]);
    let leaf = verify_drop(Builder::new(), &sk.public()).push_int(1).into_script();
    let tree = TapTree::new(vec![Leaf::new("w", leaf.clone(), Timelock::NONE)]).unwrap();
    let sink = TapTree::new(vec![Leaf::new("x", Builder::new().push_int(1).into_script(), Timelock::NONE)]).unwrap().script_pubkey();
    let spend = |items: Vec<Vec<u8>>| {
        let (op, _) = rt.fund(&tree.script_pubkey(), Amount::from_sat(50_000)).unwrap();
        let out = TxOut { value: Amount::from_sat(40_000), script_pubkey: sink.clone() };
        let mut tx = build_spend(op, &Timelock::NONE, vec![out]);
        let mut w = WitnessStack::new();
        w.extend(items);
        tx.input[0].witness = w.build(&leaf, &tree.control_block("w").unwrap());
        tx
    };
    // A message with 15s among its digits.
    let msg = 0x0f3f_f0ffu32.to_be_bytes();
    let items = sk.sign(&msg).unwrap().consumption_order();
    let fifteen = items.iter().position(|i| i.as_slice() == [15]).unwrap();
    let read = |items: &[Vec<u8>]| -> Option<Vec<u8>> {
        // Consumption order: digit, hash, last digit first.
        let digits: Option<Vec<u8>> = items.iter().step_by(2).rev().map(|d| script_digit(d)).collect();
        Some(digits?[..8].chunks(2).map(|p| (p[0] << 4) | p[1]).collect())
    };
    assert_eq!(read(&items), Some(msg.to_vec()));
    // Each encoding of 15 that relays, the statement reads as 15.
    for written in [vec![16], vec![0x7f]] {
        let mut loose = items.clone();
        loose[fifteen] = written.clone();
        rt.test_accept(&spend(loose.clone())).unwrap_or_else(|e| panic!("{written:?}: {e}"));
        assert_eq!(read(&loose), Some(msg.to_vec()), "{written:?}");
    }
    // A nonminimal one is valid in a block (minimal numbers are only
    // policy in tapscript), though it doesn't relay: read as 15 too.
    let mut nonminimal = items.clone();
    nonminimal[fifteen] = vec![15, 0];
    assert!(rt.test_accept(&spend(nonminimal.clone())).is_err());
    assert_eq!(read(&nonminimal), Some(msg.to_vec()));
    // A negative digit, Bitcoin refuses, and the statement reads nothing.
    let mut negative = items.clone();
    negative[fifteen] = vec![0x81];
    assert!(rt.test_accept(&spend(negative.clone())).is_err());
    assert_eq!(read(&negative), None);
}

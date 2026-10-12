//! The Esplora backend against the RPC one, on one regtest chain: the
//! same answers to every query, and a broadcast through Esplora reaching
//! the node. Needs Blockstream's electrs (`LICHEN_ELECTRS`, or `electrs`
//! on the PATH).

use bitcoin::{Amount, OutPoint, Transaction, TxIn, TxOut};
use lichen_chain::electrs::Electrs;
use lichen_chain::{Chain, Net};
use lngap_btc::regtest::Regtest;

#[test]
fn esplora_answers_as_the_node_does() {
    let rt = Regtest::start().unwrap();
    let mut e = Electrs::start(rt.datadir(), rt.rpc_url()).unwrap();
    let node = Chain::connect(rt.rpc_url(), rt.cookie(), "alice").unwrap();
    let esplora = Chain::esplora(&e.url, Net::Regtest).unwrap();
    assert_eq!(esplora.height().unwrap(), node.height().unwrap());

    // a coin for one of the node wallet's scripts, confirmed in one block
    let spk = node.new_spk().unwrap();
    let (op, out) = rt.fund(&spk, Amount::from_sat(100_000)).unwrap();
    e.wait_synced(rt.datadir(), rt.rpc_url()).unwrap();
    let h = node.height().unwrap();
    assert_eq!(esplora.confirmations(&op.txid).unwrap(), 1);
    assert_eq!(esplora.coins_of(&spk).unwrap(), vec![(op, out.clone(), Some(h))]);
    assert!(esplora.unspent(&op).unwrap());
    assert_eq!(esplora.get_tx(&op.txid).map(|t| t.compute_txid()), Some(op.txid));

    // spent through Esplora: the spend is unconfirmed, the coin gone
    let to = node.new_spk().unwrap();
    let spend = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn { previous_output: op, sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME, ..Default::default() }],
        output: vec![TxOut { value: Amount::from_sat(99_000), script_pubkey: to.clone() }],
    };
    let spend = node.sign_mine(&spend, &[(op, out)]).unwrap();
    let txid = esplora.broadcast(&spend).unwrap();
    assert!(node.get_tx(&txid).is_some(), "the node has it");
    assert!(!esplora.unspent(&op).unwrap(), "spent in the mempool");
    assert_eq!(esplora.confirmations(&txid).unwrap(), 0);
    let new = OutPoint { txid, vout: 0 };
    assert_eq!(esplora.coins_of(&to).unwrap().iter().map(|c| (c.0, c.2)).collect::<Vec<_>>(), vec![(new, None)]);
    rt.mine(2).unwrap();
    e.wait_synced(rt.datadir(), rt.rpc_url()).unwrap();
    assert_eq!(esplora.confirmations(&txid).unwrap(), 2);
    assert_eq!(esplora.confirmations(&txid).unwrap(), node.confirmations(&txid).unwrap());
    assert!(esplora.new_spk().is_err(), "no wallet on Esplora");
}

/// A fee budget (one key's P2TR coins): found by script on either backend,
/// split into an exact coin, its change back to the budget.
#[test]
fn a_fee_budget_on_either_backend() {
    use lichen_chain::{Fees, KeyFees};
    let rt = Regtest::start().unwrap();
    let mut e = Electrs::start(rt.datadir(), rt.rpc_url()).unwrap();
    let node = Chain::connect(rt.rpc_url(), rt.cookie(), "alice").unwrap();
    let esplora = Chain::esplora(&e.url, Net::Regtest).unwrap();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let fees = KeyFees { keypair: bitcoin::key::Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap(), feerate: 2 };
    let spk = fees.spk();
    node.watch(&spk).unwrap();
    rt.fund(&spk, Amount::from_sat(20_000)).unwrap();
    e.wait_synced(rt.datadir(), rt.rpc_url()).unwrap();
    for chain in [&node, &esplora] {
        assert_eq!(fees.balance(chain).unwrap(), Amount::from_sat(20_000));
    }
    // an exact coin, through the node; its change back to the budget
    let (op, coin) = fees.exact_coin(&node, Amount::from_sat(2_000)).unwrap();
    assert_eq!(coin.value, Amount::from_sat(2_000));
    let mut coins: Vec<_> = node.coins_of(&spk).unwrap().into_iter().map(|c| (c.0.txid, c.1.value, c.2)).collect();
    coins.sort_by_key(|c| c.1);
    assert_eq!(coins, vec![(op.txid, Amount::from_sat(2_000), None), (op.txid, Amount::from_sat(20_000 - 2_000 - 320), None)]);
    rt.mine(1).unwrap();
    e.wait_synced(rt.datadir(), rt.rpc_url()).unwrap();
    assert_eq!(esplora.coins_of(&spk).unwrap().len(), 2);
    assert_eq!(fees.balance(&esplora).unwrap(), fees.balance(&node).unwrap());
    // the budget's coins spend through Esplora too
    let (op2, _) = fees.exact_coin(&esplora, Amount::from_sat(1_000)).unwrap();
    assert!(node.get_tx(&op2.txid).is_some());
}

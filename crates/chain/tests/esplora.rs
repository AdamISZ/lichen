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

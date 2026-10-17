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

/// How the liar lies about its one transaction.
#[derive(Clone, Copy)]
enum Lie {
    /// The same txid with another witness: a move never broadcast.
    Witness,
    /// Confirmed, but in another block.
    Block,
}

/// An Esplora server that lies about `txid` and forwards everything else to
/// `upstream`; its URL.
fn liar(upstream: &str, txid: bitcoin::Txid, fake: Transaction, lie: Lie) -> String {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    let upstream = upstream.trim_end_matches('/').to_string();
    std::thread::spawn(move || {
        for mut req in server.incoming_requests() {
            let path = req.url().to_string();
            let reply = |body: Vec<u8>| tiny_http::Response::from_data(body);
            match lie {
                Lie::Witness if path == format!("/tx/{txid}/raw") => {
                    let _ = req.respond(reply(bitcoin::consensus::serialize(&fake)));
                    continue;
                }
                Lie::Block if path == format!("/tx/{txid}/status") => {
                    let body = format!(r#"{{"confirmed":true,"block_height":1,"block_hash":"{}","block_time":0}}"#, "11".repeat(32));
                    let _ = req.respond(reply(body.into_bytes()));
                    continue;
                }
                _ => {}
            }
            let r = if *req.method() == tiny_http::Method::Post {
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                ureq::post(&format!("{upstream}{path}")).send_string(&body)
            } else {
                ureq::get(&format!("{upstream}{path}")).call()
            };
            let (status, body) = match r {
                Ok(r) => (r.status(), r),
                Err(ureq::Error::Status(c, r)) => (c, r),
                Err(_) => {
                    let _ = req.respond(tiny_http::Response::empty(502));
                    continue;
                }
            };
            let mut bytes = vec![];
            let _ = std::io::Read::read_to_end(&mut body.into_reader(), &mut bytes);
            let _ = req.respond(tiny_http::Response::from_data(bytes).with_status_code(status));
        }
    });
    url
}

/// Two servers, neither trusted alone: one showing a transaction with
/// another witness (as a lying server would show a move never broadcast)
/// gets it read as unknown, and one placing it in another block gets its
/// confirmation refused; the honest pair reads as one.
#[test]
fn two_servers_neither_trusted_alone() {
    let rt = Regtest::start().unwrap();
    let mut e = Electrs::start(rt.datadir(), rt.rpc_url()).unwrap();
    let node = Chain::connect(rt.rpc_url(), rt.cookie(), "alice").unwrap();
    let (op, _) = rt.fund(&node.new_spk().unwrap(), Amount::from_sat(100_000)).unwrap();
    e.wait_synced(rt.datadir(), rt.rpc_url()).unwrap();
    // the funding, its witness altered: the same txid, another wtxid
    let real = node.get_tx(&op.txid).unwrap();
    let mut fake = real.clone();
    let i = fake.input.iter().position(|i| !i.witness.is_empty()).expect("a segwit input");
    let mut items: Vec<Vec<u8>> = fake.input[i].witness.iter().map(|w| w.to_vec()).collect();
    items[0][5] ^= 1;
    fake.input[i].witness = bitcoin::Witness::from_slice(&items);
    assert_eq!(fake.compute_txid(), real.compute_txid());
    assert_ne!(fake.compute_wtxid(), real.compute_wtxid());

    let honest = Chain::esploras(&[&e.url, &e.url], Net::Regtest).unwrap();
    assert_eq!(honest.get_tx(&op.txid).map(|t| t.compute_wtxid()), Some(real.compute_wtxid()));
    assert_eq!(honest.confirmations(&op.txid).unwrap(), 1);
    assert_eq!(honest.height().unwrap(), node.height().unwrap());

    let witness_liar = liar(&e.url, op.txid, fake.clone(), Lie::Witness);
    let pair = Chain::esploras(&[&e.url, &witness_liar], Net::Regtest).unwrap();
    assert_eq!(pair.confirmations(&op.txid).unwrap(), 1, "both confirm it, in the same block");
    assert!(pair.get_tx(&op.txid).is_none(), "two witnesses for one txid: read as unknown, never answered");
    let alone = Chain::esplora(&witness_liar, Net::Regtest).unwrap();
    assert_eq!(alone.get_tx(&op.txid).map(|t| t.compute_wtxid()), Some(fake.compute_wtxid()), "one server alone is believed");

    let block_liar = liar(&e.url, op.txid, fake, Lie::Block);
    let pair = Chain::esploras(&[&e.url, &block_liar], Net::Regtest).unwrap();
    assert!(pair.confirmations(&op.txid).is_err(), "confirmed in two blocks: refused");
    assert!(pair.unspent(&op).unwrap(), "otherwise as the honest server");
}

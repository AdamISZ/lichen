//! Opening a contract end to end (milestone 2): a regtest node with a
//! bitcoind wallet each for Alice and the hub, the sequencer, the hub
//! daemon, and Alice's wallet. Alice asks; the hub offers the contract,
//! the funding transaction and its signatures on the whole pre-signed set;
//! the deposit already minted to her, locked to the funding; Alice checks
//! it all, signs (an adaptor pre-signature on the funding's deposit
//! input); the hub completes it, broadcasts, and answers with `t`, which
//! unlocks her deposit on the L2.

use std::time::Instant;

use bitcoin::Amount;
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_proto::Statement;
use lichen_sequencer::Sequencer;
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;

/// The mock statement with an empty table (these tests never dispute).
fn mock() -> Statement {
    Statement::Mock { session: 0, returns: vec![] }
}

#[test]
fn open_a_contract_and_receive_the_deposit() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-open-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let seq = Sequencer::start("127.0.0.1:0", None, regtest_sequencer(), HUB_KEY).unwrap();
    let (hub_chain, alice_chain) = (Chain::connect(rt.rpc_url(), rt.cookie(), "hub").unwrap(), Chain::connect(rt.rpc_url(), rt.cookie(), "alice").unwrap());
    rt.fund(&hub_chain.new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
    rt.fund(&alice_chain.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
    let hub = Hub::start(Config {
        network: lichen_proto::Net::Regtest,
        listen: "127.0.0.1:0".into(),
        sequencer: seq.url.clone(),
        rpc_url: rt.rpc_url().to_string(),
        cookie: rt.cookie().clone(),
        wallet: "hub".into(),
        statement: mock(),
        dir: dir.join("hub"),
        seed: "test-hub".into(),
        l2_key: lichen_ledger::regtest_hub(),
        reserve_ppm: 20_000,
        max_bits: 24,
        duration: 500,
        refuse_folds: false,
        dispute_true_claims: false,
        first_cid: 1000,
    })
    .unwrap();

    let mut alice = Wallet::create(&dir.join("alice.json"), &seq.url).unwrap();
    let (deposit, bits, reserve) = (400_000u64, 21u32, 20_000u64);
    let t = Instant::now();
    let held = alice.open_contract(&hub.url, &alice_chain, &mock(), &dir.join("alice"), Ask { deposit, bits, reserve }, alice_chain.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { alice_chain.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
    let r = &held.record;
    println!("LICHEN opened contract {} in {:.1?}: cap {} sats, Alice's reserve {}, the hub's {}, T_close {}", r.cid(), t.elapsed(), r.terms.v_max().to_sat(), r.terms.reserve_alice, r.terms.reserve_hub, r.terms.t_close);

    // the funding is in the mempool; the contract output holds V_max and both reserves
    rt.mine(1).unwrap();
    let funding = rt.get_tx(&r.funding.txid).unwrap();
    assert_eq!(funding.output[0].value, r.terms.v_max() + r.terms.reserves());
    // both sides hold the same contract, every signature checked
    let theirs = hub.contracts();
    assert_eq!(theirs.len(), 1);
    let theirs = &theirs[0].0;
    assert_eq!((theirs.funding, &theirs.alice_sigs, &theirs.hub_sigs), (r.funding, &r.alice_sigs, &r.hub_sigs));
    let program = mock().program(&dir.join("alice")).unwrap();
    let set = r.presigned(&r.contract(&mock(), &program).unwrap()).unwrap();
    println!("LICHEN both parties hold {} pre-signed transactions, each signature checked", set.len());

    // the deposit is hers already, claimed with t
    assert!(held.mint.as_ref().unwrap().claimed);
    alice.sequencer.seal().unwrap();
    assert_eq!(alice.balance().unwrap(), deposit);
    println!("LICHEN the hub minted {deposit} sats to Alice on the L2, hers once the funding was out");
    // a restarted wallet still has its contract
    let again = Wallet::open(&dir.join("alice.json"), &seq.url).unwrap();
    assert_eq!(again.contracts.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

//! Contracts over shielded notes (docs/SHIELDED_PLAN.md), native proofs:
//! Alice and Bob open contracts and shield their deposits; Bob pays Alice
//! 50,000 sats in a shielded note; Alice withdraws 450,000 from her
//! shielded notes and the hub folds, the return a transparent note as the
//! withdrawal statement wants. Then the hub refuses folds: Bob's refused
//! withdrawal of his last 50,000 exports a dispute package whose
//! withdrawal input, built as a tower builds it, is the wallet's and
//! passes the statement.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_proto::Statement;
use lichen_l2::Client;
use lichen_sequencer::{Options, Sequencer};
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;

fn wait(what: &str, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(start.elapsed() < Duration::from_secs(60), "{what}: timed out");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn mock() -> Statement {
    Statement::Mock { session: 0, returns: vec![] }
}

#[test]
fn shielded_deposits_a_fold_and_a_dispute_input() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-hub-shielded-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let seq = Sequencer::start_with("127.0.0.1:0", None, regtest_sequencer(), HUB_KEY, Options { native_proofs: true }).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (s2, url) = (stop.clone(), seq.url.clone());
    let sealer = std::thread::spawn(move || {
        while !s2.load(Ordering::Relaxed) {
            let _ = Client::new(&url).and_then(|c| c.seal());
            std::thread::sleep(Duration::from_millis(200));
        }
    });
    let chain = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w).unwrap();
    rt.fund(&chain("hub").new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
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
        max_bits: 21,
        duration: 2_000,
        refuse_folds: false,
        dispute_true_claims: false,
        first_cid: 1000,
        windows: None,
    })
    .unwrap();
    let mut users = vec![];
    for (name, deposit) in [("alice", 400_000u64), ("bob", 100_000)] {
        let ch = chain(name);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let mut w = Wallet::create(&dir.join(format!("{name}.json")), &seq.url).unwrap();
        let held = w.open_contract(&hub.url, &ch, &mock(), &dir.join(name), Ask { deposit, bits: 21, reserve: 20_000 }, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
        users.push((w, ch, held));
    }
    rt.mine(1).unwrap();
    for (w, _, h) in &mut users {
        let d = u64::from(h.record.terms.deposit);
        wait("the deposit", || w.balance().unwrap() == d);
        w.shield(d).unwrap();
        assert_eq!(w.balances().unwrap(), (0, d), "the deposit shielded");
    }
    let to_alice = users[0].0.shielded_address();
    users[1].0.send_shielded(&to_alice, 50_000).unwrap();
    assert_eq!(users[0].0.balances().unwrap(), (0, 450_000));

    // Alice withdraws 450,000 cooperatively, returned from shielded notes
    {
        let (w, ch, h) = &mut users[0];
        let before = ch.balance().unwrap();
        let txid = w.withdraw(&hub.url, &mock(), &dir.join("alice"), h.record.cid(), 450_000).unwrap();
        rt.mine(1).unwrap();
        assert_eq!(ch.balance().unwrap() - before, Amount::from_sat(450_000) + h.record.terms.reserve_alice);
        assert_eq!(w.balance().unwrap(), 0);
        println!("LICHEN Alice withdrew 450,000 from shielded notes; the hub folded ({txid})");
    }

    // the hub refuses folds now: Bob's withdrawal of 50,000 is refused,
    // and his dispute's input is a tower's as the wallet's
    hub.set_refuse_folds(true);
    let (w, _, h) = &mut users[1];
    let cid = h.record.cid();
    assert!(w.withdraw(&hub.url, &mock(), &dir.join("bob"), cid, 50_000).is_err(), "refused");
    let input = w.withdraw_input(cid).unwrap();
    let journal = lichen_ledger::check(&input).unwrap();
    assert_eq!(journal[..8], [0x50, 0xc3, 0, 0, (cid & 0xff) as u8, (cid >> 8) as u8, 0, 0], "b = 50,000 and memo c");
    let program = mock().program(&dir.join("bob")).unwrap();
    let pkg = w.export_dispute(&mock(), &program, cid, None).unwrap();
    assert_eq!(serde_json::to_value(lichen_wallet::tower::withdraw_input(&pkg).unwrap()).unwrap(), serde_json::to_value(&input).unwrap());
    println!("LICHEN Bob's refused withdrawal of 50,000 from shielded notes: the dispute's input checks");
    stop.store(true, Ordering::Relaxed);
    sealer.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

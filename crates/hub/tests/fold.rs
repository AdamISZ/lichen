//! Milestone 3: the cooperative withdrawal and the default.
//!
//! Alice, Bob and Carol each open a contract with the hub. Bob pays Alice
//! 50,000 sats on the L2; Alice returns 450,000 (more than her deposit,
//! within her cap) and the hub folds her contract: she has 450,000 sats
//! and her reserve on chain. Bob and Carol do nothing; after T_close the
//! hub broadcasts their defaults, which return their reserves (Bob's
//! remaining 50,000 sats on the L2 are now exposed to the hub).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_proto::Statement;
use lichen_sequencer::{Client, Sequencer};
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;

fn wait(what: &str, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(start.elapsed() < Duration::from_secs(60), "{what}: timed out");
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The mock statement with an empty table (these tests never dispute).
fn mock() -> Statement {
    Statement::Mock { session: 0, returns: vec![] }
}

#[test]
fn fold_and_default() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-fold-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let seq = Sequencer::start("127.0.0.1:0", None, regtest_sequencer(), HUB_KEY).unwrap();
    // the sequencer seals a height every 200 ms
    let stop = Arc::new(AtomicBool::new(false));
    let (s2, url) = (stop.clone(), seq.url.clone());
    let sealer = std::thread::spawn(move || {
        while !s2.load(Ordering::Relaxed) {
            let _ = Client::new(&url).and_then(|c| c.seal());
            std::thread::sleep(Duration::from_millis(200));
        }
    });
    let chain = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w).unwrap();
    let hub_chain = chain("hub");
    rt.fund(&hub_chain.new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
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
        duration: 40,
        refuse_folds: false,
        dispute_true_claims: false,
        first_cid: 1000,
    })
    .unwrap();
    let ask = |deposit| Ask { deposit, bits: 21, reserve: 20_000 };
    let mut users = vec![];
    for (name, deposit) in [("alice", 400_000u64), ("bob", 100_000), ("carol", 100_000)] {
        let ch = chain(name);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let mut w = Wallet::create(&dir.join(format!("{name}.json")), &seq.url).unwrap();
        let held = w.open_contract(&hub.url, &ch, &mock(), &dir.join(name), ask(deposit), ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
        println!("LICHEN {name} opened contract {} with a deposit of {deposit} sats", held.record.cid());
        users.push((w, ch, held));
    }
    rt.mine(1).unwrap();
    for (w, _, h) in &users {
        let d = u64::from(h.record.terms.deposit);
        wait("the deposit", || w.balance().unwrap() == d);
    }

    // Bob pays Alice 50,000 on the L2
    let alice_addr = users[0].0.address();
    users[1].0.send(alice_addr, 50_000, 0).unwrap();
    assert_eq!(users[0].0.balance().unwrap(), 450_000);

    // ===== Alice withdraws 450,000 cooperatively =====
    {
        let (w, ch, h) = &mut users[0];
        let before = ch.balance().unwrap();
        let t = Instant::now();
        let txid = w.withdraw(&hub.url, &mock(), &dir.join("alice"), h.record.cid(), 450_000).unwrap();
        rt.mine(1).unwrap();
        let fold = rt.get_tx(&txid).unwrap();
        let gained = ch.balance().unwrap() - before;
        assert_eq!(gained, Amount::from_sat(450_000) + h.record.terms.reserve_alice, "450,000 and her reserve");
        assert_eq!(w.balance().unwrap(), 0);
        println!("LICHEN Alice returned 450,000 sats on the L2 and the hub folded her contract ({} vB, {:.1?}): she gained {gained} on chain", fold.vsize(), t.elapsed());
    }

    // ===== Bob and Carol do nothing; after T_close, the defaults =====
    let t_close = users[1].1.height().unwrap().max(users.iter().map(|u| u.2.record.terms.t_close).max().unwrap());
    let before: Vec<Amount> = users.iter().map(|u| u.1.balance().unwrap()).collect();
    rt.mine_to_height(t_close).unwrap();
    wait("the defaults", || hub.contracts().iter().filter(|c| c.1.is_some()).count() == 3);
    rt.mine(1).unwrap();
    for (k, name) in [(1usize, "Bob"), (2, "Carol")] {
        let gained = users[k].1.balance().unwrap() - before[k];
        assert_eq!(gained, users[k].2.record.terms.reserve_alice, "{name}'s reserve");
        println!("LICHEN after T_close the hub broadcast {name}'s default: {name}'s reserve ({gained}) is back on chain");
    }
    assert_eq!(users[1].0.balance().unwrap(), 50_000, "Bob's tokens remain on the L2, exposed to the hub now");
    stop.store(true, Ordering::Relaxed);
    sealer.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

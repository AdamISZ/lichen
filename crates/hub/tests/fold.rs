//! Milestone 3: the cooperative withdrawal and the default.
//!
//! Alice, Bob, Carol and Dave each open a contract with the hub. Bob pays
//! Alice 50,000 sats on the L2; Alice returns 450,000 (more than her
//! deposit, within her cap) and the hub folds her contract: she has
//! 450,000 sats and her reserve on chain. Bob closes his early with
//! nothing withdrawn (`b` 0): no return, his reserve back at once, his
//! remaining 50,000 sats left on the L2. Carol does nothing; after
//! T_close the hub broadcasts her default, which returns her reserve.
//! Dave's payout is his wallet's own payout address; the hub posts no
//! default for him (as if gone), and he posts it himself, then spends
//! his reserve from that address.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_proto::Statement;
use lichen_l2::Client;
use lichen_sequencer::Sequencer;
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
    Statement::BitVmxMock { session: 0, returns: vec![] }
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
        fee_ppm: 0,
        max_liquidity: 10_000_000,
        duration: 40,
        refuse_folds: false,
        dispute_true_claims: false,
        first_cid: 1000,
        windows: None,
    })
    .unwrap();
    let ask = |deposit| Ask { deposit, liquidity: 1_000_000, reserve: 20_000 };
    let mut users = vec![];
    for (name, deposit) in [("alice", 400_000u64), ("bob", 100_000), ("carol", 100_000), ("dave", 100_000)] {
        let ch = chain(name);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let mut w = Wallet::create(&dir.join(format!("{name}.json")), &seq.url).unwrap();
        // Dave's payouts to his wallet's own address, watched (the node's
        // index sees only what's paid after)
        let payout = if name == "dave" { w.payout().spk() } else { ch.new_spk().unwrap() };
        ch.watch(&payout).unwrap();
        let held = w.open_contract(&hub.url, &ch, &mock(), &dir.join(name), ask(deposit), payout, &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
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

    // ===== Bob closes early, withdrawing nothing =====
    {
        let (w, ch, h) = &mut users[1];
        let before = ch.balance().unwrap();
        let t = Instant::now();
        let txid = w.withdraw(&hub.url, &mock(), &dir.join("bob"), h.record.cid(), 0).unwrap();
        rt.mine(1).unwrap();
        let gained = ch.balance().unwrap() - before;
        assert_eq!(gained, h.record.terms.reserve_alice, "Bob's reserve alone");
        assert_eq!(w.balance().unwrap(), 50_000, "no return: Bob's tokens stay on the L2");
        assert!(hub.contracts().iter().any(|c| c.0.cid() == h.record.cid() && c.1 == Some(txid)));
        println!("LICHEN Bob closed his contract with nothing withdrawn ({:.1?}, no return): his reserve ({gained}) back before T_close, his 50,000 sats still on the L2", t.elapsed());
    }

    // ===== after T_close: Dave posts his default, the hub held; then the
    // hub posts Carol's =====
    hub.set_hold_defaults(true);
    let (carol_cid, dave_cid) = (users[2].2.record.cid(), users[3].2.record.cid());
    {
        let (w, ch, _) = &mut users[3];
        let early = w.post_default(ch, &mock(), &dir.join("dave"), dave_cid).unwrap_err();
        assert!(format!("{early:#}").contains("valid from block"), "{early:#}");
    }
    let t_close = users[2].1.height().unwrap().max(users.iter().map(|u| u.2.record.terms.t_close).max().unwrap());
    let carol_before = users[2].1.balance().unwrap();
    rt.mine_to_height(t_close).unwrap();
    std::thread::sleep(Duration::from_secs(3));
    assert!(hub.contracts().iter().all(|c| c.0.cid() != carol_cid || c.1.is_none()), "no defaults while held");
    let (w, ch, h) = &mut users[3];
    let posted = w.post_default(ch, &mock(), &dir.join("dave"), dave_cid).unwrap();
    rt.mine(1).unwrap();
    assert!(rt.get_tx(&posted).is_ok());
    let payout = w.payout();
    let at_payout = payout.balance(ch).unwrap();
    assert_eq!(at_payout, h.record.terms.reserve_alice, "Dave's reserve at his payout address");
    assert!(w.post_default(ch, &mock(), &dir.join("dave"), dave_cid).is_err(), "closed now");
    println!("LICHEN Dave posted his own default after T_close (the hub held its): his reserve ({at_payout}) at his wallet's payout address {}", w.payout_address(lichen_proto::Net::Regtest));
    // and spends it from there: 10,000 sats, then the rest
    let to = ch.new_spk().unwrap();
    let before = ch.balance().unwrap();
    w.send_payout(ch, &to, Some(Amount::from_sat(10_000))).unwrap();
    rt.mine(1).unwrap();
    assert_eq!(ch.balance().unwrap() - before, Amount::from_sat(10_000));
    let left = payout.balance(ch).unwrap();
    assert!(left < at_payout - Amount::from_sat(10_000) && left > at_payout - Amount::from_sat(11_000), "the change, less the fee: {left}");
    w.send_payout(ch, &to, None).unwrap();
    rt.mine(1).unwrap();
    assert_eq!(payout.balance(ch).unwrap(), Amount::ZERO);
    let got = ch.balance().unwrap() - before;
    assert!(got > at_payout - Amount::from_sat(1_000), "all of it, less two fees: {got}");
    println!("LICHEN Dave sent 10,000 sats from his payout address, then the rest: {got} of {at_payout} arrived");
    hub.set_hold_defaults(false);
    wait("Carol's default", || hub.contracts().iter().any(|c| c.0.cid() == carol_cid && c.1.is_some()));
    rt.mine(1).unwrap();
    let gained = users[2].1.balance().unwrap() - carol_before;
    assert_eq!(gained, users[2].2.record.terms.reserve_alice, "Carol's reserve");
    println!("LICHEN after T_close the hub broadcast Carol's default: her reserve ({gained}) is back on chain");
    stop.store(true, Ordering::Relaxed);
    sealer.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

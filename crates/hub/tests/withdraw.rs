//! The cooperative withdrawal, by claim, and the default.
//!
//! Alice, Bob, Carol, Dave and Erin each open a contract with the hub.
//! Bob pays Alice a whole number of her contract's units on the L2.
//!
//! - A: Alice withdraws exactly that note: her claim of it, signed for the
//!   contract, which the hub records on the L2 (retiring the note), then
//!   folds at once: the amount and her reserve on chain.
//! - B: Bob withdraws part of his balance: a note of the amount split off
//!   first (a payment to himself), claimed, folded; the rest stays his on
//!   the L2. Asked again, the closed contract refuses.
//! - C: Carol closes early with nothing withdrawn (`b` 0): no claim, her
//!   reserve back at once, her tokens left on the L2.
//! - D, E: after T_close, Dave posts his default himself (the hub held
//!   its), then the hub posts Erin's: their reserves back.

mod common;

use std::time::{Duration, Instant};

use bitcoin::Amount;
use common::{statement, wait, Env};
use lichen_wallet::{Ask, Wallet};

#[test]
fn withdraw_by_claim_and_default() {
    let env = Env::new("withdraw");
    let rt = &env.rt;
    let hub = env.hub("hub", |c| c.duration = 40);
    let ask = |deposit| Ask { deposit, liquidity: 1_000_000, reserve: 20_000 };
    let mut users = vec![];
    for (name, deposit) in [("alice", 400_000u64), ("bob", 100_000), ("carol", 100_000), ("dave", 100_000), ("erin", 100_000)] {
        let ch = env.chain(name);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let mut w = Wallet::create(&env.dir.join(format!("{name}.json")), &env.seq.url).unwrap();
        // Dave's payouts to his wallet's own address, watched (the node's
        // index sees only what's paid after)
        let payout = if name == "dave" { w.payout().spk() } else { ch.new_spk().unwrap() };
        ch.watch(&payout).unwrap();
        let held = w.open_contract(&hub.url, &ch, &statement(), ask(deposit), payout, &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
        println!("LICHEN {name} opened contract {} with a deposit of {deposit} sats", held.record.cid());
        users.push((w, ch, held));
    }
    rt.mine(1).unwrap();
    for (w, _, h) in &users {
        let d = u64::from(h.record.terms.deposit);
        wait("the deposit", || w.balance().unwrap() == d);
    }

    // Bob pays Alice 73 of her contract's units
    let a_unit = users[0].2.record.terms.unit.to_sat();
    let paid = 73 * a_unit;
    let alice_addr = users[0].0.address();
    let to_alice = users[1].0.send(alice_addr, paid, 0).unwrap()[0];
    assert_eq!(users[0].0.balance().unwrap(), 400_000 + paid);

    // ===== A: Alice withdraws exactly the note Bob paid =====
    {
        let (w, ch, h) = &mut users[0];
        let before = ch.balance().unwrap();
        let t = Instant::now();
        let txid = w.withdraw(&hub.url, &statement(), h.record.cid(), paid).unwrap();
        rt.mine(1).unwrap();
        let fold = rt.get_tx(&txid).unwrap();
        let gained = ch.balance().unwrap() - before;
        assert_eq!(gained, Amount::from_sat(paid) + h.record.terms.reserve_alice, "the note's value and her reserve");
        let state = w.state().unwrap();
        assert!(state.is_spent(state.note(to_alice).unwrap()), "the claimed note retired on the L2");
        assert_eq!(w.balance().unwrap(), 400_000, "no split: her deposit's note untouched");
        assert!(hub.log().iter().any(|l| l.contains("withdrawal claim of 73 units recorded on the L2")), "{:?}", hub.log());
        println!("LICHEN A: Alice's claim of the note Bob paid ({paid} sats) recorded on the L2, the hub folded at once ({} vB, {:.1?}): she gained {gained} on chain", fold.vsize(), t.elapsed());
    }

    // ===== B: Bob withdraws part of his balance: a note split off first =====
    {
        let (w, ch, h) = &mut users[1];
        let unit = h.record.terms.unit.to_sat();
        let left = w.balance().unwrap();
        let want = 30_000 / unit * unit;
        let before = ch.balance().unwrap();
        let t = Instant::now();
        let txid = w.withdraw(&hub.url, &statement(), h.record.cid(), 30_000).unwrap();
        rt.mine(1).unwrap();
        assert!(rt.get_tx(&txid).is_ok());
        assert_eq!(ch.balance().unwrap() - before, Amount::from_sat(want) + h.record.terms.reserve_alice, "30,000 rounded down to the unit, and his reserve");
        assert_eq!(w.balance().unwrap(), left - want, "the rest stays his on the L2");
        assert!(w.withdraw(&hub.url, &statement(), h.record.cid(), 1_000).is_err(), "closed");
        println!("LICHEN B: Bob split off a note of {want} sats, claimed it, and the hub folded ({:.1?}); {} sats stay his on the L2", t.elapsed(), left - want);
    }

    // ===== C: Carol closes early, withdrawing nothing =====
    {
        let (w, ch, h) = &mut users[2];
        let before = ch.balance().unwrap();
        let txid = w.withdraw(&hub.url, &statement(), h.record.cid(), 0).unwrap();
        rt.mine(1).unwrap();
        let gained = ch.balance().unwrap() - before;
        assert_eq!(gained, h.record.terms.reserve_alice, "Carol's reserve alone");
        assert_eq!(w.balance().unwrap(), 100_000, "no claim: her tokens stay on the L2");
        assert!(hub.contracts().iter().any(|c| c.0.cid() == h.record.cid() && c.1 == Some(txid)));
        println!("LICHEN C: Carol closed her contract with nothing withdrawn: her reserve ({gained}) back before T_close, her 100,000 sats still on the L2");
    }

    // ===== after T_close: Dave posts his default, the hub held; then the
    // hub posts Erin's =====
    hub.set_hold_defaults(true);
    let (erin_cid, dave_cid) = (users[4].2.record.cid(), users[3].2.record.cid());
    {
        let (w, ch, _) = &mut users[3];
        let early = w.post_default(ch, &statement(), dave_cid).unwrap_err();
        assert!(format!("{early:#}").contains("valid from block"), "{early:#}");
    }
    let t_close = users[4].1.height().unwrap().max(users.iter().map(|u| u.2.record.terms.t_close).max().unwrap());
    let erin_before = users[4].1.balance().unwrap();
    rt.mine_to_height(t_close).unwrap();
    std::thread::sleep(Duration::from_secs(3));
    assert!(hub.contracts().iter().all(|c| c.0.cid() != erin_cid || c.1.is_none()), "no defaults while held");
    let (w, ch, h) = &mut users[3];
    let posted = w.post_default(ch, &statement(), dave_cid).unwrap();
    rt.mine(1).unwrap();
    assert!(rt.get_tx(&posted).is_ok());
    let at_payout = w.payout().balance(ch).unwrap();
    assert_eq!(at_payout, h.record.terms.reserve_alice, "Dave's reserve at his payout address");
    assert!(w.post_default(ch, &statement(), dave_cid).is_err(), "closed now");
    println!("LICHEN D: Dave posted his own default after T_close (the hub held its): his reserve ({at_payout}) at his wallet's payout address");
    hub.set_hold_defaults(false);
    wait("Erin's default", || hub.contracts().iter().any(|c| c.0.cid() == erin_cid && c.1.is_some()));
    rt.mine(1).unwrap();
    let gained = users[4].1.balance().unwrap() - erin_before;
    assert_eq!(gained, users[4].2.record.terms.reserve_alice, "Erin's reserve");
    println!("LICHEN E: after T_close the hub broadcast Erin's default: her reserve ({gained}) is back on chain");
}

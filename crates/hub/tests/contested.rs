//! Exits contested (docs/GRANTS_PLAN.md, milestone 2): the hub answers a
//! claim it can correct with `correct`, signing `b_corr`, and proves "she
//! is owed at most `b_corr`" (the mock statement's proof, the statement
//! checked natively first).
//!
//! Each user's spend is recorded by a hub that withholds its answer: the
//! spend stays in flight in her wallet, and her exit claims her notes with
//! it as a fallback.
//!
//! - C: an honest hub corrects Alice's claim to her change of the spend
//!   (its unlock in `correct`'s fee child), proves it, and `success` pays
//!   her that and her reserve; the hub sweeps its bit outputs after `Δ`.
//!   Bob, paid by the spend, holds his note.
//! - F: a lying hub corrects Carol's claim, which holds in full, to 0 and
//!   asserts a forged proof: she challenges, it can't answer, `failure`
//!   pays her claim.
//! - A: a hub corrects Dave's claim and never proves it:
//!   `correct_timeout` pays his claim.

mod common;

use std::time::{Duration, Instant};

use bitcoin::Amount;
use common::{statement, wait, Env};
use lichen_wallet::dispute::Outcome;
use lichen_wallet::{Ask, Wallet};

const PAID: u64 = 150_000;

#[test]
fn exits_contested() {
    let mut env = Env::new("contested");
    env.mine_every(Duration::from_millis(250));
    let ask = Ask { deposit: 400_000, liquidity: 1_000_000, reserve: 20_000 };
    let (hub_c, hub_f, hub_a) = (env.hub("hub-c", |_| {}), env.hub("hub-f", |_| {}), env.hub("hub-a", |_| {}));
    let rt = &env.rt;
    let open = |name: &str, hub: &lichen_hub::Hub| {
        let ch = env.chain(name);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let mut w = Wallet::create(&env.dir.join(format!("{name}.json")), &hub.url).unwrap();
        let payout = ch.new_spk().unwrap();
        ch.watch(&payout).unwrap();
        let held = w.open_contract(&hub.url, &ch, &statement(), ask, payout, &|addr: &bitcoin::Address, v| ch.pay(&addr.script_pubkey(), v).map(|_| ())).unwrap();
        println!("LICHEN {name} opened contract {} on {}", held.record.cid(), hub.url);
        (w, ch, held)
    };
    let (mut alice, mut carol, mut dave) = (open("alice", &hub_c), open("carol", &hub_f), open("dave", &hub_a));
    let mut bob = Wallet::create(&env.dir.join("bob.json"), &hub_c.url).unwrap();
    let erin = Wallet::create(&env.dir.join("erin.json"), &hub_a.url).unwrap();

    // Alice pays Bob, Dave pays Erin: recorded, the answers withheld
    for (hub, payer, to) in [(&hub_c, &mut alice.0, bob.address()), (&hub_a, &mut dave.0, erin.address())] {
        hub.set_withhold_unlocks(true);
        payer.send(to, PAID).unwrap_err();
        assert_eq!(payer.inflight.len(), 1, "the spend in flight");
        hub.set_withhold_unlocks(false);
    }
    bob.sync().unwrap();
    assert_eq!(bob.balance(), PAID, "the spend recorded: Bob's note");
    // the spends stay in flight: the hubs withhold from here on
    hub_c.set_withhold_unlocks(true);
    hub_a.set_withhold_unlocks(true);
    hub_f.set_forge_assertions(true);
    hub_a.set_abandon_corrections(true);

    let unit = alice.2.record.terms.unit.to_sat();
    let b = (ask.deposit / unit) as u32;
    let t = Instant::now();
    // Alice's request, at its size (its claim one-time signed in full)
    alice.0.progress = Some(std::sync::Arc::new(|m: String| {
        if m.starts_with("requesting") {
            println!("LICHEN alice: {m}");
        }
    }));
    let exit = |u: &mut (Wallet, lichen_chain::Chain, lichen_wallet::Held)| {
        let cid = u.2.record.cid();
        let plan = u.0.keep_exit_claim(&u.1, cid).unwrap();
        assert_eq!(plan.b, b, "all her notes claimed");
        u.0.exit(&u.1, &statement(), cid).unwrap()
    };
    let exit = &exit;
    let (c, f, a) = std::thread::scope(|s| {
        let c = s.spawn(move || exit(&mut alice));
        let f = s.spawn(move || exit(&mut carol));
        let a = s.spawn(move || exit(&mut dave));
        (c.join().unwrap(), f.join().unwrap(), a.join().unwrap())
    });
    println!("LICHEN the three exits played in {:.1?}", t.elapsed());

    // C: corrected to her change, proved, paid by success
    let b_corr = ((ask.deposit - PAID) / unit) as u32;
    match &c.0 {
        Outcome::Corrected { b_corr: got, .. } => assert_eq!(*got, b_corr, "her change, in units"),
        o => panic!("C: {o:?}"),
    }
    let (_, swept) = c.1.expect("C: her bits swept");
    assert!(swept > Amount::from_sat(u64::from(b_corr) * unit / 2), "C: {swept}");
    assert!(hub_c.log().iter().any(|l| l.contains("the unlocks in")), "the unlock on chain: {:?}", hub_c.log());
    println!("LICHEN C: the claim of {b} units corrected to {b_corr} (the spend in flight recorded: her change), proved; success paid her, swept {swept}");
    wait("the hub's bit outputs of success", || hub_c.log().iter().any(|l| l.contains("collected the hub's")));

    // no contract again for an owner who exited (her exit's claim isn't
    // one a statement on another contract could cite): refused before she
    // pays
    let mut again = Wallet::open(&env.dir.join("alice.json"), &hub_c.url).unwrap();
    let ch = env.chain("alice");
    let err = again.open_contract(&hub_c.url, &ch, &statement(), ask, ch.new_spk().unwrap(), &|_: &bitcoin::Address, _| panic!("asked to pay")).unwrap_err();
    assert!(format!("{err:#}").contains("exited contract"), "{err:#}");

    // F: a forged proof against a claim owed in full
    assert!(matches!(f.0, Outcome::Refuted(_)), "F: {:?}", f.0);
    assert!(hub_f.log().iter().any(|l| l.contains("is owed 0") || l.contains("corrected to 0")), "{:?}", hub_f.log());
    println!("LICHEN F: the lying hub corrected Carol's claim to 0 with a forged proof: failure paid her {b} units");

    // A: corrected, never proved
    assert!(matches!(a.0, Outcome::HubTimedOut(_)), "A: {:?}", a.0);
    assert!(hub_a.log().iter().any(|l| l.contains("abandoning the correction")), "{:?}", hub_a.log());
    println!("LICHEN A: Dave's claim corrected and never proved: correct_timeout paid his {b} units");
}

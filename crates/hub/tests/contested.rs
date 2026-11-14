//! Exits contested on the countersigned graph (papers/lichen-grants-v0.5.6,
//! §6), on the mock statement (checked natively first).
//!
//! Each payer's payment is recorded by a hub that withholds the seed: both
//! parties are in flight, and the payer's exit claims the note the payment
//! takes.
//!
//! - C (accepted): the hub corrects Alice's claim to what the payment left
//!   her, citing it, its seed in `U`. Alice completes her new note from
//!   `U`, finds the correction right, and accepts: after `w_A`, `accept`
//!   pays her `b_corr`. Bob completes his new note from the same seed, read
//!   from the chain.
//! - P (proved): the same for Dave paying Erin, but Dave contests (a test's
//!   switch): he countersigns the hub's values in `ack`, the hub proves its
//!   statement from his four signatures, and `success` pays `b_corr`.
//! - F (forged): a lying hub corrects Carol's claim, owed in full, to 0 and
//!   asserts a forged proof: she contests, challenges, it can't answer,
//!   and `failure` pays her claim.

mod common;

use std::time::{Duration, Instant};

use bitcoin::Amount;
use common::{pay, statement, Env};
use lichen_notes::Note;
use lichen_wallet::dispute::Outcome;
use lichen_wallet::{Ask, Wallet};

const PAID: u64 = 150_000;

#[test]
fn exits_contested() {
    let mut env = Env::new("contested");
    env.mine_every(Duration::from_millis(250));
    let ask = Ask { deposit: 400_000, liquidity: 1_000_000, reserve: 20_000 };
    let (hub_c, hub_f, hub_p) = (env.hub("hub-c", |_| {}), env.hub("hub-f", |_| {}), env.hub("hub-p", |_| {}));
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
    let (mut alice, mut carol, mut dave) = (open("alice", &hub_c), open("carol", &hub_f), open("dave", &hub_p));
    let mut bob = Wallet::create(&env.dir.join("bob.json"), &hub_c.url).unwrap();
    let mut erin = Wallet::create(&env.dir.join("erin.json"), &hub_p.url).unwrap();

    // Alice pays Bob, Dave pays Erin: recorded, the seed withheld
    for (hub, payer, payee) in [(&hub_c, &mut alice.0, &mut bob), (&hub_p, &mut dave.0, &mut erin)] {
        hub.set_withhold_unlocks(true);
        pay(payer, payee, PAID).unwrap();
        let me = payer.address();
        assert!(payer.account(&me).pending.is_some_and(|p| p.signed), "the payer in flight");
        assert!(payee.account(&payee.address()).pending.is_some_and(|p| p.signed), "the payee in flight");
    }
    hub_f.set_forge_assertions(true);
    dave.0.contest = true;

    let unit = alice.2.record.terms.unit.to_sat();
    let b = (ask.deposit / unit) as u32;
    let t = Instant::now();
    alice.0.progress = Some(std::sync::Arc::new(|m: String| println!("LICHEN alice: {m}")));
    let exit = |u: &mut (Wallet, lichen_chain::Chain, lichen_wallet::Held)| {
        let cid = u.2.record.cid();
        let plan = u.0.keep_exit_claim(&u.1, cid).unwrap();
        assert_eq!(plan.b, b, "her whole note claimed (the one the payment takes)");
        let out = u.0.exit(&u.1, &statement(), cid).unwrap();
        (out, u.0.unlock_of(&u.1, &statement(), cid).unwrap())
    };
    let exit = &exit;
    let (c, f, p) = std::thread::scope(|s| {
        let c = s.spawn(|| exit(&mut alice));
        let f = s.spawn(|| exit(&mut carol));
        let p = s.spawn(|| exit(&mut dave));
        (c.join().unwrap(), f.join().unwrap(), p.join().unwrap())
    });
    println!("LICHEN the three exits played in {:.1?}", t.elapsed());
    let b_corr = ((ask.deposit - PAID) / unit) as u32;

    // C: corrected to what the payment left her, accepted
    let ((c_out, c_swept), c_seed) = c;
    match c_out {
        Outcome::Corrected { b_corr: got, .. } => assert_eq!(got, b_corr, "her new note, in units"),
        o => panic!("C: {o:?}"),
    }
    let (_, swept) = c_swept.expect("C: her bits swept");
    assert!(swept > Amount::from_sat(u64::from(b_corr) * unit / 2), "C: {swept}");
    // the contract's key (closed now: the wallet's address is its own key)
    let me = alice.2.record.l2_address;
    assert_eq!(alice.0.note_of(&me), Note { owner: me, k: 1, v: ask.deposit - PAID }, "her new note, completed from U");
    assert!(hub_c.log().iter().any(|l| l.contains("her last step cited")), "{:?}", hub_c.log());
    assert!(!hub_c.log().iter().any(|l| l.contains("asserted")), "accepted: nothing to prove");
    // Bob completes his note with the seed from the chain
    let z = c_seed.expect("C: U on chain");
    bob.complete_with(&z).unwrap();
    let bob_addr = bob.address();
    assert_eq!(bob.note_of(&bob_addr), Note { owner: bob_addr, k: 1, v: PAID });
    println!("LICHEN C: Alice's claim of {b} units corrected to {b_corr} (her step in flight cited, its seed in U), accepted; Bob's note of {PAID} settled from the same seed");

    // P: contested, proved, paid by success
    let ((p_out, _), p_seed) = p;
    match p_out {
        Outcome::Corrected { b_corr: got, .. } => assert_eq!(got, b_corr),
        o => panic!("P: {o:?}"),
    }
    assert!(hub_p.log().iter().any(|l| l.contains("asserted")), "{:?}", hub_p.log());
    erin.complete_with(&p_seed.expect("P: U on chain")).unwrap();
    assert_eq!(erin.balance(), PAID);
    println!("LICHEN P: Dave contested the correction; the hub proved it from his four signatures, success paid {b_corr} units; Erin's note settled from U");

    // F: a forged proof against a claim owed in full
    let ((f_out, _), _) = f;
    assert!(matches!(f_out, Outcome::Refuted(_)), "F: {f_out:?}");
    assert!(hub_f.log().iter().any(|l| l.contains("corrected to 0")), "{:?}", hub_f.log());
    println!("LICHEN F: the lying hub corrected Carol's claim to 0 with a forged proof: she contested and challenged, failure paid her {b} units");
}

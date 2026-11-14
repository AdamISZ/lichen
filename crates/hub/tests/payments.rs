//! Payments on the grants L2, one note per account
//! (papers/lichen-grants-v0.5.6), end to end: a regtest node, the hub
//! daemon, and wallets that talk to the hub alone.
//!
//! - Alice opens a contract: its account opens at her deposit, note 0.
//! - She pays Bob, who has no contract, 100,000 sats: both accounts one
//!   step on, both new notes settled by the one seed.
//! - Bob pays her back three times; each account's number counts its steps.
//! - Rule 2 at the hub: a second payment from a busy account waits.
//! - Cancelling: unsigned, nothing to reissue; signed by one side, its note
//!   reissued one step on, the late signature refused.
//! - A half of a note no longer live is refused.
//! - A wallet restored from its key finds its live note at the hub.

mod common;

use std::time::Instant;

use bitcoin::Amount;
use common::{pay, statement, Env};
use lichen_notes::Note;
use lichen_wallet::notes::Step;
use lichen_wallet::{Ask, Wallet};

#[test]
fn payments_by_joint_spend() {
    let env = Env::new("payments");
    let rt = &env.rt;
    let hub = env.hub("hub", |c| c.duration = 500);
    let ch = env.chain("alice");
    rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
    let mut alice = Wallet::create(&env.dir.join("alice.json"), &hub.url).unwrap();
    let mut bob = Wallet::create(&env.dir.join("bob.json"), &hub.url).unwrap();

    let ask = Ask { deposit: 400_000, liquidity: 1_000_000, reserve: 20_000 };
    let t = Instant::now();
    let held = alice.open_contract(&hub.url, &ch, &statement(), ask, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
    assert!(held.mint.as_ref().unwrap().claimed);
    let me = alice.address();
    assert_eq!(me, held.record.l2_address);
    assert_eq!(alice.note_of(&me), Note { owner: me, k: 0, v: ask.deposit });
    println!("LICHEN contract {} opened in {:.1?}: Alice's account at its mint, note 0 of {} sats", held.record.cid(), t.elapsed(), ask.deposit);
    // a fresh key per contract: the hub refuses a key it knows, before she pays
    let req = serde_json::json!({ "alice": held.record.pubs[0].payment, "deposit": ask.deposit, "liquidity": ask.liquidity, "owner": me });
    let err = ureq::post(&format!("{}/deposit", hub.url)).send_json(req).unwrap_err();
    let ureq::Error::Status(_, r) = err else { panic!("{err}") };
    assert!(r.into_string().unwrap().contains("a fresh key for each contract"));

    // Alice pays Bob, who has no contract
    let t = Instant::now();
    pay(&mut alice, &mut bob, 100_000).unwrap();
    println!("LICHEN Alice paid Bob 100,000 sats in {:.0?}: both accounts one step on", t.elapsed());
    assert_eq!(alice.note_of(&me), Note { owner: me, k: 1, v: 300_000 });
    let bob_addr = bob.address();
    assert_eq!(bob.note_of(&bob_addr), Note { owner: bob_addr, k: 1, v: 100_000 });
    assert!(alice.live().verify(&alice.issuer()) && bob.live().verify(&bob.issuer()));

    // Bob pays her back three times
    for _ in 0..3 {
        pay(&mut bob, &mut alice, 10_000).unwrap();
    }
    assert_eq!(alice.note_of(&me), Note { owner: me, k: 4, v: 330_000 });
    assert_eq!(bob.note_of(&bob_addr), Note { owner: bob_addr, k: 4, v: 70_000 });
    println!("LICHEN Bob paid Alice back three times: her note 4 of 330,000 sats, his note 4 of 70,000");

    // Alice proposes: only the payee's half is taken, and her account is
    // busy (Rule 2 at the hub)
    let id = alice.pay(bob_addr, 1_000).unwrap();
    let carol = Wallet::create(&env.dir.join("carol.json"), &hub.url).unwrap();
    let other = ureq::post(&format!("{}/half", hub.url)).send_json(serde_json::json!({ "id": id, "half": lichen_notes::Half::of(&carol.note_of(&carol.address()), 1_000) }));
    assert!(matches!(other, Err(ureq::Error::Status(400, _))), "another's half for Alice's payment");
    let busy = ureq::post(&format!("{}/pay", hub.url)).send_json(serde_json::json!({ "half": lichen_notes::Half::of(&alice.note_of(&me), 329_000), "to": hex::encode(carol.address()), "amount": 1_000 }));
    let Err(ureq::Error::Status(400, r)) = busy else { panic!("a second payment from a busy account") };
    assert!(r.into_string().unwrap().contains("busy, retry"));
    // cancelled unsigned: nothing to reissue
    match alice.cancel().unwrap() {
        Step::Cancelled(_, live) => assert_eq!(live.note, Note { owner: me, k: 4, v: 330_000 }),
        s => panic!("{s:?}"),
    }
    // signed by Alice alone, then cancelled: her note reissued one step on
    let id = alice.pay(bob_addr, 2_000).unwrap();
    assert_eq!(bob.receive().unwrap().as_deref(), Some(id.as_str()));
    assert!(matches!(alice.progress().unwrap()[..], [Step::Signed(_)]));
    match alice.cancel().unwrap() {
        Step::Cancelled(_, live) => assert_eq!(live.note, Note { owner: me, k: 5, v: 330_000 }, "reissued at k + 1"),
        s => panic!("{s:?}"),
    }
    // Bob's late signature: the payment is cancelled, he applies it
    assert!(matches!(bob.progress().unwrap()[..], [Step::Cancelled(..)]));
    assert_eq!(bob.note_of(&bob_addr), Note { owner: bob_addr, k: 4, v: 70_000 }, "Bob never signed: no reissue");
    println!("LICHEN cancels: unsigned, nothing reissued; signed by one side, its note reissued at k + 1");

    // a half of a note no longer live is refused
    let stale = lichen_notes::Half::of(&Note { owner: me, k: 4, v: 330_000 }, 300_000);
    let r = ureq::post(&format!("{}/pay", hub.url)).send_json(serde_json::json!({ "half": stale, "to": hex::encode(bob_addr), "amount": 30_000 }));
    let Err(ureq::Error::Status(400, r)) = r else { panic!("a stale half accepted") };
    assert!(r.into_string().unwrap().contains("not the live one"));

    // restored from its key: the live note from the hub
    let mut restored = Wallet::open(&env.dir.join("alice.json"), "").unwrap();
    restored.accounts.clear();
    restored.sync().unwrap();
    assert_eq!(restored.note_of(&me), Note { owner: me, k: 5, v: 330_000 });
    println!("LICHEN a stale half refused; a wallet restored from its key reads its live note, note 5 of 330,000 sats");
}

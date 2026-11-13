//! Payments on the grants L2, end to end: a regtest node, the hub daemon,
//! and wallets that talk to the hub alone.
//!
//! - Alice opens a contract: her deposit, pre-issued under the funding's
//!   adaptor point, is a note of hers once the funding is out.
//! - She pays Bob, who has no contract, 100,000 sats: final when the hub
//!   answers, her change one note.
//! - Bob pays her back in three payments; she holds four notes, and merges
//!   them into one.
//! - A note spent can't be granted again; another's notes can't be spent.
//! - A wallet restored from the hub's book finds its notes.

mod common;

use std::time::Instant;

use bitcoin::Amount;
use common::{statement, Env};
use lichen_notes::{Output, Spend};
use lichen_wallet::{Ask, Wallet};

#[test]
fn payments_by_grant() {
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
    assert_eq!((alice.balance(), alice.notes.len()), (ask.deposit, 1));
    println!("LICHEN contract {} opened in {:.1?}: Alice holds her deposit, a note of {} sats signed by the hub", held.record.cid(), t.elapsed(), ask.deposit);
    // one contract at a time per owner key: refused before she pays
    let err = alice.open_contract(&hub.url, &ch, &statement(), ask, ch.new_spk().unwrap(), &|_: &bitcoin::Address, _| panic!("asked to pay")).unwrap_err();
    assert!(format!("{err:#}").contains("one at a time"), "{err:#}");

    // Alice pays Bob, who has no contract: final at once
    let bobs_first = {
        let t = Instant::now();
        alice.send(bob.address(), 100_000).unwrap();
        println!("LICHEN Alice paid Bob 100,000 sats in {:.0?}: final", t.elapsed());
        assert_eq!((alice.balance(), alice.notes.len()), (300_000, 1), "her change, one note");
        assert_eq!(bob.sync().unwrap(), 1);
        assert_eq!(bob.balance(), 100_000);
        bob.notes[0].clone()
    };

    // Bob pays her back in three payments: she merges the four notes
    for _ in 0..3 {
        bob.send(alice.address(), 10_000).unwrap();
    }
    assert_eq!((bob.balance(), bob.notes.len()), (70_000, 1));
    assert_eq!(alice.sync().unwrap(), 3);
    assert_eq!(alice.notes.len(), 4);
    alice.merge().unwrap().expect("merged");
    assert_eq!((alice.balance(), alice.notes.len()), (330_000, 1));
    assert!(alice.merge().unwrap().is_none(), "one note: nothing to merge");
    println!("LICHEN Bob paid Alice back in three payments; her four notes merged into one of 330,000 sats");

    // a note spent can't be granted again; another's notes can't be spent
    let grant = |spend: &Spend| -> Result<serde_json::Value, String> {
        match ureq::post(&format!("{}/grant", hub.url)).send_json(spend) {
            Ok(r) => Ok(r.into_json().unwrap()),
            Err(ureq::Error::Status(_, r)) => Err(r.into_string().unwrap()),
            Err(e) => Err(e.to_string()),
        }
    };
    let again = grant(&Spend { inputs: vec![bobs_first.note], outputs: vec![Output { owner: bob.address(), value: 100_000 }] }).unwrap_err();
    assert!(again.contains("is spent"), "{again}");
    let theirs = Spend { inputs: vec![alice.notes[0].note], outputs: vec![Output { owner: bob.address(), value: 330_000 }] };
    let g: lichen_notes::Grant = serde_json::from_value(grant(&theirs).unwrap()).unwrap();
    // Bob signs a spend of Alice's note: the hub refuses to record it
    let forged = lichen_notes::sign(&lichen_notes::keypair(&[7; 32]).unwrap(), &lichen_notes::auth_msg(&g.sid, &g.commitment()));
    let r = ureq::post(&format!("{}/spend", hub.url)).send_json(lichen_notes::Authorized { sid: g.sid, sigs: vec![hex::encode(forged)] });
    assert!(matches!(r, Err(ureq::Error::Status(400, _))), "a spend not signed by the owner");
    alice.sync().unwrap();
    assert_eq!(alice.balance(), 330_000, "her note untouched");
    println!("LICHEN a spent note's second spend and a spend of another's note refused");

    // restored from the hub's book: the same notes
    let mut restored = Wallet::open(&env.dir.join("alice.json"), "").unwrap();
    restored.notes.clear();
    assert_eq!(restored.restore_notes().unwrap(), 1);
    assert_eq!(restored.balance(), 330_000);
    restored.sync().unwrap();
    assert_eq!(restored.balance(), 330_000, "no note read again from the mailbox");
}

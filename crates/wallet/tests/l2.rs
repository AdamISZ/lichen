//! The L2 end to end: a sequencer, the hub minting, two wallets paying
//! each other, a return to the hub, and the withdrawal statement's input.

use lichen_ledger::{check, regtest_hub, regtest_sequencer, xonly, Deployment, Mint, Tx, HUB_KEY};
use lichen_sequencer::Sequencer;
use lichen_wallet::Wallet;

#[test]
fn pay_return_and_the_withdrawal_input() {
    let dir = std::env::temp_dir().join(format!("lichen-l2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let seq = Sequencer::start("127.0.0.1:0", Some(dir.join("ledger.json")), regtest_sequencer(), HUB_KEY).unwrap();
    let mut alice = Wallet::create(&dir.join("alice.json"), &seq.url).unwrap();
    let mut bob = Wallet::create(&dir.join("bob.json"), &seq.url).unwrap();

    // the hub issues 10 to Alice (her deposit, in a contract with the hub)
    let mint = Mint::new(&regtest_hub(), &alice.sequencer.deployment, vec![lichen_ledger::note(alice.address(), 10, 0)]);
    alice.sequencer.submit(&Tx::Mint(mint)).unwrap();
    assert!(alice.sequencer.submit(&Tx::Mint(Mint::new(&regtest_sequencer(), &alice.sequencer.deployment, vec![lichen_ledger::note(bob.address(), 5, 0)]))).is_err(), "only the hub mints");
    alice.sequencer.seal().unwrap();
    assert_eq!(alice.balance().unwrap(), 10);

    // Alice pays Bob 4; Bob pays 1 back
    alice.send(bob.address(), 4, 0).unwrap();
    bob.send(alice.address(), 1, 0).unwrap();
    assert_eq!((alice.balance().unwrap(), bob.balance().unwrap()), (7, 3));
    assert!(bob.send(alice.address(), 4, 0).is_err(), "Bob has 3");

    // Alice returns 7 to the hub with her contract's memo 42
    let r = alice.return_to_hub(7, 42).unwrap();
    assert_eq!(alice.balance().unwrap(), 0);
    assert!(alice.withdraw_input(42).is_err(), "not sealed yet");
    let sealed = alice.sequencer.seal().unwrap();
    let input = alice.withdraw_input(42).unwrap();
    assert_eq!((input.index, input.height), (r, sealed.height));
    let journal = check(&input).unwrap();
    assert_eq!(journal[..8], [7, 0, 0, 0, 42, 0, 0, 0]);
    assert_eq!(journal[8..], Deployment::toy().id(), "the wallet pinned the sequencer's deployment");
    assert_eq!(xonly(&regtest_hub()), input.note.owner);
    // for proving it elsewhere (lngap-r0 prove-input / claim)
    if let Ok(path) = std::env::var("LICHEN_WRITE_WITHDRAW_INPUT") {
        std::fs::write(&path, serde_json::to_string_pretty(&input).unwrap()).unwrap();
    }

    // the wallet keeps the input and, once proved, the chain receipt: a
    // sequencer gone after that stops neither
    assert!(alice.chain_receipt(42).is_err(), "height not proved yet");
    std::fs::write(dir.join(format!("ledger.json.blocks/{}.chain", input.height)), b"a receipt").unwrap();
    assert_eq!(alice.chain_receipt(42).unwrap(), b"a receipt");
    drop(seq);
    let mut alice = Wallet::open(&dir.join("alice.json"), "http://127.0.0.1:9").unwrap();
    assert!(alice.balance().is_err(), "the sequencer is gone");
    assert_eq!(serde_json::to_value(alice.withdraw_input(42).unwrap()).unwrap(), serde_json::to_value(&input).unwrap());
    assert_eq!(alice.chain_receipt(42).unwrap(), b"a receipt");

    // a restarted sequencer keeps the ledger
    let seq = Sequencer::start("127.0.0.1:0", Some(dir.join("ledger.json")), regtest_sequencer(), HUB_KEY).unwrap();
    let bob = Wallet::open(&dir.join("bob.json"), &seq.url).unwrap();
    assert_eq!(bob.balance().unwrap(), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A sequencer signing two histories (two ledgers under one key, as a
/// sequencer showing one fork to Alice and another to Bob): a wallet that
/// sees both roots at one height refuses to go on, and writes the
/// evidence, which anyone can check; two wallets comparing their roots
/// catch it too.
#[test]
fn two_histories_are_caught() {
    let dir = std::env::temp_dir().join(format!("lichen-equivocation-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let a = Sequencer::start("127.0.0.1:0", Some(dir.join("a.json")), regtest_sequencer(), HUB_KEY).unwrap();
    let b = Sequencer::start("127.0.0.1:0", Some(dir.join("b.json")), regtest_sequencer(), HUB_KEY).unwrap();
    let alice = Wallet::create(&dir.join("alice.json"), &a.url).unwrap();
    let bob = Wallet::create(&dir.join("bob.json"), &b.url).unwrap();
    for (w, v) in [(&alice, 10), (&bob, 7)] {
        w.sequencer.submit(&Tx::Mint(Mint::new(&regtest_hub(), &w.sequencer.deployment, vec![lichen_ledger::note(w.address(), v, 0)]))).unwrap();
        w.sequencer.seal().unwrap();
        assert_eq!(w.balance().unwrap(), v);
    }

    // each history alone checks; together they conflict at height 1
    let theirs: Vec<_> = bob.seen().roots.into_values().collect();
    let e = alice.compare_roots(&theirs).unwrap_err().to_string();
    assert!(e.contains("two roots at height 1"), "{e}");
    let evidence = dir.join("alice.equivocation.json");
    let eq: lichen_l2::Equivocation = serde_json::from_slice(&std::fs::read(&evidence).unwrap()).unwrap();
    eq.verify(&Deployment::toy().sequencer).unwrap();
    let mut forged = eq.clone();
    forged.second.signature = forged.first.signature.clone();
    assert!(forged.verify(&Deployment::toy().sequencer).is_err(), "a root signed by no one is no evidence");
    assert_eq!(bob.compare_roots(&bob.seen().roots.into_values().collect::<Vec<_>>()).unwrap(), 1, "a history agrees with itself");

    // Alice's wallet shown the other history refuses to go on
    std::fs::remove_file(&evidence).unwrap();
    let alice = Wallet::open(&dir.join("alice.json"), &b.url).unwrap();
    let e = alice.balance().unwrap_err().to_string();
    assert!(e.contains("signed two histories"), "{e}");
    assert!(evidence.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

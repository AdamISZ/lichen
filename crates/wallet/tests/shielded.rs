//! Shielded notes end to end, with native proofs: Alice shields her
//! deposit, pays Bob, Bob pays her back, she returns to the hub from her
//! shielded notes, and the withdrawal statement takes the return as ever.
//! The sequencer's state shows no shielded value or owner.

use lichen_ledger::{check, regtest_hub, regtest_sequencer, Leaf, Mint, Tx, HUB_KEY};
use lichen_sequencer::{Options, Sequencer};
use lichen_wallet::Wallet;

#[test]
fn shield_pay_and_return() {
    let dir = std::env::temp_dir().join(format!("lichen-shielded-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let seq = Sequencer::start_with("127.0.0.1:0", Some(dir.join("ledger.json")), regtest_sequencer(), HUB_KEY, Options { native_proofs: true }).unwrap();
    let mut alice = Wallet::create(&dir.join("alice.json"), &seq.url).unwrap();
    let mut bob = Wallet::create(&dir.join("bob.json"), &seq.url).unwrap();
    alice.sequencer.submit(&Tx::Mint(Mint::new(&regtest_hub(), vec![lichen_ledger::note(alice.address(), 100, 0)]))).unwrap();
    alice.sequencer.seal().unwrap();

    // Alice shields 70 (30 stays transparent)
    alice.shield(70).unwrap();
    assert_eq!(alice.balances().unwrap(), (30, 70));
    // she pays Bob 45 from her shielded notes; Bob pays 5 back
    let to_bob = bob.shielded_address();
    alice.send_shielded(&to_bob, 45).unwrap();
    assert_eq!(alice.balances().unwrap(), (30, 25));
    assert_eq!(bob.balances().unwrap(), (0, 45));
    bob.send_shielded(&alice.shielded_address(), 5).unwrap();
    assert_eq!((alice.balances().unwrap(), bob.balances().unwrap()), ((30, 30), (0, 40)));
    assert!(bob.send_shielded(&alice.shielded_address(), 41).is_err(), "Bob has 40");
    // the state shows commitments and ciphertexts, no shielded value or
    // owner: the transparent notes are the mint, Alice's change and nothing else
    let state = alice.sequencer.state().unwrap();
    assert_eq!(state.notes.iter().filter(|l| matches!(l, Leaf::Shielded { .. })).count(), 5);
    assert_eq!(state.transparent().map(|(_, n)| n.value).collect::<Vec<_>>(), vec![100, 30]);

    // Alice returns 28 to the hub with memo 42, from her shielded notes
    let r = alice.return_to_hub(28, 42).unwrap();
    assert_eq!(alice.balances().unwrap(), (30, 2));
    alice.sequencer.seal().unwrap();
    let journal = check(&alice.withdraw_input(42).unwrap()).unwrap();
    assert_eq!(journal[..8], [28, 0, 0, 0, 42, 0, 0, 0]);
    assert_eq!(alice.sequencer.state().unwrap().note(r).unwrap().owner, HUB_KEY);

    // a sequencer that accepts no native proofs refuses them
    drop(seq);
    let seq = Sequencer::start("127.0.0.1:0", Some(dir.join("ledger.json")), regtest_sequencer(), HUB_KEY).unwrap();
    let mut bob = Wallet::open(&dir.join("bob.json"), &seq.url).unwrap();
    assert_eq!(bob.balances().unwrap(), (0, 40), "the restarted sequencer kept the shielded notes");
    let a = alice.shielded_address();
    assert!(bob.send_shielded(&a, 1).unwrap_err().to_string().contains("no native proofs"));
    let _ = std::fs::remove_dir_all(&dir);
}

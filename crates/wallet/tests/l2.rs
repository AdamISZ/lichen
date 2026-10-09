//! The L2 end to end: a sequencer, the hub minting, two wallets paying
//! each other, a return to the hub, and the withdrawal statement's input.

use lichen_ledger::{check, regtest_hub, regtest_sequencer, xonly, Mint, Tx, HUB_KEY, SEQUENCER_KEY};
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
    let mint = Mint::new(&regtest_hub(), vec![lichen_ledger::note(alice.address(), 10, 0)]);
    alice.sequencer.submit(&Tx::Mint(mint)).unwrap();
    assert!(alice.sequencer.submit(&Tx::Mint(Mint::new(&regtest_sequencer(), vec![lichen_ledger::note(bob.address(), 5, 0)]))).is_err(), "only the hub mints");
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
    assert_eq!(check(&input, &SEQUENCER_KEY, &HUB_KEY), Ok([7, 0, 0, 0, 42, 0, 0, 0]));
    assert_eq!(xonly(&regtest_hub()), input.note.owner);

    // a restarted sequencer keeps the ledger
    drop(seq);
    let seq = Sequencer::start("127.0.0.1:0", Some(dir.join("ledger.json")), regtest_sequencer(), HUB_KEY).unwrap();
    let bob = Wallet::open(&dir.join("bob.json"), &seq.url).unwrap();
    assert_eq!(bob.balance().unwrap(), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

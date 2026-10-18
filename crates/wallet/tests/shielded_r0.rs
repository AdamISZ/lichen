//! Opt-in (`--ignored`; the prover image, `docker build -f r0/Dockerfile -t
//! lichen-r0 .`, or LICHEN_SPEND_PROVER naming another prover command):
//! shielding, a payment and a return with real RISC Zero receipts, to a
//! sequencer that accepts no native proofs; then every height it recorded
//! proved by the chain prover (r0/chain-prover.sh, in the same image, or
//! LICHEN_R0 naming lichen-r0), the last receipt ending at the last
//! sealed root.

use lichen_ledger::{check, regtest_hub, regtest_sequencer, Mint, Tx, HUB_KEY};
use lichen_sequencer::Sequencer;
use lichen_wallet::shielded::SpendProver;
use lichen_wallet::Wallet;

#[test]
#[ignore]
fn shield_pay_and_return_with_receipts() {
    let dir = std::env::temp_dir().join(format!("lichen-shielded-r0-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let prover = std::env::var("LICHEN_SPEND_PROVER").map(std::path::PathBuf::from).unwrap_or_else(|_| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../r0/spend-prover.sh"));
    let seq = Sequencer::start("127.0.0.1:0", Some(dir.join("ledger.json")), regtest_sequencer(), HUB_KEY).unwrap();
    let mut alice = Wallet::create(&dir.join("alice.json"), &seq.url).unwrap();
    let mut bob = Wallet::create(&dir.join("bob.json"), &seq.url).unwrap();
    alice.spend_prover = SpendProver::Command(prover.clone());
    bob.spend_prover = SpendProver::Command(prover);
    alice.sequencer.submit(&Tx::Mint(Mint::new(&regtest_hub(), vec![lichen_ledger::note(alice.address(), 100, 0)]))).unwrap();
    alice.sequencer.seal().unwrap();
    let t = std::time::Instant::now();
    alice.shield(100).unwrap();
    println!("LICHEN shielded 100 in {:.1?}", t.elapsed());
    let t = std::time::Instant::now();
    alice.send_shielded(&bob.shielded_address(), 60).unwrap();
    println!("LICHEN paid Bob 60 in {:.1?}", t.elapsed());
    assert_eq!((alice.balances().unwrap(), bob.balances().unwrap()), ((0, 40), (0, 60)));
    let t = std::time::Instant::now();
    bob.return_to_hub(60, 42).unwrap();
    println!("LICHEN Bob returned 60 to the hub in {:.1?}", t.elapsed());
    bob.sequencer.seal().unwrap();
    assert_eq!(check(&bob.withdraw_input(42).unwrap()).unwrap()[..8], [60, 0, 0, 0, 42, 0, 0, 0]);

    // the chain: every recorded height proved, each from the last
    let blocks = lichen_sequencer::blocks_dir(&dir.join("ledger.json"));
    let r0 = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../r0");
    let t = std::time::Instant::now();
    let ok = std::process::Command::new(r0.join("chain-prover.sh")).arg(&blocks).arg("--once").status().unwrap();
    assert!(ok.success(), "the chain prover");
    let sealed = bob.sequencer.state().unwrap().sealed.last().unwrap().clone();
    println!("LICHEN proved {} heights in {:.1?}", sealed.height, t.elapsed());
    let last = std::fs::read(blocks.join(format!("{}.chain", sealed.height))).unwrap();
    let out = match std::env::var("LICHEN_R0") {
        Ok(cmd) => std::process::Command::new(cmd).arg("verify-chain").arg("-").stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn(),
        Err(_) => std::process::Command::new("docker").args(["run", "--rm", "-i", "lichen-r0", "verify-chain", "-"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn(),
    }
    .unwrap();
    use std::io::Write;
    out.stdin.as_ref().unwrap().write_all(&last).unwrap();
    let out = out.wait_with_output().unwrap();
    assert!(out.status.success(), "the last chain receipt verifies");
    let line = String::from_utf8(out.stdout).unwrap();
    println!("LICHEN {line}");
    assert!(line.starts_with(&format!("height {} root {} ", sealed.height, hex::encode(sealed.root()))), "it ends at the last sealed root: {line}");
    let _ = std::fs::remove_dir_all(&dir);
}

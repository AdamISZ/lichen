//! Opt-in (`--ignored`; the prover image, `docker build -f r0/Dockerfile -t
//! lichen-r0 .` (or another tag, named by LICHEN_R0_IMAGE), or
//! LICHEN_SPEND_PROVER naming another prover command; a
//! regtest bitcoind): shielding, a payment and a return with real RISC
//! Zero receipts, to a sequencer that accepts no native proofs and
//! anchors its history on regtest (docs/ANCHOR_PLAN.md); then every height
//! it recorded proved by the chain prover (r0/chain-prover.sh, in the same
//! image, or LICHEN_R0 naming lichen-r0), the last receipt ending at the
//! last sealed root and carrying the return's anchor; then Bob's
//! withdrawal proved by the withdrawal guest (r0/withdraw-prover.sh),
//! under the anchored root, the chain receipt first carrying its anchor
//! (which the sequencer serves) and ten blocks on the anchor (a succinct
//! receipt: the Groth16 wrap is x86 Linux's, LICHEN_WRAP=1 there).
//! LICHEN_KEEP=1 keeps the files: the canned claim of crates/proto/tests/data
//! is `withdraw-prover.sh claim` on x86 Linux of the withdrawal's input and
//! chain receipt kept so, and `claim-60-42.seal` the deployment's genesis
//! seal (the claim's D commits to it).

use std::time::{Duration, Instant};

use bitcoin::Amount;
use lichen_chain::Chain;
use lichen_ledger::{check, regtest_hub, regtest_sequencer, xonly, Mint, Tx, HUB_KEY};
use lichen_sequencer::anchor::{genesis_seal, Anchoring};
use lichen_sequencer::{Options, Sequencer};
use lichen_wallet::shielded::SpendProver;
use lichen_wallet::Wallet;
use lngap_btc::regtest::Regtest;

#[test]
#[ignore]
fn shield_pay_and_return_with_receipts() {
    let dir = std::env::temp_dir().join(format!("lichen-shielded-r0-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let prover = std::env::var("LICHEN_SPEND_PROVER").map(std::path::PathBuf::from).unwrap_or_else(|_| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../r0/spend-prover.sh"));
    let rt = Regtest::start().unwrap();
    let chain = || Chain::connect(rt.rpc_url(), rt.cookie(), "sequencer").unwrap();
    rt.fund(&chain().new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
    rt.mine(1).unwrap();
    let seal = genesis_seal(&chain(), &xonly(&regtest_sequencer())).unwrap();
    rt.mine(1).unwrap();
    let mut seq = Sequencer::start_with("127.0.0.1:0", Some(dir.join("ledger.json")), regtest_sequencer(), HUB_KEY, Options { seal: Some(seal), ..Default::default() }).unwrap();
    seq.anchor(chain(), Anchoring { every: Duration::from_millis(200), ..Default::default() }).unwrap();
    let mut alice = Wallet::create(&dir.join("alice.json"), &seq.url).unwrap();
    let mut bob = Wallet::create(&dir.join("bob.json"), &seq.url).unwrap();
    alice.spend_prover = SpendProver::Command(prover.clone());
    bob.spend_prover = SpendProver::Command(prover);
    alice.sequencer.submit(&Tx::Mint(Mint::new(&regtest_hub(), &alice.sequencer.deployment, vec![lichen_ledger::note(alice.address(), 100, 0)]))).unwrap();
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
    // anchored: blocks until the anchor's record, then its height sealed
    let index = bob.returned(42).unwrap();
    let start = Instant::now();
    while bob.sequencer.state().unwrap().anchored_input(index, &bob.sequencer.deployment).is_err() {
        assert!(start.elapsed() < Duration::from_secs(120), "the return anchored");
        rt.mine(1).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        bob.sequencer.seal().unwrap();
    }
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
        Err(_) => std::process::Command::new("docker").args(["run", "--rm", "-i", &std::env::var("LICHEN_R0_IMAGE").unwrap_or("lichen-r0".into()), "verify-chain", "-"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn(),
    }
    .unwrap();
    use std::io::Write;
    out.stdin.as_ref().unwrap().write_all(&last).unwrap();
    let out = out.wait_with_output().unwrap();
    assert!(out.status.success(), "the last chain receipt verifies");
    let line = String::from_utf8(out.stdout).unwrap();
    println!("LICHEN {line}");
    assert!(line.starts_with(&format!("height {} root {} ", sealed.height, hex::encode(sealed.root()))), "it ends at the last sealed root: {line}");

    assert!(line.contains(&format!("anchored at {}", bob.withdraw_input(42).unwrap().height)), "and carries the return's anchor: {line}");

    // the withdrawal: ln-gap's statement under the anchored root, the
    // chain receipt first carrying the anchor, ten blocks on it (the
    // contract's W at regtest's difficulty: a checkpoint here)
    rt.mine(10).unwrap();
    let input = bob.withdraw_input(42).unwrap();
    let anchor = bob.kept(index).and_then(|k| k.anchor).expect("the anchor kept");
    let checkpoint = lichen_proto::Checkpoint::tip(&chain()).unwrap();
    let full = lichen_wallet::prover_input(input.clone(), Some(&anchor), Some(&checkpoint), &chain()).unwrap();
    let (json, chain_file, receipt) = (dir.join("withdraw-input.json"), dir.join("chain.receipt"), dir.join("withdraw.receipt"));
    std::fs::write(&json, serde_json::to_vec_pretty(&full).unwrap()).unwrap();
    std::fs::write(&chain_file, bob.chain_receipt(42).unwrap()).unwrap();
    std::fs::write(dir.join("seal"), lichen_ledger::outpoint::to_string(&seal)).unwrap();
    assert_eq!(std::fs::read(&chain_file).unwrap(), std::fs::read(blocks.join(format!("{}.chain", anchor.from))).unwrap(), "the sequencer serves its prover's receipt");
    let t = std::time::Instant::now();
    let cmd = if std::env::var("LICHEN_WRAP").is_ok() { "claim" } else { "withdraw" };
    let ok = std::process::Command::new(r0.join("withdraw-prover.sh")).arg(cmd).arg(&json).arg(&chain_file).arg(&receipt).status().unwrap();
    assert!(ok.success(), "the withdrawal prover");
    println!("LICHEN proved Bob's withdrawal ({cmd}) under the anchored height {} in {:.1?}", input.height, t.elapsed());
    drop(seq);
    match std::env::var("LICHEN_KEEP") {
        Ok(_) => println!("LICHEN kept {}", dir.display()),
        Err(_) => drop(std::fs::remove_dir_all(&dir)),
    }
}

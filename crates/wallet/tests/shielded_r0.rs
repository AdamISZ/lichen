//! Opt-in (`--ignored`; the prover image, `docker build -f r0/Dockerfile -t
//! lichen-r0 .` (or another tag, named by LICHEN_R0_IMAGE), or
//! LICHEN_SPEND_PROVER naming another prover command; a
//! regtest bitcoind): shielding, a payment and an unshielding with real
//! RISC Zero receipts, to a sequencer that accepts no native proofs and
//! anchors its history on regtest (docs/ANCHOR_PLAN.md); then every height
//! it recorded proved by the chain prover (r0/chain-prover.sh, in the same
//! image, or LICHEN_R0 naming lichen-r0), the last receipt ending at the
//! last sealed root and carrying the last anchor. LICHEN_KEEP=1 keeps the
//! files.

use std::time::{Duration, Instant};

use bitcoin::Amount;
use lichen_chain::Chain;
use lichen_ledger::{regtest_hub, regtest_sequencer, xonly, Mint, Tx, HUB_KEY};
use lichen_sequencer::anchor::{genesis_seal, Anchoring};
use lichen_sequencer::{Options, Sequencer};
use lichen_wallet::shielded::SpendProver;
use lichen_wallet::Wallet;
use lngap_btc::regtest::Regtest;

#[test]
#[ignore]
fn shield_pay_and_unshield_with_receipts() {
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
    alice.sequencer.submit(&Tx::Mint(Mint::new(&regtest_hub(), &alice.sequencer.deployment, vec![lichen_ledger::note(alice.address(), 100_000, 0)]))).unwrap();
    alice.sequencer.seal().unwrap();
    let t = std::time::Instant::now();
    alice.shield(100_000).unwrap();
    println!("LICHEN shielded 100,000 in {:.1?}", t.elapsed());
    let t = std::time::Instant::now();
    let ret = 41_040;
    alice.send_shielded(&bob.shielded_address(), ret).unwrap();
    println!("LICHEN paid Bob {ret} in {:.1?}", t.elapsed());
    assert_eq!((alice.balances().unwrap(), bob.balances().unwrap()), ((0, 100_000 - ret), (0, ret)));
    let t = std::time::Instant::now();
    let index = bob.unshield(ret).unwrap();
    println!("LICHEN Bob unshielded {ret} in {:.1?}", t.elapsed());
    bob.sequencer.seal().unwrap();
    // anchored: blocks until an anchor covering it is recorded
    let start = Instant::now();
    let mut anchored = 0;
    while anchored == 0 {
        assert!(start.elapsed() < Duration::from_secs(120), "the unshielding anchored");
        rt.mine(1).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        bob.sequencer.seal().unwrap();
        let s = bob.sequencer.state().unwrap();
        let h = s.sealed.iter().find(|x| x.size > index).map_or(u64::MAX, |x| x.height);
        anchored = s.anchors.iter().find(|a| a.anchor.height >= h).map_or(0, |a| a.anchor.height);
    }

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

    assert!(line.contains("anchored at "), "and carries the last anchor: {line}");
    drop(seq);
    match std::env::var("LICHEN_KEEP") {
        Ok(_) => println!("LICHEN kept {}", dir.display()),
        Err(_) => drop(std::fs::remove_dir_all(&dir)),
    }
}

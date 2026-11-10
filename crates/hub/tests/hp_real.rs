//! Opt-in (`--ignored`): the hub's statement for real (HUB_PROVES_PLAN
//! step 7), RISC Zero's proof wrapped in Groth16, on regtest. Needs the
//! hub's prover: LICHEN_HP_PROVER (r0/hp-prover.sh on x86 Linux with the
//! prover image; from a Mac, r0/hp-remote.sh with LICHEN_R0_HOST and
//! LICHEN_R0_TREE naming such a box).
//!
//! Mal opens a contract on `hub-proves` (she garbles under RISC Zero's
//! key) and requests an exit whose posted claim is malformed (a position
//! repeated: not the claim she signed `E` of). The hub proves the claim
//! false (no chain receipt: a malformed claim needs none) and asserts; her
//! wallet finds the proof valid and concedes; `success` is the hub's.
//!
//! Blocks come every 150 ms, but one a minute while the hub proves (its
//! files in `hp/<cid>/`: the prover's log and no seal yet), so that `w_H`
//! covers the proof and the wallet's stall check (5 minutes on regtest)
//! doesn't fire.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use bitcoincore_rpc::{Auth, RpcApi};
use common::{wait, Env};
use lichen_proto::Statement;
use lichen_wallet::dispute::Outcome;
use lichen_wallet::{Ask, Wallet};

/// Whether a prover runs in `hp`: a contract's prover's log without its
/// seal.
fn proving(hp: &std::path::Path) -> bool {
    let Ok(dirs) = std::fs::read_dir(hp) else { return false };
    dirs.flatten().filter(|d| d.path().is_dir()).any(|d| d.path().join("prover.log").exists() && !d.path().join("proof.seal").exists())
}

#[test]
#[ignore]
fn a_malformed_claim_proved_false_for_real() {
    assert!(std::env::var("LICHEN_HP_PROVER").is_ok(), "set LICHEN_HP_PROVER (r0/hp-prover.sh, or r0/hp-remote.sh)");
    let statement = Statement::HubProves { mock: false };
    let mut env = Env::new("hp-real");
    env.anchor();
    let env = env;
    let rt = &env.rt;
    let hub = env.hub("hub", |c| {
        c.statement = statement.clone();
        c.refuse_folds = true;
    });
    let hp_dir = env.dir.join("hub").join("hp");
    let stop = Arc::new(AtomicBool::new(false));
    let miner = {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", rt.rpc_url()), Auth::CookieFile(rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        let (s, hp) = (stop.clone(), hp_dir.clone());
        std::thread::spawn(move || {
            let mut last = Instant::now();
            while !s.load(Ordering::Relaxed) {
                let every = if proving(&hp) { Duration::from_secs(60) } else { Duration::from_millis(150) };
                if last.elapsed() >= every {
                    let _ = rpc.generate_to_address(1, &addr);
                    last = Instant::now();
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
    };

    let ch = env.chain("mal");
    rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
    let mut w = Wallet::create(&env.dir.join("mal.json"), &env.seq.url).unwrap();
    w.progress = Some(Arc::new(|m: String| println!("LICHEN mal: {m}")));
    let ask = Ask { deposit: 200_000, liquidity: 1_000_000, reserve: 20_000 };
    let t = Instant::now();
    let cid = w.open_contract(&hub.url, &ch, &statement, ask, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| ch.pay(&addr.script_pubkey(), v).map(|_| ())).unwrap().record.cid();
    println!("LICHEN mal: contract {cid} opened on the real statement in {:.1?}", t.elapsed());
    wait("the deposit", || w.balance().unwrap() == ask.deposit);
    w.acknowledge_all(&ch, 120).unwrap();

    // her claim, then a position repeated: not the claim of the E she signs
    let mut plan = w.hp_exit_plan(&ch, cid).unwrap();
    let mut claim = lichen_withdraw::hp::Claim::from_bytes(&plan.posted().unwrap()).unwrap();
    claim.positions.push(claim.positions[0]);
    assert!(!claim.well_formed());
    plan.posted = hex::encode(claim.to_bytes());
    let k = w.contracts.iter().position(|h| h.record.cid() == cid).unwrap();
    w.contracts[k].exit = Some(plan);

    let t = Instant::now();
    let (o, _) = w.exit(&ch, &statement, cid).unwrap();
    println!("LICHEN mal: {o:?} in {:.1?}", t.elapsed());
    assert_eq!(o, Outcome::Countered, "the hub proves the malformed claim false, and she concedes");
    assert!(hub.log().iter().any(|l| l.contains(&format!("contract {cid}: the user's exit claim is false: the claim is malformed: proved; asserting"))), "with a real proof");
    let start = Instant::now();
    while !hub.contracts().iter().any(|(r, closed)| r.cid() == cid && closed.is_some()) {
        assert!(start.elapsed() < Duration::from_secs(120), "success the hub's: timed out");
        std::thread::sleep(Duration::from_millis(200));
    }
    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
}

/// The highest height in `blocks` with an input, and with a chain receipt.
fn heights(blocks: &std::path::Path) -> (u64, u64) {
    let (mut input, mut chain) = (0, 0);
    for f in std::fs::read_dir(blocks).into_iter().flatten().flatten() {
        let name = f.file_name().to_string_lossy().into_owned();
        if let Some(h) = name.strip_suffix(".input").and_then(|h| h.parse::<u64>().ok()) {
            input = input.max(h);
        }
        if let Some(h) = name.strip_suffix(".chain").and_then(|h| h.parse::<u64>().ok()) {
            chain = chain.max(h);
        }
    }
    (input, chain)
}

/// Opt-in, the timing run on the real circuit: a stale claim proved false
/// at `A*`, the chain receipt there composed. Needs LICHEN_HP_PROVER as
/// above, and LICHEN_R0 naming lichen-r0 for the chain prover
/// (r0/chain-prover.sh, run here on every height the sequencer records:
/// natively on a Mac, `cargo build --release` in r0).
///
/// Sam opens a contract, prepares his claim of his deposit's note, pays
/// it to Bob and acknowledges the payment; once it is anchored before the
/// cutoff he claims the note anyway. Before his request, mining pauses
/// until the chain is proved to the last height; during the exit, a block
/// comes every 150 ms, but one each 30 s while the chain prover lags or
/// the hub proves. The hub proves the note spent at `A*` and asserts; his
/// wallet concedes. Printed: how long each part took.
#[test]
#[ignore]
fn a_stale_claim_proved_false_for_real() {
    assert!(std::env::var("LICHEN_HP_PROVER").is_ok(), "set LICHEN_HP_PROVER (r0/hp-prover.sh, or r0/hp-remote.sh)");
    let r0 = std::env::var("LICHEN_R0").expect("set LICHEN_R0: lichen-r0 for the chain prover");
    let statement = Statement::HubProves { mock: false };
    let mut env = Env::new("hp-real-stale");
    env.anchor();
    let env = env;
    let rt = &env.rt;
    let blocks = lichen_sequencer::blocks_dir(&env.dir.join("ledger.json"));
    std::fs::create_dir_all(&blocks).unwrap();
    let chain_log = env.dir.join("chain-prover.log");
    let log = std::fs::File::create(&chain_log).unwrap();
    // in a process group of its own, so that its prover goes with it
    let prover = std::os::unix::process::CommandExt::process_group(&mut std::process::Command::new(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../r0/chain-prover.sh")), 0)
        .arg(&blocks)
        .env("LICHEN_R0", &r0)
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let hub = env.hub("hub", |c| c.statement = statement.clone());
    let hp_dir = env.dir.join("hub").join("hp");
    // 0: fast; 1: paused; 2: the exit's (slow while the chain lags or the
    // hub proves)
    let mode = Arc::new(std::sync::atomic::AtomicU8::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let miner = {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", rt.rpc_url()), Auth::CookieFile(rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        let (s, m, hp, b) = (stop.clone(), mode.clone(), hp_dir.clone(), blocks.clone());
        std::thread::spawn(move || {
            let mut last = Instant::now();
            while !s.load(Ordering::Relaxed) {
                let every = match m.load(Ordering::Relaxed) {
                    1 => None,
                    2 if proving(&hp) || heights(&b).0 > heights(&b).1 => Some(Duration::from_secs(30)),
                    _ => Some(Duration::from_millis(150)),
                };
                if every.is_some_and(|e| last.elapsed() >= e) {
                    let _ = rpc.generate_to_address(1, &addr);
                    last = Instant::now();
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
    };

    let t0 = Instant::now();
    let ch = env.chain("sam");
    rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
    let mut w = Wallet::create(&env.dir.join("sam.json"), &env.seq.url).unwrap();
    w.progress = Some(Arc::new(|m: String| println!("LICHEN sam: {m}")));
    let ask = Ask { deposit: 200_000, liquidity: 1_000_000, reserve: 20_000 };
    let cid = w.open_contract(&hub.url, &ch, &statement, ask, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| ch.pay(&addr.script_pubkey(), v).map(|_| ())).unwrap().record.cid();
    wait("the deposit", || w.balance().unwrap() == ask.deposit);
    w.acknowledge_all(&ch, 120).unwrap();
    let plan = w.hp_exit_plan(&ch, cid).unwrap();
    let old = w.notes(&w.state().unwrap())[0].note;
    w.send(lichen_ledger::xonly(&lichen_ledger::key_from_label("test/bob")), ask.deposit, 0).unwrap();
    w.acknowledge_all(&ch, 120).unwrap();
    let c = lichen_l2::Client::new(&env.seq.url).unwrap();
    let spent = c.spent(&lichen_ledger::nullifier(&old)).unwrap().expect("spent").1;
    let margin = lichen_proto::hp::margin(lichen_proto::Net::Regtest);
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(120), "past the cutoff: timed out");
        let s = c.state().unwrap();
        let deep = s.anchors.iter().find(|a| a.anchor.height >= spent).and_then(|a| ch.block_height(&<bitcoin::BlockHash as bitcoin::hashes::Hash>::from_byte_array(a.anchor.block)).unwrap());
        if deep.is_some_and(|b| ch.height().unwrap() >= b + margin + 2) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let k = w.contracts.iter().position(|h| h.record.cid() == cid).unwrap();
    w.contracts[k].exit = Some(plan);
    println!("LICHEN timing: set up in {:.0?}", t0.elapsed());

    // the chain proved to the last height, mining paused
    mode.store(1, Ordering::Relaxed);
    let t = Instant::now();
    let (h, _) = heights(&blocks);
    while heights(&blocks).1 < h {
        assert!(t.elapsed() < Duration::from_secs(3 * 3600), "the chain prover: timed out");
        std::thread::sleep(Duration::from_secs(2));
    }
    println!("LICHEN timing: the chain proved to height {h} in {:.0?}", t.elapsed());

    mode.store(2, Ordering::Relaxed);
    let t = Instant::now();
    let (o, _) = w.exit(&ch, &statement, cid).unwrap();
    println!("LICHEN timing: the exit, {o:?}, in {:.0?}", t.elapsed());
    let said: Vec<String> = hub.log().into_iter().filter(|l| l.contains(&format!("contract {cid}:"))).collect();
    for l in &said {
        println!("LICHEN hub: {l}");
    }
    for l in std::fs::read_to_string(hp_dir.join(cid.to_string()).join("prover.log")).unwrap_or_default().lines().filter(|l| l.contains("lichen-r0")) {
        println!("LICHEN hub's prover: {l}");
    }
    for l in std::fs::read_to_string(&chain_log).unwrap().lines().filter(|l| l.contains("proved height")) {
        println!("LICHEN chain prover: {l}");
    }
    assert_eq!(o, Outcome::Countered, "the hub proves the stale claim false, and he concedes");
    assert!(said.iter().any(|l| l.contains("was spent by A*") && l.contains("proved; asserting")), "with a real proof");
    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
    let _ = std::process::Command::new("kill").arg("--").arg(format!("-{}", prover.id())).status();
}

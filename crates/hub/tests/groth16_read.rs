//! Opt-in (release; about half an hour): a read lie on the REAL
//! statement, BitVMX's Groth16 verifier, as a rehearsal for a trial on a
//! test network. The claim is groth16.rs's (the toy deployment's return of
//! 60, memo 42) with `b` changed to 61 (false, as G3 there). Alice props it up with a lie in a read
//! near the end of the execution, of a value written long before: the
//! honest hub's search lands on her step, and the hub posts the jump-list
//! path to the step that last wrote that address; its `read` verdict
//! takes everything.
//!
//!     cargo test --release -p lichen-hub --test groth16_read -- --ignored --nocapture

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use bitcoincore_rpc::{Auth, RpcApi};
use emulator::decision::challenge::ForceCondition;
use emulator::executor::utils::{FailConfiguration, FailReads};
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_proto::Statement;
use lichen_sequencer::{Options, Sequencer};
use lichen_wallet::dispute::Outcome;
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;

/// A read lie in the last `tail` steps that the search lands on: the read
/// whose last write is furthest back, its value flipped. (the step, its
/// path's hops, the lie)
fn a_late_read_lie(statement: &Statement, input: &[u8], dir: &std::path::Path, tail: u64) -> (u64, usize, FailConfiguration) {
    let program = statement.program(dir).unwrap();
    let j = program.schedule.jump.expect("a jump list");
    let d = format!("{}/exec/", dir.display());
    std::fs::create_dir_all(&d).unwrap();
    let (_, last, _) = emulator::decision::challenge::prover_execute(&program.pdf, input.to_vec(), &d, &d, true, None, false).unwrap();
    let pd = emulator::loader::program_definition::ProgramDefinition::from_config(&program.pdf).unwrap();
    let (_, trace) = pd.execute_helper(&d, &d, input.to_vec(), Some((last - tail..=last).collect()), None, false).unwrap();
    let never = u64::MAX;
    let mut candidates = vec![];
    for (t, _) in &trace {
        for (r, rd) in [(2u8, &t.read_2), (1, &t.read_1)] {
            if rd.last_step == never || rd.last_step == 0 || t.step_number <= rd.last_step + 2 || t.step_number == last {
                continue;
            }
            candidates.push((t.step_number - rd.last_step, r, t.step_number, rd.address, rd.value, rd.last_step));
        }
    }
    candidates.sort_by(|a, b| b.cmp(a));
    for (_, r, step, address, value, last_step) in candidates.into_iter().take(8) {
        let args: Vec<String> = vec![step.to_string(), format!("{address:#x}"), format!("{:#x}", value ^ 1), format!("{address:#x}"), last_step.to_string()];
        let fail = FailConfiguration::new_fail_reads(if r == 1 { FailReads::new(Some(&args), None) } else { FailReads::new(None, Some(&args)) });
        let found = lngap_zk::dispute::search(&program.pdf, input, &dir.join(format!("probe-{step}")), &lngap_zk::dispute::Behaviour { fail: Some(fail.clone()) }, &lngap_zk::dispute::Behaviour::default(), ForceCondition::No).unwrap();
        if let Some(sr) = found {
            if sr.step == step && sr.final_step.claim_last_step != sr.step {
                return (step, j.path(step - 1, last_step).len(), fail);
            }
        }
    }
    panic!("no read lie lands the search on its step");
}

#[test]
#[ignore]
fn a_read_lie_on_the_groth16_verifier() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-g16r-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let statement = Statement::groth16().unwrap();
    let mut input = hex::decode(include_str!("../../proto/tests/data/claim-60-42.hex").trim()).unwrap();
    input[164] = 61; // b, word 41's low byte: a false claim
    let t = Instant::now();
    let (step, hops, lie) = a_late_read_lie(&statement, &input, &dir.join("probe"), 20_000);
    println!("LICHEN R: a read lie at step {step}, a path of {hops} hops, found in {:.0?}", t.elapsed());

    // the deployment the canned claim's D commits to: its genesis seal (no
    // anchoring needed: the dispute reads only the claim's words)
    let seq = Sequencer::start_with("127.0.0.1:0", None, regtest_sequencer(), HUB_KEY, Options { seal: Some(lichen_proto::canned_seal()), ..Default::default() }).unwrap();
    let chain = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    // blocks when the mempool has something, else every 15 s (as groth16.rs)
    let miner = {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", rt.rpc_url()), Auth::CookieFile(rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        let s = stop.clone();
        std::thread::spawn(move || {
            let mut last = Instant::now();
            while !s.load(Ordering::Relaxed) {
                let busy = rpc.get_raw_mempool().map(|m| !m.is_empty()).unwrap_or(false);
                if busy || last.elapsed() > Duration::from_secs(15) {
                    let _ = rpc.generate_to_address(1, &addr);
                    last = Instant::now();
                }
                std::thread::sleep(Duration::from_millis(300));
            }
        })
    };
    rt.fund(&chain("hub").new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
    let hub = Hub::start(Config {
        network: lichen_proto::Net::Regtest,
        listen: "127.0.0.1:0".into(),
        sequencer: seq.url.clone(),
        rpc_url: rt.rpc_url().to_string(),
        cookie: rt.cookie().clone(),
        wallet: "hub".into(),
        statement: statement.clone(),
        dir: dir.join("hub"),
        seed: "test-g16r-hub".into(),
        l2_key: lichen_ledger::regtest_hub(),
        reserve_ppm: 20_000,
        max_bits: 24,
        duration: 5_000,
        refuse_folds: true,
        dispute_true_claims: false,
        first_cid: 42,
        windows: None,
    })
    .unwrap();
    let ch = chain("alice");
    rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
    let mut w = Wallet::create(&dir.join("alice.json"), &seq.url).unwrap();
    let ask = Ask { deposit: 400_000, bits: 21, reserve: 20_000 };
    let held = w.open_contract(&hub.url, &ch, &statement, &dir.join("alice"), ask, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
    assert_eq!(held.record.cid(), 42);
    w.lie = Some(lie);
    w.progress = Some(Arc::new(|m: String| println!("alice: {m}")));
    let t = Instant::now();
    let (o, swept) = w.dispute(&ch, &statement, &dir.join("alice"), 42, 10, &input).unwrap();
    println!("LICHEN R: claim of 10 propped up by a read lie at step {step}: {o:?} in {:.0?}; swept {swept:?}", t.elapsed());
    assert_eq!(o, Outcome::Lost, "the hub's path proves its verdict");
    let start = Instant::now();
    while !hub.log().iter().any(|l| l.contains("disprove_read_")) {
        assert!(start.elapsed() < Duration::from_secs(120), "the hub's read verdict: {:?}", hub.log());
        std::thread::sleep(Duration::from_millis(500));
    }
    for l in hub.log() {
        println!("hub: {l}");
    }
    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

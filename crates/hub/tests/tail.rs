//! The read and jump challenges (a jump list), played by the wallet's
//! engine against the hub's on the mock statement. Each claim is false (a
//! return the mock's table doesn't have), and Alice lies in her execution
//! to prop it up; the honest hub disputes, and the search lands on her lie:
//!
//! - J: a wrong long-jump hash in her disputed step: the hub posts a path
//!   to the long jump; its `jump` verdict takes everything;
//! - L: a read of a value never written there: the hub posts a path to the
//!   step that last wrote it; its `read` verdict takes everything;
//! - F: the same lie, but the hub forges a hash in its path: Alice finds
//!   it against her own history and challenges that hop; the hub can't
//!   reveal it; her timeout pays her;
//! - L2 and F2: L and F with a path of more than ten hops, posted as a
//!   combine of two inputs.

use std::path::Path;
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
use lichen_sequencer::{Client, Sequencer};
use lichen_wallet::dispute::Outcome;
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;
use lngap_sessions::contract::Program;

const B: u32 = 300_000;
/// What each claim says: not in the table.
const FALSE_B: u32 = B + 1_024;

/// The mock's table, full (16 returns, any memo, under any session: the
/// contracts' memo check still applies): a false claim scans all of it,
/// so its trace is long enough for paths of more than ten hops.
fn statement() -> Statement {
    let any = lngap_sessions::statement::ANY;
    let mut returns: Vec<(u32, u32)> = (1..16).map(|i| (B + 4_096 * i, any)).collect();
    returns.push((B, any));
    Statement::Mock { session: any, returns }
}

fn background(stop: &Arc<AtomicBool>, every: Duration, f: impl Fn() + Send + 'static) -> std::thread::JoinHandle<()> {
    let s = stop.clone();
    std::thread::spawn(move || {
        while !s.load(Ordering::Relaxed) {
            f();
            std::thread::sleep(every);
        }
    })
}

/// A read lie the search lands on: a step of the claim's execution reading
/// an address written earlier, its value flipped, such that the honest
/// hub's search disputes that very step (and it isn't the halt). (the
/// step, the lie)
fn a_read_lie(program: &Program, claim: &[u8], dir: &Path, min_hops: usize) -> (u64, FailConfiguration) {
    let j = program.schedule.jump.expect("a jump list");
    let d = format!("{}/", dir.display());
    std::fs::create_dir_all(&d).unwrap();
    let (_, last, _) = emulator::decision::challenge::prover_execute(&program.pdf, claim.to_vec(), &d, &d, true, None, false).unwrap();
    let pd = emulator::loader::program_definition::ProgramDefinition::from_config(&program.pdf).unwrap();
    let (_, trace) = pd.execute_helper(&d, &d, claim.to_vec(), Some((1..=last).collect()), None, false).unwrap();
    // BitVMX's "never written"
    let never = u64::MAX;
    for (t, _) in trace.iter().rev() {
        for (r, rd) in [(2u8, &t.read_2), (1, &t.read_1)] {
            if rd.last_step == never || rd.last_step == 0 || t.step_number <= rd.last_step + 2 || j.path(t.step_number - 1, rd.last_step).len() < min_hops.max(1) {
                continue;
            }
            let args: Vec<String> = vec![t.step_number.to_string(), format!("{:#x}", rd.address), format!("{:#x}", rd.value ^ 1), format!("{:#x}", rd.address), rd.last_step.to_string()];
            let fail = FailConfiguration::new_fail_reads(if r == 1 { FailReads::new(Some(&args), None) } else { FailReads::new(None, Some(&args)) });
            let sd = dir.join(format!("probe-{}", t.step_number));
            let found = lngap_zk::dispute::search(&program.pdf, claim, &sd, &lngap_zk::dispute::Behaviour { fail: Some(fail.clone()) }, &lngap_zk::dispute::Behaviour::default(), ForceCondition::No);
            if let Ok(Some(sr)) = found {
                if sr.step == t.step_number && sr.final_step.claim_last_step != sr.step {
                    return (t.step_number, fail);
                }
            }
        }
    }
    panic!("no read lie lands the search on its step");
}

#[test]
fn the_read_and_jump_challenges_on_the_mock_statement() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-tail-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let seq = Sequencer::start("127.0.0.1:0", None, regtest_sequencer(), HUB_KEY).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let url = seq.url.clone();
    let sealer = background(&stop, Duration::from_millis(200), move || {
        let _ = Client::new(&url).and_then(|c| c.seal());
    });
    let chain = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w).unwrap();
    rt.fund(&chain("hub").new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
    let hub = Hub::start(Config {
        network: lichen_proto::Net::Regtest,
        listen: "127.0.0.1:0".into(),
        sequencer: seq.url.clone(),
        rpc_url: rt.rpc_url().to_string(),
        cookie: rt.cookie().clone(),
        wallet: "hub".into(),
        statement: statement(),
        dir: dir.join("hub"),
        seed: "test-tail-hub".into(),
        l2_key: lichen_ledger::regtest_hub(),
        reserve_ppm: 20_000,
        max_bits: 24,
        duration: 2_000,
        refuse_folds: true,
        dispute_true_claims: false,
        first_cid: 1000,
    })
    .unwrap();
    let miner = {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", rt.rpc_url()), Auth::CookieFile(rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        background(&stop, Duration::from_millis(150), move || {
            let _ = rpc.generate_to_address(1, &addr);
        })
    };
    let ask = Ask { deposit: 400_000, bits: 21, reserve: 20_000 };
    let program = statement().program(&dir.join("probe")).unwrap();

    for (label, user, kind, forge, min_hops) in [("J", "jo", "jump", false, 0), ("L", "lou", "read", false, 0), ("F", "fay", "read", true, 0), ("L2", "lee", "read", false, 10), ("F2", "flo", "read", true, 10)] {
        let ch = chain(user);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let wdir = dir.join(user);
        let mut w = Wallet::create(&dir.join(format!("{user}.json")), &seq.url).unwrap();
        let held = w.open_contract(&hub.url, &ch, &statement(), &wdir, ask).unwrap();
        let cid = held.record.cid();
        let claim = statement().mock_input(FALSE_B, cid).unwrap();
        // a lie the search lands on, on this claim; or a wrong long-jump
        // hash at that step
        let (step, read_lie) = a_read_lie(&program, &claim, &dir.join(format!("probe-{cid}")), min_hops);
        w.lie = Some(if kind == "jump" { FailConfiguration { fail_jump: Some(step), ..Default::default() } } else { read_lie });
        hub.set_forge_paths(forge);
        let t = Instant::now();
        let (outcome, swept) = w.dispute(&ch, &statement(), &wdir, cid, FALSE_B, &claim).unwrap();
        println!("LICHEN {label}: contract {cid}, a {kind} lie at step {step}{}: {outcome:?} in {:.1?}; swept {swept:?}", if forge { ", the hub forging its path" } else { "" }, t.elapsed());
        if forge {
            assert!(matches!(outcome, Outcome::PathRefuted(_)), "{label}: she refutes the forged hop");
            assert!(swept.is_some(), "{label}: and sweeps her winnings");
        } else {
            assert_eq!(outcome, Outcome::Lost, "{label}: the hub's path proves its verdict");
        }
        if min_hops > 9 {
            let chunks = hub.log().iter().filter(|l| l.starts_with(&format!("contract {cid}: "))).find_map(|l| l.split(" hops in ").nth(1).and_then(|r| r.split(' ').next()).and_then(|n| n.parse::<usize>().ok()));
            assert!(chunks.is_some_and(|k| k >= 2), "{label}: a path of several chunks ({chunks:?})");
        }
        // the hub closed the contract on its side too
        let start = Instant::now();
        while !hub.log().iter().any(|l| l.starts_with(&format!("contract {cid}: ")) && (l.contains("disprove_") || l.contains("settled"))) {
            assert!(start.elapsed() < Duration::from_secs(60), "{label}: the hub settles");
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    let log = hub.log();
    assert!(log.iter().any(|l| l.contains("disprove_jump")), "J: the jump verdict");
    assert!(log.iter().any(|l| l.contains("disprove_read_")), "L: a read verdict");
    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
    sealer.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

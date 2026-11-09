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
//! files in `hp/<cid>/`: a prover's log and no seal yet), so that `w_H`
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

/// Whether a prover runs in `hp`: a prover's log without its seal.
fn proving(hp: &std::path::Path) -> bool {
    let Ok(dirs) = std::fs::read_dir(hp) else { return false };
    dirs.flatten().filter(|d| d.path().is_dir()).any(|d| {
        let names: Vec<String> = std::fs::read_dir(d.path()).into_iter().flatten().flatten().map(|f| f.file_name().to_string_lossy().into_owned()).collect();
        names.iter().filter_map(|n| n.strip_prefix("prover-").and_then(|n| n.strip_suffix(".log"))).any(|tag| !names.contains(&format!("proof-{tag}.seal")))
    })
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

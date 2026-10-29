//! A tower plays Alice's dispute from a package (docs/TOWER_PLAN.md, phase
//! 1), on the mock statement, blocks every 150 ms.
//!
//! The hub refuses cooperative withdrawals and disputes true claims too.
//! Alice returns 300,000 sats on the L2, is refused, and exports the
//! package: the contract and its one-time secrets, not her payment key nor
//! `b`'s key. Her wallet then stays idle. A tower with nothing but the
//! package (and a chain of its own) escalates, plays the whole search
//! against the hub, posts each of its links at its floor, and proves the
//! last step. Run again, it finds the payout and stops. The wallet sweeps
//! what it won.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use bitcoincore_rpc::{Auth, RpcApi};
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_proto::Statement;
use lichen_l2::Client;
use lichen_sequencer::Sequencer;
use lichen_wallet::engine::{Options, Outcome};
use lichen_wallet::tower::{self, Package};
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;

const B: u32 = 300_000;

/// The mock statement: the return of `B` with memo 1000 is true.
fn statement() -> Statement {
    Statement::BitVmxMock { session: 1000, returns: vec![(B, 1000)] }
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

#[test]
fn a_tower_plays_the_dispute_from_a_package() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-tower-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ledger = dir.join("ledger.json");
    let seq = Sequencer::start("127.0.0.1:0", Some(ledger.clone()), regtest_sequencer(), HUB_KEY).unwrap();
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
        seed: "test-tower-hub".into(),
        l2_key: lichen_ledger::regtest_hub(),
        reserve_ppm: 20_000,
        max_bits: 24,
        duration: 2_000,
        windows: None,
        refuse_folds: true,
        dispute_true_claims: true,
        first_cid: 1000,
    })
    .unwrap();
    // blocks every 150 ms from here on
    let miner = {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", rt.rpc_url()), Auth::CookieFile(rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        background(&stop, Duration::from_millis(150), move || {
            let _ = rpc.generate_to_address(1, &addr);
        })
    };

    // Alice opens a contract, returns B on the L2, and is refused
    let ch = chain("alice");
    rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
    let wdir = dir.join("alice");
    let mut w = Wallet::create(&dir.join("alice.json"), &seq.url).unwrap();
    let ask = Ask { deposit: 400_000, bits: 21, reserve: 20_000 };
    let held = w.open_contract(&hub.url, &ch, &statement(), &wdir, ask, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
    let cid = held.record.cid();
    let start = Instant::now();
    while w.balance().unwrap() < ask.deposit {
        assert!(start.elapsed() < Duration::from_secs(60), "the deposit");
        std::thread::sleep(Duration::from_millis(200));
    }
    let refused = w.withdraw(&hub.url, &statement(), &wdir, cid, u64::from(B)).unwrap_err();
    println!("LICHEN contract {cid}: Alice returned {B} on the L2; the hub refused to fold ({refused:#})");
    // asked again, the same return: no second one
    let before = w.balance().unwrap();
    assert!(w.withdraw(&hub.url, &statement(), &wdir, cid, u64::from(B)).is_err(), "refused again");
    assert_eq!(w.balance().unwrap(), before, "no second return");
    assert!(w.withdraw(&hub.url, &statement(), &wdir, cid, u64::from(B) - 1).unwrap_err().to_string().contains("has a return of"), "another amount is refused before any return");
    assert_eq!(w.balance().unwrap(), before);

    // the package: this contract's one-time secrets, not her payment key
    // nor b's key
    let program = statement().program(&wdir).unwrap();
    let pkg = w.export_dispute(&statement(), Some(&program), cid, None).unwrap();
    assert_eq!(pkg.b, B);
    let path = dir.join("tower").join("contract.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_vec_pretty(&pkg).unwrap()).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    let nonce = &held.nonce;
    assert!(!text.contains(&hex::encode(w.contract_keys(nonce).payment.secret_bytes())), "no payment key in the package");
    let b_word = held.record.spec(&statement()).unwrap().b_word;
    assert!(pkg.inputs[b_word].is_none() && !text.contains(&hex::encode(w.secrets(nonce).input_entropy(b_word))), "no key for b's word");
    let reloaded = Package::load(&path).unwrap();
    assert_eq!(reloaded.cid(), cid);
    println!("LICHEN the package: {} bytes", text.len());

    // proving, for a statement without a mock: the tower builds the input
    // from the sequencer as the wallet would, and hands it to the prover
    // and the chain receipt of the withdrawal's height, fetched from the
    // sequencer (here a stand-in for the chain prover's), to the prover
    // (here a stub that keeps what it was given and answers a claim)
    let input = tower::withdraw_input(&pkg).unwrap();
    assert_eq!(serde_json::to_value(&input).unwrap(), serde_json::to_value(w.withdraw_input(cid).unwrap()).unwrap(), "the input the wallet would print");
    let stub = dir.join("stub-prover.sh");
    std::fs::write(&stub, format!("#!/bin/sh\n[ \"$1\" = claim ] || exit 2\ncp \"$2\" {}\ncp \"$3\" {}\necho c1a1 > \"$4\"\n", dir.join("seen.json").display(), dir.join("seen.chain").display())).unwrap();
    std::fs::set_permissions(&stub, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    assert!(tower::prove(&pkg, &ch, &dir.join("proof"), &stub).is_err(), "no chain receipt yet");
    std::fs::create_dir_all(lichen_sequencer::blocks_dir(&ledger)).unwrap();
    std::fs::write(lichen_sequencer::blocks_dir(&ledger).join(format!("{}.chain", input.height)), [7, 7, 7]).unwrap();
    let claim = tower::prove(&pkg, &ch, &dir.join("proof"), &stub).unwrap();
    assert_eq!(claim, vec![0xc1, 0xa1], "the prover's claim, read back");
    let seen: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("seen.json")).unwrap()).unwrap();
    let given = lichen_ledger::ProverInput { input: w.withdraw_input(cid).unwrap(), headers: vec![], work: String::new() };
    assert_eq!(seen, serde_json::to_value(&given).unwrap(), "the prover was given the withdrawal's input (no anchoring here: no headers)");
    assert_eq!(std::fs::read(dir.join("seen.chain")).unwrap(), [7, 7, 7], "and the sequencer's chain receipt");
    assert!(tower::prove(&pkg, &ch, &dir.join("proof"), std::path::Path::new("/usr/bin/false")).is_err(), "a failing prover is an error");

    // the tower, with a chain of its own, plays the dispute to its end
    let tch = chain("tower");
    let progress: Arc<dyn Fn(String) + Send + Sync> = Arc::new(|m: String| println!("LICHEN tower: {m}"));
    let t = Instant::now();
    let no_prover = std::path::Path::new("/nonexistent/prover");
    let outcome = tower::run(&tch, &statement(), &path, &dir.join("tower").join("work"), no_prover, Options { progress: Some(progress), ..Default::default() }).unwrap();
    println!("LICHEN tower: {outcome:?} in {:.1?}", t.elapsed());
    assert!(matches!(outcome, Outcome::Proved(_)), "the tower proves the last step: {outcome:?}");
    // run again: the payout is kept, nothing is posted
    let again = tower::run(&tch, &statement(), &path, &dir.join("tower").join("work"), no_prover, Options::default()).unwrap();
    assert_eq!(again, outcome, "a resumed tower stops at the payout");
    // its links went at their floors: no anchor of hers was spent
    // the wallet sweeps what the tower won
    let state: tower::TowerState = serde_json::from_slice(&std::fs::read(path.with_extension("state.json")).unwrap()).unwrap();
    assert_eq!(state.claim.as_ref().map(|c| c.0), Some(B));
    let (_, swept) = w.sweep_dispute(&ch, &statement(), &wdir, cid, B, state.payout.clone().unwrap()).unwrap();
    let (sweep, value) = swept.expect("swept");
    // b rounded down to 512 sats, and both reserves less the floors of the
    // links played, less the sweep's fee; the sweep takes the fee budget's
    // rest besides
    let t = held.record.terms;
    let payout = rt.get_tx(&outcome.payout().unwrap()).unwrap();
    let op = payout.input[0].previous_output;
    let floors = t.v_max() + t.reserves() - rt.get_tx(&op.txid).unwrap().output[op.vout as usize].value;
    let paid = Amount::from_sat(u64::from(B / 512 * 512)) + t.reserves() - floors;
    let start = Instant::now();
    while ch.confirmations(&sweep).unwrap() == 0 {
        assert!(start.elapsed() < Duration::from_secs(30), "the sweep confirms");
        std::thread::sleep(Duration::from_millis(200));
    }
    let sweep_tx = rt.get_tx(&sweep).unwrap();
    let in_value = |op: &bitcoin::OutPoint| rt.get_tx(&op.txid).unwrap().output[op.vout as usize].value;
    let extra: Amount = sweep_tx.input.iter().map(|i| &i.previous_output).filter(|op| op.txid != payout.compute_txid()).map(in_value).sum();
    let won = value - extra;
    println!("LICHEN Alice swept {value} ({sweep}): {won} of the payout ({paid} less the sweep's fee), {extra} besides; the floors {floors}");
    assert!(won <= paid && won > paid - Amount::from_sat(20_000), "swept {won} of {paid}");
    assert_eq!(w.fees_for(cid).unwrap().balance(&ch).unwrap(), Amount::ZERO, "the fee budget emptied by the sweep");

    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
    sealer.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

//! A keyless tower plays Alice's BABE dispute from a package, on the mock
//! statement, blocks every 150 ms. The hub refuses cooperative
//! withdrawals and challenges true claims too.
//!
//! Alice returns 300,000 sats on the L2, is refused, and exports the
//! package with her proof: her signatures on `b` and on π1, and in the
//! contract her signature on `wrongly_challenged`; none of her keys. A
//! proof for another contract's journal is refused at export. The kept
//! instances are copied beside the package. Her wallet then stays idle.
//! The tower requests, asserts, reads π1's secrets from the hub's
//! challenge, opens a kept instance and answers with its `msg`;
//! `wrongly_challenged` pays her. Run again, it finds the payout and
//! stops. The wallet sweeps what it won.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use bitcoincore_rpc::{Auth, RpcApi};
use lichen_babe::setup::digits;
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_l2::Client;
use lichen_proto::Statement;
use lichen_sequencer::Sequencer;
use lichen_wallet::engine::{Options, Outcome};
use lichen_wallet::tower::{self, Package};
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;

const B: u32 = 300_000;

fn statement() -> Statement {
    Statement::Babe { mock: true }
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
fn a_keyless_tower_plays_the_babe_dispute() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-babe-tower-{}", std::process::id()));
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
        seed: "test-babe-tower".into(),
        l2_key: lichen_ledger::regtest_hub(),
        reserve_ppm: 20_000,
        max_bits: 24,
        duration: 2_000,
        refuse_folds: true,
        dispute_true_claims: true,
        first_cid: 1000,
        windows: None,
    })
    .unwrap();
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
    let refused = w.withdraw(&hub.url, &statement(), &wdir, cid, u64::from(B)).unwrap_err();
    println!("LICHEN contract {cid}: Alice returned {B} on the L2; the hub refused to fold ({refused:#})");

    // the package, with her proof; one for another journal is refused
    let input = w.babe_mock_input(cid).unwrap();
    let mut j = held.record.babe_journal().unwrap();
    j[0] ^= 1;
    let other = lichen_babe::statement::proof_to_bytes(&lichen_babe::statement::mock_prove(&j));
    assert!(w.export_dispute(&statement(), None, cid, Some(&other)).is_err(), "a proof the hub would win against");
    assert!(w.export_dispute(&statement(), None, cid, None).is_err(), "no proof, no package");
    let pkg = w.export_dispute(&statement(), None, cid, Some(&input)).unwrap();
    assert_eq!(pkg.b, B);
    let path = dir.join("tower").join("contract.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_vec_pretty(&pkg).unwrap()).unwrap();
    let copied = w.export_instances(&wdir, cid, &path).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    println!("LICHEN the package: {} bytes; the instances beside it, {:.1} MiB", text.len(), copied as f64 / f64::from(1 << 20));
    // keyless: signatures, no key. Not her payment key; for π1, only the
    // preimages of the digits she asserts
    let nonce = &held.nonce;
    assert!(!text.contains(&hex::encode(w.contract_keys(nonce).payment.secret_bytes())), "no payment key in the package");
    assert!(pkg.inputs.is_empty() && pkg.moves.is_empty() && pkg.hops.is_empty(), "no BitVMX keys");
    let proof = lichen_babe::statement::proof_from_bytes(&input).unwrap();
    let ds = digits(&lichen_babe::gadget::input(&proof.a));
    let lamport = w.secrets(nonce).babe_lamport();
    for k in 1..4u8 {
        let others: Vec<u8> = ds.iter().map(|v| (v + k) % 4).collect();
        assert!(lamport.sign(&others).iter().all(|p| !text.contains(&hex::encode(p))), "no preimage of another digit's value");
    }
    assert_eq!(Package::load(&path).unwrap().cid(), cid);

    // the tower, with a chain of its own, plays the dispute to its end
    let tch = chain("tower");
    let progress: Arc<dyn Fn(String) + Send + Sync> = Arc::new(|m: String| println!("LICHEN tower: {m}"));
    let no_prover = std::path::Path::new("/nonexistent/prover");
    let t = Instant::now();
    let outcome = tower::run(&tch, &statement(), &path, &tower::work_dir(&path), no_prover, Options { progress: Some(progress), ..Default::default() }).unwrap();
    println!("LICHEN tower: {outcome:?} in {:.1?}", t.elapsed());
    assert!(matches!(outcome, Outcome::Answered(_)), "the tower answers the challenge: {outcome:?}");
    let start = Instant::now();
    while !hub.log().iter().any(|l| l.contains(&format!("contract {cid}: the user answered the challenge"))) {
        assert!(start.elapsed() < Duration::from_secs(30), "the hub sees her answer");
        std::thread::sleep(Duration::from_millis(200));
    }
    // run again: the payout is kept, nothing is posted
    let again = tower::run(&tch, &statement(), &path, &tower::work_dir(&path), no_prover, Options::default()).unwrap();
    assert_eq!(again, outcome, "a resumed tower stops at the payout");

    // the wallet sweeps what the tower won: b rounded down to 512 sats and
    // both reserves, less the floors of the links played and the sweep's
    // fee; and the fee budget's rest
    let state: tower::TowerState = serde_json::from_slice(&std::fs::read(path.with_extension("state.json")).unwrap()).unwrap();
    let (_, swept) = w.sweep_dispute(&ch, &statement(), &wdir, cid, B, state.payout.clone().unwrap()).unwrap();
    let (sweep, value) = swept.expect("swept");
    let start = Instant::now();
    while ch.confirmations(&sweep).unwrap() == 0 {
        assert!(start.elapsed() < Duration::from_secs(30), "the sweep confirms");
        std::thread::sleep(Duration::from_millis(200));
    }
    let terms = held.record.terms;
    let paid = Amount::from_sat(u64::from(B / 512 * 512)) + terms.reserves();
    println!("LICHEN Alice swept {value} ({sweep}) for {paid}");
    assert!(value > paid - Amount::from_sat(60_000) && value < paid + lichen_proto::fee_budget(lichen_proto::Net::Regtest), "swept {value} for {paid}");

    drop(hub);
    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
    sealer.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

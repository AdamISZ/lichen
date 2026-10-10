//! A dispute survives restarts: Alice's wallet stops after her move 5; the
//! hub is shut down and started again from its data directory; the wallet
//! is reopened from its file and resumes. Each side rebuilds its emulator
//! from the claim on chain, replays the moves already made (checking its
//! own), and the dispute ends as it would have: the hub disputed a true
//! claim, Alice proves the last step and is paid.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use bitcoincore_rpc::{Auth, RpcApi};
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_proto::Statement;
use lichen_sequencer::{Client, Sequencer};
use lichen_wallet::dispute::Outcome;
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;

const B: u32 = 300_000;

fn statement() -> Statement {
    Statement::Mock { session: 1000, returns: vec![(B, 1000)] }
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
fn a_dispute_resumes_after_restarts() {
    let rt = Regtest::start().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-resume-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let seq = Sequencer::start("127.0.0.1:0", None, regtest_sequencer(), HUB_KEY).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let url = seq.url.clone();
    let sealer = background(&stop, Duration::from_millis(200), move || {
        let _ = Client::new(&url).seal();
    });
    let chain = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w).unwrap();
    rt.fund(&chain("hub").new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
    let config = || Config {
        listen: "127.0.0.1:0".into(),
        sequencer: seq.url.clone(),
        rpc_url: rt.rpc_url().to_string(),
        cookie: rt.cookie().clone(),
        wallet: "hub".into(),
        statement: statement(),
        dir: dir.join("hub"),
        seed: "test-hub".into(),
        reserve_ppm: 20_000,
        max_bits: 24,
        duration: 2_000,
        refuse_folds: true,
        dispute_true_claims: true,
        first_cid: 1000,
    };
    let hub = Hub::start(config()).unwrap();
    let miner = {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", rt.rpc_url()), Auth::CookieFile(rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        background(&stop, Duration::from_millis(300), move || {
            let _ = rpc.generate_to_address(1, &addr);
        })
    };
    let ch = chain("alice");
    rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
    let (wfile, wdir) = (dir.join("alice.json"), dir.join("alice"));
    let mut w = Wallet::create(&wfile, &seq.url).unwrap();
    let cid = w.open_contract(&hub.url, &ch, &statement(), &wdir, Ask { deposit: 400_000, bits: 21, reserve: 20_000 }).unwrap().record.cid();
    let start = Instant::now();
    while w.balance().unwrap() < 400_000 {
        assert!(start.elapsed() < Duration::from_secs(60), "the deposit");
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(w.withdraw(&hub.url, &statement(), &wdir, cid, u64::from(B)).is_err(), "the hub refuses");
    let input = statement().mock_input(B, cid).unwrap();

    // Alice's wallet stops after her move 5
    w.pause_after = Some(5);
    let (o, _) = w.dispute(&ch, &statement(), &wdir, cid, B, &input).unwrap();
    assert_eq!(o, Outcome::Paused);
    println!("LICHEN Alice's wallet stopped after move 5");
    // the hub goes down and comes back from its data directory
    drop(hub);
    let hub = Hub::start(config()).unwrap();
    println!("LICHEN the hub restarted at {}", hub.url);
    // the wallet is reopened from its file and resumes
    drop(w);
    let mut w = Wallet::open(&wfile, &seq.url).unwrap();
    assert!(w.contracts[0].claim.is_some(), "the claim is kept with the contract");
    let t = Instant::now();
    let (o, swept) = w.dispute(&ch, &statement(), &wdir, cid, B, &input).unwrap();
    println!("LICHEN resumed: {o:?} in {:.1?}; swept {swept:?}", t.elapsed());
    assert!(matches!(o, Outcome::Proved(_)), "{o:?}");
    assert!(swept.is_some());
    drop(hub);
    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
    sealer.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

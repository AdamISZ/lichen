//! The last step's proof races the hub's timeout: a hub that disputes true
//! claims finds Alice's last step valid, and takes the output by its
//! timeout once her window to prove has passed with no proof. Alice's
//! wallet stops after her last move and comes back too late.

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
fn the_hubs_timeout_takes_a_valid_step_not_proved_in_time() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-race-{}", std::process::id()));
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
        seed: "test-race-hub".into(),
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
    let ch = chain("alice");
    rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
    let wdir = dir.join("alice");
    let mut w = Wallet::create(&dir.join("alice.json"), &seq.url).unwrap();
    let cid = w.open_contract(&hub.url, &ch, &statement(), &wdir, Ask { deposit: 400_000, bits: 21, reserve: 20_000 }, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap().record.cid();
    let start = Instant::now();
    while w.balance().unwrap() < 400_000 {
        assert!(start.elapsed() < Duration::from_secs(60), "the deposit");
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(w.withdraw(&hub.url, &statement(), &wdir, cid, u64::from(B)).is_err(), "the hub refuses");
    let input = statement().mock_input(B, cid).unwrap();

    // Alice plays to her last move (7 on the mock), then stops
    w.pause_after = Some(7);
    let (o, _) = w.dispute(&ch, &statement(), &wdir, cid, B, &input).unwrap();
    assert_eq!(o, Outcome::Paused);
    println!("LICHEN Alice's wallet stopped after her last move");
    // the hub finds the step valid and races her proof with its timeout:
    // with none, its timeout takes the output
    let raced = format!("contract {cid}: the user's last step is valid; the hub's timeout races her proof");
    let took = format!("contract {cid}: the user's last step was valid, but no proof came in her window; timeout");
    let start = Instant::now();
    while !hub.log().iter().any(|l| l.starts_with(&took)) {
        assert!(start.elapsed() < Duration::from_secs(60), "the hub's timeout: {:?}", hub.log());
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(hub.log().contains(&raced), "{:?}", hub.log());
    println!("LICHEN {}", hub.log().iter().find(|l| l.starts_with(&took)).unwrap());
    // back too late: the claim is lost
    w.pause_after = None;
    let (o, _) = w.dispute(&ch, &statement(), &wdir, cid, B, &input).unwrap();
    println!("LICHEN Alice resumed: {o:?}");
    assert_eq!(o, Outcome::Lost);
    drop(hub);
    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
    sealer.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

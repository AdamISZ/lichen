//! A BABE dispute survives restarts, and Alice's absence costs her the
//! contract only after `T_A`; the mock statement, blocks every 150 ms. The
//! hub refuses cooperative withdrawals and challenges true claims too.
//!
//! - R: Alice's wallet stops after `assert`; with the chain halted, the hub
//!   restarts from its data directory and the wallet is reopened from its
//!   file. Both replay what is on chain: the hub checks her proof and
//!   challenges it, she reads π1's secrets from the challenge, opens a kept
//!   instance and answers; `wrongly_challenged` pays her.
//! - A: Alice's wallet stops after `request`; the hub responds and she
//!   never asserts. At `T_A` the hub takes the contract by
//!   `respond_timeout`; her wallet, resumed, finds the contract lost.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use bitcoincore_rpc::{Auth, RpcApi};
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_l2::Client;
use lichen_proto::babe::Disputed;
use lichen_proto::Statement;
use lichen_sequencer::Sequencer;
use lichen_wallet::dispute::Outcome;
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

fn wait(what: &str, secs: u64, f: impl Fn() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < Duration::from_secs(secs), "{what}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn a_babe_dispute_resumes_and_alice_gone_loses_at_t_a() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-babe-resume-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let seq = Sequencer::start("127.0.0.1:0", None, regtest_sequencer(), HUB_KEY).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let url = seq.url.clone();
    let sealer = background(&stop, Duration::from_millis(200), move || {
        let _ = Client::new(&url).and_then(|c| c.seal());
    });
    let chain = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w).unwrap();
    rt.fund(&chain("hub").new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
    let config = || Config {
        network: lichen_proto::Net::Regtest,
        listen: "127.0.0.1:0".into(),
        sequencer: seq.url.clone(),
        rpc_url: rt.rpc_url().to_string(),
        cookie: rt.cookie().clone(),
        wallet: "hub".into(),
        statement: statement(),
        dir: dir.join("hub"),
        seed: "test-babe-resume".into(),
        l2_key: lichen_ledger::regtest_hub(),
        reserve_ppm: 20_000,
        max_bits: 24,
        duration: 2_000,
        refuse_folds: true,
        dispute_true_claims: true,
        first_cid: 1000,
        windows: None,
    };
    let hub = Hub::start(config()).unwrap();
    // blocks every 150 ms while `mining`
    let mining = Arc::new(AtomicBool::new(true));
    let miner = {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", rt.rpc_url()), Auth::CookieFile(rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        let mining = mining.clone();
        background(&stop, Duration::from_millis(150), move || {
            if mining.load(Ordering::Relaxed) {
                let _ = rpc.generate_to_address(1, &addr);
            }
        })
    };
    let ask = Ask { deposit: 400_000, bits: 21, reserve: 20_000 };
    // a contract opened and its withdrawal refused: the wallet, its file
    // and directory, the contract, her proof
    let open = |user: &str, hub_url: &str| {
        let ch = chain(user);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let (wfile, wdir) = (dir.join(format!("{user}.json")), dir.join(user));
        let mut w = Wallet::create(&wfile, &seq.url).unwrap();
        let label = user.to_string();
        w.progress = Some(Arc::new(move |m: String| println!("LICHEN {label}: {m}")));
        let held = w.open_contract(hub_url, &ch, &statement(), &wdir, ask, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
        let cid = held.record.cid();
        assert!(w.withdraw(hub_url, &statement(), &wdir, cid, u64::from(B)).is_err(), "the hub refuses");
        let input = w.babe_mock_input(cid).unwrap();
        (ch, w, wfile, wdir, held, input)
    };

    // R: her wallet stops after assert
    let (ch, mut w, wfile, wdir, held, input) = open("rae", &hub.url);
    let cid = held.record.cid();
    w.pause_after = Some(2);
    let (o, _) = w.dispute(&ch, &statement(), &wdir, cid, B, &input).unwrap();
    assert_eq!(o, Outcome::Paused);
    // the chain halts; the hub restarts, the wallet is reopened. The hub
    // may have judged her proof and posted its challenge before the halt
    // (then it is dropped waiting for a block that won't come), or not
    mining.store(false, Ordering::Relaxed);
    println!("LICHEN R: Alice's wallet stopped after assert; the chain halted");
    // (its log once it has stopped: it may judge her proof, and note it,
    // until then)
    let before = hub.stop();
    let hub = Hub::start(config()).unwrap();
    println!("LICHEN R: the hub restarted at {}", hub.url);
    drop(w);
    let mut w = Wallet::open(&wfile, &seq.url).unwrap();
    w.progress = Some(Arc::new(|m: String| println!("LICHEN R: {m}")));
    assert!(w.contracts[0].claim.is_some(), "the claim is kept with the contract");
    mining.store(true, Ordering::Relaxed);
    let t = Instant::now();
    let (o, swept) = w.dispute(&ch, &statement(), &wdir, cid, B, &input).unwrap();
    println!("LICHEN R: resumed: {o:?} in {:.1?}; swept {swept:?}", t.elapsed());
    assert!(matches!(o, Outcome::Answered(_)), "R: she answers the challenge after the restarts: {o:?}");
    let (sweep, _) = swept.expect("R: swept");
    wait("R: the sweep confirms", 30, || ch.confirmations(&sweep).unwrap() > 0);
    let judged = format!("contract {cid}: the user's proof is valid, but the hub disputes true claims");
    assert!(before.iter().chain(&hub.log()).any(|l| l.contains(&judged)), "R: a hub judged her proof");
    assert!(hub.log().iter().any(|l| l.contains(&format!("contract {cid}: the user answered the challenge"))), "R: the restarted hub followed the dispute to her answer");

    // A: her wallet stops after request, and she never asserts
    let (ch, mut w, _, wdir, held, input) = open("abe", &hub.url);
    let cid = held.record.cid();
    w.pause_after = Some(1);
    let (o, _) = w.dispute(&ch, &statement(), &wdir, cid, B, &input).unwrap();
    assert_eq!(o, Outcome::Paused);
    let d = Disputed::new(&held.record, &statement()).unwrap();
    wait("A: the hub responds", 30, || ch.confirmations(&d.txid("respond")).unwrap() > 0);
    let t_a = d.babe.spec.windows.t_a;
    println!("LICHEN A: the hub responded; Alice is gone. Mining to T_A, block {t_a}");
    rt.mine_to_height(t_a).unwrap();
    wait("A: the hub's respond_timeout", 60, || hub.log().iter().any(|l| l.contains(&format!("contract {cid}: the user never asserted by T_A"))));
    // the hub's respond_timeout confirms; her wallet comes back to a loss
    let s_op = bitcoin::OutPoint { txid: d.txid("respond"), vout: 0 };
    wait("A: respond_timeout confirms", 30, || !ch.unspent(&s_op).unwrap());
    w.pause_after = None;
    let (o, swept) = w.dispute(&ch, &statement(), &wdir, cid, B, &input).unwrap();
    println!("LICHEN A: resumed after T_A: {o:?}");
    assert_eq!((o, swept), (Outcome::Lost, None), "A: respond_timeout took the contract");

    drop(hub);
    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
    sealer.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

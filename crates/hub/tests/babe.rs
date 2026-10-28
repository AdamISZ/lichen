//! BABE through the hub and the wallet, on the mock statement (a Groth16
//! proof of a toy circuit for the contract's journal), blocks every
//! 150 ms. Each opening runs the setup's cut-and-choose (2 instances kept
//! of 4): the hub commits, Alice chooses, checks the opened ones, downloads
//! the kept ones and pre-signs the reveal.
//!
//! - T: a hub that refuses cooperative withdrawals but disputes honestly:
//!   Alice requests, the hub responds, she asserts her proof; it is valid,
//!   so the hub doesn't challenge, and `success` pays her after `Δ2`.
//! - W: a hub that challenges true claims too: Alice reads π1's secrets
//!   from its challenge, opens a kept instance on her proof, and answers
//!   with its `msg`; `wrongly_challenged` pays her.
//! - F: a false claim (a proof for another contract's journal): the hub
//!   challenges, no kept instance opens, and `failure` takes everything.
//! - G: the hub gone after the opening: `request_timeout` pays her `b`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use bitcoincore_rpc::{Auth, RpcApi};
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_l2::Client;
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

#[test]
fn babe_disputes_on_the_mock_statement() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-babe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let seq = Sequencer::start("127.0.0.1:0", None, regtest_sequencer(), HUB_KEY).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let url = seq.url.clone();
    let sealer = background(&stop, Duration::from_millis(200), move || {
        let _ = Client::new(&url).and_then(|c| c.seal());
    });
    let chain = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w).unwrap();
    let hub_config = |name: &str, dispute_true_claims: bool| Config {
        network: lichen_proto::Net::Regtest,
        listen: "127.0.0.1:0".into(),
        sequencer: seq.url.clone(),
        rpc_url: rt.rpc_url().to_string(),
        cookie: rt.cookie().clone(),
        wallet: name.into(),
        statement: statement(),
        dir: dir.join(name),
        seed: format!("test-{name}"),
        l2_key: lichen_ledger::regtest_hub(),
        reserve_ppm: 20_000,
        max_bits: 24,
        duration: 2_000,
        refuse_folds: true,
        dispute_true_claims,
        first_cid: 1000,
        windows: None,
    };
    for name in ["hub-honest", "hub-hostile", "hub-gone"] {
        rt.fund(&chain(name).new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
    }
    let honest = Hub::start(hub_config("hub-honest", false)).unwrap();
    let hostile = Hub::start(hub_config("hub-hostile", true)).unwrap();
    let mut gone = Some(Hub::start(Config { first_cid: 2000, ..hub_config("hub-gone", false) }).unwrap());
    let miner = {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", rt.rpc_url()), Auth::CookieFile(rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        background(&stop, Duration::from_millis(150), move || {
            let _ = rpc.generate_to_address(1, &addr);
        })
    };
    let ask = Ask { deposit: 400_000, bits: 21, reserve: 20_000 };

    for (label, user) in [("T", "tess"), ("W", "will"), ("F", "fay"), ("G", "gil")] {
        let hub_url = match label {
            "W" | "F" => hostile.url.clone(),
            "G" => gone.as_ref().unwrap().url.clone(),
            _ => honest.url.clone(),
        };
        let ch = chain(user);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let wdir = dir.join(user);
        let mut w = Wallet::create(&dir.join(format!("{user}.json")), &seq.url).unwrap();
        w.progress = Some(Arc::new(move |m: String| println!("LICHEN {label}: {m}")));
        let t = Instant::now();
        let held = w.open_contract(&hub_url, &ch, &statement(), &wdir, ask, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
        let cid = held.record.cid();
        let keys = held.record.babe().unwrap();
        println!("LICHEN {label}: contract {cid} opened in {:.1?}: {} kept of {}", t.elapsed(), keys.kept.len(), keys.n);
        assert_eq!((keys.kept.len(), keys.n, keys.presigs.len()), (2, 4, 254), "{label}: the cut-and-choose and the pre-signatures");
        if label == "G" {
            drop(gone.take());
            println!("LICHEN G: the hub is gone");
        } else {
            let refused = w.withdraw(&hub_url, &statement(), &wdir, cid, u64::from(B)).unwrap_err();
            println!("LICHEN {label}: the hub refused to fold ({refused:#})");
        }
        // her proof: the mock's for this contract's journal, or for another's
        let input = if label == "F" {
            let mut j = held.record.babe_journal().unwrap();
            j[0] ^= 1;
            lichen_babe::statement::proof_to_bytes(&lichen_babe::statement::mock_prove(&j))
        } else {
            w.babe_mock_input(cid).unwrap()
        };
        let t = Instant::now();
        let (outcome, swept) = w.dispute(&ch, &statement(), &wdir, cid, B, &input).unwrap();
        println!("LICHEN {label}: {outcome:?} in {:.1?}; swept {swept:?}", t.elapsed());
        match label {
            "T" => assert!(matches!(outcome, Outcome::Unchallenged(_)), "T: the honest hub lets her proof stand"),
            "W" => assert!(matches!(outcome, Outcome::Answered(_)), "W: she answers the challenge"),
            "F" => assert_eq!(outcome, Outcome::Lost, "F: failure takes everything"),
            _ => assert!(matches!(outcome, Outcome::HubTimedOut(_)), "G: her timeout pays her"),
        }
        if let Some((sweep, swept)) = swept {
            // b rounded down to 512 sats and both reserves, less the floors
            // of the links played, less the sweep's fee; and the fee
            // budget's rest
            let start = Instant::now();
            while ch.confirmations(&sweep).unwrap() == 0 {
                assert!(start.elapsed() < Duration::from_secs(30), "{label}: the sweep confirms");
                std::thread::sleep(Duration::from_millis(200));
            }
            let t = held.record.terms;
            let paid = Amount::from_sat(u64::from(B / 512 * 512)) + t.reserves();
            assert!(swept > paid - Amount::from_sat(60_000) && swept < paid + lichen_proto::fee_budget(lichen_proto::Net::Regtest), "{label}: swept {swept} for {paid}");
            if label != "G" {
                // the hub collects its bit outputs, those of the bits clear in b
                let hub = if label == "T" { &honest } else { &hostile };
                let start = Instant::now();
                while !hub.log().iter().any(|l| l.contains(&format!("contract {cid}: collected the hub's"))) {
                    assert!(start.elapsed() < Duration::from_secs(60), "{label}: the hub collects its bit outputs");
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
    sealer.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

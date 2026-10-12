//! Milestone 4: disputes, played by the wallet's engine against the hub's,
//! each reading the other's moves from the chain (blocks every 150 ms).
//!
//! - A: a hub that refuses cooperative withdrawals but disputes honestly.
//!   Alice returns 300,000 sats on the L2; the hub refuses to fold; she
//!   escalates; her claim is true, so the hub doesn't dispute it; her
//!   timeout pays her (b rounded down to 512 sats, and both reserves), and
//!   her wallet sweeps it.
//! - B: a hub that refuses, and disputes true claims too: the whole search
//!   is played; at the end nothing applies, Alice proves the last step and
//!   is paid.
//! - C: a claim the statement rejects (the right memo, but the mock's table
//!   is for another): the honest hub disputes it, and its disprove takes
//!   everything;
//! - M: a claim naming another contract's memo: the hub's memo check takes
//!   everything, with no search.

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

/// The mock statement: the return of `B` with memo 1000 is true.
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
fn disputes_on_the_mock_statement() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-dispute-{}", std::process::id()));
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
    };
    for name in ["hub-a", "hub-b"] {
        rt.fund(&chain(name).new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
    }
    let (hub_a, hub_b) = (Hub::start(hub_config("hub-a", false)).unwrap(), Hub::start(hub_config("hub-b", true)).unwrap());
    // blocks every 150 ms from here on
    let miner = {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", rt.rpc_url()), Auth::CookieFile(rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        background(&stop, Duration::from_millis(150), move || {
            let _ = rpc.generate_to_address(1, &addr);
        })
    };
    let ask = Ask { deposit: 400_000, bits: 21, reserve: 20_000 };

    for (label, user, hub, claim_c) in [("A", "alice", &hub_a, Some(1000u32)), ("B", "bob", &hub_b, Some(1000)), ("C", "carol", &hub_a, None), ("M", "mallory", &hub_a, Some(1000))] {
        let ch = chain(user);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let wdir = dir.join(user);
        let mut w = Wallet::create(&dir.join(format!("{user}.json")), &seq.url).unwrap();
        let held = w.open_contract(&hub.url, &ch, &statement(), &wdir, ask, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
        let cid = held.record.cid();
        let start = Instant::now();
        while w.balance().unwrap() < ask.deposit {
            assert!(start.elapsed() < Duration::from_secs(60), "{label}: the deposit");
            std::thread::sleep(Duration::from_millis(200));
        }
        // the hub refuses the cooperative withdrawal
        let refused = w.withdraw(&hub.url, &statement(), &wdir, cid, u64::from(B)).unwrap_err();
        println!("LICHEN {label}: contract {cid}; Alice returned {B} on the L2; the hub refused to fold ({refused:#})");
        // she enforces it: her claim's input (the mock's: b and the memo)
        let input = statement().mock_input(B, claim_c.unwrap_or(cid)).unwrap();
        if label == "M" {
            // the wallet refuses a claim that breaks a check; a careless (or
            // dishonest) one could escalate it anyway: the hub's check takes it
            let e = w.dispute(&ch, &statement(), &wdir, cid, B, &input).unwrap_err();
            println!("LICHEN M: the wallet refuses the claim ({e:#}); escalated anyway:");
            w.unchecked_claims = true;
        }
        let t = Instant::now();
        let (outcome, swept) = w.dispute(&ch, &statement(), &wdir, cid, B, &input).unwrap();
        println!("LICHEN {label}: {outcome:?} in {:.1?}; swept {swept:?}", t.elapsed());
        let t = held.record.terms;
        match label {
            "A" => assert!(matches!(outcome, Outcome::HubTimedOut(_)), "A: the honest hub concedes"),
            "B" => assert!(matches!(outcome, Outcome::Proved(_)), "B: she proves the last step"),
            _ => assert_eq!(outcome, Outcome::Lost, "{label}: the hub takes everything"),
        }
        if let Some((sweep, swept)) = swept {
            // b rounded down to 512 sats, and both reserves less the floors
            // of the links played (the hub's, D-J2), less the sweep's fee
            let payout = match &outcome {
                Outcome::HubTimedOut(x) | Outcome::Proved(x) | Outcome::PathRefuted(x) => rt.get_tx(x).unwrap(),
                _ => unreachable!(),
            };
            let op = payout.input[0].previous_output;
            let floors = t.v_max() + t.reserves() - rt.get_tx(&op.txid).unwrap().output[op.vout as usize].value;
            let paid = Amount::from_sat(u64::from(B / 512 * 512)) + t.reserves() - floors;
            println!("LICHEN {label}: the floors of the links played: {floors}");
            assert!(swept <= paid && swept > paid - Amount::from_sat(20_000), "{label}: swept {swept} of {paid}");
            let start = Instant::now();
            while ch.confirmations(&sweep).unwrap() == 0 {
                assert!(start.elapsed() < Duration::from_secs(30), "{label}: the sweep confirms");
                std::thread::sleep(Duration::from_millis(200));
            }
            assert_eq!(rt.get_tx(&sweep).unwrap().output[0].value, swept);
        } else {
            assert!(label == "C" || label == "M");
        }
    }
    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
    sealer.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

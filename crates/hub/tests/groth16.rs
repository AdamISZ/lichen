//! Opt-in (release; about half an hour): disputes on the REAL statement,
//! BitVMX's Groth16 verifier (8-ary, its trace hashed as a jump list: 21
//! depths), with a real proof of the
//! withdrawal guest: ln-gap's test vector, a return of 9 sats with memo
//! 42 (proved on x86 Linux). Each hub's first contract is number 42.
//!
//! - G1: an honest hub checks the claim's proof natively (milliseconds):
//!   valid, so it concedes; Alice's timeout pays her (9 sats round down to no bit
//!   output; the reserves);
//! - G2: a hub disputing true claims: the whole search, each side its own
//!   emulator over the 478M-step verifier; Alice proves the last step;
//! - G3: the same proof with b changed to 10: the honest hub disputes and
//!   disproves it.
//!
//! Blocks come when the mempool has something, else every 15 s, so that
//! a 12-block window (3 minutes) outlasts a move's computation: before its
//! first move the hub executes the whole 478M-step verifier, a minute or
//! two. (On Bitcoin the window is two hours.)

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use bitcoincore_rpc::{Auth, RpcApi};
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_proto::Statement;
use lichen_sequencer::Sequencer;
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;

#[test]
#[ignore]
fn disputes_on_the_groth16_verifier() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-g16-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // BitVMX's verifier, as BitVMX-CPU ships it (GPL, not vendored), from
    // the cargo checkout
    let statement = Statement::groth16().unwrap();
    // the canned claim: the toy deployment's return of 9 with memo 42,
    // proved under the committed guest (ln-gap's r0/scripts/linux-withdraw.sh
    // prints it, on x86 Linux)
    let canned = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../ln-gap/crates/apps/sessions/tests/data/withdraw-9-42-deployment.hex");
    let valid = hex::decode(std::fs::read_to_string(canned).unwrap_or_else(|e| panic!("{canned}: {e} (make it with linux-withdraw.sh)")).trim()).unwrap();
    let mut tampered = valid.clone();
    tampered[164] = 10; // b, word 41's low byte
    let seq = Sequencer::start("127.0.0.1:0", None, regtest_sequencer(), HUB_KEY).unwrap();
    let chain = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
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
    let ask = Ask { deposit: 400_000, bits: 21, reserve: 20_000 };
    for (label, dispute_true_claims, input, want) in [("G1", false, &valid, "HubTimedOut"), ("G2", true, &valid, "Proved"), ("G3", false, &tampered, "Lost")] {
        let hub_name = format!("hub-{label}");
        rt.fund(&chain(&hub_name).new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
        let hub = Hub::start(Config {
            network: lichen_proto::Net::Regtest,
            listen: "127.0.0.1:0".into(),
            sequencer: seq.url.clone(),
            rpc_url: rt.rpc_url().to_string(),
            cookie: rt.cookie().clone(),
            wallet: hub_name.clone(),
            statement: statement.clone(),
            dir: dir.join(&hub_name),
            seed: format!("test-{hub_name}"),
            l2_key: lichen_ledger::regtest_hub(),
            reserve_ppm: 20_000,
            max_bits: 24,
            duration: 5_000,
            refuse_folds: true,
            dispute_true_claims,
            first_cid: 42,
            windows: None,
        })
        .unwrap();
        let user = format!("alice-{label}");
        let ch = chain(&user);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let mut w = Wallet::create(&dir.join(format!("{user}.json")), &seq.url).unwrap();
        let t = Instant::now();
        let held = w.open_contract(&hub.url, &ch, &statement, &dir.join(&user), ask, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
        assert_eq!(held.record.cid(), 42);
        println!("LICHEN {label}: contract 42 on the Groth16 verifier opened in {:.1?}", t.elapsed());
        if label == "G1" {
            // the test networks' budgets pay for the heaviest of her
            // terminals on this statement (the sizes are the statement's)
            let c = held.record.contract(&statement, &statement.program(&dir.join(&user)).unwrap()).unwrap();
            let set = c.presign(held.record.funding).unwrap();
            for net in [lichen_proto::Net::Mutinynet, lichen_proto::Net::Signet] {
                let need = lichen_proto::terminal_need(&c, &set, net).unwrap();
                println!("LICHEN {label}: on {net} the heaviest terminal needs {need} of the fee budget's {}", lichen_proto::fee_budget(net));
                assert!(need <= lichen_proto::fee_budget(net), "{net}: {need}");
            }
        }
        let b = lngap_zk::final_d60::input_words(input)[41];
        let t = Instant::now();
        let (o, swept) = w.dispute(&ch, &statement, &dir.join(&user), 42, b, input).unwrap();
        println!("LICHEN {label}: claim of {b}: {o:?} in {:.0?}; swept {swept:?}", t.elapsed());
        assert!(format!("{o:?}").starts_with(want), "{label}: {o:?}");
        drop(hub);
    }
    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

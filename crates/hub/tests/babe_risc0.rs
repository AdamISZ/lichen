//! Opt-in (release; a few minutes): BABE on the REAL statement, a RISC
//! Zero Groth16 receipt of the BABE guest (r0/guests/babe.bin), through the
//! hub and the wallet; blocks every 150 ms.
//!
//! The toy deployment's return of 60 sats with memo 42 (the real-receipt
//! tests'), each hub's first contract number 42 and every hub of the same
//! seed: the hub's key for `b`, and so the journal `c ‖ D ‖ H(pk_H)`, is
//! the same for each. The canned claim
//! (crates/proto/tests/data/babe-claim-60-42.hex) was proved on lichen-vps
//! with `lichen-r0 babe`, `wrap`, `bitvmx-input` from the hub's signature
//! on 60 as `respond` carries it (babe-auth-60-42.json, which the wallet
//! writes). Without the claim the test stops there, the signature written,
//! for proving.
//!
//! - T: an honest hub. Alice disputes before proving: she requests, the
//!   hub responds, and her wallet stops with the proof due, the hub's
//!   signature on 60 written; it is the canned one. With the claim she
//!   asserts; the proof is valid, the hub doesn't challenge, `success`
//!   pays her.
//! - W: a hub that challenges true claims: she opens a kept instance with
//!   the challenge's secrets and the real proof, and answers.
//! - F: a real proof under another hub key (step 1's,
//!   crates/babe/tests/data/babe-60-42.hex): the hub challenges, no kept
//!   instance opens, `failure` takes the contract.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use bitcoincore_rpc::{Auth, RpcApi};
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_proto::Statement;
use lichen_sequencer::{Options, Sequencer};
use lichen_wallet::dispute::Outcome;
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;

const B: u32 = 60;

fn data(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../proto/tests/data").join(name)
}

#[test]
#[ignore]
fn babe_disputes_on_a_risc0_proof() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-babe-r0-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let statement = Statement::Babe { mock: false };
    // the deployment the return's D commits to: the toy one's genesis seal
    let seq = Sequencer::start_with("127.0.0.1:0", None, regtest_sequencer(), HUB_KEY, Options { seal: Some(lichen_proto::canned_seal()), ..Default::default() }).unwrap();
    let chain = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let miner = {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", rt.rpc_url()), Auth::CookieFile(rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        let s = stop.clone();
        std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let _ = rpc.generate_to_address(1, &addr);
                std::thread::sleep(Duration::from_millis(150));
            }
        })
    };
    let claim = std::fs::read_to_string(data("babe-claim-60-42.hex")).ok().map(|h| hex::decode(h.trim()).unwrap());
    // step 1's proof: valid, but for another hub's key
    let other = {
        let d = hex::decode(include_str!("../../babe/tests/data/babe-60-42.hex").trim()).unwrap();
        let (_, points, _) = lngap_zk::groth16::split_input(&d).unwrap();
        lichen_babe::statement::proof_to_bytes(&lichen_babe::risc0::proof(points).unwrap())
    };
    let ask = Ask { deposit: 400_000, bits: 21, reserve: 20_000 };
    for (label, dispute_true_claims) in [("T", false), ("W", true), ("F", false)] {
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
            seed: "test-babe-risc0".into(),
            l2_key: lichen_ledger::regtest_hub(),
            reserve_ppm: 20_000,
            max_bits: 24,
            duration: 2_000,
            refuse_folds: true,
            dispute_true_claims,
            first_cid: 42,
            windows: None,
        })
        .unwrap();
        let user = format!("alice-{label}");
        let ch = chain(&user);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let wdir = dir.join(&user);
        let mut w = Wallet::create(&dir.join(format!("{user}.json")), &seq.url).unwrap();
        w.progress = Some(Arc::new(move |m: String| println!("LICHEN {label}: {m}")));
        let t = Instant::now();
        let held = w.open_contract(&hub.url, &ch, &statement, &wdir, ask, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
        assert_eq!(held.record.cid(), 42);
        println!("LICHEN {label}: contract 42 on RISC Zero's statement opened in {:.1?}", t.elapsed());
        let input = match label {
            "F" => other.clone(),
            _ => {
                // before proving: the request, the hub's response, its
                // signature on b written for the prover
                let (o, _) = w.dispute(&ch, &statement, &wdir, 42, B, &[]).unwrap();
                assert!(matches!(o, Outcome::ProofDue(_)), "{label}: {o:?}");
                let auth = std::fs::read_to_string(lichen_wallet::engine::babe::data_dir(&wdir, 42).join("hub-auth.json")).unwrap();
                let canned = data("babe-auth-60-42.json");
                let Some(claim) = &claim else {
                    std::fs::write(&canned, &auth).unwrap();
                    panic!("no canned claim: prove the hub's signature on 60, written to {}, on x86 Linux (lichen-r0 babe-claim) into {}", canned.display(), data("babe-claim-60-42.hex").display());
                };
                let a: serde_json::Value = serde_json::from_str(&auth).unwrap();
                let c: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&canned).unwrap()).unwrap();
                assert_eq!(a, c, "{label}: the hub's signature on 60 is the canned claim's");
                w.babe_claim_input(42, claim).unwrap()
            }
        };
        let t = Instant::now();
        let (o, swept) = w.dispute(&ch, &statement, &wdir, 42, B, &input).unwrap();
        println!("LICHEN {label}: {o:?} in {:.1?}; swept {swept:?}", t.elapsed());
        match label {
            "T" => assert!(matches!(o, Outcome::Unchallenged(_)), "T: the honest hub lets her proof stand: {o:?}"),
            "W" => assert!(matches!(o, Outcome::Answered(_)), "W: she answers the challenge: {o:?}"),
            _ => assert_eq!(o, Outcome::Lost, "F: failure takes everything"),
        }
        assert_eq!(swept.is_some(), label != "F", "{label}: a win is swept");
        drop(hub);
    }
    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

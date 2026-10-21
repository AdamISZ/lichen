//! An anchored deployment on regtest (docs/ANCHOR_PLAN.md), natively (the
//! mock statement; no receipts): the sequencer anchors its history; Alice
//! opens a contract whose checkpoint both sides check and whose `D` is
//! the contract's; she returns her deposit, the return is anchored, ten
//! blocks pass. The withdrawal statement with anchoring accepts her input
//! (as the wallet builds it, headers from her own chain) under the chain
//! journal the recorded blocks end at, with the contract's `D`; refuses
//! it with too few blocks on the anchor; and the tower's package carries
//! the anchor.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_l2::Client;
use lichen_ledger::{regtest_sequencer, xonly, HUB_KEY};
use lichen_proto::Statement;
use lichen_sequencer::anchor::{genesis_seal, Anchoring};
use lichen_sequencer::{blocks_dir, Options, Sequencer};
use lichen_validity as v;
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;

fn wait(what: &str, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(start.elapsed() < Duration::from_secs(60), "{what}: timed out");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn mock() -> Statement {
    Statement::Mock { session: 0, returns: vec![] }
}

#[test]
fn a_withdrawal_under_an_anchor() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-hub-anchored-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let chain = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w).unwrap();
    for w in ["sequencer", "hub", "alice"] {
        rt.fund(&chain(w).new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
    }
    rt.mine(1).unwrap();
    let key = regtest_sequencer();
    let seal = genesis_seal(&chain("sequencer"), &xonly(&key)).unwrap();
    rt.mine(1).unwrap();
    let ledger = dir.join("ledger.json");
    let mut seq = Sequencer::start_with("127.0.0.1:0", Some(ledger.clone()), key, HUB_KEY, Options { native_proofs: true, seal: Some(seal) }).unwrap();
    seq.anchor(chain("sequencer"), Anchoring { every: Duration::from_millis(100), ..Default::default() }).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (s2, url) = (stop.clone(), seq.url.clone());
    let sealer = std::thread::spawn(move || {
        while !s2.load(Ordering::Relaxed) {
            let _ = Client::new(&url).and_then(|c| c.seal());
            std::thread::sleep(Duration::from_millis(200));
        }
    });
    let hub = Hub::start(Config {
        network: lichen_proto::Net::Regtest,
        listen: "127.0.0.1:0".into(),
        sequencer: seq.url.clone(),
        rpc_url: rt.rpc_url().to_string(),
        cookie: rt.cookie().clone(),
        wallet: "hub".into(),
        statement: mock(),
        dir: dir.join("hub"),
        seed: "test-hub".into(),
        l2_key: lichen_ledger::regtest_hub(),
        reserve_ppm: 20_000,
        max_bits: 21,
        duration: 2_000,
        refuse_folds: true,
        dispute_true_claims: false,
        first_cid: 1000,
        windows: None,
    })
    .unwrap();

    // the contract: a checkpoint, and the contract's D
    let ch = chain("alice");
    let mut w = Wallet::create(&dir.join("alice.json"), &seq.url).unwrap();
    assert_eq!(w.sequencer.deployment.seal, Some(seal));
    let ask = Ask { deposit: 100_000, bits: 21, reserve: 20_000 };
    let held = w.open_contract(&hub.url, &ch, &mock(), &dir.join("alice"), ask, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
    let cp = held.record.checkpoint.expect("a checkpoint");
    assert_eq!(cp.bits, 0x207fffff);
    assert_eq!(cp.work(), 20, "ten blocks of regtest's work");
    let d = w.sequencer.deployment;
    assert_eq!(held.record.deployment, lichen_withdraw::contract_id(&d.id(), &seal, 20), "D is the contract's");
    let cid = held.record.cid();
    rt.mine(1).unwrap();
    wait("the deposit", || w.balance().unwrap() == ask.deposit);

    // the return, refused (this hub folds nothing), anchored once mined
    assert!(w.withdraw(&hub.url, &mock(), &dir.join("alice"), cid, ask.deposit).is_err());
    let index = w.returned(cid).unwrap();
    let c = Client::new(&seq.url).unwrap();
    wait("the return's anchor sent and mined", || {
        let _ = rt.mine(1);
        c.state().unwrap().anchored_input(index, &d).is_ok()
    });
    let (_, a) = c.state().unwrap().anchored_input(index, &d).unwrap();
    wait("the height carrying the anchor sealed", || c.state().unwrap().sealed.last().is_some_and(|s| s.height >= a.from));

    // too few blocks on the anchor yet: the wallet says how far it's got
    let e = w.prover_input(cid, &ch);
    if let Err(e) = &e {
        assert!(format!("{e:#}").contains("isn't deep enough yet"), "{e:#}");
    }
    rt.mine(10).unwrap();
    let full = w.prover_input(cid, &ch).unwrap();
    assert_eq!(full.input.height, a.anchor.height, "the input is under the anchored root");
    assert_eq!(full.work, "20");
    assert!(full.headers.len() >= 10);

    // the statement, natively: the chain journal the recorded blocks end
    // at the height first carrying the anchor
    let id = [0xc4; 32];
    let mut prev: Option<v::ChainJournal> = None;
    for h in 1..=a.from {
        let b = std::fs::read(blocks_dir(&ledger).join(format!("{h}.input"))).unwrap();
        let input = v::BlockInput::from_bytes(&b).unwrap();
        let p = prev.as_ref().map(|j| j.to_bytes());
        prev = Some(v::chain(&id, &input, &mut |_| true, &mut |jb| p.as_deref() == Some(jb)).unwrap());
    }
    let cj = prev.unwrap();
    assert_eq!(cj.anchor, a.anchor);
    let headers: Vec<[u8; 80]> = full.headers.iter().map(|h| hex::decode(h).unwrap().try_into().unwrap()).collect();
    let wi = lichen_ledger::with_chain(&full.input, &cj, headers.clone(), 20).unwrap();
    let ends = cj.to_bytes();
    let j = lichen_withdraw::check(&wi, &id, &mut |jb| jb == ends).unwrap();
    assert_eq!(j[..4], (ask.deposit as u32).to_le_bytes());
    assert_eq!(j[4..8], cid.to_le_bytes());
    assert_eq!(j[8..], held.record.deployment, "the claim's D: what the contract pins");
    let short = lichen_ledger::with_chain(&full.input, &cj, headers[..9].to_vec(), 20).unwrap();
    assert_eq!(lichen_withdraw::check(&short, &id, &mut |jb| jb == ends), Err(lichen_withdraw::Reject::Depth));
    println!("LICHEN contract {cid}: the return at height {} anchored ({}), ten blocks on it: the statement accepts", a.anchor.height, a.from);

    // the tower's package carries the anchor
    let program = mock().program(&dir.join("alice")).unwrap();
    let pkg = w.export_dispute(&mock(), &program, cid, None).unwrap();
    assert_eq!(pkg.anchor, Some(a));
    let mut gone = pkg.clone();
    gone.sequencer = "http://127.0.0.1:9".into();
    assert_eq!(lichen_wallet::tower::withdraw_input(&gone).unwrap().height, a.anchor.height, "packed: no sequencer needed");

    // the hub folds again: Bob withdraws at once, his return not yet
    // anchored (the mock statement's fold doesn't wait for one), and
    // Alice's refused return is folded when asked again
    hub.set_refuse_folds(false);
    let bch = chain("bob");
    rt.fund(&bch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
    let mut bob = Wallet::create(&dir.join("bob.json"), &seq.url).unwrap();
    let bheld = bob.open_contract(&hub.url, &bch, &mock(), &dir.join("bob"), ask, bch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { bch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
    rt.mine(1).unwrap();
    wait("Bob's deposit", || bob.balance().unwrap() == ask.deposit);
    // the receiver's view: his deposit's note sealed, then anchored, then
    // final ten blocks on, each anchor checked on Bitcoin
    let f = bob.finality(&bch).unwrap();
    assert_eq!(f.sealed + f.anchored + f.fin, ask.deposit);
    wait("Bob's deposit anchored", || {
        let _ = rt.mine(1);
        bob.finality(&bch).unwrap().sealed == 0
    });
    rt.mine(10).unwrap();
    let f = bob.finality(&bch).unwrap();
    assert_eq!((f.sealed, f.anchored, f.fin), (0, 0, ask.deposit), "final: {f:?}");
    assert!(f.last.unwrap().confirmations >= 10);
    // a sequencer's state whose anchors don't check: refused
    let state = bob.sequencer.state().unwrap();
    let mut forged = state.clone();
    forged.anchors[0].anchor.root = [1; 32];
    let e = bob.checked_anchors(&forged, &bch).unwrap_err();
    assert!(format!("{e:#}").contains("another root"), "{e:#}");
    let mut forged = state.clone();
    let h = forged.anchors[0].anchor.height as usize;
    forged.sealed[h - 1].tree = [2; 32];
    let e = bob.checked_anchors(&forged, &bch).unwrap_err();
    assert!(format!("{e:#}").contains("commits another history"), "{e:#}");
    let mut forged = state.clone();
    forged.anchors.remove(0);
    if !forged.anchors.is_empty() {
        let e = bob.checked_anchors(&forged, &bch).unwrap_err();
        assert!(format!("{e:#}").contains("doesn't spend the last seal"), "{e:#}");
    }
    let txid = bob.withdraw(&hub.url, &mock(), &dir.join("bob"), bheld.record.cid(), ask.deposit).unwrap();
    println!("LICHEN contract {}: Bob's return folded before any anchor, {txid}", bheld.record.cid());
    let txid = w.withdraw(&hub.url, &mock(), &dir.join("alice"), cid, ask.deposit).unwrap();
    println!("LICHEN contract {cid}: Alice's, asked again, folded, {txid}");

    stop.store(true, Ordering::Relaxed);
    sealer.join().unwrap();
    drop(hub);
    drop(seq);
    let _ = std::fs::remove_dir_all(&dir);
}

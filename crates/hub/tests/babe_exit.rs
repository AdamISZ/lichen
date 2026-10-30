//! The exit (docs/EXIT_PLAN.md) through the hub and the wallet, on the
//! mock BABE statement, in an anchored deployment on regtest (blocks every
//! 150 ms; no receipts: the mock decides the exit's statement natively).
//! The hub refuses cooperative withdrawals, so each claim is an exit.
//!
//! - E: an honest exit. Alice claims her note from the latest anchored
//!   state; the hub has no counter, so it responds plainly, holds the note
//!   and records the exit on the L2; she proves her claim, and `success`
//!   pays her. Her claim's chain fields are the chain journal's the blocks
//!   recorded end at.
//! - S: a stale claim. Sam prepares his claim, then pays Bob; once the
//!   payment is anchored he claims the old note anyway: the hub counters
//!   with the spend, and he can't win.
//! - Q: the same note through two contracts. Quinn claims it through both,
//!   the second request after the first: the second is countered (the
//!   first's signed claim, or its exit record), the first paid.
//! - K: a forged counter. The hub counters Kim's honest claim with a `K`
//!   that isn't one; she proves it false, and `success` pays her.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use bitcoincore_rpc::{Auth, RpcApi};
use lichen_chain::Chain;
use lichen_hub::{Config, Hub};
use lichen_l2::Client;
use lichen_ledger::{nullifier, regtest_sequencer, xonly, HUB_KEY};
use lichen_proto::Statement;
use lichen_sequencer::anchor::{genesis_seal, Anchoring};
use lichen_sequencer::{blocks_dir, Options, Sequencer};
use lichen_validity as v;
use lichen_wallet::dispute::Outcome;
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;

fn statement() -> Statement {
    Statement::Babe { mock: true }
}

fn wait(what: &str, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(start.elapsed() < Duration::from_secs(90), "{what}: timed out");
        std::thread::sleep(Duration::from_millis(200));
    }
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
fn exits_on_the_mock_statement() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-babe-exit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let chain = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w).unwrap();
    for w in ["sequencer", "hub"] {
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
    let url = seq.url.clone();
    let sealer = background(&stop, Duration::from_millis(200), move || {
        let _ = Client::new(&url).and_then(|c| c.seal());
    });
    let hub = Hub::start(Config {
        network: lichen_proto::Net::Regtest,
        listen: "127.0.0.1:0".into(),
        sequencer: seq.url.clone(),
        rpc_url: rt.rpc_url().to_string(),
        cookie: rt.cookie().clone(),
        wallet: "hub".into(),
        statement: statement(),
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
    let miner = {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", rt.rpc_url()), Auth::CookieFile(rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        background(&stop, Duration::from_millis(150), move || {
            let _ = rpc.generate_to_address(1, &addr);
        })
    };
    let c = Client::new(&seq.url).unwrap();
    let ask = Ask { deposit: 200_000, bits: 21, reserve: 20_000 };
    // a wallet with `n` contracts opened, its deposits ours and anchored
    let open = |user: &str, n: usize| -> (Wallet, Chain, Vec<u32>) {
        let ch = chain(user);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let mut w = Wallet::create(&dir.join(format!("{user}.json")), &seq.url).unwrap();
        let label = user.to_string();
        w.progress = Some(Arc::new(move |m: String| println!("LICHEN {label}: {m}")));
        let cids = (0..n)
            .map(|_| w.open_contract(&hub.url, &ch, &statement(), &dir.join(user), ask, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v).map(|_| ()) }).unwrap().record.cid())
            .collect();
        wait("the deposits", || w.balance().unwrap() == ask.deposit * n as u64);
        let state = c.state().unwrap();
        let last = state.sealed.last().unwrap().height;
        wait("our notes anchored", || c.state().unwrap().anchors.last().is_some_and(|a| a.anchor.height >= last));
        (w, ch, cids)
    };
    let exit = |w: &mut Wallet, ch: &Chain, user: &str, cid: u32| {
        let t = Instant::now();
        let (o, swept) = w.exit(ch, &statement(), &dir.join(user), cid, &[]).unwrap();
        println!("LICHEN {user}: {o:?} in {:.1?}; swept {swept:?}", t.elapsed());
        o
    };

    // E: an honest exit
    let (mut w, ch, cids) = open("eve", 1);
    let plan = w.exit_plan(cids[0]).unwrap();
    let mine = w.notes(&w.state().unwrap());
    let claim = plan.input(lichen_withdraw::Request { funding: vec![], tx: vec![], header: [0; 80], index: 0, path: vec![], coinbase: vec![], coinbase_path: vec![], reserved: [0; 32] }, vec![]).unwrap();
    {
        // the claim's chain fields: the chain journal's, at the height first
        // carrying its anchor, as the blocks recorded end there
        let a = *c.state().unwrap().anchors.last().unwrap();
        wait("the height carrying the anchor sealed", || c.state().unwrap().sealed.last().is_some_and(|s| s.height >= a.from));
        let id = [0xc4; 32];
        let mut prev: Option<v::ChainJournal> = None;
        for h in 1..=a.from {
            let input = v::BlockInput::from_bytes(&std::fs::read(blocks_dir(&ledger).join(format!("{h}.input"))).unwrap()).unwrap();
            let p = prev.as_ref().map(|j| j.to_bytes());
            prev = Some(v::chain(&id, &input, &mut |_| true, &mut |jb| p.as_deref() == Some(jb)).unwrap());
        }
        let cj = prev.unwrap();
        let s = &claim.state;
        assert_eq!((s.chain_height, s.chain_root, s.recent, s.hist, s.anchor), (cj.height, cj.root, cj.recent, cj.hist, cj.anchor), "E: the claim's chain fields");
        assert_eq!(claim.notes.len(), mine.len());
    }
    assert!(matches!(exit(&mut w, &ch, "eve", cids[0]), Outcome::Unchallenged(_)), "E: the honest exit is paid");
    assert!(hub.log().iter().any(|l| l.contains(&format!("contract {}: the exit claim recorded on the L2", cids[0]))), "E: the hub records the exit");
    for o in &mine {
        assert_eq!(c.spent(&nullifier(&o.note)).unwrap().map(|s| s.0), Some(v::smt::exited(cids[0])), "E: the note retired by the record");
    }

    // S: a stale claim, after a spend anchored before the request
    let (mut w, ch, cids) = open("sam", 1);
    let stale = w.exit_plan(cids[0]).unwrap();
    let bob = lichen_ledger::key_from_label("test/bob");
    let old = w.notes(&w.state().unwrap());
    w.send(xonly(&bob), ask.deposit, 0).unwrap();
    // the height whose block spent the old note, anchored
    let mut spent = 0;
    wait("the payment sealed", || {
        spent = c.spent(&nullifier(&old[0].note)).unwrap().map_or(0, |s| s.1);
        spent > 0 && c.state().unwrap().sealed.last().is_some_and(|s| s.height >= spent)
    });
    wait("the payment anchored", || c.state().unwrap().anchors.last().is_some_and(|a| a.anchor.height >= spent));
    let k = w.contracts.iter().position(|h| h.record.cid() == cids[0]).unwrap();
    w.contracts[k].exit = Some(stale);
    assert_eq!(exit(&mut w, &ch, "sam", cids[0]), Outcome::Countered, "S: the stale claim is countered");

    // Q: the same note through two contracts
    let (mut w, ch, cids) = open("quinn", 2);
    let (p1, p2) = (w.exit_plan(cids[0]).unwrap(), w.exit_plan(cids[1]).unwrap());
    for (cid, p) in [(cids[0], &p1), (cids[1], &p2)] {
        let k = w.contracts.iter().position(|h| h.record.cid() == cid).unwrap();
        w.contracts[k].exit = Some(p.clone());
    }
    w.pause_after = Some(1);
    assert_eq!(exit(&mut w, &ch, "quinn", cids[0]), Outcome::Paused, "Q: the first request posted");
    w.pause_after = None;
    wait("the hub responds to the first", || hub.log().iter().any(|l| l.contains(&format!("contract {}: the user requests", cids[0]))));
    assert_eq!(exit(&mut w, &ch, "quinn", cids[1]), Outcome::Countered, "Q: the second claim is countered");
    assert!(matches!(exit(&mut w, &ch, "quinn", cids[0]), Outcome::Unchallenged(_)), "Q: the first is paid");

    // K: a forged counter, proved false
    let (mut w, ch, cids) = open("kim", 1);
    hub.set_forge_counters(true);
    let o = exit(&mut w, &ch, "kim", cids[0]);
    hub.set_forge_counters(false);
    assert!(matches!(o, Outcome::Unchallenged(_)), "K: the forged counter proved false, she is paid");

    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
    sealer.join().unwrap();
    drop(seq);
    let _ = std::fs::remove_dir_all(&dir);
}

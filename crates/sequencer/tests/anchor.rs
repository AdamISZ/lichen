//! Anchoring on regtest (docs/ANCHOR_PLAN.md, step 1): the genesis seal,
//! an anchor of each new sealed height once the last is recorded, its
//! record in the next block; every recorded block checked by the chain
//! statement natively, its anchoring state the anchor's; a restart with
//! an anchor in flight picks it up.

use std::time::{Duration, Instant};

use bitcoin::Amount;
use lichen_chain::Chain;
use lichen_l2::Client;
use lichen_ledger::{regtest_hub, regtest_sequencer, xonly, Mint, Tx, HUB_KEY};
use lichen_sequencer::anchor::{genesis_seal, in_flight_file, Anchoring};
use lichen_sequencer::{blocks_dir, Options, Sequencer};
use lichen_validity as v;
use lngap_btc::regtest::Regtest;

fn wait(what: &str, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(start.elapsed() < Duration::from_secs(60), "waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn heights_anchored_and_recorded() {
    let rt = Regtest::start().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-anchor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ledger = dir.join("ledger.json");
    let chain = || Chain::connect(rt.rpc_url(), rt.cookie(), "sequencer").unwrap();
    rt.fund(&chain().new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
    rt.mine(1).unwrap();
    let key = regtest_sequencer();
    let seal = genesis_seal(&chain(), &xonly(&key)).unwrap();
    // the wallet's change confirmed: it pays the anchors' fees
    rt.mine(1).unwrap();
    let opts = Anchoring { every: Duration::from_millis(100), ..Default::default() };
    let start = || {
        let mut s = Sequencer::start_with("127.0.0.1:0", Some(ledger.clone()), key.clone(), HUB_KEY, Options { seal: Some(seal), ..Default::default() }).unwrap();
        s.anchor(chain(), opts.clone()).unwrap();
        s
    };
    let s = start();
    let c = Client::new(&s.url).unwrap();
    assert_eq!(c.deployment.seal, Some(seal), "the deployment names its genesis seal");
    let mint = |v: u64| c.submit(&Tx::Mint(Mint::new(&regtest_hub(), vec![lichen_ledger::note([7; 32], v, 0)]))).unwrap();

    // height 1 sealed: an anchor of it goes out, and is recorded once
    // mined, in the block after
    mint(5);
    c.seal().unwrap();
    wait("the anchor of height 1 in flight", || in_flight_file(&ledger).exists());
    rt.mine(1).unwrap();
    wait("its record", || !in_flight_file(&ledger).exists());
    let s2 = c.seal().unwrap();
    assert_eq!(s2.height, 2, "the record is a new height's block");
    let st = c.state().unwrap();
    assert_eq!(st.anchors.len(), 1);
    let a = st.anchors[0];
    assert_eq!((a.from, a.anchor.height, a.anchor.root, a.anchor.genesis), (2, 1, st.sealed[0].root(), seal));

    // height 2 holds only that record: not anchored in turn
    std::thread::sleep(Duration::from_millis(500));
    assert!(!in_flight_file(&ledger).exists(), "no anchor of a height holding only an anchor's record");

    // a mint at 3: its anchor sent; the sequencer stopped with it in
    // flight, restarted, records it
    mint(6);
    c.seal().unwrap();
    wait("the anchor of height 3 in flight", || in_flight_file(&ledger).exists());
    drop(s);
    rt.mine(1).unwrap();
    let s = start();
    let c = Client::new(&s.url).unwrap();
    wait("its record, after the restart", || !in_flight_file(&ledger).exists());
    c.seal().unwrap();
    let st = c.state().unwrap();
    assert_eq!(st.anchors.iter().map(|a| (a.from, a.anchor.height)).collect::<Vec<_>>(), vec![(2, 1), (4, 3)]);

    // every block recorded is the chain statement's, from genesis; the
    // last chain journal's anchoring state is the last anchor's
    let id = [0xc4; 32];
    let mut prev: Option<v::ChainJournal> = None;
    for h in 1.. {
        let Ok(b) = std::fs::read(blocks_dir(&ledger).join(format!("{h}.input"))) else { break };
        let input = v::BlockInput::from_bytes(&b).unwrap();
        let p = prev.as_ref().map(|j| j.to_bytes());
        let j = v::chain(&id, &input, &mut |_| true, &mut |jb| p.as_deref() == Some(jb)).unwrap();
        assert_eq!(j.height, h);
        prev = Some(j);
    }
    let st = c.state().unwrap();
    let j = prev.unwrap();
    assert_eq!((j.height, j.root), (st.sealed.last().unwrap().height, st.sealed.last().unwrap().root()));
    assert_eq!(j.anchor, st.anchors.last().unwrap().anchor);

    // ten blocks on the last anchor's: their work on it, as a withdrawal
    // would show it
    rt.mine(10).unwrap();
    let block = bitcoin::BlockHash::from_byte_array(j.anchor.block);
    let headers = chain().headers_after(&block, 10).unwrap();
    assert_eq!(headers.len(), 10);
    assert_eq!(lichen_withdraw::work_on(&j.anchor.block, &headers), Some(20), "regtest's work, 2 a block");
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

use bitcoin::hashes::Hash as _;

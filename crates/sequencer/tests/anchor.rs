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

/// A sequencer signing two histories (two ledgers under one key and one
/// genesis seal, as a sequencer forking): both try to anchor, Bitcoin
/// lets the seal be spent once, so one history is anchored and the other
/// never is; nor can the other take the winner's anchor as its own.
#[test]
fn a_forked_history_is_never_anchored() {
    let rt = Regtest::start().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-fork-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let chain = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w).unwrap();
    for w in ["a", "b"] {
        rt.fund(&chain(w).new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
    }
    rt.mine(1).unwrap();
    let key = regtest_sequencer();
    let seal = genesis_seal(&chain("a"), &xonly(&key)).unwrap();
    rt.mine(1).unwrap();
    let opts = Anchoring { every: Duration::from_millis(100), ..Default::default() };
    let mut seqs = vec![];
    for (name, v) in [("a", 5), ("b", 6)] {
        let ledger = dir.join(format!("{name}.json"));
        let mut s = Sequencer::start_with("127.0.0.1:0", Some(ledger.clone()), key.clone(), HUB_KEY, Options { seal: Some(seal), ..Default::default() }).unwrap();
        let c = Client::new(&s.url).unwrap();
        c.submit(&Tx::Mint(Mint::new(&regtest_hub(), vec![lichen_ledger::note([7; 32], v, 0)]))).unwrap();
        c.seal().unwrap();
        s.anchor(chain(name), opts.clone()).unwrap();
        seqs.push((s, c, ledger));
    }
    let (ra, rb) = (seqs[0].1.state().unwrap().sealed[0].root(), seqs[1].1.state().unwrap().sealed[0].root());
    assert_ne!(ra, rb, "two histories at height 1");
    wait("an anchor in flight", || seqs.iter().any(|s| in_flight_file(&s.2).exists()));
    std::thread::sleep(Duration::from_millis(1000));
    rt.mine(1).unwrap();
    wait("one history's anchor recorded", || seqs.iter().any(|s| s.1.events(0).unwrap().iter().any(|e| matches!(e.1, lichen_l2::Event::Anchored { .. }))));
    // a few more blocks: the other keeps trying, never anchors
    for _ in 0..5 {
        std::thread::sleep(Duration::from_millis(500));
        rt.mine(1).unwrap();
    }
    for (_, c, _) in &seqs {
        c.seal().unwrap();
    }
    let anchored: Vec<bool> = seqs.iter().map(|s| !s.1.state().unwrap().anchors.is_empty()).collect();
    assert_eq!(anchored.iter().filter(|a| **a).count(), 1, "exactly one history anchored: {anchored:?}");
    let (win, lose) = if anchored[0] { (0, 1) } else { (1, 0) };

    // the winner's anchor, offered to the other as its own: refused, with
    // the other's own roots or the winner's
    let a = seqs[win].1.state().unwrap().anchors[0].anchor;
    let txid = bitcoin::Txid::from_byte_array(a.seal.txid);
    let mut tx = chain("a").get_tx(&txid).unwrap();
    for i in &mut tx.input {
        i.witness = bitcoin::Witness::new();
    }
    let block = chain("a").block_of(&txid).unwrap().unwrap();
    let txids: Vec<[u8; 32]> = chain("a").block_txids(&block).unwrap().iter().map(|t| t.to_byte_array()).collect();
    let index = txids.iter().position(|t| *t == a.seal.txid).unwrap();
    let header = chain("a").header(&block).unwrap();
    for from in [lose, win] {
        let roots: Vec<[u8; 32]> = seqs[from].1.state().unwrap().sealed[..1].iter().map(|s| s.root()).collect();
        let rec = v::AnchorRecord { tx: bitcoin::consensus::serialize(&tx), header, index: index as u32, path: lichen_sequencer::anchor::merkle_path(&txids, index), before: [0; 32], roots };
        let e = seqs[lose].1.submit(&Tx::Anchor(rec.to_bytes())).unwrap_err();
        assert!(format!("{e:#}").contains("doesn't check"), "{e:#}");
    }
    assert!(seqs[lose].1.state().unwrap().anchors.is_empty(), "the other history: never anchored");
    drop(seqs);
    let _ = std::fs::remove_dir_all(&dir);
}

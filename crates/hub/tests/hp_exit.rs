//! The exit where only the hub proves (docs/HUB_PROVES_PLAN.md) through
//! the hub and the wallet, on the mock statement, in an anchored
//! deployment on regtest (blocks every 150 ms; no receipts: the hub
//! decides its statement natively, and asserts the mock's proof). Alice
//! garbles; the hub keeps her instances. The hub refuses cooperative
//! withdrawals, so each claim is an exit.
//!
//! - E: an honest exit. Eve claims her note; the hub finds no ground, holds
//!   it and records the exit on the L2, and `request_timeout` pays her.
//! - S: a stale claim. Sam prepares his claim, then pays Bob; once the
//!   payment is anchored before the cutoff he claims the old note anyway:
//!   the hub asserts it isn't live at A*, and his wallet, finding the
//!   proof valid, concedes.
//! - C: the same, but Cleo challenges the valid assertion anyway: the hub
//!   evaluates her kept instances on its proof and answers with a `msg`.
//! - Q: the same note through two contracts, requested together: the hub
//!   asserts a second claim against each.
//! - K: a lying hub. It asserts a false proof against Kim's honest claim;
//!   she challenges, it can't answer, and `failure` pays her.
//! - R: an exit after a withdrawal not folded. Rita withdraws part of her
//!   note: the hub records her claim on the L2 (retiring the note split
//!   off) but won't fold. Her exit posts the same claim: this contract's
//!   own exit record isn't a spend against it, and she is paid.
//! - U: an unacknowledged spend. Uma pays Bob and never acknowledges it;
//!   her exit claims the note it spent: it doesn't count against her, she
//!   is paid, and the exit record voids the payment, Bob's note locked for
//!   good.
//! - W: an acknowledgment withheld. Wendy pays Bob and signs her
//!   acknowledgment, but it never reaches the L2 (a sequencer that drops
//!   it); her exit claims her locked change, carrying it: she is paid, and
//!   the record applies it, unlocking Bob's note.
//! - G: the operator gone. Gail pays Bob, her acknowledgment never
//!   reaching the L2, and her wallet keeps its exit set with her locked
//!   change; the hub and the sequencer stop. She exits from the set alone,
//!   the claim of her change carrying her acknowledgment, and
//!   `request_timeout` pays her.

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
use lichen_sequencer::{Options, Sequencer};
use lichen_validity as v;
use lichen_wallet::dispute::Outcome;
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;

fn statement() -> Statement {
    Statement::HubProves { mock: true }
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
fn the_hub_proves_on_the_mock_statement() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-hp-exit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // the statement's inputs the hub asserts on (S's chain journal, below),
    // here unless LICHEN_DUMP_HP names a directory to keep them in
    if std::env::var_os("LICHEN_DUMP_HP").is_none() {
        std::env::set_var("LICHEN_DUMP_HP", &dir);
    }
    let dumps = std::path::PathBuf::from(std::env::var_os("LICHEN_DUMP_HP").unwrap());
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
    seq.anchor(chain("sequencer"), Anchoring { every: Duration::from_millis(100), confirmations: lichen_proto::hp::margin(lichen_proto::Net::Regtest), ..Default::default() }).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let url = seq.url.clone();
    // the sealer stops apart from the miner, with the sequencer (G)
    let seal_stop = Arc::new(AtomicBool::new(false));
    let sealer = background(&seal_stop, Duration::from_millis(200), move || {
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
        fee_ppm: 0,
        max_liquidity: 10_000_000,
        duration: 2_000,
        refuse_folds: true,
        forge_assertions: false,
        first_cid: 1000,
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
    let hub_url = hub.url.clone();
    let ask = Ask { deposit: 200_000, liquidity: 1_000_000, reserve: 20_000 };
    // a wallet with `n` contracts opened, its deposits ours and anchored
    let open = |user: &str, n: usize| -> (Wallet, Chain, Vec<u32>) {
        let ch = chain(user);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let mut w = Wallet::create(&dir.join(format!("{user}.json")), &seq.url).unwrap();
        let label = user.to_string();
        w.progress = Some(Arc::new(move |m: String| println!("LICHEN {label}: {m}")));
        let cids = (0..n)
            .map(|_| w.open_contract(&hub_url, &ch, &statement(), ask, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v).map(|_| ()) }).unwrap().record.cid())
            .collect();
        wait("the deposits", || w.balance().unwrap() == ask.deposit * n as u64);
        // the deposits' notes moved to our key, acknowledged: unlocked
        w.acknowledge_all(&ch, 120).unwrap();
        // the exit set kept with our notes, once anchored (as the wallet
        // does as it reads the state, at most every 30 s; at any height: a
        // claim by position needs no kit at one height)
        wait("our notes anchored and kept", || {
            let kept = w.keep_exit_set(&w.state().unwrap()).unwrap();
            if kept.is_some() {
                println!("LICHEN {user}: {kept:?}");
            }
            w.exit_sets().last().is_some_and(|s| s.notes.len() == n)
        });
        (w, ch, cids)
    };
    let exit = |w: &mut Wallet, ch: &Chain, user: &str, cid: u32| {
        let t = Instant::now();
        let (o, swept) = w.exit(ch, &statement(), cid).unwrap();
        println!("LICHEN {user}: {o:?} in {:.1?}; swept {swept:?}", t.elapsed());
        o
    };

    // the claim's cutoff past the height `h`'s anchor: margin blocks after
    // its block
    let past_cutoff = |h: u64| {
        let mut at = None;
        wait("anchored", || {
            at = c.state().unwrap().anchors.iter().find(|a| a.anchor.height >= h).copied();
            at.is_some()
        });
        let block = <bitcoin::BlockHash as bitcoin::hashes::Hash>::from_byte_array(at.unwrap().anchor.block);
        let ch = chain("hub");
        let mut confirmed = None;
        wait("the anchor confirmed", || {
            confirmed = ch.block_height(&block).unwrap();
            confirmed.is_some()
        });
        let until = confirmed.unwrap() + lichen_proto::hp::margin(lichen_proto::Net::Regtest) + 2;
        wait("past the cutoff", || ch.height().unwrap() >= until);
    };
    // a stale claim: the plan made, the note paid away, anchored before the
    // cutoff
    let stale = |w: &mut Wallet, ch: &Chain, cid: u32| {
        let plan = w.hp_exit_plan(&chain("hub"), cid).unwrap();
        let bob = lichen_ledger::key_from_label("test/bob");
        let old = w.notes(&w.state().unwrap());
        w.send(xonly(&bob), ask.deposit, 0).unwrap();
        // acknowledged: it counts against him
        w.acknowledge_all(ch, 120).unwrap();
        let mut spent = 0;
        wait("the payment sealed", || {
            spent = c.spent(&nullifier(&old[0].note)).unwrap().map_or(0, |s| s.1);
            spent > 0 && c.state().unwrap().sealed.last().is_some_and(|s| s.height >= spent)
        });
        past_cutoff(spent);
        let k = w.contracts.iter().position(|h| h.record.cid() == cid).unwrap();
        w.contracts[k].exit = Some(plan);
    };

    // E: an honest exit
    let (mut w, ch, cids) = open("eve", 1);
    let mine = w.notes(&w.state().unwrap());
    assert!(matches!(exit(&mut w, &ch, "eve", cids[0]), Outcome::HubTimedOut(_)), "E: the honest exit is paid");
    assert!(hub.log().iter().any(|l| l.contains(&format!("contract {}: the exit claim recorded on the L2", cids[0]))), "E: the hub records the exit");
    for o in &mine {
        assert_eq!(c.spent(&nullifier(&o.note)).unwrap().map(|s| s.0), Some(v::smt::exited(cids[0])), "E: the note retired by the record");
    }

    // S: a stale claim, the payment anchored before the cutoff
    let (mut w, ch, cids) = open("sam", 1);
    stale(&mut w, &ch, cids[0]);
    assert_eq!(exit(&mut w, &ch, "sam", cids[0]), Outcome::Countered, "S: the hub asserts the stale claim false");
    wait("success the hub's", || hub.contracts().iter().any(|(r, closed)| r.cid() == cids[0] && closed.is_some()));
    // the chain receipt the statement asks for at A* is the one the chain
    // statement gives for the block sealing that height (checked natively:
    // on the mock no receipt is read)
    let input = lichen_withdraw::hp::HubInput::from_bytes(&std::fs::read(dumps.join(format!("hp-{}.bin", cids[0]))).unwrap()).unwrap();
    let lichen_withdraw::hp::Ground::At { last, .. } = &input.ground else { panic!("S: a ground at A*") };
    let h = last.state.chain_height;
    let block = v::BlockInput::from_bytes(&std::fs::read(lichen_sequencer::blocks_dir(&ledger).join(format!("{h}.input"))).unwrap()).unwrap();
    let id: [u8; 32] = hex::decode(lichen_ledger::CHAIN_IMAGE_ID.trim()).unwrap().try_into().unwrap();
    let journal = v::chain(&id, &block, &mut |_| true, &mut |_| true).unwrap();
    assert_eq!(journal.to_bytes(), last.state.chain_journal(&id).to_bytes(), "S: the statement asks for the chain receipt at A*'s chain height");

    // C: the same, challenged anyway: the hub answers
    let (mut w, ch, cids) = open("cleo", 1);
    stale(&mut w, &ch, cids[0]);
    w.unchecked_claims = true;
    assert_eq!(exit(&mut w, &ch, "cleo", cids[0]), Outcome::Lost, "C: the hub answers a challenge of its valid proof");
    assert!(hub.log().iter().any(|l| l.contains(&format!("contract {}: answered the challenge", cids[0]))), "C: with a kept instance's msg");

    // Q: the same note through two contracts, requested together
    let (mut w, ch, cids) = open("quinn", 2);
    let (p1, p2) = (w.hp_exit_plan(&ch, cids[0]).unwrap(), w.hp_exit_plan(&ch, cids[1]).unwrap());
    for (cid, p) in [(cids[0], &p1), (cids[1], &p2)] {
        let k = w.contracts.iter().position(|h| h.record.cid() == cid).unwrap();
        w.contracts[k].exit = Some(p.clone());
    }
    w.pause_after = Some(1);
    assert_eq!(exit(&mut w, &ch, "quinn", cids[0]), Outcome::Paused, "Q: the first request posted");
    w.pause_after = None;
    assert_eq!(exit(&mut w, &ch, "quinn", cids[1]), Outcome::Countered, "Q: the second claim is asserted false");
    assert_eq!(exit(&mut w, &ch, "quinn", cids[0]), Outcome::Countered, "Q: and the first");

    // K: a lying hub, its false proof challenged
    let (mut w, ch, cids) = open("kim", 1);
    hub.set_forge_assertions(true);
    let o = exit(&mut w, &ch, "kim", cids[0]);
    hub.set_forge_assertions(false);
    assert!(matches!(o, Outcome::Refuted(_)), "K: the false assertion refuted, she is paid");

    // R: an exit after a withdrawal the hub recorded but won't fold
    let (mut w, ch, cids) = open("rita", 1);
    let back = 50_000;
    let refused = w.withdraw(&chain("hub"), &hub_url, &statement(), cids[0], back);
    assert!(refused.is_err(), "R: the hub refuses the fold");
    assert!(hub.log().iter().any(|l| l.contains(&format!("contract {}: the user's withdrawal claim", cids[0]))), "R: the hub recorded the claim");
    let plan = w.contracts.iter().find(|h| h.record.cid() == cids[0]).unwrap().exit.clone().expect("R: the claim kept");
    let claim = lichen_withdraw::hp::Claim::from_bytes(&plan.posted().unwrap()).unwrap();
    let unit = w.contracts[0].record.terms.unit.to_sat();
    assert_eq!(u64::from(plan.b), back / unit, "R: b the withdrawal's, in units");
    let state = w.state().unwrap();
    let split = *state.note(claim.positions[0]).unwrap();
    assert!(claim.positions.len() == 1 && split.value == u64::from(plan.b) * unit, "R: the claim of the note split off");
    assert_eq!(c.spent(&nullifier(&split)).unwrap().map(|s| s.0), Some(v::smt::exited(cids[0])), "R: retired by the contract's own record");
    assert!(matches!(exit(&mut w, &ch, "rita", cids[0]), Outcome::HubTimedOut(_)), "R: the exit posting the same claim is paid");

    // U: an unacknowledged spend: its input claimed, and paid
    use lichen_ledger::lichen_validity::ack;
    let bob = xonly(&lichen_ledger::key_from_label("test/bob"));
    let (mut w, ch, cids) = open("uma", 1);
    let old = w.notes(&w.state().unwrap())[0];
    let to_bob = w.send(bob, 150_000, 0).unwrap()[0];
    wait("the payment sealed", || c.state().unwrap().sealed.last().is_some_and(|s| s.size > to_bob));
    assert!(matches!(exit(&mut w, &ch, "uma", cids[0]), Outcome::HubTimedOut(_)), "U: the note her unacknowledged payment spent, claimed and paid");
    let txid = c.spent(&nullifier(&old.note)).unwrap().unwrap().0;
    wait("the payment voided", || c.state().unwrap().spent(&ack::void_key(&txid)));
    assert!(c.state().unwrap().locked(to_bob), "U: Bob's note locked for good");
    assert!(w.acknowledge(&ch).is_ok() && !c.state().unwrap().spent(&ack::acked_key(&txid)), "U: the payment can't be acknowledged now");

    // W: an acknowledgment withheld: the locked change claimed, carrying it
    let (mut w, ch, cids) = open("wendy", 1);
    let idx = w.send(bob, 150_000, 0).unwrap();
    let (to_bob, change) = (idx[0], idx[1]);
    w.acks_unsent = true;
    w.acknowledge_all(&ch, 120).unwrap();
    let state = c.state().unwrap();
    assert!(state.locked(change) && state.locked(to_bob), "W: no acknowledgment on the L2");
    let plan = w.hp_exit_plan(&ch, cids[0]).unwrap();
    let claim = lichen_withdraw::hp::Claim::from_bytes(&plan.posted().unwrap()).unwrap();
    assert_eq!((claim.positions.clone(), claim.acks.len()), (vec![change], 1), "W: the claim of her change, carrying her acknowledgment");
    assert!(matches!(exit(&mut w, &ch, "wendy", cids[0]), Outcome::HubTimedOut(_)), "W: paid");
    wait("the acknowledgment applied", || !c.state().unwrap().locked(to_bob));

    // G: the operator gone, the exit from the set kept: her change from a
    // payment whose acknowledgment never reached the L2, locked there,
    // claimed carrying it
    let (mut w, ch, cids) = open("gail", 1);
    let change = w.send(bob, 150_000, 0).unwrap()[1];
    w.acks_unsent = true;
    w.acknowledge_all(&ch, 120).unwrap();
    wait("her change anchored and kept", || {
        let _ = w.keep_exit_set(&w.state().unwrap()).unwrap();
        w.exit_sets().last().is_some_and(|s| s.notes.iter().any(|n| n.index == change))
    });
    assert!(c.state().unwrap().locked(change), "G: her change locked on the L2");
    let log = hub.stop();
    seal_stop.store(true, Ordering::Relaxed);
    sealer.join().unwrap();
    drop(seq);
    assert!(w.sequencer.state().is_err(), "G: the sequencer is gone");
    let plan = w.hp_exit_plan(&ch, cids[0]).unwrap();
    let claim = lichen_withdraw::hp::Claim::from_bytes(&plan.posted().unwrap()).unwrap();
    assert_eq!((claim.positions.clone(), claim.acks.len()), (vec![change], 1), "G: the claim of her change, carrying her acknowledgment, from the set kept");
    assert!(matches!(exit(&mut w, &ch, "gail", cids[0]), Outcome::HubTimedOut(_)), "G: request_timeout pays her");
    assert!(!log.iter().any(|l| l.contains(&format!("contract {}", cids[0])) && l.contains("exit claim")), "G: the hub saw no request");

    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

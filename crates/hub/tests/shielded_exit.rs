//! Exits that claim shielded notes directly (docs/HUB_PROVES_PLAN.md,
//! "Shielded notes"), on the mock statement, native proofs: no
//! unshielding, which needs the sequencer.
//!
//! - Carol shields her deposit and exits claiming her shielded note: her
//!   claim reveals her keys but the spend key, and her exit key signs it.
//!   The hub finds no ground, records the exit (her note's nullifier
//!   retired), and `request_timeout` pays her.
//! - Dan prepares his claim of his shielded note, then pays it to Carol:
//!   once the payment is anchored before the cutoff he claims it anyway,
//!   and the hub asserts it spent at A* (its nullifier from his keys).

mod common;

use std::time::Duration;

use bitcoin::Amount;
use common::{statement, wait, Env};
use lichen_l2::Client;
use lichen_wallet::dispute::Outcome;
use lichen_wallet::{Ask, Wallet};

#[test]
fn exits_of_shielded_notes() {
    let mut env = Env::new("shielded-exit");
    env.anchor();
    let env = env;
    let rt = &env.rt;
    let hub = env.hub("hub", |_| {});
    let c = Client::new(&env.seq.url).unwrap();
    let ask = Ask { deposit: 200_000, liquidity: 1_000_000, reserve: 20_000 };
    // a wallet with a contract, its deposit shielded and acknowledged
    let open = |name: &str| {
        let ch = env.chain(name);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let mut w = Wallet::create(&env.dir.join(format!("{name}.json")), &env.seq.url).unwrap();
        let label = name.to_string();
        w.progress = Some(std::sync::Arc::new(move |m: String| println!("LICHEN {label}: {m}")));
        let cid = w.open_contract(&hub.url, &ch, &statement(), ask, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap().record.cid();
        rt.mine(1).unwrap();
        wait("the deposit", || w.balance().unwrap() == ask.deposit);
        env.acknowledge(&mut w, &ch);
        w.shield(ask.deposit).unwrap();
        env.acknowledge(&mut w, &ch);
        assert_eq!(w.balances().unwrap(), (0, ask.deposit));
        (w, ch, cid)
    };

    // Carol: her shielded note claimed directly, and paid
    let (mut w, ch, cid) = open("carol");
    let carol = w.shielded_address();
    let plan = env.mining(|| w.hp_exit_plan(&ch, cid)).unwrap();
    let claim = lichen_withdraw::hp::Claim::from_bytes(&plan.posted().unwrap()).unwrap();
    let sc = claim.shielded.clone().expect("a claim of shielded notes");
    assert!(claim.positions.is_empty() && sc.notes.len() == 1 && sc.owner() == carol.owner, "her shielded note alone, by its owner's keys");
    let (o, _) = env.mining(|| w.exit(&ch, &statement(), cid)).unwrap();
    assert!(matches!(o, Outcome::HubTimedOut(_)), "Carol paid: {o:?}");
    assert!(hub.log().iter().any(|l| l.contains(&format!("contract {cid}: the exit claim recorded on the L2"))));
    let nf = sc.nullifier(&sc.notes[0]);
    wait("the note retired", || c.spent(&nf).unwrap().map(|s| s.0) == Some(lichen_validity::smt::exited(cid)));

    // Dan: a stale claim of a shielded note he paid away
    let (mut w, ch, cid) = open("dan");
    let plan = env.mining(|| w.hp_exit_plan(&ch, cid)).unwrap();
    let sc = lichen_withdraw::hp::Claim::from_bytes(&plan.posted().unwrap()).unwrap().shielded.unwrap();
    let nf = sc.nullifier(&sc.notes[0]);
    w.send_shielded(&carol, ask.deposit).unwrap();
    env.acknowledge(&mut w, &ch);
    // the payment anchored, and that anchor's block the margin deep and two
    let spent = c.spent(&nf).unwrap().expect("spent").1;
    env.mining(|| {
        let margin = lichen_proto::hp::margin(lichen_proto::Net::Regtest);
        let start = std::time::Instant::now();
        loop {
            assert!(start.elapsed() < Duration::from_secs(120), "past the cutoff: timed out");
            let s = c.state().unwrap();
            let deep = s.anchors.iter().find(|a| a.anchor.height >= spent).and_then(|a| ch.block_height(&<bitcoin::BlockHash as bitcoin::hashes::Hash>::from_byte_array(a.anchor.block)).unwrap());
            if deep.is_some_and(|b| ch.height().unwrap() >= b + margin + 2) {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    });
    let k = w.contracts.iter().position(|h| h.record.cid() == cid).unwrap();
    w.contracts[k].exit = Some(plan);
    let (o, _) = env.mining(|| w.exit(&ch, &statement(), cid)).unwrap();
    assert_eq!(o, Outcome::Countered, "the hub asserts Dan's shielded note spent");
    assert!(hub.log().iter().any(|l| l.contains(&format!("contract {cid}: the user's exit claim is false: note")) && l.contains("was spent by A*")), "spent at A*");
}

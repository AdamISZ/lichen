//! Contracts over shielded notes (docs/SHIELDED_PLAN.md), native proofs:
//! Alice and Bob open contracts and shield their deposits; Bob pays Alice
//! 50,000 sats in a shielded note; Alice unshields what she withdraws (a
//! claim takes transparent notes), claims it, and the hub folds. Then the
//! hub refuses folds: Bob's refused withdrawal keeps its claim, of his
//! unshielded note, for his exit.

mod common;

use bitcoin::Amount;
use common::{statement, wait, Env};
use lichen_wallet::{Ask, Wallet};

#[test]
fn contracts_over_shielded_notes() {
    let mut env = Env::new("shielded");
    env.anchor();
    let env = env;
    let rt = &env.rt;
    let hub = env.hub("hub", |c| c.duration = 500);
    let mut users = vec![];
    for (name, deposit) in [("alice", 400_000u64), ("bob", 100_000)] {
        let ch = env.chain(name);
        rt.fund(&ch.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();
        let mut w = Wallet::create(&env.dir.join(format!("{name}.json")), &env.seq.url).unwrap();
        let held = w.open_contract(&hub.url, &ch, &statement(), Ask { deposit, liquidity: 1_000_000, reserve: 20_000 }, ch.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { ch.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
        users.push((w, ch, held));
    }
    rt.mine(1).unwrap();
    // each step's notes locked until its spend is acknowledged
    for (w, ch, h) in &mut users {
        let d = u64::from(h.record.terms.deposit);
        wait("the deposit", || w.balance().unwrap() == d);
        env.acknowledge(w, ch);
        w.shield(d).unwrap();
        assert_eq!(w.balances().unwrap(), (0, d), "the deposit shielded");
        env.acknowledge(w, ch);
    }
    let to_alice = users[0].0.shielded_address();
    users[1].0.send_shielded(&to_alice, 50_000).unwrap();
    assert_eq!(users[0].0.balances().unwrap(), (0, 450_000));
    {
        let (w, ch, _) = &mut users[1];
        env.acknowledge(w, ch);
    }

    // Alice withdraws 450,000 cooperatively: unshielded, then claimed
    {
        let (w, ch, h) = &mut users[0];
        let want = 450_000 / h.record.terms.unit.to_sat() * h.record.terms.unit.to_sat();
        w.unshield(want).unwrap();
        assert_eq!(w.balances().unwrap(), (want, 450_000 - want));
        env.acknowledge(w, ch);
        let before = ch.balance().unwrap();
        let txid = w.withdraw(&env.chain("hub"), &hub.url, &statement(), h.record.cid(), 450_000).unwrap();
        rt.mine(1).unwrap();
        assert_eq!(ch.balance().unwrap() - before, Amount::from_sat(want) + h.record.terms.reserve_alice);
        assert_eq!(w.balances().unwrap(), (0, 450_000 - want), "the rest still shielded");
        println!("LICHEN Alice unshielded {want} sats and withdrew them; the hub folded ({txid})");
    }

    // the hub refuses folds now: Bob's withdrawal of 50,000 is refused,
    // and his claim is kept for his exit
    hub.set_refuse_folds(true);
    let (w, ch, h) = &mut users[1];
    let cid = h.record.cid();
    let want = 50_000 / h.record.terms.unit.to_sat() * h.record.terms.unit.to_sat();
    let note = w.unshield(want).unwrap();
    env.acknowledge(w, ch);
    assert!(w.withdraw(&env.chain("hub"), &hub.url, &statement(), cid, 50_000).is_err(), "refused");
    let plan = w.contracts.iter().find(|x| x.record.cid() == cid).unwrap().exit.clone().expect("the claim kept");
    let claim = lichen_withdraw::hp::Claim::from_bytes(&plan.posted().unwrap()).unwrap();
    assert_eq!((claim.positions, u64::from(plan.b) * h.record.terms.unit.to_sat()), (vec![note], want), "the claim of his unshielded note");
    assert!(w.withdraw(&env.chain("hub"), &hub.url, &statement(), cid, 60_000).is_err(), "another amount than the claim kept");
    println!("LICHEN Bob's refused withdrawal of {want} sats from an unshielded note: its claim kept for his exit");
}

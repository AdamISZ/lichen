//! Opening a contract end to end: a regtest node with a bitcoind wallet
//! each for Alice and the hub, the sequencer, the hub daemon, and Alice's
//! wallet. Alice asks; she garbles her instances for the hub's statement,
//! the hub keeps some; the hub offers the contract, the funding
//! transaction and its signatures on the whole pre-signed set, the
//! deposit already minted to her, locked to the funding; Alice checks it
//! all, signs (an adaptor pre-signature on the funding's deposit input);
//! the hub completes it, broadcasts, and answers with `t`, which unlocks
//! her deposit on the L2.

mod common;

use std::time::Instant;

use bitcoin::Amount;
use common::{statement, Env};
use lichen_wallet::{Ask, Wallet};

#[test]
fn open_a_contract_and_receive_the_deposit() {
    let env = Env::new("open");
    let rt = &env.rt;
    let hub = env.hub("hub", |c| c.duration = 500);
    let alice_chain = env.chain("alice");
    rt.fund(&alice_chain.new_spk().unwrap(), Amount::from_sat(10_000_000)).unwrap();

    let mut alice = Wallet::create(&env.dir.join("alice.json"), &env.seq.url).unwrap();
    let (deposit, liquidity, reserve) = (400_000u64, 1_000_000u64, 20_000u64);
    let t = Instant::now();
    let held = alice.open_contract(&hub.url, &alice_chain, &statement(), Ask { deposit, liquidity, reserve }, alice_chain.new_spk().unwrap(), &|addr: &bitcoin::Address, v| { alice_chain.pay(&addr.script_pubkey(), v)?; rt.mine(1)?; Ok(()) }).unwrap();
    let r = &held.record;
    println!("LICHEN opened contract {} in {:.1?}: cap {} sats, Alice's reserve {}, the hub's {}, T_close {}", r.cid(), t.elapsed(), r.terms.v_max().to_sat(), r.terms.reserve_alice, r.terms.reserve_hub, r.terms.t_close);

    // the funding is in the mempool; the contract output holds V_max and both reserves
    rt.mine(1).unwrap();
    let funding = rt.get_tx(&r.funding.txid).unwrap();
    assert_eq!(funding.output[0].value, r.terms.v_max() + r.terms.reserves());
    // both sides hold the same contract, every signature checked
    let theirs = hub.contracts();
    assert_eq!(theirs.len(), 1);
    let theirs = &theirs[0].0;
    assert_eq!((theirs.funding, &theirs.alice_sigs), (r.funding, &r.alice_sigs));
    let set = r.presigned(&r.build(&statement()).unwrap()).unwrap();
    println!("LICHEN both parties hold {} pre-signed transactions, each signature checked", set.len());

    // the deposit is hers already, claimed with t
    assert!(held.mint.as_ref().unwrap().claimed);
    alice.sequencer.seal().unwrap();
    assert_eq!(alice.balance().unwrap(), deposit);
    println!("LICHEN the hub minted {deposit} sats to Alice on the L2, hers once the funding was out");
    // a restarted wallet still has its contract
    let again = Wallet::open(&env.dir.join("alice.json"), &env.seq.url).unwrap();
    assert_eq!(again.contracts.len(), 1);
}

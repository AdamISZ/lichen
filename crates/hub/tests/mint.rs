//! The deposit's note and the funding are a swap: the hub pre-issues `D`
//! with its offer, a note settled only by the funding's adaptor secret `t`
//! (which her completed signature in the funding reveals). Each fault at
//! the hub's end:
//!
//! - M1: the hub broadcasts the funding but its answer is lost: Alice's
//!   wallet opens the contract from the chain, reads `t` from the funding
//!   and settles `D`.
//! - M2: the hub takes Alice's pre-signature and never funds: nothing
//!   settles the note; she refunds her deposit after its timeout.
//! - M3: the hub pre-issues a sat short: Alice refuses the offer, signing
//!   nothing.
//! - M4: an opening resumed too late (the deposit's refund matures too
//!   soon for the funding to be sure of confirming first): the hub refuses.

mod common;

use std::time::Instant;

use bitcoin::Amount;
use common::{statement as mock, Env};
use lichen_hub::OpeningFault;
use lichen_proto::{deposit_timeout, Net};
use lichen_wallet::{Ask, Wallet};

#[test]
fn the_mint_is_alices_only_once_the_funding_is_out() {
    let env = Env::new("mint");
    let (rt, dir) = (&env.rt, &env.dir);
    // past the blocks M2 and M4 mine (the deposit's timeout and half of
    // it): a contract reaching T_close would be defaulted, its fee coin
    // leaving the hub's coins unconfirmed for the next opening
    let hub = env.hub("hub", |c| c.duration = 2_000);
    let ask = Ask { deposit: 400_000, liquidity: 1_000_000, reserve: 20_000 };
    let user = |name: &str| {
        let chain = env.chain(name);
        (Wallet::create(&dir.join(format!("{name}.json")), &hub.url).unwrap(), chain)
    };
    // the deposit paid from elsewhere (the harness), confirmed
    let pay = |addr: &bitcoin::Address, v: Amount| rt.fund(&addr.script_pubkey(), v).map(|_| ());

    // M1: the funding broadcast, the answer lost
    hub.set_opening_fault(OpeningFault::DropAnswer);
    let (mut alice, chain) = user("alice");
    let t = Instant::now();
    let err = alice.open_contract(&hub.url, &chain, &mock(), ask, chain.new_spk().unwrap(), &pay).unwrap_err();
    assert!(alice.contracts.is_empty() && alice.deposits[0].offered.is_some(), "the offer accepted is kept ({err:#})");
    let cid = alice.deposits[0].cid;
    assert_eq!(alice.balance(), 0);
    alice.claim_mint(&chain, cid).unwrap();
    assert!(alice.deposits.is_empty());
    assert!(alice.contracts[0].mint.as_ref().unwrap().claimed);
    assert_eq!(alice.balance(), ask.deposit);
    // the hub's book has it too: spendable
    alice.send(alice.address(), ask.deposit).unwrap();
    assert_eq!(hub.contracts().iter().filter(|c| c.0.cid() == cid).count(), 1);
    println!("LICHEN M1: the hub's answer lost ({err:#}); contract {cid} opened from the chain and its {} sats claimed with t read from the funding, in {:.1?}", ask.deposit, t.elapsed());

    // M2: the pre-signature taken, the funding never broadcast
    hub.set_opening_fault(OpeningFault::NeverFund);
    let (mut bob, chain) = user("bob");
    let err = bob.open_contract(&hub.url, &chain, &mock(), ask, chain.new_spk().unwrap(), &pay).unwrap_err();
    let cid = bob.deposits[0].cid;
    let (_, locked) = bob.deposits[0].offered.clone().expect("the offer accepted is kept");
    let not_out = bob.claim_mint(&chain, cid).unwrap_err();
    assert!(format!("{not_out:#}").contains("not out"), "{not_out:#}");
    assert_eq!((locked.note.owner, locked.note.value), (bob.address(), ask.deposit));
    rt.mine(u64::from(deposit_timeout(Net::Regtest))).unwrap();
    let refund = bob.refund(&chain, cid, Amount::from_sat(500)).unwrap();
    rt.mine(1).unwrap();
    assert!(rt.get_tx(&refund).is_ok());
    assert_eq!(bob.restore_notes().unwrap(), 0, "the note was never in the hub's book");
    println!("LICHEN M2: the hub never funded ({err:#}); Bob refunded {refund}, his note of {} sats never settled", ask.deposit);

    // M3: a mint a sat short: refused before anything is signed
    hub.set_opening_fault(OpeningFault::ShortMint);
    let (mut carol, chain) = user("carol");
    let err = carol.open_contract(&hub.url, &chain, &mock(), ask, chain.new_spk().unwrap(), &pay).unwrap_err();
    assert!(format!("{err:#}").contains("the deposit pre-issued is"), "{err:#}");
    assert!(carol.deposits[0].offered.is_none(), "nothing signed");
    println!("LICHEN M3: a short mint refused: {err:#}");

    // M4: resumed too late, with half the refund's timeout gone
    hub.set_opening_fault(OpeningFault::None);
    let (mut dave, chain) = user("dave");
    hub.set_opening_fault(OpeningFault::Refuse);
    dave.open_contract(&hub.url, &chain, &mock(), ask, chain.new_spk().unwrap(), &pay).unwrap_err();
    hub.set_opening_fault(OpeningFault::None);
    let cid = dave.deposits[0].cid;
    rt.mine(u64::from(deposit_timeout(Net::Regtest)) / 2).unwrap();
    let err = dave.resume_open(&hub.url, &chain, &mock(), Ask { deposit: 400_000, liquidity: 1_000_000, reserve: 20_000 }, cid).unwrap_err();
    assert!(format!("{err:#}").contains("matures too soon"), "{err:#}");
    println!("LICHEN M4: resumed too late: {err:#}");
}

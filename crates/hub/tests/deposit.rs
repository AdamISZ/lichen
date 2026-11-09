//! The user's side with no wallet and no node: Bitcoin through Esplora
//! (Blockstream's electrs on the regtest node), a deposit address paid
//! from elsewhere, payouts to an address of another wallet, dispute fees
//! from the contract's fee budget. The hubs keep their bitcoind wallets.
//!
//! - E1: open and withdraw cooperatively: the payout address receives
//!   `b + r_A`.
//! - E2: a hub that refuses folds: the exit played through Esplora
//!   (blocks every second), fees from the budget; the hub finds no ground
//!   and `request_timeout` pays Bob; his sweep takes the budget's rest to
//!   his payout address too.
//! - P: a hub short of coins refuses the ask at the deposit request,
//!   before any address is given or paid.
//! - R: a hub that never funds (the opening fails after the deposit):
//!   the deposit refunds by its timeout, not before.
//! - S: an opening that fails after the deposit, resumed with it at a
//!   small cap (2^16).
//!
//! Needs electrs (`LICHEN_ELECTRS`, or `electrs` on the PATH).

mod common;

use std::time::{Duration, Instant};

use bitcoin::Amount;
use common::{statement, Env};
use lichen_chain::electrs::Electrs;
use lichen_chain::{Chain, Net};
use lichen_hub::OpeningFault;
use lichen_wallet::dispute::Outcome;
use lichen_wallet::{Ask, Wallet};

const B: u32 = 300_000;

#[test]
fn a_user_with_no_wallet() {
    let mut env = Env::new("deposit");
    // the history anchored, a block every second (the exit, E2)
    env.anchor();
    env.mine_every(Duration::from_secs(1));
    let mut e = Electrs::start(env.rt.datadir(), env.rt.rpc_url()).unwrap();
    let node = |w: &str| env.chain(w);
    let refusing = |c: &mut lichen_hub::Config| c.refuse_folds = true;
    let (hub_e, hub_d, hub_s) = (env.hub("hub-e", |_| {}), env.hub("hub-d", refusing), env.hub("hub-s", |_| {}));
    let (rt, dir, seq) = (&env.rt, env.dir.clone(), env.seq.url.clone());
    // the user's Bitcoin: Esplora, nothing else; payouts to another wallet
    let esplora = Chain::esplora(&e.url, Net::Regtest).unwrap();
    let payee = node("payee");
    // the deposit paid from elsewhere (here, the harness), confirmed
    let pay = |addr: &bitcoin::Address, v: Amount| rt.fund(&addr.script_pubkey(), v).map(|_| ());
    let ask = Ask { deposit: 400_000, liquidity: 1_000_000, reserve: 20_000 };
    let minted = |w: &Wallet| {
        let start = Instant::now();
        while w.balance().unwrap() < ask.deposit {
            assert!(start.elapsed() < Duration::from_secs(60), "the deposit was never minted");
            rt.mine(1).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        }
    };

    // E1: open, withdraw cooperatively
    let mut alice = Wallet::create(&dir.join("alice.json"), &seq).unwrap();
    let to_alice = payee.new_spk().unwrap();
    let t = Instant::now();
    let held = alice.open_contract(&hub_e.url, &esplora, &statement(), ask, to_alice.clone(), &pay).unwrap();
    println!("LICHEN E1: contract {} opened through Esplora in {:.1?} (deposit {} sats)", held.record.cid(), t.elapsed(), Wallet::deposit_amount(&ask, Net::Regtest).to_sat());
    assert!(alice.deposits.is_empty());
    minted(&alice);
    let fold = alice.withdraw(&hub_e.url, &statement(), held.record.cid(), u64::from(B)).unwrap();
    rt.mine(1).unwrap();
    let b = u64::from(B) / held.record.terms.unit.to_sat() * held.record.terms.unit.to_sat();
    assert_eq!(rt.get_tx(&fold).unwrap().output.iter().filter(|o| o.script_pubkey == to_alice).map(|o| o.value).sum::<Amount>(), Amount::from_sat(b + ask.reserve));
    println!("LICHEN E1: folded {fold}: {} sats to the payout address", b + ask.reserve);

    // P: a hub with too few coins for the ask refuses it at the deposit
    // request: no address, nothing paid, no deposit kept
    let hub_p = env.hub("hub-p", |_| {});
    // its coin spent elsewhere but for 100,000 sats
    let p = node("hub-p");
    p.pay(&node("payee").new_spk().unwrap(), p.balance_pending().unwrap() - Amount::from_sat(110_000)).unwrap();
    let mut erin = Wallet::create(&dir.join("erin.json"), &seq).unwrap();
    let paid = std::cell::Cell::new(false);
    let err = erin
        .open_contract(&hub_p.url, &esplora, &statement(), ask, payee.new_spk().unwrap(), &|_, _| {
            paid.set(true);
            Ok(())
        })
        .unwrap_err();
    assert!(format!("{err:#}").contains("can't fund a contract"), "{err:#}");
    assert!(!paid.get() && erin.deposits.is_empty(), "refused before a deposit address: {err:#}");
    println!("LICHEN P: {err:#}");

    // R: the hub never funds (here: it refuses the opening): refund by the
    // timeout
    let mut carol = Wallet::create(&dir.join("carol.json"), &seq).unwrap();
    let to_carol = payee.new_spk().unwrap();
    hub_e.set_opening_fault(OpeningFault::Refuse);
    let err = carol.open_contract(&hub_e.url, &esplora, &statement(), ask, to_carol.clone(), &pay).unwrap_err();
    hub_e.set_opening_fault(OpeningFault::None);
    assert_eq!(carol.deposits.len(), 1, "the deposit is kept ({err:#})");
    let cid = carol.deposits[0].cid;
    let early = carol.refund(&esplora, cid, Amount::from_sat(500)).unwrap_err();
    assert!(format!("{early:#}").contains("can be refunded from height"), "{early:#}");
    rt.mine(u64::from(lichen_proto::deposit_timeout(Net::Regtest))).unwrap();
    let mut refunded = None;
    for _ in 0..50 {
        // electrs catching up with the blocks just mined
        match carol.refund(&esplora, cid, Amount::from_sat(500)) {
            Ok(txid) => {
                refunded = Some(txid);
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    let refund = refunded.expect("the refund");
    rt.mine(1).unwrap();
    assert_eq!(rt.get_tx(&refund).unwrap().output[0], bitcoin::TxOut { value: Wallet::deposit_amount(&ask, Net::Regtest) - Amount::from_sat(500), script_pubkey: to_carol });
    assert!(carol.deposits.is_empty());
    println!("LICHEN R: the opening failed ({err:#}); refunded {refund} after {} blocks", lichen_proto::deposit_timeout(Net::Regtest));

    // S: an opening refused after the deposit, resumed with the same
    // deposit on terms the hub takes (a small cap: 2^16, below the floors
    // a dispute's links take, which the hub's first measure once tripped on)
    let mut dave = Wallet::create(&dir.join("dave.json"), &seq).unwrap();
    let small = Ask { deposit: 30_000, liquidity: 35_535, reserve: 20_000 };
    // (hub-s's first opening: its floors are measured at this small cap)
    hub_s.set_opening_fault(OpeningFault::Refuse);
    dave.open_contract(&hub_s.url, &esplora, &statement(), small, payee.new_spk().unwrap(), &pay).unwrap_err();
    hub_s.set_opening_fault(OpeningFault::None);
    let cid = dave.deposits[0].cid;
    let held = dave.resume_open(&hub_s.url, &esplora, &statement(), small, cid).unwrap();
    // the cap 65,535 scaled: 127 units of 517 sats
    assert_eq!((held.record.cid(), held.record.terms.v_max().to_sat()), (cid, 65_659));
    assert!(dave.deposits.is_empty());
    println!("LICHEN S: contract {cid} refused at a cap of 2^25, resumed with its deposit at 2^16 (the hub's reserve {} sats)", held.record.terms.reserve_hub.to_sat());

    // E2: the exit through Esplora
    let mut bob = Wallet::create(&dir.join("bob.json"), &seq).unwrap();
    let to_bob = payee.new_spk().unwrap();
    let held = bob.open_contract(&hub_d.url, &esplora, &statement(), ask, to_bob.clone(), &pay).unwrap();
    let cid = held.record.cid();
    minted(&bob);
    bob.withdraw(&hub_d.url, &statement(), cid, u64::from(B)).unwrap_err();
    e.wait_synced(rt.datadir(), rt.rpc_url()).unwrap();
    let budget = bob.fees_for(cid).unwrap().balance(&esplora).unwrap();
    let t = Instant::now();
    let (outcome, swept) = bob.exit(&esplora, &statement(), cid).unwrap();
    let left = bob.fees_for(cid).unwrap().balance(&esplora).unwrap();
    println!("LICHEN E2: {outcome:?} in {:.1?}; swept {swept:?}; the fee budget {} -> {} sats", t.elapsed(), budget.to_sat(), left.to_sat());
    assert!(matches!(outcome, Outcome::HubTimedOut(_)), "{outcome:?}");
    let (txid, value) = swept.expect("swept");
    assert_eq!(budget, lichen_proto::fee_budget(Net::Regtest));
    let sweep = esplora.get_tx(&txid).unwrap();
    assert!(sweep.output.iter().all(|o| o.script_pubkey == to_bob), "swept to the payout address");
    assert!(value > Amount::from_sat(u64::from(B) / 2), "{value}");
    // the sweep took what was left of the budget, so there is nothing for
    // sweep-fees
    let budget_spk = bob.fees_for(cid).unwrap().spk();
    let from_budget: Amount = sweep.input.iter().map(|i| esplora.get_tx(&i.previous_output.txid).unwrap().output[i.previous_output.vout as usize].clone()).filter(|o| o.script_pubkey == budget_spk).map(|o| o.value).sum();
    assert!(from_budget > Amount::ZERO && from_budget <= budget, "the budget's rest swept: {from_budget}");
    bob.sweep_fees(&esplora, cid, Amount::from_sat(500), false).unwrap_err();
    println!("LICHEN E2: the sweep took the fee budget's rest, {} sats", from_budget.to_sat());
}

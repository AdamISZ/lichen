//! The user's side with no wallet and no node: Bitcoin through Esplora
//! (Blockstream's electrs on the regtest node), a deposit address paid
//! from elsewhere, payouts to an address of another wallet, dispute fees
//! from the contract's fee budget. The hubs keep their bitcoind wallets.
//!
//! - E1: open and withdraw cooperatively: the payout address receives
//!   `b + r_A`.
//! - E2: a hub that refuses and disputes true claims: the whole search
//!   played through Esplora (blocks every second), fees from the budget;
//!   Alice proves the last step and is paid; the budget's rest is swept
//!   to her payout address.
//! - R: a hub that never funds (the opening fails after the deposit):
//!   the deposit refunds by its timeout, not before.
//! - S: an opening that fails after the deposit, resumed with it at a
//!   small cap (2^16).
//!
//! Needs electrs (`LICHEN_ELECTRS`, or `electrs` on the PATH).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::Amount;
use bitcoincore_rpc::{Auth, RpcApi};
use lichen_chain::electrs::Electrs;
use lichen_chain::{Chain, Net};
use lichen_hub::{Config, Hub};
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_proto::Statement;
use lichen_sequencer::{Client, Sequencer};
use lichen_wallet::dispute::Outcome;
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;

const B: u32 = 300_000;

fn statement() -> Statement {
    Statement::Mock { session: 1000, returns: vec![(B, 1000)] }
}

fn background(stop: &Arc<AtomicBool>, every: Duration, f: impl Fn() + Send + 'static) {
    let s = stop.clone();
    std::thread::spawn(move || {
        while !s.load(Ordering::Relaxed) {
            f();
            std::thread::sleep(every);
        }
    });
}

#[test]
fn a_user_with_no_wallet() {
    let rt = Regtest::start_standard().unwrap();
    let mut e = Electrs::start(rt.datadir(), rt.rpc_url()).unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-deposit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let seq = Sequencer::start("127.0.0.1:0", None, regtest_sequencer(), HUB_KEY).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let url = seq.url.clone();
    background(&stop, Duration::from_millis(200), move || {
        let _ = Client::new(&url).and_then(|c| c.seal());
    });
    let node = |w: &str| Chain::connect(rt.rpc_url(), rt.cookie(), w).unwrap();
    let hub_config = |name: &str, refuse: bool| Config {
        network: Net::Regtest,
        listen: "127.0.0.1:0".into(),
        sequencer: seq.url.clone(),
        rpc_url: rt.rpc_url().to_string(),
        cookie: rt.cookie().clone(),
        wallet: name.into(),
        statement: statement(),
        dir: dir.join(name),
        seed: format!("test-{name}"),
        l2_key: lichen_ledger::regtest_hub(),
        reserve_ppm: 20_000,
        max_bits: 24,
        duration: 2_000,
        refuse_folds: refuse,
        dispute_true_claims: refuse,
        first_cid: 1000,
    };
    for name in ["hub-e", "hub-d", "hub-s"] {
        rt.fund(&node(name).new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
    }
    let (hub_e, hub_d, hub_s) = (Hub::start(hub_config("hub-e", false)).unwrap(), Hub::start(hub_config("hub-d", true)).unwrap(), Hub::start(hub_config("hub-s", false)).unwrap());
    // the user's Bitcoin: Esplora, nothing else; payouts to another wallet
    let esplora = Chain::esplora(&e.url, Net::Regtest).unwrap();
    let payee = node("payee");
    // the deposit paid from elsewhere (here, the harness), confirmed
    let pay = |addr: &bitcoin::Address, v: Amount| rt.fund(&addr.script_pubkey(), v).map(|_| ());
    let ask = Ask { deposit: 400_000, bits: 21, reserve: 20_000 };
    let minted = |w: &Wallet| {
        let start = Instant::now();
        while w.balance().unwrap() < ask.deposit {
            assert!(start.elapsed() < Duration::from_secs(60), "the deposit was never minted");
            rt.mine(1).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        }
    };

    // E1: open, withdraw cooperatively
    let mut alice = Wallet::create(&dir.join("alice.json"), &seq.url).unwrap();
    let to_alice = payee.new_spk().unwrap();
    let t = Instant::now();
    let held = alice.open_contract(&hub_e.url, &esplora, &statement(), &dir.join("alice"), ask, to_alice.clone(), &pay).unwrap();
    println!("LICHEN E1: contract {} opened through Esplora in {:.1?} (deposit {} sats)", held.record.cid(), t.elapsed(), Wallet::deposit_amount(&ask, Net::Regtest).to_sat());
    assert!(alice.deposits.is_empty());
    minted(&alice);
    let fold = alice.withdraw(&hub_e.url, &statement(), &dir.join("alice"), held.record.cid(), u64::from(B)).unwrap();
    rt.mine(1).unwrap();
    assert_eq!(rt.get_tx(&fold).unwrap().output.iter().filter(|o| o.script_pubkey == to_alice).map(|o| o.value).sum::<Amount>(), Amount::from_sat(u64::from(B) + ask.reserve));
    println!("LICHEN E1: folded {fold}: {} sats to the payout address", u64::from(B) + ask.reserve);

    // R: the hub never funds (here: it refuses the cap): refund by the timeout
    let mut carol = Wallet::create(&dir.join("carol.json"), &seq.url).unwrap();
    let to_carol = payee.new_spk().unwrap();
    let too_big = Ask { bits: 25, ..ask };
    let err = carol.open_contract(&hub_e.url, &esplora, &statement(), &dir.join("carol"), too_big, to_carol.clone(), &pay).unwrap_err();
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
    assert_eq!(rt.get_tx(&refund).unwrap().output[0], bitcoin::TxOut { value: Wallet::deposit_amount(&too_big, Net::Regtest) - Amount::from_sat(500), script_pubkey: to_carol });
    assert!(carol.deposits.is_empty());
    println!("LICHEN R: the opening failed ({err:#}); refunded {refund} after {} blocks", lichen_proto::deposit_timeout(Net::Regtest));

    // S: an opening refused after the deposit, resumed with the same
    // deposit on terms the hub takes (a small cap: 2^16, below the floors
    // a dispute's links take, which the hub's first measure once tripped on)
    let mut dave = Wallet::create(&dir.join("dave.json"), &seq.url).unwrap();
    let small = Ask { deposit: 30_000, bits: 16, reserve: 20_000 };
    // (hub-s's first opening: its floors are measured at this small cap)
    dave.open_contract(&hub_s.url, &esplora, &statement(), &dir.join("dave"), Ask { bits: 25, ..small }, payee.new_spk().unwrap(), &pay).unwrap_err();
    let cid = dave.deposits[0].cid;
    let held = dave.resume_open(&hub_s.url, &esplora, &statement(), &dir.join("dave"), small, cid).unwrap();
    assert_eq!((held.record.cid(), held.record.terms.v_max().to_sat()), (cid, 65_535));
    assert!(dave.deposits.is_empty());
    println!("LICHEN S: contract {cid} refused at a cap of 2^25, resumed with its deposit at 2^16 (the hub's reserve {} sats)", held.record.terms.reserve_hub.to_sat());

    // E2: the whole dispute through Esplora, blocks every second
    let mut bob = Wallet::create(&dir.join("bob.json"), &seq.url).unwrap();
    let to_bob = payee.new_spk().unwrap();
    let held = bob.open_contract(&hub_d.url, &esplora, &statement(), &dir.join("bob"), ask, to_bob.clone(), &pay).unwrap();
    let cid = held.record.cid();
    minted(&bob);
    {
        let rpc = bitcoincore_rpc::Client::new(&format!("{}/wallet/harness", rt.rpc_url()), Auth::CookieFile(rt.cookie().clone())).unwrap();
        let addr = rpc.get_new_address(None, None).unwrap().assume_checked();
        background(&stop, Duration::from_secs(1), move || {
            let _ = rpc.generate_to_address(1, &addr);
        });
    }
    bob.withdraw(&hub_d.url, &statement(), &dir.join("bob"), cid, u64::from(B)).unwrap_err();
    e.wait_synced(rt.datadir(), rt.rpc_url()).unwrap();
    let budget = bob.fees_for(cid).unwrap().balance(&esplora).unwrap();
    let t = Instant::now();
    let (outcome, swept) = bob.dispute(&esplora, &statement(), &dir.join("bob"), cid, B, &statement().mock_input(B, cid).unwrap()).unwrap();
    let left = bob.fees_for(cid).unwrap().balance(&esplora).unwrap();
    println!("LICHEN E2: {outcome:?} in {:.1?}; swept {swept:?}; the fee budget {} -> {} sats", t.elapsed(), budget.to_sat(), left.to_sat());
    assert!(matches!(outcome, Outcome::Proved(_)), "{outcome:?}");
    let (txid, value) = swept.expect("swept");
    assert_eq!(budget, lichen_proto::fee_budget(Net::Regtest));
    assert!(left < budget, "the children were paid from the budget");
    let sweep = esplora.get_tx(&txid).unwrap();
    assert!(sweep.output.iter().all(|o| o.script_pubkey == to_bob), "swept to the payout address");
    assert!(value > Amount::from_sat(u64::from(B) / 2), "{value}");
    // what's left of the budget, to the payout address too (closed now)
    let sweep = bob.sweep_fees(&esplora, cid, Amount::from_sat(500), false).unwrap();
    assert_eq!(esplora.get_tx(&sweep).unwrap().output, vec![bitcoin::TxOut { value: left - Amount::from_sat(500), script_pubkey: to_bob }]);
    println!("LICHEN E2: the fee budget's {} sats swept to the payout address", (left - Amount::from_sat(500)).to_sat());
    stop.store(true, Ordering::Relaxed);
    let _ = std::fs::remove_dir_all(&dir);
}

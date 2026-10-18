//! The deposit's mint and the funding are a swap: the hub mints `D` with
//! its offer, to a key Alice can spend only once the funding is out (its
//! adaptor secret `t`, which her completed signature in the funding
//! reveals). Each fault at the hub's end:
//!
//! - M1: the hub broadcasts the funding but its answer is lost: Alice's
//!   wallet opens the contract from the chain, reads `t` from the funding
//!   and claims `D`.
//! - M2: the hub takes Alice's pre-signature and never funds: nothing can
//!   claim the mint; she refunds her deposit after its timeout, and the
//!   mint stays locked.
//! - M3: the hub mints a sat short: Alice refuses the offer, signing
//!   nothing.
//! - M4: an opening resumed too late (the deposit's refund matures too
//!   soon for the funding to be sure of confirming first): the hub refuses.

use std::time::Instant;

use bitcoin::Amount;
use lichen_chain::Chain;
use lichen_hub::{Config, Hub, OpeningFault};
use lichen_ledger::{regtest_sequencer, HUB_KEY};
use lichen_proto::{deposit_timeout, mint_owner, Net, Statement};
use lichen_sequencer::Sequencer;
use lichen_wallet::{Ask, Wallet};
use lngap_btc::regtest::Regtest;

/// The mock statement with an empty table (these tests never dispute).
fn mock() -> Statement {
    Statement::Mock { session: 0, returns: vec![] }
}

#[test]
fn the_mint_is_alices_only_once_the_funding_is_out() {
    let rt = Regtest::start_standard().unwrap();
    let dir = std::env::temp_dir().join(format!("lichen-mint-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let seq = Sequencer::start("127.0.0.1:0", None, regtest_sequencer(), HUB_KEY).unwrap();
    let hub_chain = Chain::connect(rt.rpc_url(), rt.cookie(), "hub").unwrap();
    rt.fund(&hub_chain.new_spk().unwrap(), Amount::from_sat(100_000_000)).unwrap();
    let hub = Hub::start(Config {
        network: Net::Regtest,
        listen: "127.0.0.1:0".into(),
        sequencer: seq.url.clone(),
        rpc_url: rt.rpc_url().to_string(),
        cookie: rt.cookie().clone(),
        wallet: "hub".into(),
        statement: mock(),
        dir: dir.join("hub"),
        seed: "test-hub".into(),
        l2_key: lichen_ledger::regtest_hub(),
        reserve_ppm: 20_000,
        max_bits: 24,
        duration: 500,
        refuse_folds: false,
        dispute_true_claims: false,
        first_cid: 1000,
        windows: None,
    })
    .unwrap();
    let ask = Ask { deposit: 400_000, bits: 21, reserve: 20_000 };
    let user = |name: &str| {
        let chain = Chain::connect(rt.rpc_url(), rt.cookie(), name).unwrap();
        (Wallet::create(&dir.join(format!("{name}.json")), &seq.url).unwrap(), chain)
    };
    // the deposit paid from elsewhere (the harness), confirmed
    let pay = |addr: &bitcoin::Address, v: Amount| rt.fund(&addr.script_pubkey(), v).map(|_| ());

    // M1: the funding broadcast, the answer lost
    hub.set_opening_fault(OpeningFault::DropAnswer);
    let (mut alice, chain) = user("alice");
    let t = Instant::now();
    let err = alice.open_contract(&hub.url, &chain, &mock(), &dir.join("alice"), ask, chain.new_spk().unwrap(), &pay).unwrap_err();
    assert!(alice.contracts.is_empty() && alice.deposits[0].offered.is_some(), "the offer accepted is kept ({err:#})");
    let cid = alice.deposits[0].cid;
    assert_eq!(alice.balance().unwrap(), 0);
    alice.claim_mint(&chain, cid).unwrap();
    assert!(alice.deposits.is_empty());
    assert!(alice.contracts[0].mint.as_ref().unwrap().claimed);
    assert_eq!(alice.balance().unwrap(), ask.deposit);
    assert_eq!(hub.contracts().iter().filter(|c| c.0.cid() == cid).count(), 1);
    println!("LICHEN M1: the hub's answer lost ({err:#}); contract {cid} opened from the chain and its {} sats claimed with t read from the funding, in {:.1?}", ask.deposit, t.elapsed());

    // M2: the pre-signature taken, the funding never broadcast
    hub.set_opening_fault(OpeningFault::NeverFund);
    let (mut bob, chain) = user("bob");
    let err = bob.open_contract(&hub.url, &chain, &mock(), &dir.join("bob"), ask, chain.new_spk().unwrap(), &pay).unwrap_err();
    let cid = bob.deposits[0].cid;
    let (_, locked) = bob.deposits[0].offered.clone().expect("the offer accepted is kept");
    let not_out = bob.claim_mint(&chain, cid).unwrap_err();
    assert!(format!("{not_out:#}").contains("not out"), "{not_out:#}");
    let mint = seq_note(&bob, locked.index);
    assert_eq!((mint.owner, mint.value), (mint_owner(&bob.address(), &locked.point).unwrap(), ask.deposit));
    rt.mine(u64::from(deposit_timeout(Net::Regtest))).unwrap();
    let refund = bob.refund(&chain, cid, Amount::from_sat(500)).unwrap();
    rt.mine(1).unwrap();
    assert!(rt.get_tx(&refund).is_ok());
    let state = bob.sequencer.state().unwrap();
    assert!(!state.is_spent(&seq_note(&bob, locked.index)), "the mint stays locked");
    assert_eq!(bob.balance().unwrap(), 0);
    println!("LICHEN M2: the hub never funded ({err:#}); Bob refunded {refund}, his mint of {} sats locked for good", ask.deposit);

    // M3: a mint a sat short: refused before anything is signed
    hub.set_opening_fault(OpeningFault::ShortMint);
    let (mut carol, chain) = user("carol");
    let err = carol.open_contract(&hub.url, &chain, &mock(), &dir.join("carol"), ask, chain.new_spk().unwrap(), &pay).unwrap_err();
    assert!(format!("{err:#}").contains("not the deposit minted to us"), "{err:#}");
    assert!(carol.deposits[0].offered.is_none(), "nothing signed");
    println!("LICHEN M3: a short mint refused: {err:#}");

    // M4: resumed too late, with half the refund's timeout gone
    hub.set_opening_fault(OpeningFault::None);
    let (mut dave, chain) = user("dave");
    let too_big = Ask { bits: 25, ..ask };
    dave.open_contract(&hub.url, &chain, &mock(), &dir.join("dave"), too_big, chain.new_spk().unwrap(), &pay).unwrap_err();
    let cid = dave.deposits[0].cid;
    rt.mine(u64::from(deposit_timeout(Net::Regtest)) / 2).unwrap();
    let err = dave.resume_open(&hub.url, &chain, &mock(), &dir.join("dave"), Ask { deposit: 400_000, bits: 21, reserve: 20_000 }, cid).unwrap_err();
    assert!(format!("{err:#}").contains("matures too soon"), "{err:#}");
    println!("LICHEN M4: resumed too late: {err:#}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn seq_note(w: &Wallet, index: u32) -> lichen_ledger::Note {
    *w.sequencer.state().unwrap().note(index).unwrap()
}

//! Coin selection from a node wallet: a coin selected is locked until it
//! is spent or freed, so two fundings offered at once take different
//! coins (on Mutinynet, two openings at once both took the hub's one
//! coin, and the second funding was refused as a double spend).

use bitcoin::Amount;
use lichen_chain::Chain;
use lngap_btc::regtest::Regtest;

#[test]
fn a_coin_selected_is_not_selected_again() {
    let rt = Regtest::start().unwrap();
    let node = Chain::connect(rt.rpc_url(), rt.cookie(), "alice").unwrap();
    for _ in 0..2 {
        rt.fund(&node.new_spk().unwrap(), Amount::from_btc(1.0).unwrap()).unwrap();
    }
    rt.mine(1).unwrap();
    let half = Amount::from_btc(0.5).unwrap();

    let a = node.select(half).unwrap();
    let b = node.select(half).unwrap();
    assert_eq!((a.len(), b.len()), (1, 1));
    assert_ne!(a[0].0, b[0].0, "the second selection took the first's coin");
    assert!(node.select(half).is_err(), "both coins are locked");

    // a failed funding frees its coins; a start frees all
    node.unlock(&[a[0].0]).unwrap();
    assert_eq!(node.select(half).unwrap()[0].0, a[0].0);
    node.unlock(&[]).unwrap();
    assert_eq!(node.select(Amount::from_btc(1.5).unwrap()).unwrap().len(), 2);
}

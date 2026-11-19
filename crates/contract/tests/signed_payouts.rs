//! A payout of a value the hub signed (`Core::pay_reduced`, for an L2
//! where the hub proves what Alice is owed) on regtest, under mainnet's
//! relay policy: confirmed, then every output `Core::owned` gives each
//! party spent by it, the hub's only after `delta`; Alice taking a hub
//! bit and the hub's reserve by `equiv_b` when it signed two values. And,
//! without a node: the Alice-signed builders unchanged under their old
//! names, and the hub's reserve below dust folding into the rest.

use bitcoin::script::Builder;
use bitcoin::{absolute, Amount, OutPoint, ScriptBuf, Transaction, TxOut};
use lichen_btc::keys::{xonly, Seed};
use lichen_btc::regtest::Regtest;
use lichen_btc::secp256k1::{Keypair, SECP256K1};
use lichen_btc::sighash::sign_tapscript;
use lichen_btc::taptree::{Leaf, TapTree};
use lichen_btc::tx::{build_spend, build_tx, Timelock};
use lichen_btc::witness::tapscript_witness;
use lichen_contract::*;
use lichen_wots::{WotsParams, WotsSecret, WotsSig};

/// What the hub signs it owes her: bits 2, 3, 5 and 8 set.
const B_REDUCED: u32 = 300;

struct Fixture {
    alice: PartyKeys,
    hub: PartyKeys,
    terms: Terms,
    params: ContractParams,
    pubs: [PartyPubKeys; 2],
    hub_b: WotsSecret,
}

fn fixture() -> Fixture {
    let alice = PartyKeys::from_seed(Role::User, Seed::from_label("alice"));
    let hub = PartyKeys::from_seed(Role::Hub, Seed::from_label("hub"));
    let terms = Terms {
        id: 1,
        unit: Amount::from_sat(1_000),
        bits: 10,
        low_bits: 0,
        deposit: 400,
        t_close: 100_000,
        reserve_alice: Amount::from_sat(20_000),
        reserve_hub: Amount::from_sat(100_000),
    };
    let pubs = [alice.public(), hub.public()];
    Fixture { alice, hub, terms, params: ContractParams::regtest(Amount::ZERO), pubs, hub_b: WotsSecret::from_entropy(WotsParams::for_bytes(4), [5; 32]) }
}

impl Fixture {
    fn core(&self) -> Core<'_> {
        Core { terms: &self.terms, params: &self.params, pubs: &self.pubs }
    }
    fn sign(&self, value: u32) -> WotsSig {
        self.hub_b.sign(&value.to_be_bytes()).unwrap()
    }
}

/// A signature's wire, as the payout's leaves take it (bottom first).
fn wire(sig: &WotsSig) -> Vec<Vec<u8>> {
    sig.consumption_order().into_iter().rev().collect()
}

/// A confirmed transaction paying `outs`, from an output anyone spends.
fn pay(rt: &Regtest, outs: Vec<TxOut>) -> Transaction {
    let leaf = Builder::new().push_int(1).into_script();
    let tree = TapTree::new(vec![Leaf::new("any", leaf.clone(), Timelock::NONE)]).unwrap();
    let fee = Amount::from_sat(5_000);
    let (op, _) = rt.fund(&tree.script_pubkey(), outs.iter().map(|o| o.value).sum::<Amount>() + fee).unwrap();
    let mut tx = build_spend(op, &Timelock::NONE, outs);
    tx.input[0].witness = tapscript_witness(&[], &leaf, &tree.control_block("any").unwrap());
    rt.send_and_confirm(&tx).unwrap();
    tx
}

/// A spend of `owned` to `kp`'s key, each under `kp` and `wire`.
fn sweep(owned: &[Owned], kp: &Keypair, wire: &[Vec<u8>]) -> Transaction {
    let total: Amount = owned.iter().map(|o| o.out.value).sum();
    let to = ScriptBuf::new_p2tr(SECP256K1, xonly(kp), None);
    let inputs: Vec<(OutPoint, _)> = owned.iter().map(|o| (o.op, o.sequence)).collect();
    let mut tx = build_tx(&inputs, vec![TxOut { value: total - Amount::from_sat(5_000), script_pubkey: to }], absolute::LockTime::ZERO);
    let prevouts: Vec<TxOut> = owned.iter().map(|o| o.out.clone()).collect();
    for (n, o) in owned.iter().enumerate() {
        tx.input[n].witness = o.witness(&tx, n, &prevouts, kp, wire).unwrap();
    }
    tx
}

/// Output `vout` of `tx` spent by `tree`'s `leaf` with `args`, under
/// `kp`'s signature, at once.
fn spend(tx: &Transaction, vout: u32, tree: &TapTree, leaf: &str, args: Vec<Vec<u8>>, kp: &Keypair) -> Transaction {
    let prev = tx.output[vout as usize].clone();
    let l = tree.leaf(leaf).unwrap();
    let to = ScriptBuf::new_p2tr(SECP256K1, xonly(kp), None);
    let mut s = build_tx(&[(OutPoint { txid: tx.compute_txid(), vout }, l.timelock.sequence())], vec![TxOut { value: prev.value - Amount::from_sat(3_000), script_pubkey: to }], absolute::LockTime::ZERO);
    let mut w = args;
    w.push(sign_tapscript(kp, &s, 0, std::slice::from_ref(&prev), &l.script).unwrap().as_ref().to_vec());
    s.input[0].witness = tapscript_witness(&w, &l.script, &tree.control_block(leaf).unwrap());
    s
}

#[test]
fn a_payout_the_hub_signed_on_regtest() {
    let rt = Regtest::start_standard().unwrap();
    let f = fixture();
    let (core, ctx, t) = (f.core(), f.core().ctx(), f.terms);
    let key = f.hub_b.public();
    let floors = Amount::from_sat(7_000);
    let available = core.value() - floors;
    let outs = core.pay_reduced(&key, available).unwrap();
    // the bits, her reserve to her payout address, the hub's less the floors
    assert_eq!(outs.len(), t.bits as usize + 2);
    assert_eq!(outs[t.bits as usize], TxOut { value: t.reserve_alice, script_pubkey: f.pubs[0].payout_spk.clone() });
    assert_eq!(outs[t.bits as usize + 1].value, t.reserve_hub - floors);
    let signed = wire(&f.sign(B_REDUCED));

    // Each party sweeps what it owns: hers at once, the hub's after delta.
    let payout = pay(&rt, outs.clone());
    let hers = core.owned(&payout, &key, Role::Hub, B_REDUCED, Role::User).unwrap();
    assert_eq!(hers.iter().map(|o| o.leaf.as_str()).collect::<Vec<_>>(), ["alice_bit_2", "alice_bit_3", "alice_bit_5", "alice_bit_8"]);
    rt.send_and_confirm(&sweep(&hers, &f.alice.payment, &signed)).unwrap();
    let its = core.owned(&payout, &key, Role::Hub, B_REDUCED, Role::Hub).unwrap();
    assert_eq!(its.len(), 7, "six clear bits and its reserve");
    assert_eq!(its.last().unwrap().leaf, "hub_reserve");
    let swept = sweep(&its, &f.hub.payment, &signed);
    // its payout confirmed one block before her sweep; delta - 2 more and
    // the next block is still within delta
    rt.mine(u64::from(f.params.delta) - 3).unwrap();
    assert!(rt.test_accept(&swept).is_err(), "the hub's outputs before delta");
    rt.mine(1).unwrap();
    rt.send_and_confirm(&swept).unwrap();

    // The hub signed two values: she takes a clear bit and its reserve by
    // equiv_b, at once.
    let payout = pay(&rt, outs);
    let equiv: Vec<Vec<u8>> = wire(&f.sign(B_REDUCED + 1)).into_iter().chain(signed.clone()).collect();
    let bit9 = bit_tree_signed(&ctx, 9, &key, Role::Hub).unwrap();
    rt.send_and_confirm(&spend(&payout, 9, &bit9, "equiv_b_9", equiv.clone(), &f.alice.payment)).unwrap();
    let reserve = reserve_tree_signed(&ctx, &t, &key, Role::Hub).unwrap();
    rt.send_and_confirm(&spend(&payout, t.bits + 1, &reserve, &format!("equiv_b_{}", t.bits), equiv.clone(), &f.alice.payment)).unwrap();
    // not with one value signed twice, nor by the hub
    let again: Vec<Vec<u8>> = signed.iter().chain(&signed).cloned().collect();
    assert!(rt.test_accept(&spend(&payout, 7, &bit_out_tree(&f, 7), "equiv_b_7", again, &f.alice.payment)).is_err());
    assert!(rt.test_accept(&spend(&payout, 7, &bit_out_tree(&f, 7), "equiv_b_7", equiv, &f.hub.payment)).is_err());
}

fn bit_out_tree(f: &Fixture, i: u32) -> TapTree {
    bit_tree_signed(&f.core().ctx(), i, &f.hub_b.public(), Role::Hub).unwrap()
}

/// The hub's reserve less the floors, below dust, goes with the rest to
/// its payout address, outside `equiv_b`.
#[test]
fn the_hubs_reserve_below_dust_folds_into_the_rest() {
    let mut f = fixture();
    f.terms.low_bits = 2;
    let (core, t) = (f.core(), f.terms);
    let floors = t.reserve_hub - Amount::from_sat(100);
    let outs = core.pay_reduced(&f.hub_b.public(), core.value() - floors).unwrap();
    let bits = (t.bits - t.low_bits) as usize;
    assert_eq!(outs.len(), bits + 2, "no reserve output of the hub's");
    assert_eq!(outs[bits].script_pubkey, f.pubs[0].payout_spk);
    // bits 0 and 1 (3 units) and the 100 sats
    assert_eq!(outs[bits + 1], TxOut { value: Amount::from_sat(3_100), script_pubkey: f.pubs[1].payout_spk.clone() });
    // and her reserve must not be dust
    f.terms.reserve_alice = Amount::from_sat(100);
    assert!(f.core().pay_reduced(&f.hub_b.public(), f.core().value()).is_err());
}

/// The Alice-signed builders keep their names and their scripts.
#[test]
fn alice_signed_builders_are_unchanged() {
    let f = fixture();
    let (ctx, t) = (f.core().ctx(), f.terms);
    let b_key = WotsSecret::from_entropy(WotsParams::for_bytes(4), [6; 32]).public();
    for i in 0..t.bits {
        assert_eq!(bit_tree(&ctx, i, &b_key).unwrap().script_pubkey(), bit_tree_signed(&ctx, i, &b_key, Role::User).unwrap().script_pubkey());
        assert_eq!(bit_leaf(&ctx, i, &b_key, true).script, bit_leaf_signed(&ctx, i, &b_key, Role::User, true).script);
        assert_eq!(equiv_b_leaf(&ctx, i, &b_key).script, equiv_b_leaf_signed(&ctx, i, &b_key, Role::User).script);
    }
    assert_eq!(reserve_leaf(&ctx).script, reserve_leaf_signed(&ctx, Role::User).script);
    assert_eq!(reserve_tree(&ctx, &t, &b_key).unwrap().script_pubkey(), reserve_tree_signed(&ctx, &t, &b_key, Role::User).unwrap().script_pubkey());
    let available = f.core().value() - Amount::from_sat(7_000);
    let outs = payout_less(&ctx, &t, &b_key, available, Amount::ZERO, Amount::from_sat(7_000)).unwrap();
    assert_eq!(outs, payout_less_signed(&ctx, &t, &b_key, Role::User, available, Amount::ZERO, Amount::from_sat(7_000)).unwrap());
    assert_eq!(outs, f.core().pay_alice(&b_key, available).unwrap());
    // her bits wait delta; the hub's don't
    assert_eq!(bit_leaf(&ctx, 0, &b_key, true).timelock, Timelock::csv(f.params.delta));
    assert_eq!(bit_leaf(&ctx, 0, &b_key, false).timelock, Timelock::NONE);
    assert_eq!(bit_leaf_signed(&ctx, 0, &b_key, Role::Hub, true).timelock, Timelock::NONE);
    assert_eq!(bit_leaf_signed(&ctx, 0, &b_key, Role::Hub, false).timelock, Timelock::csv(f.params.delta));
}

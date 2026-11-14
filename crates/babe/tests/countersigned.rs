//! The countersigned exit's graph on regtest, under mainnet's relay
//! policy (papers/lichen-grants-v0.5.6): every link relayed at its floor,
//! the terminals mined, and their bit outputs spent by each leaf.
//!
//! - accepted: `request`, `correct`; after `w_A`, `accept` pays `b_corr`
//!   in bits (her set bit, the hub's clear bit after δ, her `equiv_corr`).
//! - proved: `request`, `correct`; a countersignature on another `b_corr`
//!   or another `U` is refused; `ack`, `assert`; after `Δ2`, `success`.
//! - timeouts: `request_timeout` pays `b` (SHA-256 key: her set bit after
//!   δ, the hub's clear bit, the hub's `equiv_b`); `ack_timeout` pays `b`.
//!
//! `challenge_assert` and what follows are v0.1's, unchanged
//! (tests/reveal.rs).

use std::collections::HashMap;

use lichen_babe::countersigned::{corr_bit_tree, Countersigned, Spec, Windows, Q_LEN, U_LEN};
use lichen_babe::reveal::{AdaptorKeys, LamportKey};
use lichen_babe::setup::DIGITS;
use lngap_btc::bitcoin::hashes::{sha256, Hash};
use lngap_btc::bitcoin::{absolute, Amount, OutPoint, ScriptBuf, Transaction, TxOut};
use lngap_btc::keys::{xonly, Seed};
use lngap_btc::regtest::Regtest;
use lngap_btc::secp256k1::{Keypair, SECP256K1};
use lngap_btc::sighash::sign_tapscript;
use lngap_btc::taptree::TapTree;
use lngap_btc::tx::build_tx;
use lngap_btc::witness::tapscript_witness;
use lngap_channel::{ChannelParams, CommitCtx, PartyKeys, Role};
use lngap_lamport::winternitz::{Wots256Secret, WotsParams, WotsSecret};
use lngap_sessions::session::{bit_tree, reserve_tree, Terms};
use lngap_sessions::skeleton::{sign_all, Presign};

const B: u32 = 600; // 0b10_0101_1000
const B_CORR: u32 = 300; // 0b01_0010_1100

struct Fixture {
    alice: PartyKeys,
    hub: PartyKeys,
    g: Countersigned,
    b: Wots256Secret,
    q: Wots256Secret,
    a_corr: Wots256Secret,
    a_u: Wots256Secret,
    corr: WotsSecret,
    u: WotsSecret,
    lamport: LamportKey,
}

fn fixture() -> Fixture {
    let alice = PartyKeys::from_seed(Role::User, Seed::from_label("alice"));
    let hub = PartyKeys::from_seed(Role::Hub, Seed::from_label("hub"));
    let w = |n: usize| WotsParams::for_bytes(n as u32);
    let b = Wots256Secret::from_entropy(w(4), [1; 32]);
    let q = Wots256Secret::from_entropy(w(Q_LEN), [2; 32]);
    let a_corr = Wots256Secret::from_entropy(w(4), [3; 32]);
    let a_u = Wots256Secret::from_entropy(w(U_LEN), [4; 32]);
    let corr = WotsSecret::from_entropy(w(4), [5; 32]);
    let u = WotsSecret::from_entropy(w(U_LEN), [6; 32]);
    let hub_seed = Seed::from_label("hub/prover");
    let lamport = LamportKey::new(&hub_seed, DIGITS);
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
    let spec = Spec {
        terms,
        params: ChannelParams::regtest(Amount::ZERO),
        pubs: [alice.public(), hub.public()],
        b_key: b.public(),
        q_key: q.public(),
        a_corr_key: a_corr.public(),
        a_u_key: a_u.public(),
        corr_key: corr.public(),
        u_key: u.public(),
        lamport: lamport.public(),
        adaptor: AdaptorKeys::new(&hub_seed, DIGITS).public(),
        hmsg: vec![sha256::Hash::hash(b"msg").to_byte_array()],
        windows: Windows { w_h: 3, w_a: 4, delta2: 3, delta1: 3 },
    };
    Fixture { alice, hub, g: Countersigned::new(spec).unwrap(), b, q, a_corr, a_u, corr, u, lamport }
}

/// A funded contract: its pre-signed set, signed by both.
struct Contract {
    set: HashMap<String, Presign>,
    alice: HashMap<String, Vec<u8>>,
    hub: HashMap<String, Vec<u8>>,
}

impl Contract {
    fn open(rt: &Regtest, f: &Fixture) -> Contract {
        let (funding, _) = rt.fund(&f.g.tree().unwrap().script_pubkey(), f.g.value()).unwrap();
        let set = f.g.presign(funding).unwrap();
        let (alice, hub) = (sign_all(&set, &f.alice.payment).unwrap(), sign_all(&set, &f.hub.payment).unwrap());
        Contract { set: set.into_iter().map(|p| (p.name.clone(), p)).collect(), alice, hub }
    }
    fn tx(&self, name: &str, wire: Vec<Vec<u8>>) -> Transaction {
        self.set[name].finish(wire, &self.hub[name], &self.alice[name])
    }
    /// Relay a link at its floor (standard policy) and mine it.
    fn post(&self, rt: &Regtest, name: &str, wire: Vec<Vec<u8>>) -> Transaction {
        let tx = self.tx(name, wire);
        rt.send_and_confirm(&tx).unwrap_or_else(|e| panic!("{name}: {e:#}"));
        tx
    }
    /// Mine a terminal (its broadcaster would add a fee input).
    fn terminal(&self, rt: &Regtest, name: &str) -> Transaction {
        let tx = self.tx(name, vec![]);
        rt.mine_with_check(&tx).unwrap_or_else(|e| panic!("{name}: {e}"));
        tx
    }
}

fn request(f: &Fixture) -> Vec<Vec<u8>> {
    let q: Vec<u8> = (0..Q_LEN).map(|i| i as u8).collect();
    Countersigned::request_wire(&f.b.sign(&B.to_be_bytes()).unwrap(), &f.q.sign(&q).unwrap()).unwrap()
}

fn seeds() -> Vec<u8> {
    (0..U_LEN).map(|i| (i * 7 + 1) as u8).collect()
}

fn correct(f: &Fixture) -> Vec<Vec<u8>> {
    Countersigned::correct_wire(&f.corr.sign(&B_CORR.to_be_bytes()).unwrap(), &f.u.sign(&seeds()).unwrap()).unwrap()
}

/// `ack`: the hub's signatures, and hers on `b_corr` and `u`.
fn ack(f: &Fixture, b_corr: u32, u: &[u8]) -> Vec<Vec<u8>> {
    Countersigned::ack_wire(&f.corr.sign(&B_CORR.to_be_bytes()).unwrap(), &f.a_corr.sign(&b_corr.to_be_bytes()).unwrap(), &f.u.sign(&seeds()).unwrap(), &f.a_u.sign(u).unwrap())
}

/// Spend output `vout` of `tx` (tree `tree`, leaf `leaf`) with `args`
/// (bottom first) under `kp`'s signature, relayed.
fn spend(rt: &Regtest, tx: &Transaction, vout: u32, tree: &TapTree, leaf: &str, args: Vec<Vec<u8>>, kp: &Keypair) {
    let prev = tx.output[vout as usize].clone();
    let l = tree.leaf(leaf).unwrap();
    let to = ScriptBuf::new_p2tr(SECP256K1, xonly(kp), None);
    let mut s = build_tx(&[(OutPoint { txid: tx.compute_txid(), vout }, l.timelock.sequence())], vec![TxOut { value: prev.value - Amount::from_sat(3_000), script_pubkey: to }], absolute::LockTime::ZERO);
    let sig = sign_tapscript(kp, &s, 0, std::slice::from_ref(&prev), &l.script).unwrap();
    let mut w = args;
    w.push(sig.as_ref().to_vec());
    s.input[0].witness = tapscript_witness(&w, &l.script, &tree.control_block(leaf).unwrap());
    rt.send_and_confirm(&s).unwrap_or_else(|e| panic!("{leaf}: {e:#}"));
}

/// The output of `tx` paying bit `i` (bit outputs from `low_bits`, 0 here).
fn bit_out(i: u32) -> u32 {
    i
}

fn ctx(f: &Fixture) -> CommitCtx<'_> {
    f.g.core().ctx()
}

#[test]
fn countersigned_graph_on_regtest() {
    let rt = Regtest::start_standard().unwrap();
    let f = fixture();
    let d = f.g.spec.params.delta as u64;
    let w = f.g.spec.windows;
    let mut sizes = vec![];

    // ---- accepted ----
    let c = Contract::open(&rt, &f);
    rt.mine(u64::from(f.g.spec.params.to_self_delay)).unwrap();
    let rq = c.post(&rt, "request", request(&f));
    sizes.push(("request", rq.vsize(), rq.input[0].witness.len() - 2));
    let co = c.post(&rt, "correct", correct(&f));
    sizes.push(("correct", co.vsize(), co.input[0].witness.len() - 2));
    rt.mine(u64::from(w.w_a) - 2).unwrap();
    assert!(rt.mine_with_check(&c.tx("accept", vec![])).is_err(), "accept before w_A");
    rt.mine(1).unwrap();
    let acc = c.terminal(&rt, "accept");
    // B_CORR's bit 8 is set: hers, at once, by the hub's signature
    let corr_sig = f.corr.sign(&B_CORR.to_be_bytes()).unwrap();
    let wire = Countersigned::word_wire(&corr_sig);
    spend(&rt, &acc, bit_out(8), &corr_bit_tree(&ctx(&f), 8, &f.g.spec.corr_key).unwrap(), "alice_corr_bit_8", wire.clone(), &f.alice.payment);
    // bit 9 clear: the hub's, after δ
    rt.mine(d).unwrap();
    spend(&rt, &acc, bit_out(9), &corr_bit_tree(&ctx(&f), 9, &f.g.spec.corr_key).unwrap(), "hub_corr_bit_9", wire.clone(), &f.hub.payment);
    // bit 7 clear, but the hub signed two values: hers by equiv_corr
    let other = Countersigned::word_wire(&f.corr.sign(&(B_CORR + 1).to_be_bytes()).unwrap());
    spend(&rt, &acc, bit_out(7), &corr_bit_tree(&ctx(&f), 7, &f.g.spec.corr_key).unwrap(), "equiv_corr_7", other.into_iter().chain(wire).collect(), &f.alice.payment);

    // ---- proved ----
    let c = Contract::open(&rt, &f);
    rt.mine(u64::from(f.g.spec.params.to_self_delay)).unwrap();
    c.post(&rt, "request", request(&f));
    c.post(&rt, "correct", correct(&f));
    // her countersignature must be on the hub's values, digit by digit
    let mut u_other = seeds();
    u_other[U_LEN - 1] ^= 1;
    for (what, wire) in [("another b_corr", ack(&f, B_CORR - 1, &seeds())), ("another U", ack(&f, B_CORR, &u_other))] {
        let r = rt.test_accept(&c.tx("ack", wire));
        assert!(r.is_err(), "ack countersigning {what} accepted");
        println!("ack countersigning {what}: refused ({})", r.unwrap_err());
    }
    let ak = c.post(&rt, "ack", ack(&f, B_CORR, &seeds()));
    sizes.push(("ack", ak.vsize(), ak.input[0].witness.len() - 2));
    let read = Countersigned::read_ack(&lngap_btc::witness::witness_args_consumption_order(&ak.input[0].witness)[2..]).unwrap();
    assert_eq!((read.0.message(), read.1.message()), (B_CORR.to_be_bytes().to_vec(), seeds()), "her countersignatures read back");
    let digits: Vec<u8> = (0..DIGITS).map(|i| (i % 4) as u8).collect();
    let asr = c.post(&rt, "assert", Countersigned::assert_wire(&f.lamport.sign(&digits), &[7u8; 64], &[9u8; 32]));
    sizes.push(("assert", asr.vsize(), asr.input[0].witness.len() - 2));
    rt.mine(u64::from(w.delta2)).unwrap();
    let su = c.terminal(&rt, "success");
    spend(&rt, &su, bit_out(5), &corr_bit_tree(&ctx(&f), 5, &f.g.spec.corr_key).unwrap(), "alice_corr_bit_5", Countersigned::word_wire(&corr_sig), &f.alice.payment);

    // ---- timeouts ----
    let c = Contract::open(&rt, &f);
    rt.mine(u64::from(f.g.spec.params.to_self_delay)).unwrap();
    c.post(&rt, "request", request(&f));
    rt.mine(u64::from(w.w_h)).unwrap();
    let rt_tx = c.terminal(&rt, "request_timeout");
    let b_sig = f.b.sign(&B.to_be_bytes()).unwrap();
    let wire = Countersigned::word_wire(&b_sig);
    let t = f.g.spec.terms;
    // bit 8 clear: the hub's at once; bit 9 set: hers after δ
    spend(&rt, &rt_tx, bit_out(8), &bit_tree(&ctx(&f), 8, &f.g.spec.b_key).unwrap(), "hub_bit_8", wire.clone(), &f.hub.payment);
    rt.mine(d).unwrap();
    spend(&rt, &rt_tx, bit_out(9), &bit_tree(&ctx(&f), 9, &f.g.spec.b_key).unwrap(), "alice_bit_9", wire.clone(), &f.alice.payment);
    // she signed two values of b: equiv_b gives the hub bit 6 and the
    // reserves
    let other = Countersigned::word_wire(&f.b.sign(&(B + 1).to_be_bytes()).unwrap());
    let equiv: Vec<Vec<u8>> = other.into_iter().chain(wire).collect();
    spend(&rt, &rt_tx, bit_out(6), &bit_tree(&ctx(&f), 6, &f.g.spec.b_key).unwrap(), "equiv_b_6", equiv.clone(), &f.hub.payment);
    spend(&rt, &rt_tx, t.bits - t.low_bits, &reserve_tree(&ctx(&f), &t, &f.g.spec.b_key).unwrap(), &format!("equiv_b_{}", t.bits), equiv, &f.hub.payment);

    let c = Contract::open(&rt, &f);
    rt.mine(u64::from(f.g.spec.params.to_self_delay)).unwrap();
    c.post(&rt, "request", request(&f));
    c.post(&rt, "correct", correct(&f));
    c.post(&rt, "ack", ack(&f, B_CORR, &seeds()));
    rt.mine(u64::from(w.w_h)).unwrap();
    c.terminal(&rt, "ack_timeout");

    println!("link       vsize  witness items");
    for (name, vsize, items) in sizes {
        println!("{name:<10} {vsize:>5}  {items:>5}");
    }
}

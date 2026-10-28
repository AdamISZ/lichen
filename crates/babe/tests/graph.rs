//! BABE's graph (`lichen_babe::graph`): the pre-signed set as both parties
//! build it, pinned; and each way a dispute ends, played on regtest under
//! mainnet's relay policy, with the real reveal and a stand-in for the
//! garbling (Alice holds a kept instance's `msg` when her proof is true).

use std::collections::HashMap;

use bitcoincore_rpc::json::{AddressType, SignRawTransactionInput};
use bitcoincore_rpc::RpcApi;
use lichen_babe::graph::{Babe, Spec, Windows};
use lichen_babe::reveal::{check_presigs, complete, extract, points, reveal_args, AdaptorKeys, LamportKey};
use lichen_babe::setup::{Hash, Secret, DIGITS};
use lichen_babe::vsss::{deal, Dealer};
use lngap_btc::bitcoin::hashes::{sha256, Hash as _};
use lngap_btc::bitcoin::{Amount, OutPoint, Transaction, TxIn, Txid};
use lngap_btc::keys::Seed;
use lngap_btc::regtest::Regtest;
use lngap_btc::witness::witness_args_consumption_order;
use lngap_channel::{ChannelParams, PartyKeys, Role};
use lngap_lamport::winternitz::{Wots256Secret, WotsParams, WotsSecret, WotsSig};
use lngap_sessions::session::Terms;
use lngap_sessions::skeleton::{sign_all, Presign, Signed};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// Both parties' secrets for a contract, and the hub's dealing.
struct Parties {
    alice: PartyKeys,
    hub: PartyKeys,
    b_key: WotsSecret,
    hub_b: Wots256Secret,
    lamport: LamportKey,
    adaptor: AdaptorKeys,
    msgs: Vec<[u8; 32]>,
    dealer: Dealer,
    dealing: lichen_babe::vsss::Dealing,
}

fn parties(label: &str) -> Parties {
    let rng = &mut ChaCha20Rng::from_seed(sha256::Hash::hash(label.as_bytes()).to_byte_array());
    let a = Seed::from_label(&format!("{label}/alice"));
    let (dealer, dealing) = deal(DIGITS, 2, rng);
    Parties {
        alice: PartyKeys::from_seed(Role::User, a.clone()),
        hub: PartyKeys::from_seed(Role::Hub, Seed::from_label(&format!("{label}/hub"))),
        b_key: WotsSecret::from_entropy(WotsParams::for_bytes(4), a.derive_bytes("b")),
        hub_b: Wots256Secret::from_entropy(WotsParams::for_bytes(4), Seed::from_label(&format!("{label}/hub")).derive_bytes("b")),
        lamport: LamportKey::new(&a, DIGITS),
        adaptor: AdaptorKeys::new(&a, DIGITS),
        msgs: (0..3).map(|_| core::array::from_fn(|_| rng.next_u32() as u8)).collect(),
        dealer,
        dealing,
    }
}

fn spec(p: &Parties, t_close: u32, t_a: u32) -> Spec {
    Spec {
        terms: Terms {
            id: 7,
            unit: Amount::from_sat(1),
            bits: 21,
            low_bits: 9,
            deposit: 500_000,
            t_close,
            reserve_alice: Amount::from_sat(20_000),
            reserve_hub: Amount::from_sat(100_000),
        },
        params: ChannelParams::regtest(Amount::from_sat(20_000_000)),
        pubs: [p.alice.public(), p.hub.public()],
        b_key: p.b_key.public(),
        hub_b: p.hub_b.public(),
        lamport: p.lamport.public(),
        adaptor: p.adaptor.public(),
        hmsg: p.msgs.iter().map(|m| sha256::Hash::hash(m).to_byte_array()).collect::<Vec<Hash>>(),
        windows: Windows { w_h: 6, t_a, delta2: 12, delta1: 6 },
    }
}

/// Both parties' signatures, Alice's on `wrongly_challenged` kept apart.
fn sign(set: &[Presign], p: &Parties) -> (Signed, HashMap<String, Vec<u8>>) {
    let mut alice = sign_all(set, &p.alice.payment).unwrap();
    let kept = alice.iter().filter(|(n, _)| Babe::withheld(n)).map(|(n, s)| (n.clone(), s.clone())).collect();
    alice.retain(|n, _| !Babe::withheld(n));
    (Signed { hub: sign_all(set, &p.hub.payment).unwrap(), alice }, kept)
}

#[test]
fn the_presigned_set() {
    let p = parties("babe/set");
    let babe = Babe::new(spec(&p, 1_000, 900)).unwrap();
    let set = babe.presign(OutPoint { txid: Txid::all_zeros(), vout: 0 }).unwrap();
    let names: Vec<&str> = set.iter().map(|x| x.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "default",
            "request",
            "request_timeout",
            "respond",
            "respond_timeout",
            "assert",
            "success",
            "challenge_assert",
            "failure",
            "wrongly_challenged_0",
            "wrongly_challenged_1",
            "wrongly_challenged_2"
        ]
    );
    // the chain: each link spends the previous one's output 0
    let links: Vec<&Presign> = set.iter().filter(|x| x.link).collect();
    assert_eq!(links.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), ["request", "respond", "assert", "challenge_assert"]);
    for w in links.windows(2) {
        assert_eq!(w[1].tx.input[0].previous_output, OutPoint { txid: w[0].tx.compute_txid(), vout: 0 }, "{} spends {}", w[1].name, w[0].name);
    }
    for x in &set {
        assert_eq!(x.tx.version.0, if Babe::withheld(&x.name) { 3 } else { 2 }, "{}: TRUC only against the challenge", x.name);
    }
    // the floors, out of the hub's reserve
    let mut prev = babe.value();
    for l in &links {
        println!("{}: floor {} sat", l.name, (prev - l.tx.output[0].value - l.tx.output[1].value).to_sat());
        prev = l.tx.output[0].value;
    }
    assert!(babe.value() - prev < babe.spec.terms.reserve_hub, "the floors and anchors fit the hub's reserve");
    // both sign and check; Alice keeps hers on wrongly_challenged
    let (signed, kept) = sign(&set, &p);
    assert_eq!(kept.len(), 3);
    let shown: Vec<Presign> = set.iter().filter(|x| !Babe::withheld(&x.name)).cloned().collect();
    signed.verify(&shown, &babe.spec.pubs).unwrap();
    for (n, s) in &kept {
        set.iter().find(|x| &x.name == n).unwrap().verify(&p.alice.public().payment, s).unwrap();
    }
    // the fingerprint: the trees and every pre-signed transaction
    let mut h = sha256::Hash::engine();
    use lngap_btc::bitcoin::hashes::HashEngine;
    for t in [babe.tree(), babe.requested(), babe.responded(), babe.asserted(), babe.challenged()] {
        h.input(t.unwrap().script_pubkey().as_bytes());
    }
    for x in &set {
        h.input(x.name.as_bytes());
        h.input(&lngap_btc::bitcoin::consensus::serialize(&x.tx));
        h.input(x.leaf.as_bytes());
        h.input(&x.control.serialize());
    }
    let fp = sha256::Hash::from_engine(h);
    println!("fingerprint: {} pre-signed, {fp}", set.len());
    assert_eq!(format!("{} pre-signed, {}", set.len(), &fp.to_string()[..16]), "12 pre-signed, 6b64a4fcb7f5b664");
}

// ----- on regtest -----

/// A contract funded and pre-signed, Alice's adaptor pre-signatures
/// checked by the hub.
struct Opened {
    p: Parties,
    babe: Babe,
    set: HashMap<String, Presign>,
    signed: Signed,
    kept: HashMap<String, Vec<u8>>,
    presigs: Vec<[lngap_btc::adaptor::AdaptorSig; 4]>,
}

fn open(rt: &Regtest, label: &str) -> Opened {
    let p = parties(label);
    let h = rt.height().unwrap();
    let babe = Babe::new(spec(&p, h + 2_000, h + 60)).unwrap();
    let (funding, _) = rt.fund(&babe.tree().unwrap().script_pubkey(), babe.value()).unwrap();
    let set = babe.presign(funding).unwrap();
    let msg = Babe::challenge_sighash(&set).unwrap();
    let pts = points(&p.dealing);
    let presigs = p.adaptor.presign(&msg, &pts);
    assert!(check_presigs(&p.adaptor.public(), &msg, &pts, &presigs));
    let (signed, kept) = sign(&set, &p);
    rt.mine(6).unwrap(); // request waits the channel's to_self_delay
    Opened { set: set.into_iter().map(|x| (x.name.clone(), x)).collect(), p, babe, signed, kept, presigs }
}

impl Opened {
    fn sigs(&self, name: &str) -> (&[u8], &[u8]) {
        (&self.signed.hub[name], self.signed.alice.get(name).or(self.kept.get(name)).unwrap())
    }
    /// Post link `name` with its wire, and mine it.
    fn link(&self, rt: &Regtest, name: &str, wire: Vec<Vec<u8>>) -> Transaction {
        let (h, a) = self.sigs(name);
        let tx = self.set[name].finish(wire, h, a);
        let (txid, _) = rt.send_and_confirm(&tx).unwrap_or_else(|e| panic!("{name}: {e:#}"));
        println!("{name}: {} vB", tx.vsize());
        rt.get_tx(&txid).unwrap()
    }
    /// Post terminal `name`, a coin of the node's wallet paying its fee.
    fn terminal(&self, rt: &Regtest, name: &str, wire: Vec<Vec<u8>>) -> Transaction {
        let p = &self.set[name];
        let (h, a) = self.sigs(name);
        let mut tx = p.finish(wire, h, a);
        let fee = Amount::from_sat(2 * (tx.vsize() as u64 + 120));
        // a confirmed coin of exactly the fee (TRUC spends no unconfirmed v2)
        let addr = rt.rpc.get_new_address(None, Some(AddressType::Bech32m)).unwrap().assume_checked();
        let (op, coin) = {
            let txid = rt.rpc.send_to_address(&addr, fee, None, None, None, None, None, None).unwrap();
            rt.mine(1).unwrap();
            let t = rt.get_tx(&txid).unwrap();
            let v = t.output.iter().position(|o| o.script_pubkey == addr.script_pubkey()).unwrap();
            (OutPoint { txid, vout: v as u32 }, t.output[v].clone())
        };
        tx.input.push(TxIn { previous_output: op, ..Default::default() });
        let utxos: Vec<SignRawTransactionInput> = [(tx.input[0].previous_output, &p.prevout), (op, &coin)]
            .iter()
            .map(|(op, o)| SignRawTransactionInput {
                txid: op.txid,
                vout: op.vout,
                script_pub_key: o.script_pubkey.clone(),
                redeem_script: None,
                amount: Some(o.value),
            })
            .collect();
        let tx = rt.rpc.sign_raw_transaction_with_wallet(&tx, Some(&utxos), None).unwrap().transaction().unwrap();
        let (txid, _) = rt.send_and_confirm(&tx).unwrap_or_else(|e| panic!("{name}: {e:#}"));
        println!("{name}: {} vB with its fee coin", tx.vsize());
        rt.get_tx(&txid).unwrap()
    }
    fn args(tx: &Transaction) -> Vec<Vec<u8>> {
        witness_args_consumption_order(&tx.input[0].witness)[2..].to_vec()
    }
    /// Alice's request of `b`, and the hub's response, read from it.
    fn request_and_respond(&self, rt: &Regtest, b: u32) -> Transaction {
        let req = self.link(rt, "request", Babe::request_wire(&self.p.b_key.sign(&b.to_be_bytes()).unwrap()));
        let alice_b = WotsSig::from_consumption_order(WotsParams::for_bytes(4), &Self::args(&req)).unwrap();
        let read = u32::from_be_bytes(alice_b.message().try_into().unwrap());
        self.link(rt, "respond", Babe::respond_wire(&self.p.hub_b.sign(&read.to_be_bytes()).unwrap(), &alice_b))
    }
    /// Alice asserts π1 (here, digits at random).
    fn assert(&self, rt: &Regtest) -> Transaction {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let digits: Vec<u8> = (0..DIGITS).map(|_| (rng.next_u32() % 4) as u8).collect();
        self.link(rt, "assert", Babe::assert_wire(&self.p.lamport.sign(&digits), &[1; 64], &[2; 32]))
    }
    /// The hub challenges: π1's secrets, from Alice's preimages on chain.
    fn challenge(&self, rt: &Regtest, asserted: &Transaction) -> Transaction {
        let args = Self::args(asserted);
        let (signed, _, _) = Babe::read_assert(&args).unwrap();
        let preimages: Vec<[u8; 20]> = signed.iter().map(|a| a[..].try_into().unwrap()).collect();
        let lpub = &self.babe.spec.lamport;
        let digits: Vec<u8> = preimages.iter().enumerate().map(|(d, x)| lpub.read(d, x).unwrap()).collect();
        let secrets: Vec<Secret> = digits.iter().enumerate().map(|(d, v)| self.p.dealer.reveal(d, *v)).collect();
        self.link(rt, "challenge_assert", Babe::challenge_wire(reveal_args(&preimages, &complete(&self.presigs, &digits, &secrets))))
    }
}

#[test]
fn every_ending_on_regtest() {
    let rt = Regtest::start_standard().unwrap();

    // a true claim, challenged: Alice reads the secrets, opens a kept
    // instance (the stand-in: its msg), and is paid
    let c = open(&rt, "babe/true");
    c.request_and_respond(&rt, 300_000);
    let asserted = c.assert(&rt);
    let challenged = c.challenge(&rt, &asserted);
    let (digits, secrets) = extract(&c.babe.spec.lamport, &c.presigs, &Opened::args(&challenged)).unwrap();
    assert!(digits.iter().zip(&secrets).enumerate().all(|(d, (v, s))| *s == c.p.dealer.reveal(d, *v)), "Alice reads π1's secrets");
    let paid = c.terminal(&rt, "wrongly_challenged_1", Babe::wrongly_wire(&c.p.msgs[1]));
    assert_eq!(&paid.output[..], &c.set["wrongly_challenged_1"].tx.output[..], "Alice's payout, in bits");
    assert!(paid.output.len() > 10);

    // a false claim: no msg, so after Δ1 the hub takes everything
    let c = open(&rt, "babe/false");
    c.request_and_respond(&rt, 300_000);
    let asserted = c.assert(&rt);
    c.challenge(&rt, &asserted);
    let early = rt.test_accept(&c.set["failure"].finish(vec![], c.sigs("failure").0, c.sigs("failure").1)).unwrap_err();
    assert!(early.contains("non-BIP68-final"), "not before Δ1: {early}");
    rt.mine(u64::from(c.babe.spec.windows.delta1) - 1).unwrap();
    c.terminal(&rt, "failure", vec![]);

    // the hub gone: after w_H Alice is paid her b unverified
    let c = open(&rt, "babe/hub-gone");
    c.link(&rt, "request", Babe::request_wire(&c.p.b_key.sign(&300_000u32.to_be_bytes()).unwrap()));
    rt.mine(u64::from(c.babe.spec.windows.w_h) - 1).unwrap();
    c.terminal(&rt, "request_timeout", vec![]);

    // Alice gone after the response: from T_A the hub takes it
    let c = open(&rt, "babe/alice-gone");
    c.request_and_respond(&rt, 300_000);
    rt.mine_to_height(c.babe.spec.windows.t_a).unwrap();
    c.terminal(&rt, "respond_timeout", vec![]);

    // a true claim the hub doesn't challenge: after Δ2, Alice is paid
    let c = open(&rt, "babe/unchallenged");
    c.request_and_respond(&rt, 300_000);
    c.assert(&rt);
    rt.mine(u64::from(c.babe.spec.windows.delta2) - 1).unwrap();
    c.terminal(&rt, "success", vec![]);

    // the hub can't respond with another b than Alice's
    let c = open(&rt, "babe/other-b");
    let req = c.link(&rt, "request", Babe::request_wire(&c.p.b_key.sign(&300_000u32.to_be_bytes()).unwrap()));
    let alice_b = WotsSig::from_consumption_order(WotsParams::for_bytes(4), &Opened::args(&req)).unwrap();
    let (h, a) = c.sigs("respond");
    let lie = c.set["respond"].finish(Babe::respond_wire(&c.p.hub_b.sign(&200_000u32.to_be_bytes()).unwrap(), &alice_b), h, a);
    assert!(rt.test_accept(&lie).is_err(), "the digits must agree");
}
